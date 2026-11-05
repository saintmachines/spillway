"""Ingress sanitizer: what the model reads from a tool return, after the floor has seen the raw return.

Three deterministic rewrites, in the order the evaluation harness applied them:

1. Forged chat-template turns are removed and residual control tokens neutralized
   (``<|im_start|>`` ChatML, ``<|start|>`` harmony, ``<start_of_turn>`` Gemma, ``[INST]``/``<<SYS>>``).
2. Injection-template regions (an ``<INFORMATION>`` block, "this is an important message from me ...")
   are replaced by ``[redacted-injected-instruction]``.
3. Agent-addressed regions (text inside tool DATA that addresses the agent about its own task, in any
   grammatical person) and payee-change claims ("our bank details have changed to IBAN ...") are
   replaced the same way. Human-directed text is kept.

Every removed region (steps 2 and 3) is appended verbatim to ``span_sink`` when one is given; the
floor's span veto later refuses any call whose target appears in a removed span.

The regexes, constants and function bodies come from the reference gate (patch series), and
CHANGELOG.md records the library checks. Two more kinds of change: the three switches are keyword arguments (paper defaults: all on) instead of
environment lookups. Several scans that took quadratic time on adversarial text run in linear time
with the same results. One regex alternative is rewritten, and the other scans find their candidates
once (see "Linear-time matching" below). The time of ``span_payload`` still grows with the
number of sender names times the length of the span.
"""

from __future__ import annotations

import re
from array import array
from bisect import bisect_left, bisect_right
from typing import List, Optional, Tuple

__all__ = ["sanitize", "neutralize_control_tokens", "redact_injected_imperatives",
           "agent_addressed_regions", "payee_claim_regions", "injection_template_spans"]

# ---------------------------------------------------------------------------------------------
# Forged chat-template turns and control tokens (the --chatml-guard ingress neutralizer).
# A FORGED TURN = an opener control token and everything up to its matching closer (or to
# end-of-text if the attacker leaves the turn open). The whole turn is removed because a weak
# backbone obeys the plaintext instruction even after the role markers are broken.
# ---------------------------------------------------------------------------------------------
_FORGED_TURN_RE = re.compile(
    r"<\|im_start\|>.*?(?:<\|im_end\|>|\Z)"        # ChatML (qwen etc.)
    r"|<\|start\|>.*?(?:<\|end\|>|\Z)"             # gpt-oss harmony
    r"|<start_of_turn>.*?(?:<end_of_turn>|\Z)"     # Gemma
    r"|\[INST\].*?(?:\[/INST\]|\Z)"                # Llama-2 / Mistral
    r"|<<SYS>>.*?(?:<</SYS>>|\Z)",
    re.DOTALL)
# Any residual stray control token (e.g. a lone closing <|im_end|> the attacker uses to break out
# of the real tool turn before opening forged ones) is defanged individually.
_CTRL_TOKEN_RE = re.compile(
    r"<\|[^|<>\n]{1,40}\|>"                 # ChatML / harmony singletons
    r"|</?(?:start|end)_of_turn>"           # Gemma
    r"|\[/?INST\]|<</?SYS>>"                # Llama-2 / Mistral
)


def neutralize_control_tokens(text, span_sink=None):
    """Return (sanitized_text, n_removed): redact whole forged turns, then defang residual stray
    control tokens. Only touches strings that actually carry a marker (clean text is unchanged).
    With ``span_sink``, each removed forged turn is appended to it."""
    if not isinstance(text, str):
        return text, 0
    if ("<|" not in text and "_of_turn>" not in text
            and "[INST" not in text and "[/INST" not in text
            and "<<SYS" not in text and "<</SYS" not in text):
        return text, 0
    cnt = [0]
    def _turn(_m):
        cnt[0] += 1
        if span_sink is not None:
            span_sink.append(_m.group(0))
        return "[redacted-forged-turn]"
    def _tok(_m):
        cnt[0] += 1
        return "[redacted-control-token]"
    text = _FORGED_TURN_RE.sub(_turn, text)
    text = _CTRL_TOKEN_RE.sub(_tok, text)
    return text, cnt[0]


# ---------------------------------------------------------------------------------------------
# Injection-template regions (the self-contained injection span: a 2nd-person task-hijack directed
# at the assistant), leaving legit page content intact.
# ---------------------------------------------------------------------------------------------
_INJ_TAG_RE = re.compile(r"<INFORMATION>.*?</INFORMATION>", re.S | re.I)
_INJ_TEMPLATE_RE = re.compile(
    r"(?:<INFORMATION>|this is an important message from me)"
    r".*?"
    r"(?:signed,\s*[^<\n]{0,40}|you can (?:now )?(?:solve|continue|proceed|do)\b[^<\n]*|</INFORMATION>|thanks!?)",
    re.S | re.I)

# a person-name-shaped sender only (letters, spaces, apostrophes, hyphens): a target (email, IBAN, URL, number)
# in the sender slot stays payload
_SENDER_CLAIM_RE = re.compile(r"(?:message\s+from\s+me,?\s*([a-z][a-z' -]{0,40}?)\s*,\s*to\s+you"
                              r"|\bsigned,?\s*([a-z][a-z' -]{0,40}?)\s*(?=$|\n|<|[.!](?:\s|$|<)))", re.I)   # senderclaim


def span_payload(span):
    """the injection span without the sender the injection claims to be (senderclaim)"""
    if not span:
        return span
    def _drop_name(m):
        nm = (m.group(1) or m.group(2) or "").strip()
        return m.group(0) if len(nm) < 3 else re.sub(re.escape(nm), " ", m.group(0), flags=re.I)
    return _SENDER_CLAIM_RE.sub(_drop_name, span)


# ---------------------------------------------------------------------------------------------
# agentaddr: the defining property of a prompt injection -- text inside tool DATA that addresses
# the AGENT about its own task (who it is, its final answer, the user's task, its prior instructions).
# Human-directed text ("please pay the amount to IBAN ...") never does, so it is kept. Region: an
# enclosing <TAG>...</TAG> block, else the paragraphs from the first to the last agent-addressing
# clause plus the directive paragraphs that follow it.
# ---------------------------------------------------------------------------------------------
_AGENT_NOUN = r"(?:ai|a\.i\.|assistant|agent|model|llm|chatbot|gpt[\w.-]*|claude|gemini|llama|qwen[\w.-]*)"
_AGENT_ADDR_RE = re.compile(
    r"(?:"
    r"\bto you,?\s+(?:the\s+)?[^.\n]{0,40}?\b" + _AGENT_NOUN + r"\b"
    r"|\baddressed\s+to\s+(?:you\b|(?:the\s+)?[^.\n]{0,30}?\b" + _AGENT_NOUN + r"\b)"
    r"|\b(?:before|after|instead\s+of)\s+(?:you\s+)?(?:can\s+)?(?:solve|solving|complete|completing|finish|finishing|produc\w*|giv\w*|writ\w*|continu\w*|answer\w*)\b[^.\n]{0,40}?\b(?:task|answer|response)\b"
    r"|\bfinal\s+answer\b"
    r"|\b(?:the\s+)?(?:user'?s|original|previous|initial)\s+(?:task|request|instructions?)\b"
    r"|\bignore\s+(?:all\s+|any\s+|the\s+|your\s+)?(?:previous|prior|above|earlier|other)\b"
    r"|\byou\s+are\s+(?:an?\s+)?(?:ai|language\s+model|assistant|agent)\b"
    r")", re.I)
# agentaddr2: the same property in any grammatical person and form -- the agent as third-person
# actor, forged turn markers without chat-template tokens, and dictated tool calls. Alternatives of
# _AGENT_ADDR_RE, so the region logic, the redaction and the injected-span sink stay the deployed ones.
_AGENT_ADDR2 = (
    r"\b(?:the|this|your|an?)\s+(?:(?:ai|a\.i\.|llm|language\s+model|chatbot)\s+)?(?:assistant|agent)\b"
    r"(?:\s*\([^)]{0,20}\))?\s+(?:(?:immediately|automatically|always|also|simply|then|first|now)\s+){0,2}"
    r"(?:needs?|should|must|has\s+to|have\s+to|is\s+(?:required|expected|asked|instructed)|shall|will\s+need|"
    r"first|then|now|completes?|finish(?:es)?|proceeds?|gets?|checks?|makes?|books?|reserves?|sends?|fetch(?:es)?|visits?|forwards?|emails?|transfers?|pays?|posts?|invites?|shares?)\b"
    r"|\b(?:requires?|asks?|instructs?|tells?|directs?|expects?)\s+the\s+(?:(?:ai|llm)\s+)?(?:assistant|agent)\s+to\b"
    r"|\b(?:step|action|task)\s+for\s+the\s+(?:(?:ai|llm)\s+)?(?:assistant|agent)\s+is\s+to\b"
    r"|\b(?:ai|a\.i\.|llm|language\s+model|chatbot)\s+(?:assistant|agent)\b"
    r"|\bthe\s+task\s+(?:that\s+)?I\s+gave\s+(?:it|you)\b"
    r"|\[(?:assistant|user|system)\](?:\s*\\n\s*|(?=[^\S\n]*\n)\s*)\[(?:instruction|response)\]"   # see below
    r"|\b[a-z]+(?:_[a-z]+)+\s+(?:function|tool)\b"
    r"|\bpassing\s+the\s+(?:parameters?|arguments?)\b"
    r"|\b(?:call|invoke|execute|run|use)\s+the\s+[a-z_]+\s+(?:function|tool)\b"
    r"|\b(?:function|tool)\s+call\b")
_AGENT_ADDR_RE = re.compile(_AGENT_ADDR_RE.pattern + "|" + _AGENT_ADDR2, re.I)
_TAG_BLOCK_RE = re.compile(r"<([A-Za-z][\w:-]{0,40})>(.*?)</\1>", re.S)
_TARGET_RE = re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+|https?://\S+|\bwww\.\S+|\b[A-Z]{2}\d{2}[A-Z0-9]{10,30}\b|\b[\w-]+\.(?:com|org|net|io|xyz)\b")
_DIRECTIVE_RE = re.compile(
    r"^\W*(?:[\w ]{0,30}=\s*)?(?:please\s+)?(?:send|forward|transfer|pay|create|invite|add|post|share|delete|remove|"
    r"email|schedule|update|change|visit|download|upload|execute|run|make|book|reserve|write|reply|move|grant|star|clone|"
    r"concatenate|find|get|say|tell|include)\b", re.I | re.M)


# ---------------------------------------------------------------------------------------------
# Linear-time matching. The patterns above are the reference gate's, except one alternative of
# _AGENT_ADDR2 (the last paragraph here). Run the way the reference runs them, some take quadratic time
# on text an attacker writes. The helpers below return the same matches: the Match objects of the same
# compiled patterns, so the same spans and groups, in the same order. Each one reads every character a
# bounded number of times.
#
# _INJ_TAG_RE, _INJ_TEMPLATE_RE and _TAG_BLOCK_RE are OPEN.*?CLOSE with a lazy DOTALL middle. finditer
# tries the pattern at every opener, and an opener with no closer after it scans to the end of the
# text, so k unclosed openers cost O(k * n). A match exists at an opener exactly when a closer starts at
# or after the opener's end. So the closers are found once, and the pattern runs only at an opener that
# has one. There the lazy scan stops at the first closer, which ends the match.
#
# The forged-turn-marker alternative of _AGENT_ADDR2 was \[...\]\s*(?:\\n|\n)\s*\[...\]. A real newline
# is itself \s, so on '[user]' and a run of newlines the two \s* tried every split of the run: O(run^2).
# That form matches in two cases only: a whitespace run that holds a real newline and ends at '[', or a
# whitespace run, an escaped newline (backslash, n), a second whitespace run and '['. The new form spells
# out the two cases, the first one with the lookahead (?=[^\S\n]*\n). It matches where the old form
# matched, with the same end, and goes over each run a bounded number of times.
# ---------------------------------------------------------------------------------------------
# The openers and closers of the two injection patterns. No opener can start inside another: '<' is only
# the first character of '<INFORMATION>', and no proper tail of either opener begins the sentence opener.
# So finditer meets every opener. Closers can overlap ('thanksigned,'), which _paired_matches handles.
_INJ_TAG_OPEN_RE = re.compile(r"(<INFORMATION>)", re.S | re.I)
_INJ_TAG_CLOSE_RE = re.compile(r"</INFORMATION>", re.S | re.I)
_INJ_TEMPLATE_OPEN_RE = re.compile(r"(<INFORMATION>|this is an important message from me)", re.S | re.I)
# A closer of _INJ_TEMPLATE_RE starts at a position exactly when one of these heads matches there: the
# tails (\s*[^<\n]{0,40}, [^<\n]*, !?) can all match the empty string.
_INJ_TEMPLATE_CLOSE_RE = re.compile(
    r"signed,|you can (?:now )?(?:solve|continue|proceed|do)\b|</INFORMATION>|thanks", re.S | re.I)
# _TAG_BLOCK_RE's opener and closer. An opener holds '<' only at its start, and so does a closer, so neither
# can overlap another of its kind and finditer finds them all. The name is the longest run that ends at '>'.
_TAG_OPEN_RE = re.compile(r"<([A-Za-z][\w:-]{0,40})>")
_TAG_CLOSE_RE = re.compile(r"</([A-Za-z][\w:-]{0,40})>")


def _paired_matches(pattern, open_re, close_re, text):
    """pattern.finditer(text) as a list, for a pattern OPEN.*?CLOSE (DOTALL). ``open_re`` matches an OPEN (in
    group 1) and ``close_re`` matches where a CLOSE starts."""
    found = None
    for found in close_re.finditer(text):
        pass
    if found is None:
        return []
    # The last closer starts where finditer's last match starts, or inside that match (a closer that overlaps
    # it, which finditer steps over). Any other closer start lies before it.
    last = found.start()
    for p in range(found.start() + 1, found.end()):
        if close_re.match(text, p):
            last = p
    out, pos = [], 0
    for o in open_re.finditer(text):
        if o.start() >= pos and o.end(1) <= last:
            m = pattern.match(text, o.start())
            if m is not None:
                out.append(m)
                pos = m.end()
    return out


def _inj_tag_matches(text):
    """_INJ_TAG_RE.finditer(text) as a list."""
    return _paired_matches(_INJ_TAG_RE, _INJ_TAG_OPEN_RE, _INJ_TAG_CLOSE_RE, text)


def _inj_template_matches(text):
    """_INJ_TEMPLATE_RE.finditer(text) as a list."""
    return _paired_matches(_INJ_TEMPLATE_RE, _INJ_TEMPLATE_OPEN_RE, _INJ_TEMPLATE_CLOSE_RE, text)


def _tag_block_matches(text):
    """_TAG_BLOCK_RE.finditer(text) as a list. The closer must carry the opener's own name, so the last
    closer is kept per name."""
    last = {}
    for c in _TAG_CLOSE_RE.finditer(text):
        last[c.group(1)] = c.start()
    out, pos = [], 0
    if not last:
        return out
    for o in _TAG_OPEN_RE.finditer(text):
        if o.start() >= pos and last.get(o.group(1), -1) >= o.end():
            m = _TAG_BLOCK_RE.match(text, o.start())
            if m is not None:
                out.append(m)
                pos = m.end()
    return out


def _sub_matches(matches, repl, text):
    """pattern.sub(repl, text) from the pattern's matches: ``repl`` is called once per match, in order. With no
    match the result is text[0:], which (as in sub) is text itself for a str and a str copy for a str subclass."""
    out, last = [], 0
    for m in matches:
        out.append(text[last:m.start()])
        out.append(repl(m))
        last = m.end()
    out.append(text[last:])
    return "".join(out)


# _DIRECTIVE_RE starts with ^\W* (MULTILINE). \W also takes the newline, so one run of non-word characters can
# hold many line starts, and search() rescans the rest of the run from each of them: O(run^2) on '!\n' repeated.
# The rest of the pattern does not look behind it, so a line start inside a run reaches only the positions the
# line start that opened the run already tried. Only that one is tried.
_NONWORD_RUN_RE = re.compile(r"\W*", re.I | re.M)


def _directive_search(seg):
    """_DIRECTIVE_RE.search(seg)."""
    run_end, p = -1, 0
    while True:
        if p > run_end:
            m = _DIRECTIVE_RE.match(seg, p)
            if m is not None:
                return m
            run_end = _NONWORD_RUN_RE.match(seg, p).end()
        nl = seg.find("\n", p)
        if nl < 0:
            return None
        p = nl + 1


def _paragraph_spans(text):
    spans, start = [], 0
    for m in re.finditer(r"\n\s*\n", text):
        spans.append((start, m.start()))
        start = m.end()
    spans.append((start, len(text)))
    return [s for s in spans if s[1] > s[0]]


# agentaddr2-scope: a tool return is one repr'd string whose line breaks are the
# two characters backslash-n, so the paragraph region of agentaddr spans the whole return and a hit wiped the
# typed data before the injection. When an agentaddr2
# form fires, the region runs from the start of the sentence or line that holds the first hit to the end of the return.
_AGENT_ADDR2_RE = re.compile(_AGENT_ADDR2, re.I)
# agentaddr-value: the end of the YAML value that holds a position. A tool
# return is YAML (real newlines) or its repr (escaped newlines); a folded scalar's continuation lines are indented deeper
# than the key that owns it. The owner is the hit's line if it starts an item/key, else the nearest earlier item/key line
# indented less; the value ends before the first later non-empty line indented no deeper than the owner.
_LINE_BREAK_RE = re.compile(r"\n|\\n")
_STRUCT_LINE_RE = re.compile(r"[ \t]*(?:-[ \t]|[A-Za-z_][\w-]{0,40}:(?:[ \t]|$))")


def _value_lines(text):
    out, s = [], 0
    for m in _LINE_BREAK_RE.finditer(text):
        out.append((s, m.start()))
        s = m.end()
    out.append((s, len(text)))
    return out


def _value_indent(text, a, b):
    seg = text[a:b]
    return len(seg) - len(seg.lstrip(" \t"))


def _value_end(text, pos):
    """End of the YAML value that holds pos; len(text) when the text has no item/key line (v3.1's scope)."""
    L = _value_lines(text)
    i = [k for k, (a, b) in enumerate(L) if a <= pos <= b][0]
    own = None
    indent_i = _value_indent(text, *L[i])   # computed once, not once per item/key line above (O(lines * len(line i)))
    for k in range(i, -1, -1):
        a, b = L[k]
        if _STRUCT_LINE_RE.match(text[a:b]) and (k == i or _value_indent(text, a, b) < indent_i):
            own = _value_indent(text, a, b)
            break
    if own is None:
        return len(text)
    for k in range(i + 1, len(L)):
        a, b = L[k]
        if text[a:b].strip() and _value_indent(text, a, b) <= own:
            return L[k - 1][1]
    return len(text)


_CLAUSE_BREAK_RE = re.compile(r"\n|\\n|[.!?](?=[\s\'\"])")


def _clause_start(text, pos):
    """Start of the sentence or line (a real or an escaped newline) that holds pos; the region runs from here to the
    end of the return, so the data before the injection stays and nothing after its first clause is shown."""
    start = 0
    for m in _CLAUSE_BREAK_RE.finditer(text, 0, pos):
        start = m.end()
    return start


# payeeclaim: a claim, inside data, that a payee's account changed ('bank
# details changed', 'our new IBAN', 'the previous account is no longer active', 'forwarding recipient') is the
# business-email-compromise pattern. Data cannot re-route money on its own word: the claim and the account it puts
# forward (the first IBAN within 400 characters after it, or the one just before it) join the injected regions, so
# the span veto keeps that account from the judge; the rest of the return, including the payee a bill names, stays.
_PC_ACCT = r"(?:iban|bank\s+accounts?|accounts?(?:\s+number)?|recipient|payee|beneficiary|routing(?:\s+details)?|payment\s+details)"
_PAYEE_CLAIM = (
    r"\b(?:bank(?:ing)?|account|payment|payee|remittance|wire|beneficiary)\s+(?:details|information|info|provider|account|number|data|routing)\s+"
    r"(?:have\s+|has\s+|had\s+)?(?:also\s+)?(?:been\s+|now\s+)?(?:changed|updated|moved|migrated|switched)\b"
    r"|\b(?:changed|switched|updated|moved)\s+(?:our|my|their|the|its)\s+(?:property\s+|bank(?:ing)?\s+)?(?:provider|bank|details|accounts?)\b"
    r"|\bmoved\b[^.\n]{0,40}\bto\s+a\s+new\s+bank\b"
    r"|\b(?:previous|old|former|originating|current|existing)\s+(?:bank\s+|payment\s+)?accounts?\b[^.\n]{0,80}?\b(?:no\s+longer|closed|inactive|deactivated|invalid|cannot\s+(?:accept|receive))\b"
    r"|\b(?:our|my|their|the|a)\s+(?:new|newly\s+\w+|updated|replacement|alternate)\s+(?:\w+\s+){0,2}" + _PC_ACCT + r"\b"
    r"|\bupdated\s+(?:\w+\s+){0,2}payment\s+details\b"
    r"|\b(?:update|change|redirect|re-?route|switch)\s+(?:the\s+)?(?:destination|recipient|payee|beneficiary|receiving)\s*(?:account|iban)?\b"
    r"|\bforwarding\s+(?:recipient|account)\b")
_PAYEE_CLAIM_RE = re.compile(_PAYEE_CLAIM, re.I)
_PC_BREAK = re.compile(r"\n|\\n|[.!?](?=[\s'\"])")
_PC_LINE = re.compile(r"\n|\\n")
_PC_IBAN_RE = re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{10,30}\b")


class _Breaks:
    """Every _PC_BREAK and every _PC_LINE match of one text, found once. The reference scanned the text from 0
    once per payee claim (O(n * claims)). A match is one or two characters and never covers a character that can
    start a match, so the scans the reference ran find these same matches, cut at their end position."""

    def __init__(self, text):
        self.text = text
        self.brk_ends = array("q", (b.end() for b in _PC_BREAK.finditer(text)))
        self.line_starts, self.line_ends = array("q"), array("q")
        for b in _PC_LINE.finditer(text):
            self.line_starts.append(b.start())
            self.line_ends.append(b.end())

    def last_break_end(self, pos):
        """The end of the last match of _PC_BREAK.finditer(text, 0, pos), or 0: a break that ends by pos, but not a
        '.', '!' or '?' that ends exactly at pos (with endpos pos its lookahead cannot read the next character).
        A break ending at pos is that one-character kind exactly when text[pos - 1] is '.', '!' or '?'."""
        k = bisect_right(self.brk_ends, pos)
        if k and self.brk_ends[k - 1] == pos and self.text[pos - 1] in ".!?":
            k -= 1
        return self.brk_ends[k - 1] if k else 0

    def last_line_end(self, pos):
        """The end of the last match of _PC_LINE.finditer(text, 0, pos), or 0."""
        k = bisect_right(self.line_ends, pos)
        return self.line_ends[k - 1] if k else 0

    def next_line_start(self, pos):
        """The start of _PC_LINE.search(text, pos), or len(text) when there is none."""
        k = bisect_left(self.line_starts, pos)
        return self.line_starts[k] if k < len(self.line_starts) else len(self.text)


def payee_claim_regions(text):
    out = []
    brk = None
    for m in _PAYEE_CLAIM_RE.finditer(text):
        if brk is None:
            brk = _Breaks(text)
        s = brk.last_break_end(m.start())
        end = m.end()
        ib = _PC_IBAN_RE.search(text, m.end(), m.end() + 400)     # the account the claim puts forward
        if ib:
            end = ib.end()
        else:                                                   # a claim after its account ('IBAN: ... (Note: previous account closed)')
            back = [x for x in _PC_IBAN_RE.finditer(text, max(0, m.start() - 200), m.start())]
            if back:
                s = brk.last_line_end(back[-1].start())
        out.append((s, brk.next_line_start(end)))
    out.sort()
    merged = []
    for a, b in out:
        if merged and a <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(b, merged[-1][1]))
        else:
            merged.append((a, b))
    return merged


def _in_last_span(starts, spans, pos):
    k = bisect_right(starts, pos)
    return k > 0 and pos < spans[k - 1][1]


def _first_at_or_after(sorted_positions, pos):
    k = bisect_left(sorted_positions, pos)
    return sorted_positions[k] if k < len(sorted_positions) else float("inf")


def agent_addressed_regions(text):
    """[(start, end)] of the regions to redact; [] when no clause addresses the agent."""
    if not isinstance(text, str) or not (_AGENT_ADDR_RE.search(text) or _PAYEE_CLAIM_RE.search(text)):
        return []
    regions = list(payee_claim_regions(text))   # payeeclaim
    covered = []
    for tm in _tag_block_matches(text):
        if _AGENT_ADDR_RE.search(tm.group(2)):
            regions.append((tm.start(), tm.end()))
            covered.append((tm.start(), tm.end()))
    # the blocks are disjoint and in order: a hit lies in one iff it lies in the last block starting at or before it
    cov_starts = [a for a, _b in covered]
    hits = [m.start() for m in _AGENT_ADDR_RE.finditer(text)
            if not _in_last_span(cov_starts, covered, m.start())]
    if hits and _AGENT_ADDR2_RE.search(text):   # agentaddr2-scope: a typed return keeps what precedes the injection
        regions.append((_clause_start(text, min(hits)), len(text)))
        hits = []
    if hits:
        paras = _paragraph_spans(text)
        # the hits are in order: a paragraph holds one iff the first hit at or after its start lies before its end
        idx = [i for i, (a, b) in enumerate(paras) if _first_at_or_after(hits, a) < b]
        lo, hi = min(idx), max(idx)
        # extend over the directive paragraphs right after the last addressing clause (a template often
        # puts the action on its own lines after the salutation)
        j = hi + 1
        while j < len(paras) and j <= hi + 3:
            seg = text[paras[j][0]:paras[j][1]]
            if _directive_search(seg) or _AGENT_ADDR_RE.search(seg) or re.match(r"\s*(signed|thanks|regards)", seg, re.I):
                hi = j
                j += 1
            else:
                break
        _r = (paras[lo][0], paras[hi][1])
        if not text[:_r[0]].strip() and not text[_r[1]:].strip():   # agentaddr-value (v3.3): the paragraph is
            _r = (_clause_start(text, min(hits)), _value_end(text, max(hits)))   # the whole return -> scope it to the value
        regions.append(_r)
    regions.sort()
    merged = []
    for a, b in regions:
        if merged and a <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(b, merged[-1][1]))
        else:
            merged.append((a, b))
    return merged


def redact_agent_addressed(text, span_sink=None):
    regs = agent_addressed_regions(text)
    if not regs:
        return text, 0
    out, last = [], 0
    for a, b in regs:
        out.append(text[last:a])
        if span_sink is not None:
            span_sink.append(text[a:b])
        out.append("[redacted-injected-instruction]")
        last = b
    out.append(text[last:])
    return "".join(out), len(regs)


def injection_template_spans(text) -> List[Tuple[int, int]]:
    """Convenience: [(start, end)] of the <INFORMATION> blocks and template spans in ``text``."""
    spans = [(m.start(), m.end()) for m in _inj_tag_matches(text)]
    spans += [(m.start(), m.end()) for m in _inj_template_matches(text)]
    return sorted(set(spans))


def redact_injected_imperatives(text, span_sink=None, *, agent_addressed: bool = True):
    """Mirror of the reference ``_redact_injected_imperatives``; ``agent_addressed`` replaces the
    SPW_INGRESS_AGENTADDR environment switch (paper default: on). Returns (text, n_regions)."""
    if not isinstance(text, str):
        return text, 0
    low = text.lower()
    if "<information>" not in low and "important message from me" not in low:
        if agent_addressed:   # agentaddr: no template -> the agent-addressing rule alone
            return redact_agent_addressed(text, span_sink)
        return text, 0
    n = [0]
    def _r(_m):
        n[0] += 1
        if span_sink is not None:
            span_sink.append(_m.group(0))
        return "[redacted-injected-instruction]"
    text = _sub_matches(_inj_tag_matches(text), _r, text)
    text = _sub_matches(_inj_template_matches(text), _r, text)
    if agent_addressed:   # agentaddr: a residual agent-addressing region outside the template
        text, _k = redact_agent_addressed(text, span_sink)
        n[0] += _k
    return text, n[0]


def sanitize(text: str, span_sink: Optional[list] = None, *,
             control_tokens: bool = True,
             injected_imperatives: bool = True,
             agent_addressed: bool = True,
             forged_turns_in_spans: bool = False) -> str:
    """Sanitize one tool-return text before the model reads it.

    The evaluation harness applied the control-token neutralizer (``--chatml-guard``) first and the
    injected-imperative redaction (``SPW_INGRESS_REDACT=1`` with ``SPW_INGRESS_AGENTADDR=1``)
    second, on the same string; this function does the same. Removed injection regions (not the
    forged turns) are appended to ``span_sink`` in order, as the raw text that was removed.

    Keyword switches (all on = the paper's configuration):
      control_tokens        forged chat-template turns and control tokens
      injected_imperatives  <INFORMATION> / "important message from me" template regions
      agent_addressed       agent-addressed clauses and payee-change claims outside a template

    ``forged_turns_in_spans`` also keeps forged turns in ``span_sink``, as ``Guard`` does, so that a
    target inside one stays out of the judge's reach. The evaluated build kept them out (off here).
    """
    if not isinstance(text, str):
        return text
    if control_tokens:
        text, _ = neutralize_control_tokens(text, span_sink if forged_turns_in_spans else None)
    if injected_imperatives:
        text, _ = redact_injected_imperatives(text, span_sink, agent_addressed=agent_addressed)
    elif agent_addressed:
        text, _ = redact_agent_addressed(text, span_sink)
    return text


def sanitize_message(msg: dict, span_sink: Optional[list] = None, **switches) -> int:
    """In-place sanitization of a chat message whose ``content`` is a str or a list of content
    blocks (``{"type": "text", "text"|"content": ...}``), as the evaluation harness did for every tool
    message. Returns the number of strings changed."""
    changed = 0
    c = msg.get("content")
    if isinstance(c, str):
        c2 = sanitize(c, span_sink, **switches)
        if c2 != c:
            msg["content"] = c2
            changed += 1
    elif isinstance(c, list):
        for blk in c:
            if not isinstance(blk, dict):
                continue
            for key in ("content", "text"):
                v = blk.get(key)
                if isinstance(v, str):
                    v2 = sanitize(v, span_sink, **switches)
                    if v2 != v:
                        blk[key] = v2
                        changed += 1
    return changed
