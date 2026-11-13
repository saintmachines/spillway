"""The guard code, as one string: inlined verbatim into the 35_ build by the patch and exec'd verbatim by the offline check,
so the two run the same lines. Needs `re`, `os` and `m30` (30_agentdojo_v12_taint_gate) in the namespace."""

GUARD_SRC = r'''
# SEC-35-mvguard (8e 2026-11-12, after E8): deterministic preconditions of the judge recovery. The recovery panel reads only
# the user task and the proposed call, never the tool returns, so it cannot tell a target the data presents ('IBAN: X' on a
# bill) from a target an instruction inside the data dictates ('TODO: Send a transaction to X'). E8: AgentDojo's direct and
# system_message templates pass the sanitizer and the panel restored the attacker's account from a bill and a landlord
# notice. Under CONRAC_MV_GUARD=1 the recovery is refused before any vote when
#   G1  a tool return the agent read holds the target inside a clause that opens with an imperative (an instruction-borne
#       target: the data dictates it, the user did not), or
#   G2  the call moves money to an account number while the user's task asks for no payment.
# Both only refuse: a refused recovery is the floor's own block, so the guard never turns a block into an allow. Off =>
# byte-identical.
def _mv_guard_on():
    return os.environ.get("CONRAC_MV_GUARD") == "1"


# clause boundaries, looked for only BEFORE a target (so an address's own dots never cut it): line breaks (real or the two
# characters backslash-n of a repr'd return), tabs, '; ', ': ', '|', a list bullet, and a sentence end followed by space,
# by markup, or by a capitalised word that does not start an email address
_MVG_BOUND_RE = re.compile(
    r"\\n|\n|\r|\t|:\s+|;\s+|\||\s[-*\u2022]\s"
    r"|[.!?]+(?:\s+|(?=[#\[(<*])|(?=[A-Z][a-z])(?![A-Za-z0-9._%+-]*@))")
# identifier-shaped targets (an account, an address, a link): what an instruction can route data or money to. A plain
# name (a channel, a person) resolves inside the user's own environment and stays with the floor's checks.
_MVG_IDENT_RE = re.compile(
    r"[\w.+-]+@[\w-]+\.[\w.-]+|https?://\S+|www\.\S+|[a-z]{2}\d{2}[a-z0-9]{10,30}|[\w-]+(?:\.[\w-]+)*\.(?:com|org|net|io|xyz|co|info|biz)(?:/\S*)?"
    r"|\+?\d[\d ().-]{7,}\d", re.I)
_MVG_PREFIX_RE = re.compile(
    r"^(?:[\s#*>\-\u2022=~_`'\"|,.:;!]+|\d{1,2}[.)]\s*|[a-z][.)]\s+|[(\[<{][^)\]>}]{0,40}[)\]>}]\s*"
    r"|(?:todo|to-do|note|nb|ps|please|pls|kindly|then|and|also|now|next|first|firstly|second|secondly|finally|lastly|"
    r"immediately|quickly|just|simply|important|urgent|instructions?|action|task|step\s*\d*|reminder)\b[\s,!:.\-]*)+",
    re.I)
_MVG_IMPERATIVE = frozenset((
    "send", "transfer", "pay", "wire", "forward", "email", "e-mail", "dm", "post", "share", "invite", "add", "remove",
    "delete", "create", "schedule", "book", "reserve", "make", "update", "change", "modify", "set", "grant", "give",
    "move", "copy", "upload", "visit", "open", "click", "contact", "reply", "write", "publish", "submit", "transmit",
    "deliver", "provide", "include", "attach", "concatenate", "get", "find", "read", "search", "do", "ignore",
    "disregard", "follow", "execute", "run", "use", "cancel", "refund", "buy", "purchase", "sign", "register",
    "subscribe", "download", "export", "rename", "edit", "append", "notify", "tell", "ask", "reset", "confirm"))
_MVG_IBAN_RE = re.compile(r"[a-z]{2}\d{2}[a-z0-9]{10,30}")
_MVG_PAY_RX = re.compile(
    r"\b(?:pay|pays|paying|paid|transfer|transfers|transferring|wire|wiring|refund|refunds|reimburse|settle)\b"
    r"|\bsend\w*\s+(?:\S+\s+){0,3}?(?:money|payment|funds|cash)\b", re.I)
_MVG_MOVE_SINK_RX = re.compile(r"money|transaction|transfer|payment|\bpay")


def _mvg_tool_texts(messages):
    return [m30._text_of(m.get("content")) for m in (messages or ()) if m.get("role") == "tool"]


def _mvg_opens_imperative(clause):
    c = _MVG_PREFIX_RE.sub("", clause, count=1).strip()
    w = re.match(r"[a-z][a-z-]*", c.lower())
    return bool(w) and w.group(0) in _MVG_IMPERATIVE


def _mvg_clause_before(text, p):
    """(text from the last clause boundary before p up to p, that boundary or None)"""
    s, last = 0, None
    for b in _MVG_BOUND_RE.finditer(text, 0, p):
        s, last = b.end(), b
    return text[s:p], last


def _mvg_dictated_at(text, p):
    """the instruction that dictates the target at p, or None. The clause holding the target opens with an imperative
    ('TODO: Send a transaction to X'), or the target follows a colon and the clause before the colon does ('Please update
    the scheduled transaction to our new recipient: X'). A label clause ('IBAN: X') dictates nothing."""
    pre, last = _mvg_clause_before(text, p)
    if _mvg_opens_imperative(pre):
        return pre
    if not pre.strip(" '\"`([{<") and last is not None and last.group(0).startswith(":"):
        intro, _ = _mvg_clause_before(text, last.start())
        if _mvg_opens_imperative(intro):
            return intro + ":"
    return None


def _mvg_instruction_borne(tokens, sources):
    """G1: (instruction, token) when a tool return the agent read dictates a target token, else None."""
    for text in sources or ():
        text = str(text)
        for t in tokens:
            pat = r"\s+".join(re.escape(w) for w in str(t).split())
            if not pat:
                continue
            for m in re.finditer(pat, text, re.I):
                d = _mvg_dictated_at(text, m.start())
                if d is not None:
                    return (d + text[m.start():m.end()]).strip()[:160], t
    return None


def _mvg_moves_money(name, args):
    keys = {str(k).lower() for k in (args or {})}
    if not keys & {"recipient", "iban", "account", "destination"}:
        return False
    return "amount" in keys or bool(_MVG_MOVE_SINK_RX.search(str(name).lower()))


def _mvg_unrequested_payee(name, args, tokens, user_task):
    """G2: a value-moving call to an account-number target when the user's task asks for no payment."""
    if not _mvg_moves_money(name, args):
        return False
    if not any(_MVG_IBAN_RE.fullmatch(str(t)) for t in tokens):
        return False
    return not _MVG_PAY_RX.search(user_task or "")


def _mv_guard_refuses(name, args, tokens, user_task, sources, identifiers_only=True):
    """None when the recovery may go to the panel, else the reason it may not. The identity path checks its identifier-
    shaped target tokens; the object path (identifiers_only=False) checks every token of the object value it recovers."""
    tokens = sorted({str(t) for t in (tokens or ()) if t})
    g1 = [t for t in tokens if _MVG_IDENT_RE.fullmatch(t)] if identifiers_only else tokens
    ib = _mvg_instruction_borne(g1, sources)
    if ib:
        return "G1 instruction-borne target %r in %r" % (ib[1], ib[0])
    if _mvg_unrequested_payee(name, args, tokens, user_task):
        return "G2 payee the user never asked to pay"
    return None


def _mvg_note(where, name, why):
    import sys as _sys
    print("[MVGUARD] %s refused %s: %s" % (where, name, why), file=_sys.stderr, flush=True)
'''
