"""8e candidate fix for D1 (e2g = e2f 5ef33861 + this). Version 2.

Found in the e2f replay of AutoDojo 389 (gpt-4o-mini, 1.0.1): AgentDojo travel tools return Python dict reprs
({'Breizh Cafe': "Rating: ...\\n...", 'Le Baratin': "Rating: 4.8..."}), which json.loads rejects, so e2f's D1 runs its
sentence splitter on the whole text. An injected sentence whose final period is followed by a quote does not split
there, and the cut runs on to the next literal \\n, taking the next entry's name and rating with it (8 of 13 cut spans,
travel user_task_2 loses Le Baratin, the right answer).

Version 1 parsed such text and ran e2f's JSON walk. On AgentDyn H9 that raised D1 changes from 9 to 57-63 episodes
per run, because the JSON walk also applies the breakout rule, and GitHub values are often nested reprs that hold
"', '" by nature. Version 1 is withdrawn.

Version 2 applies only when the whole text is exactly the Python repr of a dict or list (repr(literal_eval(s)) == s)
and not JSON. Each string value (keys untouched, nested values included) then goes through the two rules e2f applies
to plain text, role blocks and tool mentions, in e2f's order, and the result is rendered with repr(). The breakout
rule is not applied, as e2f does not apply it to plain text. Every other text goes to e2f unchanged, and one boundary is added to
e2f's tool-mention splitter everywhere: a sentence end followed by a closing quote and a list or dict separator
('...hotel'.", 'New Asiaway'...). That keeps the cut inside the value when the text cannot be parsed, as in two AutoDojo
records whose dict the 1.0.1 runner had already cut short. A finer split can only remove less than e2f removes."""
import ast
import json
import re

LIMIT = 1_000_000


def _walk_plain(E, obj, tpat, found):
    if isinstance(obj, str):
        v, sp = E._neutralize_role_blocks(obj)
        found += [("role_delimiter", x) for x in sp]
        v, sp = E._neutralize_tool_mentions(v, tpat)
        found += [("tool_mention", x) for x in sp]
        return v
    if isinstance(obj, dict):
        return {k: _walk_plain(E, v, tpat, found) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_walk_plain(E, v, tpat, found) for v in obj]
    if isinstance(obj, tuple):
        return tuple(_walk_plain(E, v, tpat, found) for v in obj)
    return obj


def exact_repr(text):
    """The parsed dict or list when text (stripped) is exactly its Python repr and not JSON, else None."""
    if not isinstance(text, str) or not text:
        return None
    s = text.strip()
    if not (s[:1] in "{[" and s[-1:] in "}]") or len(s) > LIMIT:
        return None
    try:
        json.loads(s)
        return None
    except Exception:
        pass
    try:
        obj = ast.literal_eval(s)
    except Exception:
        return None
    if not isinstance(obj, (dict, list)):
        return None
    try:
        return obj if repr(obj) == s else None
    except Exception:
        return None


_SPLIT = re.compile(r"((?<=[.!?])\s+|(?<=[.!?])(?=[\'\"]\s*[,}\]])|\n+|\\n)")


def _neutralize_tool_mentions(E):
    def f(s, pat):
        if pat is None or not pat.search(s):
            return s, []
        spans, out = [], []
        for p in _SPLIT.split(s):
            if p and pat.search(p) and E._CALL_VERBS.search(pat.sub(" ", p)):
                spans.append(p)
                out.append(E.MARK)
            else:
                out.append(p)
        return "".join(out), spans
    return f


def patch(E):
    E._neutralize_tool_mentions = _neutralize_tool_mentions(E)
    orig = E.e2_ingress

    def e2_ingress(text, tool_names):
        obj = exact_repr(text)
        if obj is None:
            return orig(text, tool_names)
        found = []
        new = _walk_plain(E, obj, E._tool_name_pattern(tool_names), found)
        if not found:
            return text, []
        s = text.strip()
        lead = text[:len(text) - len(text.lstrip())]
        trail = text[len(text.rstrip()):]
        return lead + repr(new) + trail, found

    e2_ingress.__doc__ = "e2g v2 D1: " + (orig.__doc__ or "")
    E.e2_ingress = e2_ingress
    E.E2G_D1_LITERAL = 2
    return E
