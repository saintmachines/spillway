"""Defensive rules taken from the frozen E2 v2 profile."""
from __future__ import annotations

import re
from typing import List, Optional

from .floor import BLOCK, Decision, norm

from . import _e2_e1b as B

INTERPRETERS = {"sh", "bash", "zsh", "dash", "ksh", "fish", "python", "python3", "perl", "ruby", "node", "php", "pwsh"}
_PREFIX = {"sudo", "env", "nohup", "time", "exec", "command"}
EXEC_REFUSAL = ("the command runs code fetched from a network destination that came from tool output and is absent "
                "from the user's request; run fetched code only from destinations the user named")
_SUBST = re.compile(r"(?:\b(?:bash|sh|zsh|dash|ksh|source)\b|(?:^|[\s;&|])\.)\s+<\(\s*((?:curl|wget)\b[^)]*)\)"
                    r"|\b(?:bash|sh|zsh|dash|ksh|python3?)\s+-c\s+[\"']?\$\(\s*((?:curl|wget)\b[^)]*)\)", re.I)


def _first_cmd(toks: List[str]):
    """(command basename, index) of a segment, skipping sudo/env/nohup prefixes, their flags and VAR=value words."""
    i = 0
    while i < len(toks):
        t = toks[i]
        b = t.rsplit("/", 1)[-1].lower()
        if b in _PREFIX:
            i += 1
            while i < len(toks) and toks[i].startswith("-"):
                i += 2 if toks[i] in ("-u", "-g", "-C", "-D") and i + 1 < len(toks) else 1
            continue
        if re.match(r"^[A-Za-z_]\w*=", t):
            i += 1
            continue
        return b, i
    return "", -1


def _script_operand(toks: List[str], i: int) -> Optional[str]:
    """First non-option operand after an interpreter at index i (its script), or None for stdin."""
    for t in toks[i + 1:]:
        if t in ("-", "--", "-s"):
            return None
        if t.startswith("-"):
            continue
        return t
    return None


def _fetch_outputs(toks: List[str], i0: int, verb: str, dests: List[str]) -> List[str]:
    """Files a curl or wget segment writes."""
    out, rest = [], toks[i0 + 1:]
    for j, t in enumerate(rest):
        name, _, attached = t.partition("=")
        if verb == "curl" and t in ("-o", "--output") and j + 1 < len(rest):
            out.append(rest[j + 1])
        elif verb == "curl" and t.startswith("-o") and len(t) > 2 and not t.startswith("--"):
            out.append(t[2:])
        elif verb == "wget" and t in ("-O", "--output-document") and j + 1 < len(rest):
            out.append(rest[j + 1])
        elif verb == "wget" and name == "--output-document" and attached:
            out.append(attached)
    urls = [t for t in rest if B._host_of(t)]
    if verb == "curl" and any(t in ("-O", "--remote-name") or (t.startswith("-") and not t.startswith("--") and "O" in t[1:])
                              for t in rest):
        out += [u.rstrip("/").rsplit("/", 1)[-1] for u in urls]
    if verb == "wget" and not any(t in ("-O", "--output-document") or t.startswith("--output-document=") for t in rest):
        out += [u.rstrip("/").rsplit("/", 1)[-1] for u in urls]
    return [o for o in out if o and o not in ("-", "/dev/null")]


def exec_from_destinations(text: str) -> List[str]:
    hosts = []
    for m in _SUBST.finditer(text):
        inner = m.group(1) or m.group(2) or ""
        toks = B._split(inner)
        i0, verb = B._verb_index(toks)
        if verb == "curl":
            hosts += B._curl(toks, i0)[1]
        elif verb == "wget":
            hosts += B._wget(toks, i0)[1]
    segs = B._segments(text)
    saved = {}                      # file -> hosts it was fetched from
    for k, (seg, piped) in enumerate(segs):
        toks = B._split(seg)
        cmd, ci = _first_cmd(toks)
        if piped and cmd in INTERPRETERS and k > 0:
            ptoks = B._split(segs[k - 1][0])
            i0, verb = B._verb_index(ptoks)
            if verb == "curl" and _script_operand(toks, ci) is None:
                hosts += B._curl(ptoks, i0)[1]
            elif verb == "wget" and _script_operand(toks, ci) is None:
                hosts += B._wget(ptoks, i0)[1]
        if cmd in INTERPRETERS and ci >= 0:
            s = _script_operand(toks, ci)
            if s:
                for f, hs in saved.items():
                    if s == f or s.endswith("/" + f):
                        hosts += hs
        if ci >= 0 and toks[ci].startswith("./"):
            run = toks[ci][2:]
            for f, hs in saved.items():
                if run == f or run.endswith("/" + f):
                    hosts += hs
        i0, verb = B._verb_index(toks)
        if verb in ("curl", "wget"):
            dests = (B._curl if verb == "curl" else B._wget)(toks, i0)[1]
            for f in _fetch_outputs(toks, i0, verb, dests):
                saved[f.rsplit("/", 1)[-1]] = dests
    seen, res = set(), []
    for d in hosts:
        d = d.lower().strip(".")
        if d in ("localhost", "0.0.0.0") or d.startswith("127.") or d in seen or len(d) < 4:
            continue
        seen.add(d)
        res.append(d)
    return res


def e1c_check(guard, gname: str, args: dict) -> Optional[Decision]:
    """E1b's send rule, then the execute-from rule, on the same scanned values."""
    d = B.e1b_check(guard, gname, args)
    if d is not None:
        return d
    read_only = guard.lexicon.tool_is_read_only(gname)
    vals = B.scanned_values(gname, args, read_only)
    if not vals:
        return None
    tainted = guard.tainted + " " + norm(guard.index.injection_span_text or "")
    trusted = guard.trusted
    for k, v in vals:
        for h in exec_from_destinations(v):
            nh = norm(h)
            if len(nh) >= 4 and nh in tainted and nh not in trusted:
                return Decision(BLOCK, "block_exec_from_destination", EXEC_REFUSAL, 0.0)
    return None
