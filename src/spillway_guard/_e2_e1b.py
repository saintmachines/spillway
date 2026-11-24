"""Defensive rules taken from the frozen E2 v2 profile."""
from __future__ import annotations

import re
import shlex
from typing import Iterable, List, Optional, Tuple

from .floor import BLOCK, Decision, norm

EXEC_TOOL_TOKENS = {"bash", "shell", "terminal", "exec", "execute", "run", "command", "cmd", "python", "ipython"}
EXEC_ARGS = {"command", "cmd", "commands", "script", "code"}

REFUSAL = ("the command sends local data to a network destination that came from tool output and is absent "
           "from the user's request; send data only to destinations the user named")

_SCHEME_URL = re.compile(r"\b(?:https?|ftp|wss?|rsync)://(?:[^@\s/'\"`<>]*@)?(\[[0-9a-f:]+\]|[^\s/:'\"`<>?#)\]]+)", re.I)
_IPV4 = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
_HOSTNAME = re.compile(r"^(?:[a-z0-9-]+\.)+[a-z]{2,24}$", re.I)
_EXPANSION = re.compile(r"\$\(|`|\$\{|\$[A-Za-z_]")
_NET_VERBS = {"curl", "wget", "scp", "rsync", "sftp", "nc", "ncat", "netcat", "telnet", "socat", "ssh", "ssh-copy-id", "git"}

# curl options that take a value (so the next token is not an operand)
_CURL_VAL = {"-d", "--data", "--data-binary", "--data-raw", "--data-urlencode", "--data-ascii", "--json", "-F", "--form",
             "--form-string", "-T", "--upload-file", "-H", "--header", "-o", "--output", "-u", "--user", "-A",
             "--user-agent", "-e", "--referer", "-b", "--cookie", "-c", "--cookie-jar", "-w", "--write-out", "-m",
             "--max-time", "--connect-timeout", "-K", "--config", "--resolve", "-X", "--request", "-E", "--cert",
             "--key", "--cacert", "-r", "--range", "-C", "--continue-at", "--retry", "-x", "--proxy", "-U",
             "--proxy-user", "--url", "-z", "--time-cond", "--limit-rate", "-Y", "--speed-limit", "-y", "--speed-time",
             "--interface", "--dns-servers", "-Q", "--quote", "--retry-delay", "--retry-max-time", "--max-filesize"}
_CURL_SEND = {"-d", "--data", "--data-binary", "--data-raw", "--data-urlencode", "--data-ascii", "--json", "-F", "--form",
              "--form-string", "-T", "--upload-file"}
_WGET_SEND = ("--post-data", "--post-file", "--body-data", "--body-file")
_WGET_VAL = {"-O", "--output-document", "-o", "--output-file", "-a", "--append-output", "-P", "--directory-prefix",
             "-U", "--user-agent", "--header", "--user", "--password", "-t", "--tries", "-T", "--timeout", "-e",
             "--execute", "-i", "--input-file", "--method", "--post-data", "--post-file", "--body-data", "--body-file",
             "--referer", "-Q", "--quota", "--limit-rate", "-w", "--wait"}
_SSH_VAL = {"-i", "-p", "-o", "-l", "-F", "-J", "-L", "-R", "-D", "-W", "-b", "-c", "-E", "-e", "-m", "-O", "-Q", "-S", "-w"}
_SCP_VAL = {"-i", "-P", "-o", "-F", "-S", "-l", "-c", "-J", "-e", "--rsh", "--port", "--exclude", "--include",
            "--filter", "-f", "--files-from", "--password-file", "--log-file", "--rsync-path", "--chmod", "--chown"}
_NC_VAL = {"-p", "-s", "-w", "-i", "-q", "-e", "-c", "-x", "-X", "-P", "-I", "-O", "-T", "-V", "--exec", "--sh-exec",
           "--proxy", "--source", "--source-port", "--wait"}

# a URL send carries its host in a URL; a socket, SMTP or FTP send carries it as a quoted literal
_CODE_SEND_URL = re.compile(
    r"(?:\b(?:requests|httpx|session|sess|client|s|axios|http)\s*\.\s*(?:post|put|patch)\s*\("
    r"|\burlopen\s*\([^\n]*\bdata\s*="
    r"|\bfetch\s*\([^\n]*\bmethod\s*:\s*['\"](?:post|put|patch)['\"])", re.I)
_CODE_SEND_HOST = re.compile(
    r"(?:\bsocket\b[^\n]*\.(?:connect|create_connection)\s*\("
    r"|\bcreate_connection\s*\("
    r"|\bsmtplib\s*\.\s*SMTP(?:_SSL)?\s*\("
    r"|\bftplib\s*\.\s*FTP(?:_TLS)?\s*\()", re.I)
_CODE_FIRST_ARG = re.compile(r"\.(?:post|put|patch)\s*\(\s*([A-Za-z_]\w*)", re.I)
_CODE_ASSIGN = re.compile(r"\b([A-Za-z_]\w*)\s*=\s*[rbfu]?['\"]((?:https?|wss?|ftp)://[^'\"]+)['\"]", re.I)
_QUOTED_HOST = re.compile(r"['\"]((?:[a-z0-9-]+\.)+[a-z]{2,24}|(?:\d{1,3}\.){3}\d{1,3})['\"]", re.I)
_REMOTE_SET = re.compile(r"\bgit\s+remote\s+(?:add|set-url)\s+(?:-\S+\s+)*([\w.-]+)\s+(\S+)", re.I)


def _tokens(name: str) -> set:
    s = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", str(name))
    return {t for t in re.split(r"[^a-z0-9]+", s.lower()) if t}


def _strings(obj, key="") -> Iterable[Tuple[str, str]]:
    if isinstance(obj, str):
        yield key, obj
    elif isinstance(obj, dict):
        for k, v in obj.items():
            yield from _strings(v, str(k))
    elif isinstance(obj, (list, tuple)):
        for v in obj:
            yield from _strings(v, key)


def scanned_values(tool_name: str, args: dict, read_only: bool) -> List[Tuple[str, str]]:
    exec_like = bool(_tokens(tool_name) & EXEC_TOOL_TOKENS)
    if read_only and not exec_like:
        return []
    return [(k, v) for k, v in _strings(args or {}) if exec_like or k.lower() in EXEC_ARGS]


def _segments(text: str) -> List[Tuple[str, bool]]:
    """Split shell text on unquoted separators. Each segment carries piped_in (the separator before it was |)."""
    segs, buf, q, i, piped = [], [], None, 0, False
    n = len(text)

    def flush(next_piped):
        nonlocal buf, piped
        s = "".join(buf).strip()
        if s:
            segs.append((s, piped))
        buf, piped = [], next_piped

    while i < n:
        c = text[i]
        if q:
            buf.append(c)
            if c == q:
                q = None
            elif c == "\\" and q == '"' and i + 1 < n:
                buf.append(text[i + 1])
                i += 1
        elif c in "'\"":
            q = c
            buf.append(c)
        elif c == "\\" and i + 1 < n:
            buf.append(c)
            buf.append(text[i + 1])
            i += 1
        elif c == "|":
            if text[i + 1:i + 2] == "|":
                flush(False)
                i += 1
            else:
                flush(True)
        elif c == "&":
            if text[i + 1:i + 2] == "&":
                flush(False)
                i += 1
            elif text[i - 1:i] in (">", "<") or text[i + 1:i + 2] == ">":
                buf.append(c)
            else:
                flush(False)
        elif c in ";\n":
            flush(False)
        else:
            buf.append(c)
        i += 1
    flush(False)
    return segs


def _split(seg: str) -> List[str]:
    try:
        return shlex.split(seg, posix=True)
    except ValueError:
        return seg.split()


def _host_of(tok: str) -> Optional[str]:
    """Host of a URL-like operand: scheme URL, bare host[:port][/path], IPv4[:port][/path]."""
    t = tok.strip().strip("'\"")
    m = _SCHEME_URL.search(t)
    if m:
        return m.group(1).lower().strip(".[]")
    t = re.sub(r"^[\w.+-]*@", "", t)          # user@host
    h = re.split(r"[:/?#]", t, 1)[0].lower().strip(".")
    if _IPV4.match(h) or _HOSTNAME.match(h):
        return h
    return None


def _remote_host(tok: str) -> Optional[str]:
    """Host of an scp/rsync remote operand ([user@]host:path, host::module, rsync://host/...)."""
    t = tok.strip()
    m = _SCHEME_URL.search(t)
    if m:
        return m.group(1).lower()
    m = re.match(r"^(?:[\w.+-]+@)?(\[[0-9a-f:]+\]|[a-z0-9][a-z0-9.-]*):", t, re.I)
    if m and len(m.group(1)) > 1:
        return m.group(1).lower().strip("[]")
    return None


def _operands(toks: List[str], start: int, val_opts: set) -> List[str]:
    out, i = [], start
    while i < len(toks):
        t = toks[i]
        if t.startswith("-") and len(t) > 1:
            if t in val_opts:
                i += 2
                continue
            i += 1
            continue
        if t in ("<", ">", ">>", "2>", "2>&1", "&>"):
            i += 2
            continue
        out.append(t)
        i += 1
    return out


def _verb_index(toks: List[str]) -> Tuple[int, str]:
    for i, t in enumerate(toks):
        b = t.rsplit("/", 1)[-1].lower()
        if b in _NET_VERBS:
            return i, b
    return -1, ""


def _curl(toks, i0) -> Tuple[bool, List[str]]:
    send, dests, i = False, [], i0 + 1
    while i < len(toks):
        t = toks[i]
        if t.startswith("--"):
            name, _, attached = t.partition("=")
            if name in _CURL_SEND:
                send = True
            if name == "--request":
                val = attached or (toks[i + 1] if i + 1 < len(toks) else "")
                send = send or val.upper() in ("POST", "PUT", "PATCH")
            if name == "--url":
                val = attached or (toks[i + 1] if i + 1 < len(toks) else "")
                h = _host_of(val)
                if h:
                    dests.append(h)
                    send = send or bool(_EXPANSION.search(val))
            i += 1 if (attached or name not in _CURL_VAL) else 2
            continue
        if t.startswith("-") and len(t) > 1:
            cluster = t[1:]
            consumed = False
            for j, ch in enumerate(cluster):
                if ch in "dFT":
                    send = True
                if ch == "X":
                    val = cluster[j + 1:] or (toks[i + 1] if i + 1 < len(toks) else "")
                    send = send or val.upper() in ("POST", "PUT", "PATCH")
                if "-" + ch in _CURL_VAL:
                    consumed = j == len(cluster) - 1      # value is the next token only if the option ends the cluster
                    break
            i += 2 if consumed else 1
            continue
        h = _host_of(t)
        if h:
            dests.append(h)
            send = send or bool(_EXPANSION.search(t))
        i += 1
    return send, dests


def _wget(toks, i0) -> Tuple[bool, List[str]]:
    send, dests, i = False, [], i0 + 1
    while i < len(toks):
        t = toks[i]
        name, _, attached = t.partition("=")
        if name in _WGET_SEND:
            send = True
        if name == "--method":
            val = attached or (toks[i + 1] if i + 1 < len(toks) else "")
            send = send or val.upper() in ("POST", "PUT", "PATCH")
        if t.startswith("-"):
            i += 2 if (name in _WGET_VAL and not attached) else 1
            continue
        h = _host_of(t)
        if h:
            dests.append(h)
            send = send or bool(_EXPANSION.search(t))
        i += 1
    return send, dests


def _shell_sends(text: str, remotes: dict) -> List[str]:
    """Destinations that a sending construct in this shell text sends to."""
    out = []
    for seg, piped in _segments(text):
        toks = _split(seg)
        i0, verb = _verb_index(toks)
        if i0 < 0:
            continue
        redirected_in = "<" in toks[i0 + 1:] or any(t.startswith("<") and not t.startswith("<<") for t in toks[i0 + 1:])
        if verb == "curl":
            send, dests = _curl(toks, i0)
            if send:
                out += dests
        elif verb == "wget":
            send, dests = _wget(toks, i0)
            if send:
                out += dests
        elif verb in ("scp", "rsync"):
            ops = _operands(toks, i0 + 1, _SCP_VAL)
            if len(ops) >= 2:
                h = _remote_host(ops[-1])
                if h:
                    out.append(h)
        elif verb == "sftp":
            if piped or redirected_in or re.search(r"\bput\b", seg):
                ops = _operands(toks, i0 + 1, _SSH_VAL)
                if ops:
                    h = _host_of(ops[0])
                    if h:
                        out.append(h)
        elif verb in ("nc", "ncat", "netcat", "telnet"):
            flags = "".join(t[1:] for t in toks[i0 + 1:] if t.startswith("-") and not t.startswith("--"))
            if "l" in flags or "z" in flags or "--listen" in toks:
                continue
            ops = _operands(toks, i0 + 1, _NC_VAL)
            for o in ops:
                h = _host_of(o)
                if h:
                    out.append(h)
                    break
        elif verb == "socat":
            for t in toks[i0 + 1:]:
                m = re.match(r"^(?:tcp|tcp4|tcp6|udp|udp4|udp6|openssl|ssl)(?:-connect)?:([^:,]+):", t, re.I)
                if m:
                    h = _host_of(m.group(1))
                    if h:
                        out.append(h)
        elif verb == "ssh":
            if piped or redirected_in:
                ops = _operands(toks, i0 + 1, _SSH_VAL)
                if ops:
                    h = _host_of(ops[0])
                    if h:
                        out.append(h)
        elif verb == "ssh-copy-id":
            ops = _operands(toks, i0 + 1, _SSH_VAL)
            if ops:
                h = _host_of(ops[-1])
                if h:
                    out.append(h)
        elif verb == "git":
            rest = [t for t in toks[i0 + 1:]]
            if "push" not in rest:
                continue
            ops = _operands(rest, rest.index("push") + 1, {"-o", "--push-option", "--repo", "--receive-pack", "--exec"})
            if ops:
                target = ops[0]
                h = _remote_host(target) if not _SCHEME_URL.search(target) else _host_of(target)
                if not h and target in remotes:
                    h = remotes[target]
                if h:
                    out.append(h)
    return out


def _code_sends(text: str) -> List[str]:
    assigns = {m.group(1): m.group(2) for m in _CODE_ASSIGN.finditer(text)}
    out = []
    for line in text.splitlines():
        if _CODE_SEND_URL.search(line):
            for m in _SCHEME_URL.finditer(line):
                out.append(m.group(1).lower())
            fa = _CODE_FIRST_ARG.search(line)
            if fa and fa.group(1) in assigns:
                h = _host_of(assigns[fa.group(1)])
                if h:
                    out.append(h)
        if _CODE_SEND_HOST.search(line):
            for m in _SCHEME_URL.finditer(line):
                out.append(m.group(1).lower())
            for m in _QUOTED_HOST.finditer(line):
                out.append(m.group(1).lower())
    return out


def send_destinations(text: str, remotes: Optional[dict] = None) -> List[str]:
    remotes = {} if remotes is None else remotes
    for m in _REMOTE_SET.finditer(text):
        h = _remote_host(m.group(2)) if not _SCHEME_URL.search(m.group(2)) else _host_of(m.group(2))
        if h:
            remotes[m.group(1)] = h
    seen, res = set(), []
    for d in _shell_sends(text, remotes) + _code_sends(text):
        d = d.lower().strip(".")
        if d in ("localhost", "0.0.0.0") or d.startswith("127.") or d in seen or len(d) < 4:
            continue
        seen.add(d)
        res.append(d)
    return res


def e1b_check(guard, gname: str, args: dict) -> Optional[Decision]:
    """Return a BLOCK Decision when an executing call sends local data to a taint-novel destination, else None."""
    read_only = guard.lexicon.tool_is_read_only(gname)
    vals = scanned_values(gname, args, read_only)
    if not vals:
        return None
    remotes = getattr(guard, "_e1b_remotes", None)
    if remotes is None:
        remotes = {}
        try:
            guard._e1b_remotes = remotes
        except Exception:
            pass
    tainted = guard.tainted + " " + norm(guard.index.injection_span_text or "")
    trusted = guard.trusted
    for k, v in vals:
        for d in send_destinations(v, remotes):
            nd = norm(d)
            if len(nd) >= 4 and nd in tainted and nd not in trusted:
                return Decision(BLOCK, "block_send_destination", REFUSAL, 0.0)
    return None
