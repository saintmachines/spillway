"""Classify the effects requested by terminal tools."""

import re
from .floor import BLOCK, Decision, norm as _grounding_norm
import sys
from urllib.parse import urlparse
VERSION = 'v3b'
EXEC_TOOL = re.compile('bash|shell|terminal|command|cmd|exec|sql', re.I)
NGRAM = 8
MIN_PROMPT = 20

def norm(s) -> str:
    return re.sub('\\s+', ' ', str(s)).strip().lower()

def novel(tok: str, trusted: str, tainted: str) -> bool:
    t = norm(tok).strip('"`')
    return len(t) >= 4 and t in tainted and (t not in trusted)

def strings(obj):
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, dict):
        for v in obj.values():
            yield from strings(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from strings(v)
PRIV = [('a', 'claude_skip_permissions', 'dangerously-skip-permissions', 'dangerously-skip-permissions'), ('a', 'claude_bypass_mode', 'bypasspermissions', 'bypasspermissions'), ('a', 'codex_bypass_all', 'dangerously-bypass-approvals-and-sandbox', 'dangerously-bypass-approvals-and-sandbox'), ('a', 'codex_full_access', 'danger-full-access', 'danger-full-access'), ('a', 'yolo_flag', '(?<![\\w-])--yolo(?![\\w-])', '--yolo'), ('a', 'yolo_approval_mode', 'approval[-_]?mode[\\"\'\\s:=]+yolo\\b', 'yolo'), ('a', 'aider_yes_always', '(?<![\\w-])--yes-always(?![\\w-])', '--yes-always'), ('a', 'q_trust_all_tools', '(?<![\\w-])--trust-all-tools(?![\\w-])', '--trust-all-tools'), ('c', 'container_privileged', '(?<![\\w-])--privileged(?![\\w-])', '--privileged'), ('c', 'container_unconfined', '\\b(?:seccomp|apparmor)[=:]unconfined\\b', 'unconfined'), ('c', 'container_cap_all', '--cap-add[\\s=]+[\\"\']?(?:all|sys_admin)\\b', '--cap-add')]
PRIV_RE = [(v, rule, re.compile(p, re.I), tok) for v, rule, p, tok in PRIV]
AGENT_CLI = '(?:claude|codex|gemini|qwen)(?:-code|-cli)?|aider|cursor-agent|opencode|goose|amp|crush|openhands|q'
R_AGENT = re.compile(AGENT_CLI, re.I)
SHELL_C = {'bash', 'sh', 'zsh', 'dash', 'ksh', 'su', 'script'}
SHELLS = {'bash', 'sh', 'zsh', 'dash', 'ksh'}
WRAPPERS = {'sudo': ({'-u', '-g', '-C', '-D', '-h', '-p', '-U', '-r', '-t', '-T'}, 0), 'doas': ({'-u', '-C'}, 0), 'nohup': (set(), 0), 'exec': ({'-a'}, 0), 'env': ({'-u', '-C'}, 0), 'time': ({'-f', '-o'}, 0), 'command': (set(), 0), 'builtin': (set(), 0), 'nice': ({'-n'}, 0), 'setsid': (set(), 0), 'stdbuf': ({'-i', '-o', '-e'}, 0), 'timeout': ({'-s', '-k', '--signal', '--kill-after'}, 1), 'npx': ({'-p', '--package'}, 0), 'bunx': (set(), 0), 'pnpx': (set(), 0), 'uvx': ({'--from', '--with'}, 0), 'xargs': ({'-I', '-n', '-P', '-L', '-d', '-E', '-s', '-a'}, 0), 'if': (set(), 0), 'then': (set(), 0), 'do': (set(), 0), 'else': (set(), 0), 'elif': (set(), 0), 'while': (set(), 0), 'until': (set(), 0), '!': (set(), 0), '{': (set(), 0)}
WRAPPERS_MULTI = [('pnpm', 'dlx'), ('yarn', 'dlx'), ('npm', 'exec'), ('npm', 'x'), ('bun', 'x'), ('pipx', 'run'), ('uv', 'tool', 'run')]
CMD_START_V2 = '(?:^|[;&|(`]|\\$\\(|-c[ \\t]+[\\"\'])[ \\t]*(?:(?:sudo|nohup|exec|env|time|npx|bunx|timeout[ \\t]+\\S+)[ \\t]+|[A-Za-z_][A-Za-z0-9_]*=\\S*[ \\t]+)*'
R_SPAWN_V2 = re.compile(CMD_START_V2 + '(?:[\\w.~/@-]*/)?(?P<cli>' + AGENT_CLI + ')(?=[ \\t])(?P<rest>.*)', re.I | re.S | re.M)
R_ASSIGN = re.compile('^[A-Za-z_][A-Za-z0-9_]*\\+?=')
R_SHEBANG_SH = re.compile('^\\s*#!\\s*(?:\\S*/)?(?:env\\s+)?(?:ba|z|da|k)?sh\\b')
SHELL_EXT = ('.sh', '.bash', '.zsh')
R_REDIR = re.compile('\\d*(?:&>>|&>|>>|>&|>\\||<>|<&|>|<)')
META = set(' \t\n;&|()<>')

def _skip_dollar(s, i):
    n = len(s)
    nxt = s[i + 1:i + 2]
    if nxt == '(':
        if s[i + 2:i + 3] == '(':
            depth, j = (0, i + 1)
            while j < n:
                if s[j] == '(':
                    depth += 1
                elif s[j] == ')':
                    depth -= 1
                    if depth == 0:
                        return (j + 1, None)
                j += 1
            return (n, None)
        j = _match_paren(s, i + 2)
        return (j + 1, s[i + 2:j])
    if nxt == '{':
        j = s.find('}', i + 2)
        return (n if j < 0 else j + 1, None)
    if nxt == "'":
        j = i + 2
        while j < n and s[j] != "'":
            j += 2 if s[j] == '\\' else 1
        return (min(j + 1, n), None)
    return (i + 1, None)

def _match_paren(s, i):
    n, depth, j = (len(s), 1, i)
    while j < n:
        c = s[j]
        if c == '\\':
            j += 2
            continue
        if c == "'":
            k = s.find("'", j + 1)
            j = n if k < 0 else k + 1
            continue
        if c == '"':
            j = _end_dquote(s, j + 1, [])
            continue
        if c == '(':
            depth += 1
        elif c == ')':
            depth -= 1
            if depth == 0:
                return j
        j += 1
    return n

def _end_dquote(s, i, subs):
    n, j = (len(s), i)
    while j < n:
        c = s[j]
        if c == '\\':
            j += 2
            continue
        if c == '"':
            return j + 1
        if c == '$':
            k, sub = _skip_dollar(s, j)
            if sub is not None:
                subs.append(sub)
            j = k
            continue
        if c == '`':
            k = s.find('`', j + 1)
            k = n if k < 0 else k
            subs.append(s[j + 1:k])
            j = k + 1
            continue
        j += 1
    return n

def _dq_unescape(t):
    out, i, n = ([], 0, len(t))
    while i < n:
        if t[i] == '\\' and i + 1 < n and (t[i + 1] in '$`"\\\n'):
            if t[i + 1] != '\n':
                out.append(t[i + 1])
            i += 2
        else:
            out.append(t[i])
            i += 1
    return ''.join(out)

def _read_word(s, i, subs):
    n, j, val = (len(s), i, [])
    while j < n and s[j] not in META:
        c = s[j]
        if c == '\\':
            val.append(s[j + 1:j + 2])
            j += 2
        elif c == "'":
            k = s.find("'", j + 1)
            k = n if k < 0 else k
            val.append(s[j + 1:k])
            j = k + 1
        elif c == '"':
            k = _end_dquote(s, j + 1, subs)
            val.append(_dq_unescape(s[j + 1:max(j + 1, k - 1)]))
            j = k
        elif c == '$':
            k, sub = _skip_dollar(s, j)
            if sub is not None:
                subs.append(sub)
            val.append(s[j:k])
            j = k
        elif c == '`':
            k = s.find('`', j + 1)
            k = n if k < 0 else k
            subs.append(s[j + 1:k])
            val.append(s[j:k + 1])
            j = k + 1
        else:
            val.append(c)
            j += 1
    return (''.join(val), s[i:j], j)

def _tokens(s, subs):
    toks, pending, i, n = ([], [], 0, len(s))
    at_word_start = True
    while i < n:
        c = s[i]
        if c == '\\' and s[i + 1:i + 2] == '\n':
            i += 2
            continue
        if c in ' \t':
            i += 1
            at_word_start = True
            continue
        if c == '\n':
            toks.append(('op', '\n'))
            i += 1
            at_word_start = True
            for strip, delim, ti in pending:
                body = []
                while i < n:
                    k = s.find('\n', i)
                    line = s[i:] if k < 0 else s[i:k]
                    i = n if k < 0 else k + 1
                    if (line.lstrip('\t') if strip else line).rstrip() == delim:
                        break
                    body.append(line)
                toks[ti] = ('here', '\n'.join(body))
            pending = []
            continue
        if c == '#' and at_word_start:
            k = s.find('\n', i)
            i = n if k < 0 else k
            continue
        if s.startswith('<<<', i):
            toks.append(('hstr',))
            i += 3
            continue
        if s.startswith('<<', i):
            strip = s[i + 2:i + 3] == '-'
            i += 3 if strip else 2
            while i < n and s[i] in ' \t':
                i += 1
            delim, _, i = _read_word(s, i, [])
            toks.append(('here', ''))
            pending.append((strip, delim, len(toks) - 1))
            continue
        if c in '<>' and s[i + 1:i + 2] == '(':
            toks.append(('op', '('))
            i += 2
            continue
        two = s[i:i + 2]
        if two in ('&&', '||', '|&', ';;'):
            toks.append(('op', two))
            i += 2
            at_word_start = True
            continue
        m = R_REDIR.match(s, i)
        if m:
            at_word_start = True
            op = m.group(0)
            j = m.end()
            if op.endswith('&') and j < n and (s[j].isdigit() or s[j] == '-'):
                while j < n and (s[j].isdigit() or s[j] == '-'):
                    j += 1
                toks.append(('redir', s[i:j], False))
            else:
                toks.append(('redir', op, True))
            i = j
            continue
        if c in ';&|()':
            toks.append(('op', c))
            i += 1
            at_word_start = True
            continue
        val, raw, i = _read_word(s, i, subs)
        toks.append(('w', val, raw))
        at_word_start = False
    return toks

def _pipelines(toks):

    def new():
        return {'words': [], 'bodies': [], 'targets': []}
    pipes, pipe, cur, need_target, hstr = ([], [], new(), False, False)
    for t in toks:
        if t[0] == 'op':
            pipe.append(cur)
            cur = new()
            if t[1] not in ('|', '|&'):
                pipes.append(pipe)
                pipe = []
            need_target = hstr = False
        elif t[0] == 'redir':
            need_target = t[2]
        elif t[0] == 'hstr':
            hstr = True
        elif t[0] == 'here':
            cur['bodies'].append(t[1])
        elif hstr:
            cur['bodies'].append(t[1])
            hstr = False
        elif need_target:
            cur['targets'].append(t[1])
            need_target = False
        else:
            cur['words'].append((t[1], t[2]))
    pipe.append(cur)
    pipes.append(pipe)
    return pipes

def _head(words):
    i, n = (0, len(words))
    while i < n:
        v = words[i][0]
        if R_ASSIGN.match(v):
            i += 1
            continue
        low = v.lower()
        multi = next((w for w in WRAPPERS_MULTI if tuple((x[0].lower() for x in words[i:i + len(w)])) == w), None)
        if multi:
            i += len(multi)
            while i < n and words[i][0].startswith('-') and (words[i][0] != '-'):
                i += 1
            continue
        if low in WRAPPERS:
            vflags, npos = WRAPPERS[low]
            i += 1
            while i < n and words[i][0].startswith('-') and (words[i][0] != '-'):
                f = words[i][0]
                i += 1
                if f == '--':
                    break
                if f in vflags:
                    i += 1
            while i < n and R_ASSIGN.match(words[i][0]):
                i += 1
            i += npos
            continue
        return i
    return None

def _cli_name(v):
    base = v.rsplit('/', 1)[-1]
    if '@' in base[1:]:
        base = base[0] + base[1:].split('@', 1)[0]
    return base

def spawns(s, depth=0):
    out = []
    if depth > 8 or not s:
        return out
    subs = []
    pipes = _pipelines(_tokens(s, subs))
    for pipe in pipes:
        for ci, cmd in enumerate(pipe):
            words = cmd['words']
            h = _head(words)
            if h is None:
                continue
            name = _cli_name(words[h][0])
            low = name.lower()
            if R_AGENT.fullmatch(name):
                parts = [' '.join((w[1] for w in words[h + 1:]))] + cmd['bodies']
                for p in pipe[:ci]:
                    parts.append(' '.join((w[1] for w in p['words'])))
                    parts.extend(p['bodies'])
                out.append((low, ' '.join((x for x in parts if x))))
                continue
            if low in SHELL_C:
                k = next((k for k in range(h + 1, len(words)) if re.fullmatch('-[A-Za-z]*c[A-Za-z]*', words[k][0])), None)
                if k is not None and k + 1 < len(words):
                    out += spawns(words[k + 1][0], depth + 1)
                    continue
            if low in SHELLS and (not any((not w[0].startswith('-') for w in words[h + 1:]))):
                for b in cmd['bodies']:
                    out += spawns(b, depth + 1)
                for p in pipe[:ci]:
                    for b in p['bodies']:
                        out += spawns(b, depth + 1)
                    ph = _head(p['words'])
                    if ph is not None and p['words'][ph][0] in ('echo', 'printf'):
                        out += spawns(' '.join((w[0] for w in p['words'][ph + 1:])).replace('\\n', '\n'), depth + 1)
                continue
            if low == 'eval':
                out += spawns(' '.join((w[0] for w in words[h + 1:])), depth + 1)
                continue
            to_script = any((t.lower().endswith(SHELL_EXT) for t in cmd['targets'])) or (low == 'tee' and any((w[0].lower().endswith(SHELL_EXT) for w in words[h + 1:])))
            for b in cmd['bodies']:
                if to_script or R_SHEBANG_SH.match(b):
                    out += spawns(b, depth + 1)
            if to_script and low in ('echo', 'printf'):
                out += spawns(' '.join((w[0] for w in words[h + 1:])).replace('\\n', '\n'), depth + 1)
    for sub in subs:
        out += spawns(sub, depth + 1)
    return out

def words(s: str) -> list:
    return re.sub('[^\\w\\s]+', ' ', norm(s)).split()

def copied_run(text: str, trusted_w: str, tainted_w: str):
    w = words(text)
    for i in range(len(w) - NGRAM + 1):
        run = ' ' + ' '.join(w[i:i + NGRAM]) + ' '
        if run in tainted_w and run not in trusted_w:
            return run.strip()
    return None
MANIFEST = '(?:requirements[\\w.-]*\\.(?:txt|in)|constraints[\\w.-]*\\.(?:txt|in))'
R_MWRITE = re.compile('\\b(?:echo|printf)\\s+(?:-[a-zA-Z]+\\s+)*(?P<content>(?:\\"[^\\"]*\\"|\'[^\']*\'|[^\\s;&|>]+)(?:\\s+(?:\\"[^\\"]*\\"|\'[^\']*\'|[^\\s;&|>]+))*)\\s*(?:>>?|\\|\\s*(?:sudo\\s+)?tee\\s+(?:-a\\s+)?)\\s*[\\"\']?[\\w.~/${}-]*?' + MANIFEST + '\\b', re.I)
R_HEREDOC = re.compile('\\bcat\\s*>>?\\s*[\\"\']?[\\w.~/${}-]*?' + MANIFEST + '[\\"\']?\\s*<<-?\\s*[\\"\']?(?P<tag>\\w+)[\\"\']?\\s*\\n(?P<content>.*?)\\n\\s*(?P=tag)\\b', re.I | re.S)
R_INSTALL = re.compile('(?:^|[;&|(`]|\\$\\()[ \\t]*(?:sudo[ \\t]+)?(?:(?:python3?|py)[ \\t]+-m[ \\t]+)?(?P<pm>pip3?|uv[ \\t]+pip|uv|poetry|npm|yarn|pnpm|bun|cargo|go|gem|composer)[ \\t]+(?P<verb>install|i|add|get|require)\\b(?P<rest>[^\\n;&|]*)', re.I | re.M)
R_INDEX = re.compile('(?:--(?:extra-)?index-url|\\bindex-url|(?<!\\S)-i)[\\s=]+[\\"\']?(?P<url>https?://[^\\s\\"\']+)', re.I)
VALUE_FLAGS = {'-r', '--requirement', '-c', '--constraint', '-e', '--editable', '-i', '--index-url', '--extra-index-url', '-f', '--find-links', '-t', '--target', '--prefix', '--python', '--root', '--registry', '--save-prefix', '--tag', '--version', '--source', '--path', '--git', '--branch'}
NAME = re.compile('[A-Za-z][A-Za-z0-9._-]*')

def package_names(text: str) -> list:
    out = []
    for line in text.replace('\\n', '\n').splitlines():
        line = line.split('#', 1)[0].strip().strip('"\'').strip()
        if not line or line.startswith('-'):
            continue
        name = re.split('[=<>!~\\[;@ \\t]', line)[0].strip('"\'')
        if NAME.fullmatch(name or ''):
            out.append(name)
    return out

def install_packages(rest: str) -> tuple:
    out, hosts, skip = ([], [], False)
    for tok in rest.split():
        tok = tok.strip('"\'')
        if skip:
            skip = False
            continue
        if tok.startswith('-'):
            if tok.split('=')[0] in VALUE_FLAGS and '=' not in tok:
                skip = True
            continue
        if '://' in tok:
            host = (urlparse(tok.split('+', 1)[-1] if tok.lower().startswith(('git+', 'hg+', 'svn+')) else tok).hostname or '').lower()
            if host:
                hosts.append(host)
            continue
        if '/' in tok or '\\' in tok or tok.startswith('.') or tok.lower().endswith(('.txt', '.whl', '.gz', '.zip')):
            continue
        name = re.split('[=<>!~\\[;@]', tok)[0]
        if NAME.fullmatch(name or ''):
            out.append(name)
    return (out, hosts)

def shell_effect_hits(raw_name: str, args, trusted: str, tainted: str) -> list:
    if not EXEC_TOOL.search(raw_name or ''):
        return []
    hits = []
    words_cache = {}

    def wjoin(key, s):
        if key not in words_cache:
            words_cache[key] = ' ' + ' '.join(words(s)) + ' '
        return words_cache[key]
    for v in strings(args if isinstance(args, (dict, list)) else {'_': args}):
        for var, rule, rx, tok in PRIV_RE:
            if rx.search(v):
                hits.append({'kind': 'S5', 'variant': var, 'rule': rule, 'token': tok, 'novel': novel(tok, trusted, tainted)})
        rule = 'agent_spawn'
        try:
            found = spawns(v)
        except Exception:
            rule = 'agent_spawn_v2_fallback'
            found = [(m.group('cli').lower(), m.group('rest')) for m in R_SPAWN_V2.finditer(v)]
        for cli, prompt in found:
            if len(prompt.strip()) < MIN_PROMPT:
                continue
            run = copied_run(prompt, wjoin('trusted', trusted), wjoin('tainted', tainted))
            hits.append({'kind': 'S6', 'variant': cli, 'rule': rule, 'token': run or '', 'novel': run is not None})
        for rx in (R_MWRITE, R_HEREDOC):
            for m in rx.finditer(v):
                for name in package_names(m.group('content')):
                    hits.append({'kind': 'S7', 'variant': 'm', 'rule': 'manifest_write', 'token': name, 'novel': novel(name, trusted, tainted)})
        for m in R_INSTALL.finditer(v):
            names, hosts = install_packages(m.group('rest'))
            for name in names:
                hits.append({'kind': 'S7', 'variant': 'i', 'rule': 'install_' + m.group('pm').split()[0].lower(), 'token': name, 'novel': novel(name, trusted, tainted)})
            for host in hosts:
                hits.append({'kind': 'S7', 'variant': 'x', 'rule': 'install_url', 'token': host, 'novel': novel(host, trusted, tainted)})
        for m in R_INDEX.finditer(v):
            host = (urlparse(m.group('url')).hostname or '').lower()
            if host:
                hits.append({'kind': 'S7', 'variant': 'x', 'rule': 'index_url', 'token': host, 'novel': novel(host, trusted, tainted)})
    return hits

_BLOCK_LABELS = {'S5': 'block_novel_privilege_setting', 'S6': 'block_tool_authored_agent_spawn', 'S7': 'block_novel_dependency'}
_REFUSALS = {'S5': "this command turns off a sandbox, approval or permission check with a setting that only tool content named, and the user's task does not ask for it", 'S6': "this command starts another agent with instructions copied from tool content, and the user's task does not ask for them", 'S7': "this adds a package or package source that only tool content named, and the user's task does not name it"}


def check_terminal_effects(guard, name, arguments, audit_row):
    if not EXEC_TOOL.search(name or ""):
        return None
    tool_text = guard.tainted + " " + _grounding_norm(guard.index.injection_span_text or "")
    novel_hits = [
        hit for hit in shell_effect_hits(name, arguments or {}, guard.trusted, tool_text)
        if hit["novel"]
    ]
    if not novel_hits:
        return None
    audit_row["candidate_flags"] = sorted({
        hit["kind"] + (hit["variant"] if hit["kind"] in ("S5", "S7") else "")
        for hit in novel_hits
    })
    blocked = [
        hit for hit in novel_hits
        if hit["kind"] in ("S5", "S6") or (hit["kind"] == "S7" and hit["variant"] == "m")
    ]
    if not blocked:
        return None
    kind = blocked[0]["kind"]
    audit_row["candidate_kinds"] = sorted({hit["kind"] for hit in blocked})
    return Decision(BLOCK, _BLOCK_LABELS[kind], _REFUSALS[kind], 0.0)
