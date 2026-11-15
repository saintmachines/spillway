"""HTTP fetch presence precondition; observed tool URLs are not URL consent.

The gate checks a tool's requested URL. The host must also constrain redirects
and subrequests inside its transport; a post-fetch provenance proof is too late
to prevent an unauthorized request. URI path/query/fragment case is preserved.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import unquote, urlsplit

_LABEL = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
_HOST = rf"(?:{_LABEL}\.)+[a-z]{{2,63}}"
_TOKEN = re.compile(r"(?<![\w@])(?:https?|hxxps?)://[^\s<>\"'`]+", re.I)
_BARE = re.compile(rf"(?<![\w@./:+%=-]){_HOST}(?::[0-9]{{1,5}})?(?:[/\?#][^\s<>\"'`]*)?", re.I)
_DOT = re.compile(r"\[\s*(?:dot|\.)\s*\]", re.I)
_FETCH_WORDS = {"url", "urls", "uri", "uris", "link", "links", "href", "hrefs", "website", "webpage"}


@dataclass(frozen=True)
class _URL:
    scheme: str
    host: str
    port: int | None
    path: str
    query: str
    fragment: str


def _url(value: str) -> _URL | None:
    if not isinstance(value, str) or not value or len(value) > 16384:
        return None
    if any(c.isspace() or ord(c) < 32 or ord(c) == 127 for c in value) or "\\" in value:
        return None
    if re.search(r"%(?![0-9a-f]{2})", value, re.I):
        return None
    if value.startswith("//"):
        return None  # The backend's implicit scheme is not an attested protocol.
    explicit = "://" in value
    try:
        parsed = urlsplit(value if explicit else "//" + value)
        scheme = parsed.scheme.lower() if explicit else ""
        if scheme not in {"", "http", "https"} or parsed.username is not None or parsed.password is not None:
            return None
        host = parsed.hostname
        if not host or not host.isascii() or "%" in host:
            return None
        host = host.lower()
        if ":" in host:
            host = str(ipaddress.IPv6Address(host))
        elif not all(re.fullmatch(_LABEL, part, re.I) for part in host.split(".")):
            return None
        if not explicit and "." not in host:
            return None  # Bare words are not implicit network addresses.
        port = parsed.port
        if port is not None and not 1 <= port <= 65535:
            return None
        if scheme and port is None:
            port = 443 if scheme == "https" else 80
        # Reject client-dependent path/host reinterpretation, not arbitrary
        # percent encoding. Harmless encoded spaces remain exact URI bytes.
        decoded_path = unquote(parsed.path)
        if any(part in {".", ".."} for part in decoded_path.split("/")) or "\\" in decoded_path:
            return None
        return _URL(scheme, host, port, parsed.path or "/", parsed.query, parsed.fragment)
    except (ValueError, UnicodeError):
        return None


def _user_token(token: str) -> str:
    """Narrow host/scheme aliases from original T, without folding URI data."""
    token = re.sub(r"^hxxp(s?)://", lambda m: "http" + m.group(1) + "://", token, flags=re.I)
    prefix, sep, rest = token.partition("://")
    if not sep:
        return token
    at = min((rest.find(c) for c in "/?#" if c in rest), default=len(rest))
    authority, suffix = rest[:at], rest[at:]
    return prefix + sep + _DOT.sub(".", authority) + suffix


def _user_urls(task: str) -> tuple[_URL, ...]:
    text = str(task or "")
    matches = list(_TOKEN.finditer(text))
    spans = [(match.start(), match.end()) for match in matches]
    # An inner URL in the query/path of a user-named outer URL is not an
    # independently approved destination. Do not run a bare-host extractor
    # inside already captured URI tokens.
    matches += [match for match in _BARE.finditer(text)
                if not any(left <= match.start() < right for left, right in spans)]
    result = []
    for match in matches:
        token = match.group(0)
        # Ordinary prose punctuation is outside a locator; explicit quoted or
        # code-delimited URLs preserve their final punctuation byte for byte.
        before = text[match.start() - 1] if match.start() else ""
        if before not in {'"', "'", "`", "<"}:
            token = token.rstrip(".,;!)")
        value = _url(_user_token(token))
        if value is not None:
            result.append(value)
    return tuple(result)


def raw_tool_texts(raw) -> tuple[str, ...]:
    """Snapshot original strings of an executed return, never its provenance fields.

    The host calls this at the execution boundary. A field named ``trusted`` or
    a string resembling a guard refusal has no special meaning here.
    """
    result, seen, alive = [], set(), []

    def visit(value, depth=0):
        if depth > 64:
            return
        if isinstance(value, str):
            result.append(value)
        elif isinstance(value, (bytes, bytearray)):
            result.append(bytes(value).decode("utf-8", "replace"))
        elif isinstance(value, (dict, list, tuple, set)) or hasattr(value, "model_dump"):
            if id(value) in seen:
                return
            seen.add(id(value))
            # Keep temporary model_dump containers alive for this traversal:
            # Python may reuse a freed dict's id for the next model's dump.
            alive.append(value)
            if hasattr(value, "model_dump"):
                try:
                    visit(value.model_dump(), depth + 1)
                except Exception:
                    pass  # Unavailable raw evidence cannot clear the precondition.
            elif isinstance(value, dict):
                for key, item in value.items():
                    visit(key, depth + 1)
                    visit(item, depth + 1)
            else:
                for item in value:
                    visit(item, depth + 1)

    visit(raw)
    return tuple(result)


def _exact_source_key(value: str):
    parsed_url = _url(value)
    if parsed_url is None:
        return None
    parsed = urlsplit(value if "://" in value else "//" + value)
    # Preserve empty paths and empty query/fragment delimiters for tool evidence.
    # Host/scheme case and an ordinary default port retain the URI rules above.
    return parsed_url, parsed.path, "?" in value.split("#", 1)[0], "#" in value


def _observed_url_keys(tool_return_texts):
    result = set()
    for text in tool_return_texts or ():
        if not isinstance(text, str):
            continue
        matches = list(_TOKEN.finditer(text))
        spans = [(match.start(), match.end()) for match in matches]
        matches += [match for match in _BARE.finditer(text)
                    if not any(left <= match.start() < right for left, right in spans)]
        for match in matches:
            # No user aliases, defanging or punctuation repair for a tool URL.
            key = _exact_source_key(match.group(0))
            if key is not None:
                result.add(key)
    return result


def _matches_observed(value, observed):
    key = _exact_source_key(value) if isinstance(value, str) else None
    if key is None:
        return False
    # Use the existing ordinary HTTP(S) expansion for a bare original host.
    # Explicit schemes cannot change, and every path/query/fragment byte stays
    # exact, including empty path and delimiter distinctions.
    return any(key[1:] == source[1:] and _same_request(key[0], source[0]) for source in observed)


def _same_request(requested: _URL, named: _URL) -> bool:
    if (requested.host, requested.path, requested.query, requested.fragment) != (named.host, named.path, named.query, named.fragment):
        return False
    if requested.scheme == named.scheme:
        return requested.port == named.port
    # A bare user-named host/path permits the ordinary HTTP(S) port. An
    # explicit HTTPS instruction never authorizes a scheme-less/downgraded call.
    return (not named.scheme and named.port is None and requested.scheme in {"http", "https"}
            and requested.port == (443 if requested.scheme == "https" else 80))


def _fetch_values(name, args, lexicon):
    """Preserve URL container roles; an opaque URI object is not a string URL."""
    if isinstance(args, dict):
        for key, value in args.items():
            key = str(key)
            if lexicon.is_fetch_arg(key):
                words = re.findall(r"[a-z]+", re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", key).lower())
                specific = bool(words and words[-1] in _FETCH_WORDS)
                if isinstance(value, str):
                    network_shaped = "://" in value or value.startswith("//") or bool(_BARE.fullmatch(value))
                    if value.strip() and (specific or network_shaped):
                        yield value
                elif isinstance(value, (list, tuple)):
                    for item in value:
                        if isinstance(item, str):
                            if item.strip():
                                yield item
                        elif item is not None:
                            yield None
                elif specific and value is not None:
                    yield None
                elif isinstance(value, dict):
                    yield from _fetch_values(name, value, lexicon)
            elif isinstance(value, (dict, list, tuple)):
                yield from _fetch_values(name, value, lexicon)
    elif isinstance(args, (list, tuple)):
        for item in args:
            yield from _fetch_values(name, item, lexicon)


def tool_observed_fetch_targets(name, args, *, lexicon, tool_return_texts=()):
    """Exact requested URLs found in separately captured, original tool returns."""
    if not lexicon.tool_is_read_only(name):
        return []
    observed = _observed_url_keys(tool_return_texts)
    return [value for value in _fetch_values(name, args or {}, lexicon)
            if isinstance(value, str) and _matches_observed(value, observed)]


def unrequested_fetch_targets(name, args, trusted, *, lexicon, user_task=None, tool_return_texts=()):
    if not lexicon.tool_is_read_only(name):
        return []
    named = _user_urls(user_task if user_task is not None else trusted)
    observed = _observed_url_keys(tool_return_texts)
    bad = []
    for value in _fetch_values(name, args or {}, lexicon):
        requested = _url(value) if isinstance(value, str) else None
        if (requested is None or (not any(_same_request(requested, target) for target in named)
                                  and not _matches_observed(value, observed))):
            bad.append("<unsupported URL shape>" if value is None else value)
    return bad
