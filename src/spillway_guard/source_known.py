"""Exact-address, user-directed source evidence. Never broadens a whole domain."""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Callable
from urllib.parse import urlsplit

_HOST = r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}"
_EMAIL = re.compile(r"(?<![\w@.+%-])[a-z0-9_%+-]+(?:\.[a-z0-9_%+-]+)*@" + _HOST + r"(?![\w@-]|\.[\w])", re.I)
_LOCATOR = re.compile(r"(?<![\w@./:+%-])(?:https?://[^\s<>\"']+|" + _HOST + r"(?::[0-9]{1,5})?(?:/[^\s<>\"']*)?)", re.I)
_WEB_TOKEN = re.compile(r"(?:https?://[^\s<>\"']+|" + _HOST + r"/[^\s<>\"']*)", re.I)
MAX_RESPONSE_CHARS = 1_048_576
MAX_ADDRESSES = 128


@dataclass(frozen=True)
class SourceLocator:
    scheme: str
    host: str
    port: int | None
    path: str
    query: str


def locator(value: str) -> SourceLocator | None:
    if not isinstance(value, str) or not value or len(value) > 4096 or not value.isascii():
        return None
    if any(c.isspace() or ord(c) < 32 or ord(c) == 127 for c in value) or "\\" in value:
        return None
    schemed = "://" in value
    try:
        parsed = urlsplit(value if schemed else "//" + value)
        if parsed.username is not None or parsed.password is not None:
            return None
        scheme = parsed.scheme.lower() if schemed else ""
        if scheme not in {"", "http", "https"} or not parsed.hostname or re.fullmatch(_HOST, parsed.hostname, re.I) is None:
            return None
        if any(part in {".", ".."} for part in parsed.path.split("/")):
            return None
        port = parsed.port
        if scheme:
            port = port if port is not None else (443 if scheme == "https" else 80)
        return SourceLocator(scheme, parsed.hostname.lower(), port, parsed.path or "/", parsed.query)
    except ValueError:
        return None


def same_locator(left: SourceLocator, right: SourceLocator) -> bool:
    if (left.host, left.path, left.query) != (right.host, right.path, right.query):
        return False
    if left.scheme and right.scheme:
        return (left.scheme, left.port) == (right.scheme, right.port)
    # An unspecified scheme grants only the ordinary default port; it never
    # authorizes an unrelated port or an explicitly different HTTP(S) scheme.
    bare, full = (left, right) if not left.scheme else (right, left)
    if not full.scheme:
        return bare.port == full.port
    return bare.port is None and full.port == (443 if full.scheme == "https" else 80)


def user_locators(user_task: str) -> tuple[SourceLocator, ...]:
    result = []
    for match in _LOCATOR.finditer(str(user_task or "")):
        candidate = locator(match.group(0).rstrip(".,;!?)"))
        if candidate is not None:
            result.append(candidate)
    return tuple(result)


def _strings(raw, depth=0):
    if depth > 12:
        return
    if hasattr(raw, "model_dump"):
        raw = raw.model_dump()
    if isinstance(raw, str):
        yield raw
    elif isinstance(raw, dict):
        for value in raw.values():
            yield from _strings(value, depth + 1)
    elif isinstance(raw, (list, tuple)):
        for value in raw:
            yield from _strings(value, depth + 1)


def source_addresses(raw, *, untrusted=False) -> set[str]:
    result, chars = set(), 0
    for text in _strings(raw):
        chars += len(text)
        if chars > MAX_RESPONSE_CHARS:
            return set()
        if untrusted:
            from .sanitizer import sanitize
            text = sanitize(text, [], control_tokens=True, injected_imperatives=True,
                            agent_addressed=True, forged_turns_in_spans=True, rolemark=True)
        urls = [(m.start(), m.end()) for m in _WEB_TOKEN.finditer(text)]
        for match in _EMAIL.finditer(text):
            if not any(start <= match.start() < end for start, end in urls):
                result.add(match.group(0).lower())
            if len(result) > MAX_ADDRESSES:
                return set()
    return result


@dataclass(frozen=True)
class ReadSourceProof:
    """Trusted transport metadata; never construct this from fields in a document."""
    requested_url: str
    final_url: str
    redirect_chain: tuple[str, ...] = ()

    def __post_init__(self):
        if not isinstance(self.requested_url, str) or not isinstance(self.final_url, str):
            raise TypeError("source URLs must be strings supplied by the transport")
        if not isinstance(self.redirect_chain, tuple) or not all(isinstance(v, str) for v in self.redirect_chain):
            raise TypeError("redirect_chain must be a transport-supplied tuple")


@dataclass(frozen=True)
class SourceContracts:
    """Host app explicitly registers read tools whose responses cannot redirect."""
    no_redirect_tools: frozenset[str] = frozenset()
    attestor: Callable | None = field(default=None, repr=False)

    def __post_init__(self):
        if not isinstance(self.no_redirect_tools, frozenset) or not all(isinstance(v, str) for v in self.no_redirect_tools):
            raise TypeError("no_redirect_tools must be a trusted frozenset of registered tool names")
        if self.attestor is not None and not callable(self.attestor):
            raise TypeError("source attestor must be callable")

    def proof(self, name, args, raw, *, supplied=None, context=None):
        if supplied is not None:
            if not isinstance(supplied, ReadSourceProof):
                raise TypeError("read_source must be trusted ReadSourceProof, not response metadata")
            return supplied
        if self.attestor is not None:
            value = self.attestor(name, dict(args or {}), raw, context)
            if value is not None and not isinstance(value, ReadSourceProof):
                raise TypeError("source attestor must return ReadSourceProof or None")
            return value
        if name in self.no_redirect_tools:
            urls = [v for k, v in (args or {}).items() if str(k).lower() in {"url", "uri", "website", "href", "link"}
                    and isinstance(v, str) and locator(v) is not None]
            if len(urls) == 1:
                return ReadSourceProof(urls[0], urls[0])
        return None


@dataclass
class NamedSourceIndex:
    addresses: dict[str, set[SourceLocator]] = field(default_factory=dict)
    unavailable: list[str] = field(default_factory=list)

    def reset(self):
        self.addresses.clear()
        self.unavailable.clear()

    def observe(self, name, args, raw, user_task, *, proof, lexicon):
        if not lexicon.tool_is_read_only(name) or not isinstance(proof, ReadSourceProof):
            return
        if proof.redirect_chain:
            return
        requested, final = locator(proof.requested_url), locator(proof.final_url)
        if requested is None or final is None or not same_locator(requested, final):
            return
        actual = [locator(v) for k, v in (args or {}).items()
                  if lexicon.is_fetch_arg(k) and isinstance(v, str)]
        if sum(v is not None and same_locator(requested, v) for v in actual) != 1:
            return
        if not any(same_locator(requested, named) and same_locator(final, named)
                   and (not named.scheme or final.scheme == named.scheme)
                   for named in user_locators(user_task)):
            return
        for address in source_addresses(raw, untrusted=True):
            self.addresses.setdefault(address, set()).add(requested)

    def authorized(self, user_task) -> set[str]:
        from .floor import refbind_user_task
        # This exception never inherits the broader substring-only legacy rule.
        return {address for address in self.addresses
                if refbind_user_task([address], user_task, whole_local=True)}


def strict_known_domains(identity_set, user_task) -> set[str]:
    domains = {loc.host for loc in user_locators(user_task)}
    for value in identity_set or ():
        if isinstance(value, str) and _EMAIL.fullmatch(value):
            domains.add(value.rsplit("@", 1)[1].lower())
    for address in source_addresses(str(user_task or "")):
        domains.add(address.rsplit("@", 1)[1])
    return domains


def delegated_domain_problem(name, args, user_task, trusted, identity_set, source_index, *, policy, lexicon):
    """Mandatory before judges/recovery, exact-source exception per address."""
    from .floor import iter_arg_values, norm, refbind_user_task
    from .target_grounding import is_external_target_arg, target_appears_in

    if not policy.refbind_source_known:
        return None
    domains = strict_known_domains(identity_set, user_task)
    directed = source_index.authorized(user_task) if source_index is not None else set()
    for key, value in iter_arg_values(args or {}):
        if not isinstance(value, str) or not is_external_target_arg(name, key, policy=policy, lexicon=lexicon):
            continue
        # A sender/email filter on a declared local read selects a record;
        # it does not route an outgoing action. URL-like fetch arguments
        # remain subject to this check and the separate fetch controls.
        if (lexicon.tool_is_read_only(name) and not lexicon.is_fetch_arg(key)
                and str(key).lower() in {"sender", "sender_email", "from", "from_email", "from_address", "email"}
                and _EMAIL.fullmatch(value)):
            continue
        for match in _EMAIL.finditer(value):
            address = norm(match.group(0))
            if target_appears_in(address, trusted) or address in {norm(v) for v in identity_set or ()}:
                continue
            if address in directed:
                continue
            if refbind_user_task([address], user_task, whole_local=policy.refbind_whole_local, domains=domains):
                continue
            return ("block_unverified_delegated_domain", "delegated email lacks user, typed, or exact directed-source evidence")
    return None
