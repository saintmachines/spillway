"""Opt-in target-presence filter and deterministic aliases from the USER text only.

Presence in arbitrary tool text is not typed provenance or action authorization. These
helpers never decode tool text, guess spellings, or turn tool text into trusted identities.
"""

from __future__ import annotations

import re
from urllib.parse import urlsplit

_BR_AT = re.compile(r"[\[({]\s*at\s*[\])}]", re.I)
_BR_DOT = re.compile(r"[\[({]\s*(?:dot|\.)\s*[\])}]", re.I)
_WORD_DOT = re.compile(r"(?<=[a-z0-9-])\s+dot\s+(?=[a-z0-9-])", re.I)
# The spelled word "at" is not an alias: on the paper's 97 recorded user tasks it read English prose as an address
# ("my TODO list at www.company-todo-list.com" -> list@www.company-todo-list.com, be alias audit 2026-11-14). Only the
# bracketed forms [at] (at) {at} count.
_HXXP = re.compile(r"\bhxxp(s?)(?=://|\[://\])", re.I)
_LABEL = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
_DOMAIN = rf"(?:{_LABEL}\.)+[a-z]{{2,63}}"
_EMAIL = re.compile(
    rf"(?<![\w@.+%-])[a-z0-9_%+-]+(?:\.[a-z0-9_%+-]+)*@{_DOMAIN}(?![\w@-]|\.[\w])", re.I
)
_URL = re.compile(r"(?<![\w@])https?://[^\s<>\"']+", re.I)
# Four-character groups, with a shorter last group; no prose/sentence joining or case folding.
_GROUPED_IBAN = re.compile(
    r"(?<![A-Za-z0-9])[A-Z]{2}[0-9]{2}(?:[ \t.-][A-Z0-9]{4}){2,7}"
    r"(?:[ \t.-][A-Z0-9]{1,4})?(?![A-Za-z0-9])"
)
# Full-width ASCII (U+FF01..U+FF5E) and the ideographic space map one to one onto ASCII. Read from T only.
_FULL_WIDTH = {cp: cp - 0xFEE0 for cp in range(0xFF01, 0xFF5F)}
_FULL_WIDTH[0x3000] = 0x20
# Invisible characters a copy and paste leaves inside an identifier (zero-width space, non-joiner, joiner,
# word joiner, byte-order mark, soft hyphen) are dropped. Read from T only.
_FULL_WIDTH.update(dict.fromkeys((0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF, 0x00AD)))
# A bare host the user spelled out ("status dot example dot invalid/verify") becomes an alias only when it carries
# a path or two dots, so prose such as "the dot com bubble" never turns into a host.
_BARE = re.compile(rf"(?<![\w@./:-]){_DOMAIN}(?:/[^\s<>\"']*)?", re.I)
# A period glued to a Capitalized word ends the all-lower-case identifier before it. AgentDojo's slack
# user_task_4 reads "our website www.our-company.com.They sent their hobbies ...".
_GLUED_PERIOD = re.compile(r"(?<=[a-z0-9/])\.(?=[A-Z][a-z]+(?:[\s,;:!?)\]]|$))")
# Whitespace around '@' is folded. A dot is folded only with whitespace before it. A dot glued to a label with
# whitespace only after it is a sentence period, and a Capitalized word after a dot starts a sentence, so neither
# joins the next word into a new domain: "bob@acme.example. It is urgent" never yields bob@acme.example.it.
_FOLD_AT = re.compile(r"(?<=[a-z0-9_%+-])\s*@\s*(?=[a-z0-9-])", re.I)
_FOLD_DOT = re.compile(r"(?<=[a-z0-9_%+-])\s+\.\s*(?=[a-z0-9-])(?!(?-i:[A-Z][a-z]))", re.I)
_SCHEME = re.compile(r"^https?://(\S+)$")
_HOST = re.compile(rf"{_DOMAIN}(?:[/?#]\S*)?", re.I)


def _norm(text) -> str:
    return re.sub(r"\s+", " ", str(text)).strip().lower()


def glued_periods(text) -> str:
    """Put a space after a period that glues an all-lower-case identifier to a Capitalized word."""
    text = str(text or "")
    out, last = [], 0
    for m in _GLUED_PERIOD.finditer(text):
        i = m.start()
        while i > 0 and (text[i - 1].isalnum() or text[i - 1] in "_%+@/.-"):
            i -= 1
        run = text[i:m.start()]
        if run and run == run.lower():
            out.append(text[last:m.start() + 1] + " ")
            last = m.start() + 1
    return "".join(out) + text[last:]


def user_target_aliases(user_task: str) -> tuple[str, ...]:
    """Complete ASCII email/URL/IBAN spelling aliases, derived solely from user_task.

    No edit-distance correction, transliteration beyond full-width ASCII, semantic paraphrase, or decoding.
    No alias joins the surrounding prose into an identifier: a sentence period, a comma after a complete
    address and a Capitalized word after a dot all end it.
    Returning an alias does not validate ownership, IBAN checksum, or action authorization.
    """
    orig = str(user_task or "")
    raw = glued_periods(orig.translate(_FULL_WIDTH))
    text = _BR_DOT.sub(".", _BR_AT.sub("@", raw))
    text = _HXXP.sub(lambda m: "http" + m.group(1), text).replace("[://]", "://")
    text = _WORD_DOT.sub(".", text)
    # Only punctuation inside an identifier is folded; never append the transformed prose to T.
    text = _FOLD_DOT.sub(".", _FOLD_AT.sub("@", text))
    changed = text != orig
    aliases = {m.group(0).lower() for m in _EMAIL.finditer(text)} if changed else set()
    if changed:
        for match in _URL.finditer(text):
            value = match.group(0).rstrip(".,;)")
            try:
                parsed = urlsplit(value)
                if (parsed.scheme.lower() in {"http", "https"} and parsed.hostname
                        and re.fullmatch(_DOMAIN, parsed.hostname, re.I)
                        and parsed.username is None and parsed.password is None
                        and value.isascii()):
                    _ = parsed.port  # malformed ports are not an alias
                    aliases.add(value.lower())
            except ValueError:
                continue
        plain = _norm(orig)
        for match in _BARE.finditer(text):
            value = match.group(0).rstrip(".,;)").lower()
            host = value.split("/", 1)[0]
            if (value.isascii() and value not in plain and ("/" in value or host.count(".") >= 2)
                    and not target_appears_in(value, plain)):
                aliases.add(value)
    for match in _GROUPED_IBAN.finditer(raw):
        value = re.sub(r"[ \t.-]", "", match.group(0))
        if 15 <= len(value) <= 34 and re.fullmatch(r"[A-Z]{2}[0-9]{2}[A-Z0-9]+", value):
            aliases.add(value.lower())
    return tuple(sorted(aliases))


def with_user_target_aliases(trusted_text: str, user_task: str) -> str:
    """Append complete user-derived identifiers, never transformed tool text or prose."""
    trusted = _norm(trusted_text)
    extra = [a for a in user_target_aliases(user_task) if not target_appears_in(a, trusted)]
    return trusted + (" " + " ".join(extra) if extra else "")


def grounding_text(trusted: str, user_task) -> str:
    """T as the presence check reads it: trusted, plus the user's text with glued sentence periods opened."""
    raw = str(user_task or "")
    split = glued_periods(raw)
    return trusted if split == raw else _norm(trusted) + " " + _norm(split)


def target_appears_in(value, source: str, *, user_text: bool = False) -> bool:
    """A complete normalized value at identifier boundaries, including short identifiers.

    A known host/path prefix, an email embedded in another identifier, or a token inside
    a compound value is insufficient. A sentence-ending period can follow a full value.
    A colon followed by whitespace or end is punctuation, including a typed
    mapping's rendered key. Presence alone never grants identity authority.
    """
    value = _norm(value)
    if not value:
        return False
    # A # or @ sigil that starts a word ("post in #general", "DM @alice") precedes an identifier the user named;
    # a sigil glued to other identifier text (bob@general.com) does not.
    right = r"(?![\w@/+%=#?&-]|:\S|\.[\w])"
    if _EMAIL.fullmatch(value):
        # A terminal question mark ends an email in ordinary user prose. It
        # does not authorize an email prefix in URI data such as '?cc=...'.
        right = r"(?:(?=\?(?=\s|$|[\"'<>]))|" + right + ")"
    return re.search(
        r"(?:(?<![\w@./+%:=#?&-])|(?<=(?<!\S)[#@]))" + re.escape(value) + right,
        _norm(source),
    ) is not None


def target_forms(value) -> set:
    """The value, and for a URL or a bare host the same address with or without http:// or https:// and with
    or without a trailing slash. None of these changes the host or the path that receives the call."""
    v = _norm(value)
    m = _SCHEME.match(v)
    bare = m.group(1) if m else (v if _HOST.fullmatch(v) else "")
    if not bare:
        return {v}
    stems = {bare}
    for s0 in list(stems):
        if s0.endswith("/"):
            stems.add(s0[:-1])
        elif not re.search(r"[?#]", s0):
            stems.add(s0 + "/")
    forms = {v} | {f for s in stems if s for f in (s, "http://" + s, "https://" + s)}
    # A default port names the same address only under its own scheme: http://host:80/x is http://host/x, and
    # https://host:443/x is https://host/x. The pair is never crossed (root 14:33Z: an https request must not
    # cover an http://host:443 proposal), so the stripped form is added under that one scheme only.
    scheme = (m.group(0).split("://")[0] if m else "")
    port = re.match(r"^([^/?#:]+):(80|443)(?=/|$)(.*)$", bare)
    if port and ((scheme == "http" and port.group(2) == "80") or (scheme == "https" and port.group(2) == "443")):
        stem = port.group(1) + port.group(3)
        for s1 in (stem, stem[:-1] if stem.endswith("/") else (stem + "/" if not re.search(r"[?#]", stem) else stem)):
            forms.add(scheme + "://" + s1)
    return forms


def inside_longer_identifier(value, source: str, *, user_text: bool = False) -> bool:
    """An identifier-shaped value ('@', '.' or '/' in it) that occurs in source only inside a longer
    identifier: a prefix of a URL the user named, or a parent domain or a part of an address."""
    v = _norm(value)
    return (len(v) >= 4 and re.search(r"[@./]", v) is not None
            and v in _norm(source) and not target_appears_in(v, source, user_text=user_text))


def _looks_like_url(value) -> bool:
    url = _norm(value)
    return bool(re.match(r"^[a-z][a-z0-9+.-]*://", url)
                or (len(url) >= 6 and "." in url and " " not in url and "@" not in url))


def is_fetch_url_arg(name: str, key: str, value, *, policy, lexicon) -> bool:
    """A URL-valued network read is also a possible content-exfiltration sink.

    This role check is independent of the optional target-grounding switch.
    Source-value inspection must still cover query/path data when it is off.
    """
    return bool(lexicon.tool_is_read_only(name) and lexicon.is_fetch_arg(key)
                and isinstance(value, str) and _looks_like_url(value))


def is_external_target_arg(name: str, key: str, *, policy, lexicon) -> bool:
    """Mirror the existing self-write exception and include access-grant principal roles."""
    if policy.selfwrite_integrity and lexicon.is_self_write_tool(name):
        if not (policy.selfwrite_recipients and str(key).lower() in lexicon.self_write_recipient_args):
            return False
    return lexicon.is_target_arg(key) or (
        policy.access_grant and lexicon.is_access_grant(name) and lexicon.is_principal_arg(key)
    )


def ungrounded_targets(name: str, args: dict, trusted: str, tainted: str, *, policy, lexicon,
                       user_task=None) -> list[str]:
    """Return every target value absent from both T and U. No judge can clear this filter.

    U is not a trusted identity source: existing floor tiers still decide observed targets.
    Empty/missing args are left to the tool contract; nonempty short/long values are checked.
    An identifier that occurs in T only inside a longer identifier is refused even when U repeats it.
    With policy.ground_fetch_urls the URL of a fetch, read-only tools included, is checked as well, so a
    rebuilt or data-appended fetch URL cannot carry data out; a grounded one still meets the content tier.
    """
    from .floor import iter_arg_values  # avoid a module-level cycle with the shared floor

    fetch_too = bool(getattr(policy, "ground_fetch_urls", False))
    read_only = lexicon.tool_is_read_only(name)
    if read_only and not fetch_too:
        return []
    hay = grounding_text(trusted, user_task) if user_task is not None else trusted
    bad = []
    for key, value in iter_arg_values(args or {}):
        if value is None or not str(value).strip():
            continue
        if read_only:
            if not (lexicon.is_fetch_arg(key) and _looks_like_url(value)):
                continue
        else:
            if not is_external_target_arg(name, key, policy=policy, lexicon=lexicon):
                continue
            fetch = ((policy.readfetch and lexicon.is_read_fetch_url(name, key))
                     or (policy.readfetch2 and lexicon.is_read_fetch_url2(name, key)))
            if fetch and not fetch_too and _looks_like_url(value):
                continue  # same inbound fetch exemption as the existing floor; content tier remains active
        forms = target_forms(value)
        if any(target_appears_in(f, hay, user_text=True) for f in forms):
            continue
        if (any(inside_longer_identifier(f, hay, user_text=True) for f in forms)
                or not any(target_appears_in(f, tainted) for f in forms)):
            bad.append(str(value))
    return bad
