"""Bounded, source-identified sensitive values. No identities or trusted aliases are added.

This checks explicitly supplied source fields/labels and finite copy/encoding forms;
it is not a classifier for arbitrary secrets or a general information-flow proof.
"""
from __future__ import annotations

import base64
import re
from dataclasses import dataclass, field
from urllib.parse import quote, unquote

MAX_SOURCE_CHARS = 1_048_576
MAX_TASK_CHARS = 4_194_304
MAX_VALUE_CHARS = 4096
MAX_VALUES = 128
MAX_PAYLOAD_CHARS = 1_048_576
MAX_NODES = 10_000
MAX_PARTIAL_SCAN_CHARS = 131_072

_LABELS = {
    "apikey": "api_key", "password": "password", "passwd": "password", "passcode": "password",
    "secret": "secret", "token": "token", "credential": "credential", "credentials": "credential",
    "sshkey": "ssh_key", "privatekey": "private_key", "iban": "iban", "ssn": "ssn",
    "socialsecurity": "ssn", "salary": "salary", "otp": "otp", "onetimecode": "otp",
    "verificationcode": "otp", "accesscode": "otp", "securitycode": "otp",
    "backupcode": "otp", "backupcodes": "otp", "pin": "pin",
    "seedphrase": "seed_phrase", "accountnumber": "account_number", "routingnumber": "routing_number",
}
_CATEGORY_PATTERNS = {
    "api_key": r"api[ \t_-]*key", "password": r"password|passwd|passcode", "secret": r"secret",
    "token": r"token", "credential": r"credentials?", "ssh_key": r"ssh[ \t_-]*key",
    "private_key": r"private[ \t_-]*key", "iban": r"iban", "ssn": r"ssn|social[ \t_-]*security",
    "salary": r"salary", "otp": r"otp|one[ \t_-]*time[ \t_-]*code|verification[ \t_-]*code|access[ \t_-]*code|security[ \t_-]*code|backup[ \t_-]*codes?",
    "pin": r"pin", "seed_phrase": r"seed[ \t_-]*phrase", "account_number": r"account[ \t_-]*number",
    "routing_number": r"routing[ \t_-]*number",
}
# One grammar for source extraction and per-value user authorization; horizontal
# whitespace is supported, without joining labels across lines or changing values.
_LABEL_PATTERN = "|".join(_CATEGORY_PATTERNS.values())
_SOURCE_LABEL = re.compile(
    r"\b(?P<label>" + _LABEL_PATTERN + r")\b[\"']?[ \t]*(?::|=|\bis\b)[ \t]*"
    r"(?P<value>\"[^\"\n]{1,4096}\"|'[^'\n]{1,4096}'|[^\s,;<>]{1,4096})", re.I
)
_NEG = re.compile(r"\b(?:do\s+not|don't|dont|never|without|exclude|omit|not)\b", re.I)
_ACTION = re.compile(r"\b(?:send|email|share|forward|include|copy|transmit|deliver)\b", re.I)
_COMPACT = re.compile(r"[^A-Za-z0-9]")
_CLAUSE_BOUNDARY = re.compile(r"[;\n]|[.!?](?=\s|$)|\b(?:but|however)\b", re.I)
_QUOTED = re.compile(r'''"[^"\n]*"|(?<!\w)'[^'\n]*' ''', re.X)
# Delimiter-free source fields are deliberately limited to numeric categories;
# the text "salary meeting" is neither a captured value nor a failed source.
_NUMERIC_SOURCE = re.compile(
    r"\b(?P<label>salary|ssn|social[ \t_-]*security|pin|otp|access[ \t_-]*code|security[ \t_-]*code|"
    r"verification[ \t_-]*code|account[ \t_-]*number|routing[ \t_-]*number)\b[ \t]+"
    r"(?P<value>\d(?:[\d.-]|[ \t](?=\d)){0,63})(?![A-Za-z0-9])", re.I
)


def category(label) -> str | None:
    return _LABELS.get(re.sub(r"[\s_-]", "", str(label)).lower())


@dataclass(frozen=True)
class SensitiveValue:
    value: str = field(repr=False)
    category: str
    source: str


@dataclass
class SensitiveIndex:
    values: list[SensitiveValue] = field(default_factory=list)
    complete: bool = False
    observations: int = 0
    chars: int = 0
    unavailable_reason: str = ""

    def reset(self, *, complete: bool = False):
        self.values.clear()
        self.complete = complete
        self.observations = 0
        self.chars = 0
        self.unavailable_reason = ""

    def fail(self, reason):
        self.complete = False
        self.unavailable_reason = str(reason)

    def _add(self, value, cat, source, *, typed=False):
        if value is None or isinstance(value, bool):
            return
        value = str(value)
        if not value:
            return
        if len(value) > MAX_VALUE_CHARS:
            self.fail("sensitive value exceeds capture limit")
            return
        # Numeric/account categories have value shapes; ordinary prose is not a salary/PIN.
        if not typed and cat in {"salary", "pin", "otp", "ssn", "account_number", "routing_number"}:
            if not any(c.isdigit() for c in value):
                self.fail("recognized sensitive label has an unsupported value representation")
                return
        if not typed and cat == "iban" and not re.fullmatch(r"[A-Za-z]{2}\d{2}[A-Za-z0-9 -]{11,40}", value):
            self.fail("recognized IBAN label has an incomplete or unsupported value representation")
            return
        if any(r.value == value and r.category == cat for r in self.values):
            return
        if len(self.values) >= MAX_VALUES:
            self.fail("sensitive value count exceeds capture limit")
            return
        self.values.append(SensitiveValue(value, cat, source))

    def observe(self, obj, *, source="provided_raw_tool_output"):
        if self.observations == 0 and not self.unavailable_reason:
            self.complete = True
        self.observations += 1
        start_chars, nodes = self.chars, [0]

        def walk(value, path, role=None, depth=0):
            nodes[0] += 1
            if depth > 16 or nodes[0] > MAX_NODES:
                self.fail("source structure exceeds capture limit")
                return
            if hasattr(value, "get_secret_value"):
                self._add(value.get_secret_value(), role or "credential", path, typed=True)
                return
            if hasattr(value, "model_dump"):
                try:
                    value = value.model_dump()
                except Exception:
                    self.fail("typed source could not be captured")
                    return
            if isinstance(value, dict):
                for key, child in value.items():
                    if nodes[0] >= MAX_NODES:
                        self.fail("source structure exceeds capture limit")
                        break
                    walk(child, path + "." + str(key), category(key) or (role if str(key) == "value" else None), depth + 1)
                return
            if isinstance(value, (list, tuple)):
                for i, child in enumerate(value):
                    if nodes[0] >= MAX_NODES:
                        self.fail("source structure exceeds capture limit")
                        break
                    walk(child, path + "[" + str(i) + "]", role, depth + 1)
                return
            if value is None or isinstance(value, bool):
                return
            text = str(value)
            self.chars += len(text)
            if self.chars - start_chars > MAX_SOURCE_CHARS or self.chars > MAX_TASK_CHARS:
                self.fail("source text exceeds capture limit")
                return
            if role:
                self._add(text, role, path, typed=True)
            for match in _SOURCE_LABEL.finditer(text):
                if match.end("value") < len(text) and text[match.end("value")] not in " \t\r\n,;<>" and len(match.group("value")) >= MAX_VALUE_CHARS:
                    self.fail("source label value exceeds capture limit")
                    continue
                raw = match.group("value")
                quoted = raw.startswith(("\"", "'"))
                cat = category(match.group("label"))
                if (not quoted and cat in {"salary", "ssn", "account_number", "routing_number"}
                        and re.match(r",\d", text[match.end("value"):])):
                    self.fail("recognized numeric sensitive label has an ambiguous grouped value")
                    continue
                raw = raw[1:-1] if quoted else raw.rstrip(".")
                self._add(raw, cat, path + ":label")
            for match in _NUMERIC_SOURCE.finditer(text):
                self._add(match.group("value").rstrip("."), category(match.group("label")),
                          path + ":numeric_label")

        walk(obj, source + "#" + str(self.observations))


def _category_pattern(cat):
    # Source labels and user categories share explicit word boundaries, not substring keywords.
    # Use a small explicit canonical phrase family for authorization, not payload labels.
    return r"\b(?:" + _CATEGORY_PATTERNS.get(cat, re.escape(cat)) + r")\b"


def value_authorized(record: SensitiveValue, user_task: str) -> bool:
    """Per-value authorization; negation wins even when the exact value occurs in T."""
    raw = str(user_task or "")
    cat_rx = re.compile(_category_pattern(record.category), re.I)
    clauses = _authorization_clauses(raw)
    for clause in clauses:
        for neg in _NEG.finditer(clause):
            negative = clause[neg.start():]
            if (exact_user_value(record.value, negative) or cat_rx.search(negative)
                    or re.search(r"\bsecrets?\b", negative, re.I)):
                return False
    if exact_user_value(record.value, raw):
        return True
    for clause in clauses:
        for action in _ACTION.finditer(clause):
            span = clause[action.end():action.end() + 120]
            match = cat_rx.search(span)
            if not match:
                continue
            # A value explicitly named after the category restricts that category's grant.
            tail = span[match.end():]
            quoted = re.match(r"[ \t]*[:=]?[ \t]*([\"'])(.*?)\1", tail)
            if quoted:
                return quoted.group(2) == record.value
            token = re.match(r"[ \t]*[:=]?[ \t]*([^\s,;]+)", tail)
            if token:
                named = token.group(1).strip("'\"<>()[]")
                if named.lower() not in {"to", "from", "with", "for", "and", "so", "in", "on", "of"}:
                    return named == record.value
            return True
    return False


def _authorization_clauses(raw):
    """Sentence/contrast scope without breaking quoted literal credentials."""
    quotes = [(m.start(), m.end()) for m in _QUOTED.finditer(raw)]
    starts, cursor = [], 0
    for match in _CLAUSE_BOUNDARY.finditer(raw):
        if any(left <= match.start() < right for left, right in quotes):
            continue
        starts.append(raw[cursor:match.start()])
        cursor = match.end()
    starts.append(raw[cursor:])
    return starts


def exact_user_value(value: str, raw: str) -> bool:
    """Whitespace-delimited or exactly quoted literal, never a different key's prefix.

    Unquoted attached punctuation is ambiguous with a credential character; no
    punctuation is silently removed from secret values to grant authorization.
    """
    return ('"' + value + '"') in raw or ("'" + value + "'") in raw or re.search(
        r"(?<!\S)" + re.escape(value) + r"(?!\S)", raw) is not None


def _variants(value):
    data = value.encode("utf-8")
    variants = {(value, "literal"), (value[::-1], "reverse"), (data.hex(), "hex"), (data.hex().upper(), "hex")}
    for encode in (base64.b64encode, base64.urlsafe_b64encode):
        text = encode(data).decode("ascii")
        variants.add((text, "base64"))
        variants.add((text.rstrip("="), "base64"))
    variants.add((quote(value, safe=""), "urlencode"))
    variants.add(("".join("%%%02X" % b for b in data), "urlencode"))
    variants.add(("".join("%%%02x" % b for b in data), "urlencode"))
    if len(value) >= 16:
        variants.add((value[:12], "prefix12"))
        variants.add((value[-12:], "suffix12"))
    return variants


def _partial_value_match(record, compact_views, user_task):
    """Finite strict profile: literal compact fragments, not arbitrary transforms.

    Four ASCII alphanumeric characters can be ambiguous with ordinary prose.
    Two-character matching is restricted to short numeric PIN/OTP sources.
    A fragment explicitly written in the user's instruction is not novel.
    """
    value = _COMPACT.sub("", record.value)
    width = 2 if (record.category in {"pin", "otp"} and value.isdigit() and 3 <= len(value) <= 8) else 4
    if len(value) <= width:
        return None
    source_parts = {value[i:i + width] for i in range(len(value) - width + 1)}
    for text in compact_views:
        for i in range(len(text) - width + 1):
            part = text[i:i + width]
            if part in source_parts and not exact_user_value(part, user_task):
                return "partial%d" % width
    return None


def payload_problem(name, args, user_task, state: SensitiveIndex, *, has_history, policy, lexicon):
    """Return (label, reason) or None. No raw secret is included in a refusal reason."""
    from .floor import iter_arg_values
    from .target_grounding import is_fetch_url_arg

    pieces = []
    for key, value in iter_arg_values(args or {}):
        if value is None or isinstance(value, bool):
            continue
        fetch = is_fetch_url_arg(name, key, value, policy=policy, lexicon=lexicon)
        if lexicon.tool_is_read_only(name) and not fetch:
            continue
        if not fetch and lexicon.is_target_arg(key):
            continue
        pieces.append(str(value))
    if not pieces:
        return None
    if not state.complete and (has_history or state.observations or state.unavailable_reason):
        return ("block_sensitive_source_unavailable", "raw sensitive-value source evidence unavailable or incomplete")
    if not state.values:
        return None
    if len(pieces) > 128 or sum(map(len, pieces)) > MAX_PAYLOAD_CHARS:
        return ("block_sensitive_source_unavailable", "outgoing value inspection exceeds its declared limit")
    joined = "\n".join(pieces)
    views = [joined, "".join(pieces), unquote(joined), unquote(unquote(joined))]
    compact_views = [_COMPACT.sub("", text) for text in views]
    strict_partial = bool(getattr(policy, "payload_partial_guard", False))
    if strict_partial and sum(map(len, compact_views)) > MAX_PARTIAL_SCAN_CHARS:
        return ("block_sensitive_source_unavailable", "partial-value inspection exceeds its declared limit")
    for record in state.values:
        matched = None
        for needle, form in _variants(record.value):
            if needle and any(needle in text for text in views):
                matched = form
                break
            compact = _COMPACT.sub("", needle)
            if compact and len(compact) >= 4 and any(compact in text for text in compact_views):
                matched = form + "_split"
                break
        authorized = value_authorized(record, user_task)
        if not matched and strict_partial and not authorized:
            matched = _partial_value_match(record, compact_views, user_task)
        if matched and not authorized:
            return ("block_sensitive_payload", "unauthorized source-identified " + record.category + " value (" + matched + ")")
    return None
