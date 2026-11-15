"""Short target precondition, separate from the four-character taint vocabulary.

These checks only refuse; the existing gate still decides every allowed path.
Resource identities use a kind-scoped marker emitted only by declared models.
"""
from __future__ import annotations

import re
from typing import Any

from pydantic import BaseModel

from .target_grounding import is_external_target_arg, target_appears_in

_KINDS = {
    "file": "file", "files": "file", "folder": "folder", "folders": "folder",
    "directory": "folder", "directories": "folder", "channel": "channel", "channels": "channel",
    "event": "event", "events": "event", "message": "message", "messages": "message",
    "email": "email", "emails": "email",
    "document": "document", "documents": "document", "thread": "thread", "threads": "thread",
    "calendar": "calendar", "calendars": "calendar", "resource": "resource", "resources": "resource",
}
_MARKER = "\x00spillway-resource:"


class _ResourceIdentity(str):
    """JSON-safe index entry whose authority cannot be forged by raw text.

    The existing index accepts raw string identities. A pasted/dict string
    equal to our display bytes must neither authorize a resource nor shadow
    a subsequently observed typed resource entry in the set.
    """
    def __eq__(self, other):
        return type(other) is _ResourceIdentity and str.__eq__(self, other)

    def __ne__(self, other):
        return not self.__eq__(other)

    def __hash__(self):
        return hash((_ResourceIdentity, str(self)))


def _tokens(value: str) -> list[str]:
    value = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", str(value))
    return [part for part in re.split(r"[^a-z0-9]+", value.lower()) if part]


def _kind(value: str) -> str | None:
    kinds = [_KINDS[token] for token in _tokens(value) if token in _KINDS]
    if not kinds:
        return None
    found = set(kinds)
    if len(found) == 1:
        return kinds[0]
    # Calendar is a namespace qualifier for an event object, not a second
    # competing object kind. Other unrelated compound kinds stay ambiguous.
    qualifiers = {"event": frozenset({"calendar"})}
    head = kinds[-1]
    return head if found <= ({head} | qualifiers.get(head, frozenset())) else None


def _short(value: Any, kind: str) -> str | None:
    if isinstance(value, bool) or not isinstance(value, (str, int)):
        return None
    text = str(value).strip().lower()
    if kind == "channel" and text.startswith("#"):
        text = text[1:]
    if not 1 <= len(text) <= 3 or any(c.isspace() or c in "@.:/?&=%+#<>\"'" for c in text):
        return None
    return text


def resource_identity(kind: str, value: Any) -> str | None:
    """Opaque scoped index key; never obtained by interpreting pasted prose."""
    short = _short(value, kind)
    return None if short is None else _ResourceIdentity(f"{_MARKER}{kind}:{short}")


def index_short_resource_identities(obj: Any, identity_set: set) -> None:
    """Index declared resource fields of a trusted read result, not raw dict keys.

    A model class such as CloudDriveFile gives id_/id its resource scope. An
    explicit file_id/channel_id field gives its own scope. A nested model must
    declare its OWN resource type; generic Metadata(id_=...) never inherits
    the enclosing File kind. Untyped dicts never
    create these markers, including a dict carried by a free-text model field.
    This must run only where the existing executor already indexes a legitimate
    READ result, after its query-entailment check; never on a write or paste.
    """
    if isinstance(obj, (list, tuple)):
        for item in obj:
            index_short_resource_identities(item, identity_set)
        return
    if not isinstance(obj, BaseModel):
        return
    current = _kind(type(obj).__name__)
    for field in type(obj).model_fields:
        value = getattr(obj, field, None)
        words = _tokens(field)
        explicit = _kind(field)
        role = ((explicit or (current if words == ["id"] else None)) if "id" in words
                else explicit if words in (["channel"], ["channels"]) else None)
        if role is not None:
            for leaf in value if isinstance(value, (list, tuple)) else (value,):
                marker = resource_identity(role, leaf)
                if marker is not None:
                    identity_set.add(marker)
        if isinstance(value, (BaseModel, list, tuple)):
            index_short_resource_identities(value, identity_set)


def _response_resource_kinds(obj: Any) -> set[str]:
    """Kinds declared by a read result, used only for a generic id/id_ arg."""
    if isinstance(obj, (list, tuple)):
        return set().union(*(_response_resource_kinds(item) for item in obj))
    if not isinstance(obj, BaseModel):
        return set()
    current = _kind(type(obj).__name__)
    found = set()
    for field in type(obj).model_fields:
        words = _tokens(field)
        explicit = _kind(field)
        role = ((explicit or (current if words == ["id"] else None)) if "id" in words
                else explicit if words in (["channel"], ["channels"]) else None)
        if role is not None:
            found.add(role)
        value = getattr(obj, field, None)
        if isinstance(value, (BaseModel, list, tuple)):
            found.update(_response_resource_kinds(value))
    return found


def short_resource_read_entailed(args: dict, trusted: str, identity_set: set, *, response: Any = None,
                                 tainted: str = "") -> bool:
    """A short read ID must be user-named or an existing same-kind typed ID.

    This limits NEW resource-marker creation, not the read itself. No-argument
    list reads remain indexable; prior legitimate list-read markers are retained.
    Resource ID arguments and other short scalar selectors require user or
    existing typed evidence, including decoded values absent literally from U. Numeric page/count
    controls do not exempt the other arguments. Longer selector phrases are
    checked only for literal short resource IDs actually returned by the read.
    """
    from .floor import iter_arg_values

    response_kinds = None

    def known_selector(short):
        from .short_lineage import query_identity

        nonlocal response_kinds
        if response_kinds is None:
            response_kinds = _response_resource_kinds(response)
        if response_kinds:
            return (len(response_kinds) == 1
                    and resource_identity(next(iter(response_kinds)), short) in identity_set)
        marker = query_identity(short)
        return marker is not None and marker in identity_set

    def is_counter(key, value):
        if "_".join(_tokens(str(key))) not in {"page", "count", "limit", "offset", "page_size", "page_number", "n"}:
            return False
        return (isinstance(value, (int, float)) and not isinstance(value, bool)
                or isinstance(value, str) and re.fullmatch(r"[+-]?\d+(?:\.\d+)?", value.strip()) is not None)

    returned_short_values = None
    for key, value in iter_arg_values(args or {}):
        words = _tokens(str(key))
        explicit = _kind(str(key))
        resource_arg = "id" in words or words in (["channel"], ["channels"])
        role = explicit if resource_arg else None
        if resource_arg and role is None and words == ["id"]:
            if response_kinds is None:
                response_kinds = _response_resource_kinds(response)
            role = next(iter(response_kinds)) if len(response_kinds) == 1 else "unresolved"
        if role is not None:
            short = _short(value, role)
            if short is not None and not target_appears_in(short, trusted):
                if resource_identity(role, short) not in identity_set:
                    return False
            continue
        if is_counter(key, value):
            continue
        if response_kinds is None:
            response_kinds = _response_resource_kinds(response)
        selector_kind = next(iter(response_kinds)) if len(response_kinds) == 1 else "unresolved"
        short = _short(value, selector_kind)
        if short is not None:
            if not target_appears_in(short, trusted) and not known_selector(short):
                return False
            continue
        # Avoid guessing English stopwords or scanning every word of prose.
        # Only a returned resource ID embedded in a semantic selector is tested.
        if (isinstance(value, str)
                and set(words) & {"q", "query", "name", "selector", "search", "term", "filter", "pattern"}):
            if returned_short_values is None:
                returned = set()
                index_short_resource_identities(response, returned)
                returned_short_values = {
                    str(marker)[len(_MARKER):].split(":", 1)[1]
                    for marker in returned if type(marker) is _ResourceIdentity
                }
            for token in returned_short_values:
                if (target_appears_in(token, value)
                        and not target_appears_in(token, trusted) and not known_selector(token)):
                    return False
    return True


def _target_kind(name: str, key: str, *, policy, lexicon) -> str | None:
    words = _tokens(key)
    explicit = _kind(key)
    external = is_external_target_arg(name, key, policy=policy, lexicon=lexicon)
    if "id" in words:
        # A resource ID routes an existing-object mutation, even when file_id
        # is absent from the external-recipient vocabulary. Creating a new
        # object is a self-write exception and remains the existing gate's job.
        if lexicon.is_self_write_tool(name):
            return None
        return explicit or (_kind(name) if words == ["id"] else None) or ("identity" if external else None)
    if external:
        return explicit or "identity"
    return None


def short_target_violations(name: str, args: dict, trusted: str, user_task: str,
                            identity_set: set, *, policy, lexicon,
                            injection_span: str = "") -> list[str]:
    """Refuse short target values missing user or kind-scoped typed evidence.

    Merely occurring in U never authorizes an action. Destruction additionally
    requires explicit user intent, including when a short ID is a typed leaf.
    A value explicitly present in the user task keeps the existing T contract.
    """
    from .floor import iter_arg_values
    from .sanitizer import span_payload

    if lexicon.tool_is_read_only(name):
        return []
    issues = []
    for key, value in iter_arg_values(args or {}):
        role = _target_kind(name, str(key), policy=policy, lexicon=lexicon)
        short = _short(value, role) if role is not None else None
        if short is None:
            continue
        if lexicon.is_destructive(name) and not lexicon.user_authorized_destruction(user_task):
            issues.append(f"{key}={value}:destruction_not_requested")
            continue
        if target_appears_in(short, trusted):
            continue
        if injection_span and target_appears_in(short, span_payload(injection_span)):
            issues.append(f"{key}={value}:removed_injection")
            continue
        marker = resource_identity(role, short)
        if marker in identity_set or (role == "identity" and short in identity_set):
            continue
        issues.append(f"{key}={value}:no_user_or_typed_resource_evidence")
    return issues
