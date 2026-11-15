"""Bounded typed-read lineage and receipts for actually admitted creations."""
from __future__ import annotations

import hashlib
import json
from collections import Counter
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from functools import wraps
from typing import Any, Callable

from pydantic import BaseModel

from .lexicon import DEFAULT_LEXICON
from .short_targets import _kind, _tokens, resource_identity


class _VerifiedQueryIdentity(str):
    def __eq__(self, other):
        return type(other) is _VerifiedQueryIdentity and str.__eq__(self, other)

    def __ne__(self, other):
        return not self.__eq__(other)

    def __hash__(self):
        return hash((_VerifiedQueryIdentity, str(self)))


def query_identity(value: Any) -> str | None:
    from .floor import norm

    if not isinstance(value, str):
        return None
    value = norm(value)
    return _VerifiedQueryIdentity("\x00spillway-query:" + value) if 1 <= len(value) <= 2048 else None


def index_verified_query_identities(obj: Any, identities: set, *, roster: bool = False,
                                    lexicon=DEFAULT_LEXICON) -> None:
    """Only declared models/verified rosters, never the legacy dict-key walker."""
    from .typed_identity import index_typed_identity_leaves

    typed = set()
    verified_roster = bool(roster and isinstance(obj, list) and all(isinstance(item, str) for item in obj))
    index_typed_identity_leaves(obj, typed, field_is_id_role=verified_roster, lexicon=lexicon)
    for value in typed:
        marker = query_identity(value)
        if marker is not None:
            identities.add(marker)


def query_entailed_from_verified_identities(args: dict, tainted: str, trusted: str,
                                           identities: set, *, lexicon=DEFAULT_LEXICON) -> bool:
    """Clear only novelty of whole routing values already carrying typed evidence.

    Non-routing query/body/search/count fields receive no exception. Short
    resource IDs still face short_resource_read_entailed at the index boundary.
    """
    from .floor import is_taint_novel, iter_arg_values

    recovered = False
    for key, value in iter_arg_values(args or {}):
        if not is_taint_novel(value, tainted, trusted):
            continue
        words = _tokens(str(key))
        resource_role = _kind(str(key)) if "id" in words else None
        if not (lexicon.is_target_arg(str(key)) or resource_role is not None):
            return False
        marker = query_identity(value)
        if marker is None or marker not in identities:
            return False
        recovered = True
    return recovered


def _creation_kind(name: str) -> str | None:
    words = _tokens(name)
    return _kind(name) if words and words[0] == "create" else None


def _call_key(name: str, args: dict) -> tuple[str, str] | None:
    try:
        payload = json.dumps(dict(args or {}), sort_keys=True, ensure_ascii=False,
                             separators=(",", ":"), default=str)
    except Exception:
        return None
    return str(name).lower(), hashlib.sha256(payload.encode()).hexdigest()


@dataclass(frozen=True)
class CreationContracts:
    """App-owned declarations of APIs that allocate a fresh server resource.

    A name/return shape cannot prove create-new semantics. Register only a
    reviewed backend API that never echoes/upserts an existing object, including
    when the caller supplied its filename/slug. Raw success/new/trusted fields
    are not contracts. An empty registry emits no creation authority.
    """

    fresh_tools: frozenset[str] = frozenset()

    def __post_init__(self):
        if not isinstance(self.fresh_tools, (set, frozenset)) or not all(
            isinstance(name, str) and name and _creation_kind(name) is not None
            for name in self.fresh_tools
        ):
            raise TypeError("fresh_tools must be a trusted set of declared create-new API names")
        object.__setattr__(self, "fresh_tools", frozenset(self.fresh_tools))


class CreatedObjectReceipts:
    """One outcome per admitted create call; no owner/recipient/write-echo indexing."""

    def __init__(self, contracts: CreationContracts | None = None):
        self.pending = Counter()
        self.contracts = CreationContracts()
        self.configure(contracts)

    def configure(self, contracts: CreationContracts | None = None):
        contracts = CreationContracts() if contracts is None else contracts
        if not isinstance(contracts, CreationContracts):
            raise TypeError("creation_contracts must be app-owned CreationContracts")
        if contracts != self.contracts:
            self.pending.clear()
            self.contracts = contracts

    def reset(self):
        self.pending.clear()

    def record(self, name: str, args: dict, allowed: bool) -> None:
        if name not in self.contracts.fresh_tools or _creation_kind(name) is None:
            return
        key = _call_key(name, args)
        if key is None:
            return
        if allowed is not True:
            # A refused duplicate is not executed and must not cancel an
            # earlier, separately admitted call with the same arguments.
            return
        elif len(self.pending) < 128 or key in self.pending:
            self.pending[key] += 1

    def discard(self, name: str, args: dict) -> None:
        key = _call_key(name, args)
        if key is not None and self.pending[key] > 0:
            self.pending[key] -= 1
            if not self.pending[key]:
                del self.pending[key]

    def observe(self, name: str, args: dict, raw: Any, identities: set) -> None:
        from .floor import iter_arg_values

        key, kind = _call_key(name, args), _creation_kind(name)
        if name not in self.contracts.fresh_tools or key is None or kind is None or self.pending[key] <= 0:
            return
        self.discard(name, args)
        # Receipt identity must be server-generated, not a caller-selected ID.
        if any("id" in _tokens(str(k)) for k, _ in iter_arg_values(args or {})):
            return
        if not isinstance(raw, BaseModel) or _kind(type(raw).__name__) != kind:
            return
        candidates = set()
        caller_values = {
            str(value).strip().lower()
            for _, value in iter_arg_values(args or {})
            if not isinstance(value, bool) and isinstance(value, (str, int))
        }
        for field in type(raw).model_fields:
            if _tokens(field) not in (["id"], [kind, "id"]):
                continue
            value = getattr(raw, field, None)
            marker = resource_identity(kind, value)
            if marker is not None:
                if str(value).strip().lower() in caller_values:
                    return  # a slug/filename/alias echo is not a fresh server ID
                candidates.add(marker)
        if len(candidates) == 1:
            identities.update(candidates)


@dataclass
class _ExecutionFrame:
    creations: CreatedObjectReceipts
    identities: Callable[[], set]


_CURRENT = ContextVar("spillway_created_resource_execution", default=None)


@contextmanager
def created_resource_context(creations: CreatedObjectReceipts | None, identities: Callable[[], set]):
    token = _CURRENT.set(_ExecutionFrame(creations, identities) if creations is not None else None)
    try:
        yield
    finally:
        _CURRENT.reset(token)


def current_resource_identities() -> set | None:
    frame = _CURRENT.get()
    return frame.identities() if frame is not None else None


def with_creation_receipts(decision, *, enabled: bool):
    if not enabled:
        return decision

    @wraps(decision)
    def checked(name, args, *positional, **kwargs):
        result = decision(name, args, *positional, **kwargs)
        frame = _CURRENT.get()
        if frame is not None:
            frame.creations.record(name, args, result[0] == "allow")
        return result
    return checked
