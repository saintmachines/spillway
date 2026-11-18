"""Identity indexing whose schema authority comes from declared model classes.

No string key inside an arbitrary dictionary can declare an identity role.
"""
from __future__ import annotations

import types
from collections.abc import Mapping
from typing import Annotated, Any, Union, get_args, get_origin

from pydantic import BaseModel

from .lexicon import DEFAULT_LEXICON


def _identity_format(schema: Any) -> bool:
    from .floor import CONSTRAINED_FORMATS

    if not isinstance(schema, dict):
        return False
    if schema.get("format") in CONSTRAINED_FORMATS:
        return True
    return any(_identity_format(branch)
               for key in ("anyOf", "oneOf")
               for branch in schema.get(key, ()) if isinstance(branch, dict))


def _index_declared_value(value: Any, schema: dict, identities: set, *, role: bool = False) -> None:
    from .floor import norm

    for key in ("anyOf", "oneOf"):
        for branch in schema.get(key, ()):
            if isinstance(branch, dict):
                _index_declared_value(value, branch, identities, role=role)
    if isinstance(value, str):
        if role or _identity_format(schema):
            text = norm(value)
            if text:
                identities.add(text)
    elif isinstance(value, (list, tuple, set, frozenset)):
        item_schema = schema.get("items", {})
        if not isinstance(item_schema, dict):
            item_schema = {}
        for item in value:
            _index_declared_value(item, item_schema, identities, role=role)
    elif isinstance(value, dict):
        # Only declaration-time roles/formats can make keys identities. Runtime
        # sender/email/role/source keys never assign a role to their values.
        if role or _identity_format(schema.get("propertyNames", {})):
            for key in value:
                if isinstance(key, str) and norm(key):
                    identities.add(norm(key))
        value_schema = schema.get("additionalProperties", {})
        if isinstance(value_schema, dict) and _identity_format(value_schema):
            for item in value.values():
                _index_declared_value(item, value_schema, identities)
    elif (value is not None and not isinstance(value, (BaseModel, int, float, bool))
          and (role or _identity_format(schema))):
        # Validated URL/UUID/IP fields may hold constrained scalar objects,
        # whose normalized string is also what the existing floor indexes.
        text = norm(value)
        if text:
            identities.add(text)


def _walk_annotation(value: Any, annotation: Any, identities: set, lexicon, *, resource_markers: bool = False,
                     resource_contracts=None) -> None:
    origin, arguments = get_origin(annotation), get_args(annotation)
    if origin is Annotated:
        if arguments:
            _walk_annotation(value, arguments[0], identities, lexicon, resource_markers=resource_markers,
                             resource_contracts=resource_contracts)
        return
    if origin in (Union, types.UnionType):
        for branch in arguments:
            _walk_annotation(value, branch, identities, lexicon, resource_markers=resource_markers,
                             resource_contracts=resource_contracts)
        return
    if isinstance(annotation, type) and issubclass(annotation, BaseModel):
        if isinstance(value, annotation):
            _walk_model(value, identities, lexicon, resource_markers=resource_markers,
                        resource_contracts=resource_contracts)
        return
    if origin in (list, tuple, set, frozenset) and isinstance(value, origin):
        if not arguments:
            return
        if origin is tuple and len(arguments) > 1 and arguments[-1] is not Ellipsis:
            for item, item_annotation in zip(value, arguments):
                _walk_annotation(item, item_annotation, identities, lexicon, resource_markers=resource_markers,
                                 resource_contracts=resource_contracts)
        else:
            for item in value:
                _walk_annotation(item, arguments[0], identities, lexicon, resource_markers=resource_markers,
                                 resource_contracts=resource_contracts)
        return
    if origin in (dict, Mapping) and isinstance(value, Mapping) and len(arguments) == 2:
        for item in value.values():
            _walk_annotation(item, arguments[1], identities, lexicon, resource_markers=resource_markers,
                             resource_contracts=resource_contracts)


def _walk_model(obj: BaseModel, identities: set, lexicon, *, resource_markers: bool = False,
                resource_contracts=None) -> None:
    from .floor import schema_props

    if resource_markers:
        from .short_targets import _kind, _tokens, resource_identity

        if resource_contracts is not None:
            resource_contracts.index_model(obj, identities)
        current = _kind(type(obj).__name__)
        for name in type(obj).model_fields:
            words, explicit = _tokens(name), _kind(name)
            role = ((explicit or (current if words == ["id"] else None)) if "id" in words
                    else explicit if words in (["channel"], ["channels"]) else None)
            value = getattr(obj, name, None)
            if role is not None:
                for item in value if isinstance(value, (list, tuple)) else (value,):
                    marker = resource_identity(role, item)
                    if marker is not None:
                        identities.add(marker)
    properties = schema_props(type(obj))
    for name, field in type(obj).model_fields.items():
        schema = properties.get(name, {})
        if not isinstance(schema, dict):
            schema = {}
        value = getattr(obj, name, None)
        role = lexicon.is_target_arg(name) or lexicon.agentdyn_id_field(name)
        _index_declared_value(value, schema, identities, role=role)
        # A declared nested model is authoritative; a body:dict or Any value is
        # not recursively reinterpreted by the runtime names inside it.
        _walk_annotation(value, field.annotation, identities, lexicon, resource_markers=resource_markers,
                         resource_contracts=resource_contracts)


def index_typed_identity_leaves(obj: Any, identity_set: set, *, field_is_id_role: bool = False,
                                keys_are_id: bool = False, lexicon=DEFAULT_LEXICON) -> None:
    """Index a model root or a caller-verified roster, never raw dict authority.

    field_is_id_role is a trusted caller contract (the executor derives it from
    its declared list[str] return type), not a field accepted from tool payload.
    keys_are_id is accepted for indexer signature compatibility; a raw mapping
    root still requires an explicit containing model declaration and is ignored.
    """
    if isinstance(obj, BaseModel):
        _walk_model(obj, identity_set, lexicon)
    elif isinstance(obj, (list, tuple, set, frozenset)):
        for item in obj:
            if isinstance(item, BaseModel):
                _walk_model(item, identity_set, lexicon)
            elif field_is_id_role and isinstance(item, str):
                _index_declared_value(item, {}, identity_set, role=True)
    elif field_is_id_role and isinstance(obj, str):
        _index_declared_value(obj, {}, identity_set, role=True)


def index_typed_resource_identities(obj: Any, identity_set: set, *, lexicon=DEFAULT_LEXICON,
                                    resource_contracts=None) -> None:
    """The short-marker counterpart, walking only declared model paths too."""
    if isinstance(obj, BaseModel):
        _walk_model(obj, identity_set, lexicon, resource_markers=True, resource_contracts=resource_contracts)
    elif isinstance(obj, (list, tuple, set, frozenset)):
        for item in obj:
            if isinstance(item, BaseModel):
                _walk_model(item, identity_set, lexicon, resource_markers=True, resource_contracts=resource_contracts)
