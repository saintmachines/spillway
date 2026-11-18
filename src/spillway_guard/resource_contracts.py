"""Application-owned resource roles for a declared model's alias fields.

A Python type alias such as ``CloudDriveFileID = str`` loses its resource kind
at runtime. The application can register that declaration explicitly without
editing a benchmark model or treating keys in its free-text body as a schema.
Contracts belong to the host configuration and never come from tool payloads.
"""
from __future__ import annotations

import types
from dataclasses import dataclass
from typing import Annotated, Union, get_args, get_origin

from pydantic import BaseModel


def _scalar_types(annotation):
    origin, arguments = get_origin(annotation), get_args(annotation)
    if origin is Annotated:
        return _scalar_types(arguments[0])
    if origin in (Union, types.UnionType):
        return set().union(*(_scalar_types(branch) for branch in arguments))
    return {annotation} if annotation in (str, int) else set()


def _declaration(annotation):
    if get_origin(annotation) is Annotated:
        return _declaration(get_args(annotation)[0])
    if get_origin(annotation) in (list, tuple, set, frozenset):
        arguments = get_args(annotation)
        if len(arguments) == 1 or (len(arguments) == 2 and arguments[1] is Ellipsis):
            return get_origin(annotation), _scalar_types(arguments[0])
        return None, set()
    return None, _scalar_types(annotation)


@dataclass(frozen=True)
class ResourceField:
    """Host declaration that one existing model field carries a resource ID.

    ``model`` must be the actual application class, not a class name supplied
    in JSON. Its exact class and declaration are checked again on every read.
    Only the declared scalar branch is indexed; e.g. CalendarEvent objects in
    ``list[str | CalendarEvent]`` never become file IDs.
    """
    model: type[BaseModel]
    field: str
    kind: str
    taint_fields: tuple[str, ...] = ()

    def __post_init__(self):
        from .short_targets import _KINDS, _kind, _tokens

        if not isinstance(self.model, type) or not issubclass(self.model, BaseModel):
            raise TypeError("resource model must be a host-declared Pydantic class")
        if not isinstance(self.field, str) or self.field not in self.model.model_fields:
            raise ValueError("resource field must exist in the declared model")
        if self.kind not in set(_KINDS.values()):
            raise ValueError("resource kind must be a supported kind")
        words, explicit = _tokens(self.field), _kind(self.field)
        declared_kind = ((explicit or (_kind(self.model.__name__) if words == ["id"] else None))
                         if "id" in words else explicit if words in (["channel"], ["channels"]) else None)
        if declared_kind is not None and declared_kind != self.kind:
            raise ValueError("a host alias contract cannot replace an existing declared resource kind")
        declaration = self.model.model_fields[self.field].annotation
        if not _declaration(declaration)[1]:
            raise ValueError("resource field needs a declared scalar or scalar-list branch")
        object.__setattr__(self, "_annotation", declaration)
        if (not isinstance(self.taint_fields, tuple)
                or len(set(self.taint_fields)) != len(self.taint_fields)
                or any(not isinstance(name, str) or name not in self.model.model_fields
                       or self.model.model_fields[name].annotation is not str
                       for name in self.taint_fields)):
            raise ValueError("taint fields must be distinct host-declared text fields")
        object.__setattr__(self, "_taint_annotations", tuple(
            self.model.model_fields[name].annotation for name in self.taint_fields))

    def index(self, model, identities):
        from .short_targets import resource_identity

        if type(model) is not self.model:
            return
        if self.model.model_fields[self.field].annotation != self._annotation:
            return
        if self.taint_fields:
            from .sanitizer import sanitize

            for name, annotation in zip(self.taint_fields, self._taint_annotations):
                value = getattr(model, name, None)
                if self.model.model_fields[name].annotation is not annotation or type(value) is not str:
                    return
                spans = []
                sanitize(value, span_sink=spans, forged_turns_in_spans=True)
                if spans or "[redacted-injected-instruction]" in value:
                    return
        container, scalar_types = _declaration(self._annotation)
        value = getattr(model, self.field, None)
        if container is not None:
            if type(value) is not container:
                return
            values = value
        else:
            values = (value,)
        for leaf in values:
            if type(leaf) not in scalar_types:
                continue
            marker = resource_identity(self.kind, leaf)
            if marker is not None:
                identities.add(marker)


@dataclass(frozen=True)
class ResourceContracts:
    """Explicit host configuration, empty by default and never parsed from text.

    This only supplies a missing resource kind after the existing legitimate
    read/query checks. It authorizes neither an action nor a destination, and
    does not convert a raw dict into a declared model.
    """
    fields: tuple[ResourceField, ...] = ()

    def __post_init__(self):
        if not isinstance(self.fields, tuple) or not all(type(value) is ResourceField for value in self.fields):
            raise TypeError("resource fields must be a host-created tuple of ResourceField")
        declarations = [(value.model, value.field) for value in self.fields]
        if len(set(declarations)) != len(declarations):
            raise ValueError("a resource field must have one unambiguous host kind")

    def index_model(self, model, identities):
        for declaration in self.fields:
            declaration.index(model, identities)
