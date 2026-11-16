"""Put a SPILLWAY Guard around the tools of an application.

``guarded_call`` is the whole contract: check the call, run the tool only if the floor admits it, observe what came
back, and hand the model the text. ``observe_records`` gives the read-side filter one field of one record at a time, and
``observe_whole`` gives it the whole return, as the paper's runs did. Each adapter here takes either one as ``observe``.
``describe_tools`` shows how a lexicon reads your tool names and argument names before you ship them.

Copy this file into your project. It uses the public API of spillway-guard 0.1.4 and imports no framework SDK.
"""
from __future__ import annotations

import dataclasses
import re
import types
import typing
from typing import Any, Callable, Iterable, List, Mapping, Union

from pydantic import BaseModel, ConfigDict, create_model

from spillway_guard import Guard, Lexicon, sanitize
from spillway_guard.guard import format_return


def snake_name(name: Any) -> str:
    """``chat_postMessage`` to ``chat_post_message``. A namespaced lexicon reads tool names word by word on ``_``."""
    return re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", str(name)).lower()


def plain_return(value: Any) -> Any:
    """Plain serialization without typed identity authority. Everything else is unchanged."""
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return {f.name: plain_return(getattr(value, f.name)) for f in dataclasses.fields(value)}
    if isinstance(value, tuple) and hasattr(value, "_fields"):
        return {k: plain_return(v) for k, v in zip(value._fields, value)}
    if isinstance(value, (list, tuple)):
        return [plain_return(v) for v in value]
    if isinstance(value, dict):
        return {k: plain_return(v) for k, v in value.items()}
    return value


_DECLARED: dict = {}


def typed_return(value: Any) -> Any:
    """A dataclass or a named tuple as an instance of a Pydantic model with the same declared fields.

    Since 0.1.4 the Guard takes roles only from declared fields, and a dict's keys come from the payload, so a plain dict
    states no roles and stays as it is. Lists keep their order. Unresolved annotations, unsupported tuple fields and
    values that fail strict validation remain plain values without typed identity authority.
    """
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        try:
            return _declared(type(value))(**{f.name: typed_return(getattr(value, f.name)) for f in dataclasses.fields(value)})
        except (TypeError, ValueError, NameError, RecursionError):
            return plain_return(value)
    if isinstance(value, tuple) and hasattr(value, "_fields"):
        try:
            return _declared(type(value))(**{k: typed_return(v) for k, v in zip(value._fields, value)})
        except (TypeError, ValueError, NameError, RecursionError):
            return plain_return(value)
    if isinstance(value, (list, tuple)):
        return [typed_return(v) for v in value]
    return value


def _is_declared_class(hint: Any) -> bool:
    return isinstance(hint, type) and (dataclasses.is_dataclass(hint) or (issubclass(hint, tuple) and hasattr(hint, "_fields")))


def _annotation(hint: Any) -> Any:
    if _is_declared_class(hint):
        return _declared(hint)
    origin, args = typing.get_origin(hint), typing.get_args(hint)
    if origin is tuple:
        raise ValueError("tuple field annotations are not supported by this recipe")
    if origin in (list, set, frozenset) and args:
        return List[_annotation(args[0])]
    if origin in (Union, types.UnionType) and args:
        return Union[tuple(_annotation(a) for a in args)]
    return hint


def _declared(cls: type) -> type:
    """The Pydantic model for a dataclass or named tuple class, built once from the class's own field declarations."""
    model = _DECLARED.get(cls)
    if model is None:
        names = [f.name for f in dataclasses.fields(cls)] if dataclasses.is_dataclass(cls) else list(cls._fields)
        hints = typing.get_type_hints(cls)
        if any(n not in hints for n in names):
            raise ValueError("all declared fields need resolvable annotations")
        fields = {n: (_annotation(hints[n]), ...) for n in names}
        model = create_model(cls.__name__, __config__=ConfigDict(strict=True, arbitrary_types_allowed=True), **fields)
        _DECLARED[cls] = model
    return model


def _is_record(value: Any) -> bool:
    return isinstance(value, (BaseModel, dict))


def _is_record_list(value: Any) -> bool:
    return isinstance(value, (list, tuple)) and bool(value) and all(_is_record(v) for v in value)


def records_of(value: Any) -> list | None:
    """The records of a return, or None when it has none: a list of records, or a dict or model that holds such lists."""
    if _is_record_list(value):
        return list(value)
    if not _is_record(value):
        return None
    fields = value if isinstance(value, dict) else {k: getattr(value, k, None) for k in type(value).model_fields}
    nested = {k: v for k, v in fields.items() if _is_record_list(v)}
    if not nested:
        return None
    rest = {k: v for k, v in fields.items() if k not in nested}
    return ([rest] if rest else []) + [item for items in nested.values() for item in items]


def _paragraphs(text: str) -> list:
    parts = re.split(r"(\n\s*\n)", text)
    return [parts[i] + (parts[i + 1] if i + 1 < len(parts) else "") for i in range(0, len(parts), 2)]


def _fields(record: Any) -> list:
    """One record's fields, each rendered alone, in the order ``format_return`` prints them."""
    data = record.model_dump() if isinstance(record, BaseModel) else record
    if not isinstance(data, dict) or not data:
        return [format_return(data)]
    return [format_return({key: data[key]}) for key in sorted(data, key=str)]


def _filtered(guard: Guard, piece: str) -> str:
    spans: list = []
    text = sanitize(piece, spans, control_tokens=True, injected_imperatives=True,
                    agent_addressed=guard.policy.ingress_agentaddr, forged_turns_in_spans=True)
    if spans and guard.policy.injspan_recover:
        guard.index.add_spans(spans)
    guard.observe_text(text)
    return text


def observe_records(guard: Guard, name: str, args: dict | None, value: Any, *, roster: bool = False, paragraphs: bool = False) -> str:
    """Record one return and give back the text for the model, one field of one record at a time.

    The read-side filter replaces a region up to the end of the text it receives. With one field per pass, a region in a
    mail's body stays in that body, and its sender and the other mails still reach the model. The floor indexes the whole
    return once, so its identities and its taint are those of ``Guard.observe_tool_return``.

    ``paragraphs=True`` treats a text return as records split on blank lines, for a tool that returns long documents.
    """
    value = typed_return(value)
    pieces = _paragraphs(value) if paragraphs and isinstance(value, str) else None
    records = None if roster or pieces else records_of(value) or ([value] if _is_record(value) else None)
    if not (pieces or records) or not guard.sanitize_returns:
        return guard.observe_tool_return(name, args, value, roster=roster)
    guard.observe_tool_return(name, args, value, text="")
    if pieces:
        return "".join(_filtered(guard, piece) for piece in pieces)
    return "\n---\n".join("\n".join(_filtered(guard, field) for field in _fields(record)) for record in records)


def observe_whole(guard: Guard, name: str, args: dict | None, value: Any, *, roster: bool = False) -> str:
    """The path the paper evaluated: the whole return through one pass of the read-side filter."""
    return guard.observe_tool_return(name, args, typed_return(value), roster=roster)


def guarded_call(guard: Guard, name: str, args: dict | None, tool: Callable[..., Any], *, observe: Callable[..., str] = observe_records) -> str:
    """Check, run if admitted, observe. The returned text is what the model should read as the tool's result.

    A refused call never reaches ``tool``. A tool that raises is observed as text, like any other tool output, so an
    address in an error message counts as tool text too. One Guard serves one task, in order. Hold a lock around it if
    your loop runs the calls of a task on several threads.
    """
    args = dict(args or {})
    decision = guard.check_call(name, args)
    if not decision.allowed:
        return guard.observe_refusal(name, decision)
    try:
        value = tool(**args)
    except Exception as exc:  # the model reads the failure as the tool's result
        return observe(guard, name, args, f"Error: {type(exc).__name__}: {exc}")
    return observe(guard, name, args, value)


@dataclasses.dataclass(frozen=True)
class ToolRoles:
    """How a lexicon reads one tool. The floor checks ``targets`` as the places a side effect goes to."""

    name: str
    read_only: bool
    destructive: bool
    access_grant: bool
    targets: list
    other_args: list


def _arg_names(tool: Any) -> Iterable[str]:
    if isinstance(tool, Mapping):
        fn = tool.get("function", tool)
        schema = fn.get("parameters") or fn.get("input_schema") or fn.get("inputSchema") or fn.get("params_json_schema") or fn
        return schema.get("properties", {}).keys() if isinstance(schema, Mapping) else ()
    if isinstance(tool, (list, tuple, set, frozenset)):
        return tool
    code = getattr(tool, "__code__", None)
    return code.co_varnames[:code.co_argcount + code.co_kwonlyargcount] if code else ()


def describe_tools(tools: Mapping[str, Any] | Iterable[Mapping[str, Any]], lexicon: Lexicon | None = None) -> list:
    """How ``lexicon`` reads each tool. ``tools`` maps a name to a function, a schema or a list of argument names, or is a
    list of tool schemas (OpenAI, Anthropic or MCP form). Read the result before you ship a new tool surface, and
    declare what it misses with ``Lexicon.extend``.
    """
    lex = lexicon or Lexicon()
    items = dict(tools) if isinstance(tools, Mapping) else {t.get("function", t).get("name"): t for t in tools}
    out = []
    for name, tool in items.items():
        args = list(_arg_names(tool))
        out.append(ToolRoles(name=name, read_only=lex.tool_is_read_only(name), destructive=lex.is_destructive(name),
                             access_grant=lex.is_access_grant(name),
                             targets=[a for a in args if lex.is_target_arg(a)],
                             other_args=[a for a in args if not lex.is_target_arg(a)]))
    return out
