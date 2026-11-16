"""MCP: a stdio proxy that puts a Guard in front of another MCP server.

    python mcp_proxy.py --task "Triage the support inbox." -- python my_server.py

Your MCP host starts this file as its server, and this file starts yours. A host does not send a server the user's
message, so the proxy reads the deployment's task from --task and keeps it for the connection. One proxy holds one Guard
and handles one call at a time.
"""
from __future__ import annotations

import argparse
import asyncio
import os
from typing import Any, List

from guarded_tools import observe_records, observe_whole, snake_name
from mcp import ClientSession, StdioServerParameters, types
from mcp.client.stdio import stdio_client
from mcp.server.lowlevel import Server
from mcp.server.stdio import stdio_server
from pydantic import BaseModel, ConfigDict, ValidationError, create_model

from spillway_guard import Guard, Lexicon


def _text_of(result) -> str:
    return "\n".join(block.text for block in result.content if getattr(block, "type", "") == "text")


def _names(values: list | None) -> set:
    return {v.strip() for raw in values or [] for v in raw.split(",") if v.strip()}


_JSON_TYPES = {"string": str, "integer": int, "number": float, "boolean": bool, "null": type(None)}
_SCHEMA_NOTES = {"title", "description", "default", "examples", "$schema"}


def _supported(schema: dict, structural: set) -> None:
    # This recipe deliberately implements a small subset, not a JSON Schema validator.
    # Never turn an unsupported constraint or unresolved reference into typed authority.
    if not isinstance(schema, dict) or set(schema) - structural - _SCHEMA_NOTES:
        raise ValueError("unsupported output schema")


def _model_of(name: str, schema: dict, defs: dict, built: dict, building: set) -> Any:
    """A Pydantic model for one object schema the downstream server declared."""
    if name in building:
        raise ValueError("recursive output schema")
    _supported(schema, {"type", "properties", "required", "additionalProperties"})
    if schema.get("type") != "object" or not isinstance(schema.get("properties"), dict):
        raise ValueError("output object must declare properties")
    required_names = schema.get("required", [])
    if not isinstance(required_names, list) or any(not isinstance(k, str) for k in required_names):
        raise ValueError("invalid required fields")
    if len(set(required_names)) != len(required_names) or set(required_names) - set(schema["properties"]):
        raise ValueError("required fields must be declared")
    additional = schema.get("additionalProperties", True)
    if not isinstance(additional, bool):
        raise ValueError("unsupported additionalProperties schema")
    building.add(name)
    required, fields = set(required_names), {}
    for key, prop in schema["properties"].items():
        if not isinstance(key, str) or not key.isidentifier() or key.startswith("_") or hasattr(BaseModel, key):
            raise ValueError(f"field {key!r} cannot be declared")
        kind = _type_of(f"{name}_{key}", prop, defs, built, building)
        fields[key] = (kind, ...) if key in required else (kind, None)
    built[name] = create_model(name, __config__=ConfigDict(strict=True, extra="ignore" if additional else "forbid"), **fields)
    building.discard(name)
    return built[name]


def _type_of(name: str, prop: dict, defs: dict, built: dict, building: set) -> Any:
    if not isinstance(prop, dict):
        raise ValueError("invalid property schema")
    kind = prop.get("type")
    if kind == "object":
        return _model_of(name, prop, defs, built, building)
    if kind == "array":
        _supported(prop, {"type", "items"})
        return List[_type_of(name + "_item", prop.get("items"), defs, built, building)]
    _supported(prop, {"type"})
    if not isinstance(kind, str) or kind not in _JSON_TYPES:
        raise ValueError("unsupported property type")
    return _JSON_TYPES[kind]


def declared_models(tools) -> dict:
    """One model per tool whose output schema is an object, built once from the tools the server listed at connection.

    The Guard takes roles only from declared fields. The proxy validates each structured return against the schema the
    server you launched declared when the proxy connected, and it reads that list once, so a later change is ignored.
    Only objects with declared properties, homogeneous arrays and primitive JSON types are supported. Unsupported
    keywords (including enum, const, pattern, formats, unions and references) leave the entire tool's returns as plain
    dicts, which state no roles. Invalid values do likewise. No schema is inferred from a result's keys.
    """
    models = {}
    for tool in tools:
        schema = getattr(tool, "output_schema", None)
        if isinstance(schema, dict) and schema.get("type") == "object" and schema.get("properties"):
            try:
                models[tool.name] = _model_of("Output", schema, schema.get("$defs") or {}, {}, set())
            except Exception:
                pass
    return models


def typed_value(model: Any, value: Any) -> Any:
    """A structured return validated against its declared output schema, or the value unchanged if it does not fit."""
    if model is None or not isinstance(value, dict):
        return value
    try:
        return model.model_validate(value)
    except ValidationError:
        return value


def lexicon_from(read_verbs: list | None, target_args: list | None) -> Lexicon:
    more: dict = {}
    if read_verbs:
        more["read_prefixes"] = tuple(sorted(v + "_" for v in _names(read_verbs)))
    if target_args:
        more["target_arg_hints"] = _names(target_args)
    return Lexicon.for_agentdyn().extend(**more)


async def serve(task: str, command: str, command_args: list, lexicon: Lexicon, observe=observe_records) -> None:
    guard = Guard(task, lexicon=lexicon)
    turn = asyncio.Lock()   # a read finishes before the next call is checked against it
    params = StdioServerParameters(command=command, args=command_args, env=dict(os.environ))
    async with stdio_client(params) as (down_read, down_write), ClientSession(down_read, down_write) as downstream:
        await downstream.initialize()
        listed = (await downstream.list_tools()).tools
        declared = declared_models(listed)
        # The proxy answers in text it has checked, so a tool's output schema no longer describes its answer.
        tools = [t.model_copy(update={"output_schema": None}) for t in listed]

        async def on_list_tools(ctx, params):
            return types.ListToolsResult(tools=tools)

        async def on_call_tool(ctx, params):
            name, arguments = params.name, params.arguments or {}
            role_name = snake_name(name)
            async with turn:
                decision = guard.check_call(role_name, arguments)
                if not decision.allowed:
                    text = guard.observe_refusal(role_name, decision)
                    return types.CallToolResult(content=[types.TextContent(type="text", text=text)], is_error=True)
                try:
                    result = await downstream.call_tool(name, arguments)
                except Exception as exc:   # the host shows a failed call to the model, so its message goes through the Guard
                    text = observe(guard, role_name, arguments, f"Error: {type(exc).__name__}: {exc}")
                    return types.CallToolResult(content=[types.TextContent(type="text", text=text)], is_error=True)
                value = result.structured_content if result.structured_content is not None else _text_of(result)
                value = typed_value(declared.get(name), value)
                text = observe(guard, role_name, arguments, value)
            return types.CallToolResult(content=[types.TextContent(type="text", text=text)], is_error=bool(result.is_error))

        server = Server("spillway-proxy", on_list_tools=on_list_tools, on_call_tool=on_call_tool)
        async with stdio_server() as (up_read, up_write):
            await server.run(up_read, up_write, server.create_initialization_options())


def main() -> None:
    parser = argparse.ArgumentParser(description="Put a SPILLWAY Guard in front of a stdio MCP server.")
    parser.add_argument("--task", default="", help="what this deployment was asked to do; the floor treats it as the user's words")
    parser.add_argument("--read-verb", action="append", help="extra verbs of read-only tools, comma separated, such as fetch,history")
    parser.add_argument("--target-arg", action="append", help="extra argument names that route a side effect, comma separated")
    parser.add_argument("--whole-returns", action="store_true", help="filter each return whole, as the paper's runs did, instead of one field at a time")
    parser.add_argument("server", nargs=argparse.REMAINDER, help="-- then the command and arguments of the MCP server to guard")
    args = parser.parse_args()
    command = args.server[1:] if args.server[:1] == ["--"] else args.server
    if not command:
        parser.error("give the server command after --")
    asyncio.run(serve(args.task, command[0], command[1:], lexicon_from(args.read_verb, args.target_arg),
                      observe_whole if args.whole_returns else observe_records))


if __name__ == "__main__":
    main()
