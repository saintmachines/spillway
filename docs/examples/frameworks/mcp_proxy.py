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

from mcp import ClientSession, StdioServerParameters, types
from mcp.client.stdio import stdio_client
from mcp.server.lowlevel import Server
from mcp.server.stdio import stdio_server
from spillway_guard import Guard, Lexicon

from guarded_tools import observe_records, observe_whole, snake_name


def _text_of(result) -> str:
    return "\n".join(block.text for block in result.content if getattr(block, "type", "") == "text")


def _names(values: list | None) -> set:
    return {v.strip() for raw in values or [] for v in raw.split(",") if v.strip()}


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
        # The proxy answers in text it has checked, so a tool's output schema no longer describes its answer.
        tools = [t.model_copy(update={"output_schema": None}) for t in (await downstream.list_tools()).tools]

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
