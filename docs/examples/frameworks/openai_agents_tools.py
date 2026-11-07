"""OpenAI Agents SDK: wrap FunctionTools so each call goes through a Guard.

    guard = Guard(user_message)
    agent = Agent(name="mail", tools=guard_tools(guard, [get_mail, send_mail]))
"""
from __future__ import annotations

import dataclasses
import json
from typing import Any, Callable, Iterable

from agents import FunctionTool
from spillway_guard import Guard

from guarded_tools import observe_records


def guard_tools(guard: Guard, tools: Iterable[Any], *, observe: Callable[..., str] = observe_records) -> list:
    """Copies of ``tools`` that check every call and observe every return. Build one Guard and one list per user task."""
    wrapped = []
    for tool in tools:
        if not isinstance(tool, FunctionTool):
            raise TypeError(f"guard_tools takes FunctionTool objects, got {type(tool).__name__}")
        wrapped.append(dataclasses.replace(tool, on_invoke_tool=_invoke(guard, tool, observe)))
    return wrapped


def _invoke(guard: Guard, tool: Any, observe: Callable[..., str]):
    inner = tool.on_invoke_tool

    async def on_invoke_tool(ctx, input_json: str):
        try:
            args = json.loads(input_json or "{}")
        except ValueError:
            args = None
        if not isinstance(args, dict):   # the guard cannot read this call, so it does not run, whatever the tool's own parser accepts
            text = f"Error: the arguments of {tool.name} must be a JSON object."
            guard.observe_text(text)
            return text
        decision = guard.check_call(tool.name, args)
        if not decision.allowed:
            return guard.observe_refusal(tool.name, decision)
        try:
            value = await inner(ctx, json.dumps(args))   # the tool parses what the guard read
        except Exception as exc:   # the SDK's error handler may show this to the model, so it counts as tool text
            observe(guard, tool.name, args, f"Error: {type(exc).__name__}: {exc}")
            raise
        return observe(guard, tool.name, args, value)

    return on_invoke_tool
