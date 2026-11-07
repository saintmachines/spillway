"""LangChain and LangGraph: a middleware that runs every tool call of an agent through a Guard.

    agent = create_agent(model, [typed_tool(get_mail), typed_tool(send_mail)], middleware=[spillway_middleware()])
"""
from __future__ import annotations

import inspect
import threading
import uuid
from collections import OrderedDict
from typing import Annotated, Any, Callable

from langchain.agents.middleware import AgentMiddleware
from langchain.agents.middleware.types import AgentState, PrivateStateAttr
from langchain_core.messages import ToolMessage
from langchain_core.tools import StructuredTool
from langgraph.errors import GraphBubbleUp
from langgraph.types import Command
from typing_extensions import NotRequired
from spillway_guard import Guard

from guarded_tools import observe_records

MAX_OPEN_TASKS = 4096


def _command_messages(command: Command) -> list:
    """The messages a tool's ``Command`` adds to the conversation. The model reads them as it reads a tool's return."""
    update = command.update
    pairs = update.items() if isinstance(update, dict) else update if isinstance(update, (list, tuple)) else ()
    out: list = []
    for pair in pairs:
        if isinstance(pair, (list, tuple)) and len(pair) == 2 and pair[0] == "messages":
            value = pair[1]
            out.extend(value if isinstance(value, (list, tuple)) else [value])
    return out


def _messages(state: Any) -> list:
    return state.get("messages", []) if isinstance(state, dict) else getattr(state, "messages", [])


def _human_messages(state: Any) -> list:
    return [m for m in _messages(state) if getattr(m, "type", None) == "human"]


def _text(message: Any) -> str:
    content = message.content
    if isinstance(content, str):
        return content
    return " ".join(part.get("text", "") if isinstance(part, dict) else str(part) for part in content)


def _field(state: Any, name: str) -> Any:
    return state.get(name) if isinstance(state, dict) else getattr(state, name, None)


def _scope(request: Any) -> Any:
    """LangGraph's thread when the run has one, and otherwise this invocation. Message ids are the application's, so two users may share one."""
    config = getattr(getattr(request, "runtime", None), "config", None) or {}
    return (config.get("configurable") or {}).get("thread_id") or _field(request.state, "spillway_run")


class _RunState(AgentState):
    spillway_run: NotRequired[Annotated[str, PrivateStateAttr]]


class SpillwayMiddleware(AgentMiddleware):
    """Each thread gets its own Guard, and an invocation with no thread gets one for itself. The user's text is every human
    message so far. Only messages with the human role count as the user's words, so keep retrieved text out of them. A new
    Guard first reads the tool messages already in the conversation. LangGraph may run the calls of one step on several
    threads, so a lock covers each Guard.
    """

    name = "spillway"
    state_schema = _RunState

    def __init__(self, guard_factory: Callable[[str], Guard] = Guard, observe: Callable[..., str] = observe_records):
        super().__init__()
        self._factory = guard_factory
        self._observe = observe
        self._guards: OrderedDict = OrderedDict()
        self._lock = threading.Lock()

    def before_agent(self, state, runtime):
        return {"spillway_run": uuid.uuid4().hex}

    async def abefore_agent(self, state, runtime):
        return self.before_agent(state, runtime)

    def guard_for(self, state: Any, scope: Any = None) -> Guard:
        humans = _human_messages(state)
        task = " ".join(_text(m) for m in humans)
        if scope is None:
            scope = _field(state, "thread_id")
        key = (scope, (humans[0].id or _text(humans[0])) if humans else "")
        guard = self._guards.get(key)
        if guard is None:
            guard = self._guards[key] = self._factory(task)
            for message in _messages(state):
                if getattr(message, "type", None) == "tool":
                    artifact = getattr(message, "artifact", None)
                    guard.observe_tool_return(message.name or "", None, artifact if artifact is not None else message.content)
            if len(self._guards) > MAX_OPEN_TASKS:
                self._guards.popitem(last=False)
        else:
            self._guards.move_to_end(key)
            guard.user_task = task
        return guard

    def _admit(self, request):
        call = request.tool_call
        with self._lock:
            guard = self.guard_for(request.state, _scope(request))
            decision = guard.check_call(call["name"], call["args"])
            if decision.allowed:
                return guard, None
            text = guard.observe_refusal(call["name"], decision)
        return guard, ToolMessage(content=text, name=call["name"], tool_call_id=call["id"], status="error")

    def _observed(self, guard, request, result):
        call = request.tool_call
        messages = [result] if isinstance(result, ToolMessage) else _command_messages(result) if isinstance(result, Command) else []
        for message in messages:
            if isinstance(message, dict):
                with self._lock:
                    message["content"] = self._observe(guard, call["name"], call["args"], message.get("content", ""))
                continue
            artifact = getattr(message, "artifact", None)
            with self._lock:
                message.content = self._observe(guard, call["name"], call["args"], artifact if artifact is not None else message.content)
        return result

    def _failed(self, guard, request, exc):
        """A failure on its way out can reach the model through an outer handler, so it counts as tool text."""
        call = request.tool_call
        with self._lock:
            self._observe(guard, call["name"], call["args"], f"Error: {type(exc).__name__}: {exc}")

    def wrap_tool_call(self, request, handler):
        guard, refused = self._admit(request)
        if refused is not None:
            return refused
        try:
            result = handler(request)
        except GraphBubbleUp:   # LangGraph's own control flow, such as an interrupt
            raise
        except Exception as exc:
            self._failed(guard, request, exc)
            raise
        return self._observed(guard, request, result)

    async def awrap_tool_call(self, request, handler):
        guard, refused = self._admit(request)
        if refused is not None:
            return refused
        try:
            result = await handler(request)
        except GraphBubbleUp:
            raise
        except Exception as exc:
            self._failed(guard, request, exc)
            raise
        return self._observed(guard, request, result)


def spillway_middleware(guard_factory: Callable[[str], Guard] = Guard, observe: Callable[..., str] = observe_records) -> SpillwayMiddleware:
    """``guard_factory(user_task)`` sets the lexicon or the judge of the Guards this middleware builds."""
    return SpillwayMiddleware(guard_factory, observe)


def typed_tool(function: Callable[..., Any]) -> StructuredTool:
    """A tool that keeps its typed return for the floor. LangChain turns a plain tool's return into a string before a
    middleware sees it, and a string states no roles."""

    def run(*args, **kwargs):
        value = function(*args, **kwargs)
        return str(value), value

    run.__signature__ = inspect.signature(function).replace(return_annotation=inspect.Signature.empty)
    run.__annotations__ = {k: v for k, v in getattr(function, "__annotations__", {}).items() if k != "return"}
    return StructuredTool.from_function(run, name=function.__name__, description=function.__doc__ or function.__name__,
                                        response_format="content_and_artifact")
