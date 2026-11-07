"""Claude Code: a hook command that keeps one Guard per session.

Use this file as the command of the UserPromptSubmit, PreToolUse, PostToolUse and PostToolUseFailure hooks. Each hook runs in a new process,
so the session's events are kept in a file and replayed. PreToolUse denies a call the floor refuses, and blocks a call it
cannot check. For the shell tool the floor checks the URLs and addresses in the command. The hook checks calls and records
returns. The model reads each tool's own output here.
"""
from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path

try:
    from spillway_guard import Guard, Lexicon
    from spillway_guard.floor import EMAIL_RE, URL_RE

    from guarded_tools import snake_name
except ImportError as exc:   # exit code 2 stops the prompt or the call, any other code lets it through
    print(f"SPILLWAY hook cannot load: {exc}", file=sys.stderr)
    sys.exit(2)

SHELL_TOOLS = {"bash"}
READ_VERBS = ("fetch_", "grep_", "glob_", "ls_", "search_")


def session_lexicon() -> Lexicon:
    return Lexicon.for_agentdyn().extend(read_prefixes=READ_VERBS)


def _log_path(session_id: str) -> Path:
    root = Path(os.environ.get("SPILLWAY_STATE_DIR") or Path.home() / ".cache" / "spillway" / "claude_code")
    return root / (re.sub(r"[^A-Za-z0-9_.-]", "_", str(session_id or "session")) + ".jsonl")


def _append(session_id: str, event: dict) -> None:
    path = _log_path(session_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(event, ensure_ascii=False, default=str) + "\n")


def _events(session_id: str) -> list:
    path = _log_path(session_id)
    if not path.exists():
        return []
    with open(path, encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def checked_args(tool: str, args: dict | None) -> dict:
    """What the floor checks for one call. A shell command is one long string, so its targets are its URLs and addresses."""
    args = dict(args or {})
    if snake_name(tool) in SHELL_TOOLS:
        command = str(args.get("command", ""))
        return {"url": [m.group(0) for m in URL_RE.finditer(command)],
                "recipients": [m.group(0) for m in EMAIL_RE.finditer(command)]}
    return args


def guard_for(session_id: str) -> Guard:
    """Replay the session: the user's prompts so far are the task, the tool returns are what the agent has read."""
    events = _events(session_id)
    task = "\n".join(e["prompt"] for e in events if e.get("kind") == "prompt")
    guard = Guard(task, lexicon=session_lexicon())
    for e in events:
        if e.get("kind") == "tool":
            guard.observe_tool_return(snake_name(e["tool"]), e.get("args"), e.get("response"))
    return guard


def handle(event: dict) -> dict | None:
    """One hook event in, the hook's JSON answer out (None for no answer)."""
    kind, session_id = event.get("hook_event_name"), event.get("session_id", "")
    if kind == "UserPromptSubmit":
        _append(session_id, {"kind": "prompt", "prompt": event.get("prompt", "")})
    elif kind == "PostToolUse":
        _append(session_id, {"kind": "tool", "tool": event.get("tool_name", ""), "args": event.get("tool_input"),
                             "response": event.get("tool_response")})
    elif kind == "PostToolUseFailure":   # the model reads a failed tool's error text too
        _append(session_id, {"kind": "tool", "tool": event.get("tool_name", ""), "args": event.get("tool_input"),
                             "response": str(event.get("error", ""))})
    elif kind == "PreToolUse":
        tool = event.get("tool_name", "")
        decision = guard_for(session_id).check_call(snake_name(tool), checked_args(tool, event.get("tool_input")))
        if not decision.allowed:
            return {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny",
                                           "permissionDecisionReason": "SPILLWAY: " + decision.reason}}
    return None


if __name__ == "__main__":
    try:
        answer = handle(json.load(sys.stdin))
    except Exception as exc:   # a call this hook cannot check does not run: Claude Code blocks it on exit code 2 only
        print(f"SPILLWAY could not check this event: {type(exc).__name__}: {exc}", file=sys.stderr)
        sys.exit(2)
    if answer is not None:
        print(json.dumps(answer))
