"""A single-task, sequential SPILLWAY 0.1.1 boundary for a localhost example.

Only ``model_text`` is intended for the agent's tool-result channel. Metadata
reports what the client knows, without claiming that an HTTP error rolled back
a write. This is an example adapter, not a Gmail/Slack/framework integration.
"""
from __future__ import annotations

import http.client
import json
import math
import re
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any, Callable, Literal, get_args, get_origin

from pydantic import BaseModel, ConfigDict

from spillway_guard import Guard, Lexicon
from spillway_guard.guard import format_return
from spillway_guard.sanitizer import sanitize


class StrictModel(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid")


class BoundaryStopped(RuntimeError):
    """The task must stop; do not return an unchecked answer or execute a tool."""


@dataclass(frozen=True)
class ToolSpec:
    name: str
    args_model: type[StrictModel]
    response_model: type[StrictModel]
    effect: Literal["read", "write"]
    # A trusted schema field containing independent records, not a delimiter
    # inferred from the untrusted text. Other responses keep the library path.
    record_field: str | None = None
    # The application declares these routing fields; registration checks the
    # schema and vocabulary agree. Their meaning is not inferred from values.
    target_fields: tuple[str, ...] = ()


@dataclass(frozen=True)
class ToolResult:
    tool: str
    status: str
    model_text: str
    guard_checked: bool = False
    guard_label: str | None = None
    request_attempted: bool = False
    requests_sent: int | None = 0
    response_received: bool = False
    http_status: int | None = None
    response_validated: bool = False
    side_effects: str = "not_attempted"


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class ToolBoundary:
    """Use one instance per user task. Do not share it across parallel callers.

    The tool owner must supply trusted schemas and a complete role lexicon.
    This wrapper cannot infer missing observations or target roles. The only
    destination is the constructor's fixed http://127.0.0.1:<port> fixture.
    """

    def __init__(self, user_task: str, base_url: str, tools: list[ToolSpec], *,
                 lexicon: Lexicon | None = None, judge: Callable | None = None,
                 timeout: float = 2.0, max_response_bytes: int = 65536):
        url = urllib.parse.urlsplit(base_url)
        if (url.scheme != "http" or url.hostname != "127.0.0.1"
                or url.username is not None or url.password is not None
                or url.path not in ("", "/") or url.query or url.fragment
                or url.port is None or not 1 <= url.port <= 65535):
            raise ValueError("Use a fixed http://127.0.0.1:<port> example endpoint")
        if not math.isfinite(timeout) or not 0 < timeout <= 10:
            raise ValueError("timeout must be greater than zero and at most ten seconds")
        if type(max_response_bytes) is not int or not 1 <= max_response_bytes <= 1048576:
            raise ValueError("Set a response bound between one byte and one MiB")
        lex = lexicon or Lexicon()
        self.tools: dict[str, ToolSpec] = {}
        for spec in tools:
            if not re.fullmatch(r"[a-z][a-z0-9_]*", spec.name) or spec.name in self.tools:
                raise ValueError("Register unique literal tool names")
            if spec.effect not in ("read", "write"):
                raise ValueError("Register each tool as read or write")
            if lex.tool_is_read_only(spec.name) != (spec.effect == "read"):
                raise ValueError("The tool's declared effect and read-role lexicon disagree")
            for model in (spec.args_model, spec.response_model):
                if (not issubclass(model, StrictModel)
                        or model.model_config.get("strict") is not True
                        or model.model_config.get("extra") != "forbid"):
                    raise ValueError("Use strict, extra-forbid argument and response models")
            if spec.record_field is not None:
                field = spec.response_model.model_fields.get(spec.record_field)
                annotation = field.annotation if field is not None else None
                members = get_args(annotation)
                if (get_origin(annotation) is not list or len(members) != 1
                        or not isinstance(members[0], type)
                        or not issubclass(members[0], StrictModel)
                        or members[0].model_config.get("strict") is not True
                        or members[0].model_config.get("extra") != "forbid"):
                    raise ValueError("record_field must name a list of strict, extra-forbid record models")
            if (not isinstance(spec.target_fields, tuple)
                    or any(not isinstance(field, str) for field in spec.target_fields)
                    or len(set(spec.target_fields)) != len(spec.target_fields)):
                raise ValueError("Declare unique target field names as a tuple")
            for field in spec.target_fields:
                if field not in spec.args_model.model_fields:
                    raise ValueError("A declared target field must exist in the argument model")
                if not lex.is_target_arg(field):
                    raise ValueError("Declare each target field in the role lexicon before registration")
            self.tools[spec.name] = spec
        self.guard = Guard(user_task, lexicon=lex, judge=judge)
        self.base_url = f"http://127.0.0.1:{url.port}"
        self.timeout = timeout
        self.max_response_bytes = max_response_bytes
        # Do not follow a fixture's redirects or pick up environment proxies.
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())

    def _notice(self, name: str, text: str) -> str:
        try:
            # A string error cannot introduce a typed identity, even for a read tool.
            return self.guard.observe_tool_return(name, {}, text)
        except Exception as exc:
            raise BoundaryStopped("Tool-result observation failed; task stopped") from exc

    def observe_context(self, text: str) -> str:
        """Sanitize/observe untyped retrieved context or memory before the agent reads it."""
        if not isinstance(text, str):
            raise BoundaryStopped("External context must be text; task stopped")
        return self._notice("external_context", text)

    def _body(self, response) -> tuple[bytes, bool]:
        data = response.read(self.max_response_bytes + 1)
        return data[:self.max_response_bytes], len(data) > self.max_response_bytes

    def _observe_response(self, spec: ToolSpec, args: dict, value: StrictModel) -> str:
        if spec.record_field is None:
            return self.guard.observe_tool_return(spec.name, args, value)

        # Index the whole typed return once, before recording any of its text.
        # Calling observe_tool_return for each record would let earlier records'
        # taint change whether later records can be indexed for the same read.
        self.guard.observe_tool_return(spec.name, args, value, text="")
        records = getattr(value, spec.record_field)
        parts = []

        def filtered(piece: str) -> str:
            spans: list[str] = []
            text = sanitize(piece, spans, control_tokens=True,
                            injected_imperatives=True,
                            agent_addressed=self.guard.policy.ingress_agentaddr,
                            forged_turns_in_spans=True)
            if spans and self.guard.policy.injspan_recover:
                self.guard.index.add_spans(spans)
            self.guard.observe_text(text)
            return text

        def segment(raw: Any) -> str:
            # The trusted model supplies each field boundary. A region in a
            # message body then stays in that body, preserving its sender.
            data = raw.model_dump() if isinstance(raw, BaseModel) else raw
            return "\n".join(filtered(format_return({key: data[key]})) for key in sorted(data))

        metadata = value.model_dump(exclude={spec.record_field})
        if metadata:
            parts.append(segment(metadata))
        for i, record in enumerate(records, 1):
            parts.append(f"{spec.record_field} record {i}/{len(records)}:\n" + segment(record))
        if not records:
            parts.append(segment({spec.record_field: []}))
        return "\n\n".join(parts)

    def call(self, name: str, args: Any) -> ToolResult:
        if not isinstance(name, str) or name not in self.tools:
            return ToolResult("<unknown>", "unknown_tool", self._notice(
                "boundary_error", "Unknown tool. No HTTP request was made."))
        spec = self.tools[name]
        try:
            if not isinstance(args, dict):
                raise ValueError("Tool arguments must be a JSON object")
            validated = spec.args_model.model_validate(args, strict=True)
            # Freeze the JSON representation before checking it. The very same
            # immutable bytes go to the HTTP tool, avoiding post-check mutation.
            body = json.dumps(validated.model_dump(mode="json"), allow_nan=False).encode("utf-8")
            checked_args = json.loads(body)
        except Exception:
            return ToolResult(name, "invalid_arguments", self._notice(
                name, "Tool arguments did not match the registered schema. No HTTP request was made."))
        try:
            decision = self.guard.check_call(name, checked_args)  # reads included
        except Exception as exc:
            self._notice(name, "The action check failed. No HTTP request was made.")
            raise BoundaryStopped("The action check failed; task stopped") from exc
        if not decision.allowed:
            try:
                text = self.guard.observe_refusal(name, decision)
            except Exception as exc:
                raise BoundaryStopped("Refusal observation failed; task stopped") from exc
            return ToolResult(name, "blocked", text, True, decision.label)

        request = urllib.request.Request(self.base_url + "/tools/" + name, data=body,
                                         headers={"Content-Type": "application/json"}, method="POST")
        state = {"guard_checked": True, "guard_label": decision.label,
                 "request_attempted": True,
                 "side_effects": "unknown" if spec.effect == "write" else "read_only_contract"}
        headers_received, code = False, None
        try:
            with self.opener.open(request, timeout=self.timeout) as response:
                code = response.status
                headers_received = True
                raw, oversized = self._body(response)
        except urllib.error.HTTPError as exc:
            try:
                with exc:
                    raw, oversized = self._body(exc)
            except (TimeoutError, OSError, http.client.HTTPException):
                return ToolResult(name, "incomplete_response", self._notice(
                    name, "HTTP error headers were received but the body was incomplete. Side effects are not rolled back."),
                    **state, requests_sent=1, response_received=True, http_status=exc.code)
            if oversized:
                return ToolResult(name, "response_too_large", self._notice(
                    name, f"The tool returned HTTP {exc.code}, but its error body exceeded this example's size limit. The error body was not given to the agent."),
                    **state, requests_sent=1, response_received=True, http_status=exc.code)
            detail = raw.decode("utf-8", "replace")
            return ToolResult(name, "http_error", self._notice(
                name, f"The tool returned HTTP {exc.code}. Its untrusted error body follows:\n{detail}"),
                **state, requests_sent=1, response_received=True, http_status=exc.code)
        except (urllib.error.URLError, TimeoutError, OSError, http.client.HTTPException):
            # A transport failure cannot tell us whether a write reached the server.
            return ToolResult(name, "transport_error", self._notice(
                name, "No complete HTTP response was received. Delivery and side effects are unknown; do not retry a write blindly."),
                **state, requests_sent=1 if headers_received else None,
                response_received=headers_received, http_status=code)

        if oversized:
            return ToolResult(name, "response_too_large", self._notice(
                name, "The tool response exceeded this example's size limit. The response was not given to the agent."),
                **state, requests_sent=1, response_received=True, http_status=code)
        try:
            response_obj = spec.response_model.model_validate(json.loads(raw), strict=True)
        except Exception:
            # Never pass an invalid dict to the identity index. Preserve its
            # contents only as observed, sanitized, untyped error text.
            detail = raw.decode("utf-8", "replace")
            return ToolResult(name, "invalid_response", self._notice(
                name, "The tool response did not match its registered schema. Untrusted response:\n" + detail),
                **state, requests_sent=1, response_received=True, http_status=code)
        try:
            model_text = self._observe_response(spec, checked_args, response_obj)
        except Exception as exc:
            raise BoundaryStopped("Response observation failed; task stopped; an HTTP request was already sent") from exc
        return ToolResult(name, "ok", model_text, **state, requests_sent=1,
                          response_received=True, http_status=code, response_validated=True)

    def final_answer(self, candidate: str) -> str:
        """Return only a checked answer. A failing output check never falls back to raw text."""
        if not isinstance(candidate, str):
            raise BoundaryStopped("Final answer must be text; task stopped")
        try:
            checked_text, _dropped = self.guard.check_final_answer(candidate)
            return checked_text
        except Exception as exc:
            raise BoundaryStopped("Final-answer check failed; no unchecked answer returned") from exc
