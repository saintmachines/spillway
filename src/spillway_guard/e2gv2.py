"""Opt-in E2g v2 guard for applications that control tool dispatch."""

from collections.abc import Callable, Iterable
from copy import deepcopy
from dataclasses import dataclass
from ipaddress import ip_address
import re
from time import perf_counter
from typing import Any
from urllib.parse import urlsplit

from . import _e2_policy
from ._e2g_d1 import patch as _apply_frozen_d1
from ._terminal_effects import check_terminal_effects
from .file_policy import file_call_refusal
from .floor import Decision
from .guard import Guard
from .ingress import request_fields
from .judge import Judge
from .source_known import ReadSourceProof


if getattr(_e2_policy, "E2G_D1_LITERAL", None) != 2:
    _apply_frozen_d1(_e2_policy)


@dataclass(frozen=True)
class E2VerdictRequest:
    """A permissive tool decision for the application's explicit D2 reviewer."""

    operator_policy: str
    user_task: str
    tool_returns: tuple[str, ...]
    tool_name: str
    arguments: dict[str, Any]


@dataclass(frozen=True)
class _D2Adapter:
    callback: Callable[[E2VerdictRequest], bool | None]
    raw_tool_name: str

    def verdict(self, system, user, tools, _name, args):
        start = perf_counter()
        timed_out = False
        try:
            supported = self.callback(E2VerdictRequest(
                system, user, tuple(tools), self.raw_tool_name, deepcopy(args),
            ))
        except TimeoutError:
            supported = None
            timed_out = True
        except Exception:
            supported = None
        parsed = type(supported) is bool
        return (int(supported) if parsed else None), {
            "parsed": parsed, "timed_out": timed_out, "latency_s": perf_counter() - start,
        }


def _frozen_d2_judge(guard_judge) -> _e2_policy.VerdictJudge | None:
    """Reuse a configured local SDK Judge's endpoint and first model."""
    if not isinstance(guard_judge, Judge) or guard_judge.api_key or not guard_judge.models:
        return None
    model = guard_judge.models[0]
    if not isinstance(model, str) or not model.strip():
        return None

    try:
        endpoint = urlsplit(guard_judge.endpoint)
        host = endpoint.hostname
        if (endpoint.scheme not in ("http", "https") or not host or
                endpoint.username is not None or endpoint.password is not None or
                endpoint.query or endpoint.fragment):
            return None
        if host != "localhost" and not ip_address(host).is_loopback:
            return None
    except (TypeError, ValueError):
        return None
    return _e2_policy.VerdictJudge(guard_judge.endpoint, model)


class E2gV2Guard(Guard):
    """Apply the E2g v2 tool-return and pre-dispatch rules to a single task."""

    def __init__(
        self, user_task: str, *,
        operator_policy: str = "",
        tool_names: Iterable[str] = (),
        d2_judge: Callable[[E2VerdictRequest], bool | None] | None = None,
        **guard_options,
    ):
        if not isinstance(operator_policy, str):
            raise TypeError("operator_policy must be text supplied by the host application")
        if d2_judge is not None and not callable(d2_judge):
            raise TypeError("d2_judge must be callable")
        if isinstance(tool_names, str):
            raise TypeError("tool_names must be a collection of names")
        names = tuple(tool_names)
        if any(not isinstance(name, str) or not name for name in names):
            raise TypeError("tool names must be non-empty strings")
        super().__init__(user_task, **guard_options)
        self._e2_operator_policy = operator_policy
        self._e2_tool_names = names
        self._e2_judge = d2_judge
        self._e2_default_judge = _frozen_d2_judge(self.judge) if d2_judge is None else None
        self._e2_tool_history: list[dict[str, str]] = []
        self._e2_original_returns: list[str] = []
        self.e2_audit: list[dict[str, Any]] = []

    @classmethod
    def from_request(cls, request, **options):
        """Construct from the same app-owned request fields as Guard."""
        instruction, material = request_fields(request)
        return cls(instruction, pasted=material, **options)

    def reset(self, user_task: str | None = None) -> None:
        super().reset(user_task)
        self._created_resources.reset()
        self._e2_tool_history.clear()
        self._e2_original_returns.clear()
        self.e2_audit.clear()

    def check_call(self, name: str, args: dict | None) -> Decision:
        refusal = file_call_refusal(name, args)
        if refusal is not None:
            self.audit.append({"tool": name, "decision": refusal.label, "score": refusal.score})
            return refusal

        base = super().check_call(name, args)
        if not base.allowed:
            return base

        audit_row = self.audit[-1]
        e2_allowed = False
        try:
            normalized_name = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", name.split("__")[-1]).lower()
            context = [
                {"role": "system", "content": self._e2_operator_policy},
                {"role": "user", "content": self.user_task},
                *self._e2_tool_history,
            ]
            judge = (_D2Adapter(self._e2_judge, name) if self._e2_judge is not None
                     else self._e2_default_judge)
            decision = _e2_policy.e2_check(
                self, normalized_name, deepcopy(args or {}), context, judge,
                self.e2_audit, self._e2_original_returns, raw_name=name,
            )
            if decision is not None and not decision.allowed:
                audit_row.update(decision=decision.label, score=decision.score)
                return decision
            decision = check_terminal_effects(self, name, args, audit_row)
            if decision is not None:
                audit_row.update(decision=decision.label, score=decision.score)
                return decision
            e2_allowed = True
            return base
        except Exception:
            audit_row.update(decision="error_e2_policy", score=0.0)
            raise
        finally:
            if not e2_allowed and self.policy.short_target_guard:
                self._created_resources.discard(name, args or {})

    def observe_tool_return(
        self, name: str, args: dict | None, typed_return: Any, *,
        text: str | None = None, roster: bool = False,
        read_source: ReadSourceProof | None = None,
    ) -> str:
        original = super().observe_tool_return(
            name, args, typed_return, text=text, roster=roster, read_source=read_source,
        )
        display, _ = _e2_policy.e2_ingress(original, self._e2_tool_names)
        self._e2_original_returns.append(original)
        self._e2_tool_history.append({"role": "tool", "content": display})
        return display

    def observe_refusal(self, name: str, decision: Decision) -> str:
        text = super().observe_refusal(name, decision)
        self._e2_tool_history.append({"role": "tool", "content": text})
        return text

    def observe_text(self, text: str) -> None:
        super().observe_text(text)
        self._e2_tool_history.append({"role": "tool", "content": str(text)})
