"""Guard: the drop-in egress layer for any tool-calling loop.

    guard = Guard(user_task)
    ...
    text = guard.observe_tool_return(name, args, typed_return)   # what the model should read
    ...
    d = guard.check_call(name, args)                             # before executing a call
    if d.blocked:
        feed d.refusal_text(name) back to the model as the tool result

``observe_tool_return`` does what the evaluation harness's executor did after every executed call:
it indexes the typed identities of a READ-ONLY return (never a write's), harvests free-text
co-residence, and sanitizes the text the model will read (forged turns, injection templates,
agent-addressed regions, payee claims), keeping the removed spans for the span veto. ``check_call``
runs the floor. A call that the floor refers to the judge goes to the configured ``Judge`` or,
with no judge, to ``Decision.resolve_without_judge``. The ladder then resumes, and a rule after
the judge can still admit the call.
"""

from __future__ import annotations

import json
from typing import Any, Callable, List, Optional, Tuple

from .floor import (
    DEFAULT_POLICY,
    Decision,
    IdentityIndex,
    JudgeRequest,
    Policy,
    admit,
    norm,
    output_injected_sentences,
    output_recommend_authorized,
    strip_injected_endorsements,
    text_of,
)
from .lexicon import DEFAULT_LEXICON, Lexicon
from .sanitizer import sanitize, span_payload

__all__ = ["Guard", "format_return"]


def format_return(obj: Any) -> str:
    """Default rendering of a typed return into the text the model reads. Mirrors the evaluation harness
    (YAML dump of the model's fields, JSON if the dump fails, a str as is), except that scalars never wrap,
    dict returns are dumped as YAML, and non-ASCII text stays as written, where the harness's dump escaped it."""
    if obj is None:
        return "None"
    if isinstance(obj, str):
        return obj
    dumped = _dump(obj)
    try:
        import yaml  # type: ignore
        # width=inf: a scalar never wraps, so a target that contains spaces (a spaced IBAN) stays on one line
        # and the sanitizer's payee-claim region covers the whole value instead of ending at a wrapped line.
        # allow_unicode: the taint lookup matches a target as written, and an escaped b\xFCcher would not match.
        return yaml.safe_dump(dumped, width=float("inf"), allow_unicode=True).strip()
    except Exception:
        return json.dumps(dumped, indent=2, default=str, ensure_ascii=False)


def _dump(obj: Any) -> Any:
    if hasattr(obj, "model_dump"):
        try:
            return _dump(obj.model_dump())
        except Exception:
            return str(obj)
    if isinstance(obj, dict):
        return {k: _dump(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple, set)):
        return [_dump(v) for v in obj]
    if isinstance(obj, (bytes, bytearray)):
        return bytes(obj).decode("utf-8", "replace")
    return obj


def _raw_strings(obj: Any) -> List[str]:
    """Every key and scalar of a dumped return as text. The renderer escapes some characters, and a
    model decodes them, so the taint lookup also needs the values as the tool produced them."""
    if isinstance(obj, dict):
        return [s for k, v in obj.items() for s in (*_raw_strings(k), *_raw_strings(v))]
    if isinstance(obj, (list, tuple, set)):
        return [s for v in obj for s in _raw_strings(v)]
    if obj is None or isinstance(obj, bool):
        return []
    try:
        return [str(obj)]
    except Exception:
        return []


class Guard:
    """Per-task egress guard. Construct one per user task (the index never crosses tasks).

    Typed returns (Pydantic models) are indexed by their declared field types and roles. For an untyped ``dict``
    return the key name alone decides the role: a value under a routing key such as ``sender``, ``from``, ``to``,
    ``owner`` or ``author`` (``Lexicon.agentdyn_id_fields``) is indexed as a trusted identity. A tool whose dict keys
    or values are attacker-controlled (parsed message headers, for example) is the attacker-as-sender case of the
    paper's threat model, in which the attacker's address enters the index.
    """

    def __init__(self, user_task: str, *, policy: Policy = DEFAULT_POLICY,
                 lexicon: Lexicon = DEFAULT_LEXICON,
                 judge: Optional[Callable[[JudgeRequest], Tuple[bool, float]]] = None,
                 sanitize_returns: bool = True):
        self.user_task = str(user_task or "")
        self.policy = policy
        self.lexicon = lexicon
        self.judge = judge
        self.sanitize_returns = sanitize_returns
        self.index = IdentityIndex(lexicon=lexicon)
        self._tool_texts: List[str] = []
        self._tainted = ""
        self.audit: List[dict] = []

    # ---- state ---------------------------------------------------------------------------------
    @property
    def trusted(self) -> str:
        return norm(self.user_task)

    @property
    def tainted(self) -> str:
        """Normalized text of every tool return the agent has read so far (kept as one running string)."""
        return self._tainted

    def _read(self, text: Any) -> None:
        s = norm(text)
        if s:
            self._tainted = (self._tainted + " " + s) if self._tainted else s

    def reset(self, user_task: Optional[str] = None) -> None:
        if user_task is not None:
            self.user_task = str(user_task)
        self.index.reset()
        self._tool_texts = []
        self._tainted = ""
        self.audit = []

    # ---- ingress ---------------------------------------------------------------------------------
    def observe_tool_return(self, name: str, args: Optional[dict], typed_return: Any, *,
                            text: Optional[str] = None, roster: bool = False) -> str:
        """Record one executed call's return and give back the sanitized text for the model.

        ``typed_return`` is the raw return object (a Pydantic model, list, dict or str). ``text``
        is the rendering the model would read (defaults to ``format_return(typed_return)``).
        ``roster=True`` marks a read-only tool whose declared return type is ``list[str]`` (a
        typed roster of identifiers), the signal-C case the evaluation harness decided from the type contract.
        Only READ-ONLY returns are indexed; a write's return is sanitized and added to the tainted
        text but never to the identity set.
        """
        if text is None:
            text = format_return(typed_return)
        if self.lexicon.tool_is_read_only(name):
            # Like the evaluated executor, a read steered by a value from removed text indexes nothing.
            tainted = self.tainted
            if self.policy.ingress_agentaddr and self.index.injection_span_text:
                tainted = tainted + " " + span_payload(self.index.injection_span_text)
            self.index.index_read_return(name, args, typed_return, tainted=tainted,
                                         trusted=self.trusted,
                                         roster=(roster and self.policy.signal_c),
                                         policy=self.policy)
        if self.sanitize_returns:
            spans: List[str] = []
            text = sanitize(text, spans, control_tokens=True, injected_imperatives=True,
                            agent_addressed=self.policy.ingress_agentaddr, forged_turns_in_spans=True,
                            rolemark=self.policy.rolemark)
            if spans and self.policy.injspan_recover:
                self.index.add_spans(spans)
        self._tool_texts.append(text_of(text))
        self._read(text)
        if not isinstance(typed_return, str):
            for raw in _raw_strings(_dump(typed_return)):
                self._read(raw)
        return text

    def observe_refusal(self, name: str, decision: Decision) -> str:
        """Record the refusal text fed back to the model for a blocked call (it is tool text too)."""
        txt = decision.refusal_text(name)
        self._tool_texts.append(txt)
        self._read(txt)
        return txt

    def observe_text(self, text: str) -> None:
        """Record any other tool-channel text the model read (already sanitized by the caller)."""
        self._tool_texts.append(text_of(text))
        self._read(text_of(text))

    # ---- egress ----------------------------------------------------------------------------------
    def check_call(self, name: str, args: Optional[dict]) -> Decision:
        """Admit, refuse, or (with a judge) re-examine one proposed call."""
        d = admit(name, args, self.user_task, self.trusted, self.tainted, self.index,
                  policy=self.policy, lexicon=self.lexicon,
                  tool_texts=tuple(self._tool_texts))
        while d.referred:
            if self.judge is None:
                d = d.resolve_without_judge()
                break
            try:
                ok, sc = self.judge(d.judge_request)
            except Exception:
                ok, sc = False, 0.0   # a judge that fails counts as a no
            d = d.resume(ok is True, sc)
        self.audit.append({"tool": name, "decision": d.label, "score": d.score})
        return d

    def check_calls(self, calls) -> List[Decision]:
        """``calls`` is an iterable of (name, args); decisions are independent, as in the evaluation harness."""
        return [self.check_call(n, a) for n, a in calls]

    # ---- output tier ---------------------------------------------------------------------------------
    def check_final_answer(self, answer: str) -> Tuple[str, List[Tuple[str, str]]]:
        """Strip an injected endorsement of a taint-novel entity from the final answer (the
        output tier of ``--auto``). Returns (answer_text, dropped sentences)."""
        if not self.policy.output_guard or not str(answer).strip():
            return answer, []
        hits = output_injected_sentences(answer, self.trusted, self.tainted)
        if not hits:
            return answer, []
        authorized = output_recommend_authorized(self.trusted)
        to_drop = []
        for sent, ent in hits:
            if authorized and self.judge is not None:
                ok, _ = self.judge(JudgeRequest("output", self.user_task, "final_answer",
                                                {"answer": str(answer)[:600], "endorsed_entity": ent},
                                                True, self.policy.threshold))
                if ok:
                    continue
            to_drop.append((sent, ent))
        if not to_drop:
            return answer, []
        return strip_injected_endorsements(answer, to_drop), to_drop
