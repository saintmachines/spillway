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
from typing import Any, Callable, List, Optional, Sequence, Tuple

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
from .ingress import pasted_texts, request_fields, split_pasted
from .lexicon import DEFAULT_LEXICON, Lexicon
from .sanitizer import sanitize, span_payload
from .short_lineage import CreatedObjectReceipts, CreationContracts
from .source_known import ReadSourceProof, SourceContracts

__all__ = ["Guard", "format_return", "split_pasted"]


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

    The default profile indexes declared Pydantic identity fields and application-declared rosters.
    A raw dictionary key such as ``sender`` does not supply that authority. Applications may validate
    tool responses against their own declared schema before passing typed values. Source transport
    and create-new semantics require separate application-owned contracts.
    """

    def __init__(self, user_task: str, *, policy: Policy = DEFAULT_POLICY,
                 lexicon: Lexicon = DEFAULT_LEXICON,
                 judge: Optional[Callable[[JudgeRequest], Tuple[bool, float]]] = None,
                 sanitize_returns: bool = True, pasted: Optional[Sequence[str]] = None,
                 source_contracts: Optional[SourceContracts] = None,
                 creation_contracts: Optional[CreationContracts] = None):
        self.user_task = str(user_task or "")
        self.policy = policy
        self.lexicon = lexicon
        self.judge = judge
        self.sanitize_returns = sanitize_returns
        if source_contracts is not None and not isinstance(source_contracts, SourceContracts):
            raise TypeError("source_contracts must be trusted app configuration")
        self.source_contracts = source_contracts if source_contracts is not None else SourceContracts()
        self.index = IdentityIndex(lexicon=lexicon)
        if policy.payload_secret_guard:
            self.index.sensitive_index.reset(complete=True)
        self._tool_texts: List[str] = []
        # Unlike the shared tainted/channel history, this list receives only
        # original strings at observe_tool_return's executed-call boundary.
        self._fetch_tool_texts: List[str] = []
        self._tainted = ""
        self.audit: List[dict] = []
        self._created_resources = CreatedObjectReceipts(creation_contracts)
        # 0.1.4 integrated candidate (item b, owner 2026-11-14): material the user pasted into the request is read like tool text,
        # not like the user's own words. ``user_task`` is then only the user's instruction. ``split_pasted`` separates
        # the two when the harness marks the paste with an explicit delimiter.
        self.pasted_views: List[str] = [self.observe_pasted(t) for t in pasted_texts(pasted)]

    @classmethod
    def from_request(cls, request, *, policy: Policy = DEFAULT_POLICY,
                     lexicon: Lexicon = DEFAULT_LEXICON,
                     judge: Optional[Callable[[JudgeRequest], Tuple[bool, float]]] = None,
                     sanitize_returns: bool = True, source_contracts: Optional[SourceContracts] = None,
                     creation_contracts: Optional[CreationContracts] = None):
        """Use fields the app supplied, never an envelope extracted from pasted text.

        The model reads ``user_task`` and the sanitized ``pasted_views`` in
        separate content blocks. The app must call ``check_call`` before dispatch.
        No parsed sender/role field from a paste is promoted to a typed identity.
        """
        instruction, material = request_fields(request)
        return cls(instruction, policy=policy, lexicon=lexicon, judge=judge,
                   sanitize_returns=sanitize_returns, pasted=material, source_contracts=source_contracts,
                   creation_contracts=creation_contracts)

    # ---- state ---------------------------------------------------------------------------------
    @property
    def trusted(self) -> str:
        if self.policy.trusted_target_aliases:
            from .target_grounding import with_user_target_aliases
            return with_user_target_aliases(self.user_task, self.user_task)
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
        if self.policy.payload_secret_guard:
            self.index.sensitive_index.reset(complete=True)
        self._tool_texts = []
        self._fetch_tool_texts = []
        self._tainted = ""
        self.audit = []
        self.pasted_views = []
        self._created_resources.reset()

    # ---- ingress ---------------------------------------------------------------------------------
    def observe_tool_return(self, name: str, args: Optional[dict], typed_return: Any, *,
                            text: Optional[str] = None, roster: bool = False,
                            read_source: Optional[ReadSourceProof] = None) -> str:
        """Record one executed call's return and give back the sanitized text for the model.

        ``typed_return`` is the raw return object (a Pydantic model, list, dict or str). ``text``
        is the rendering the model would read (defaults to ``format_return(typed_return)``).
        ``roster=True`` marks a read-only tool whose declared return type is ``list[str]`` (a
        typed roster of identifiers), the signal-C case the evaluation harness decided from the type contract.
        Only READ-ONLY returns are indexed; a write's return is sanitized and added to the tainted
        text but never to the identity set.
        """
        if self.lexicon.tool_is_read_only(name):
            from .fetch_boundary import raw_tool_texts
            self._fetch_tool_texts.extend(raw_tool_texts(typed_return))
        if self.policy.refbind_source_known:
            proof = self.source_contracts.proof(name, args, typed_return, supplied=read_source)
            self.index.named_source_index.observe(name, args, typed_return, self.user_task,
                                                  proof=proof, lexicon=self.lexicon)
        if self.policy.payload_secret_guard:
            self.index.sensitive_index.observe(typed_return, source="Guard.raw_return:" + str(name))
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
        elif self.policy.short_target_guard:
            self._created_resources.observe(name, args or {}, typed_return, self.index.identity_set)
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
        """Give the model a refusal without treating guard output as fresh tool evidence."""
        txt = decision.refusal_text(name)
        if not self.policy.ground_targets:
            self._tool_texts.append(txt)
            self._read(txt)
        return txt

    def observe_text(self, text: str) -> None:
        """Record any other tool-channel text the model read (already sanitized by the caller)."""
        if self.policy.payload_secret_guard:
            self.index.sensitive_index.observe(text_of(text), source="Guard.sanitized_text_only")
            self.index.sensitive_index.fail("sanitized text alone cannot establish complete raw source evidence")
        self._tool_texts.append(text_of(text))
        self._read(text_of(text))

    def observe_pasted(self, text: str) -> str:
        """Read material the user pasted into the request as UNTRUSTED text: sanitized like a tool return (templates,
        forged turns, agent-addressed regions removed from what the model should read, the removed spans kept for the
        span veto), added to the tainted text, never to the trusted text or the identity index. An address that
        appears only in the paste is therefore not user-named, and a call to it meets the target rules. Returns the
        text the model should read for the paste. Only text is accepted: a dict or list carrying role-like keys
        ("sender", "trusted") must not be laundered into the identity index through this entrance (Codex A27, 2026-11-14);
        structured material a harness trusts goes through observe_tool_return as a typed value."""
        if not isinstance(text, str):
            raise TypeError("pasted material must be a str; pass structured material through observe_tool_return")
        raw = text
        if self.policy.payload_secret_guard:
            self.index.sensitive_index.observe(raw, source="Guard.raw_pasted")
        spans: List[str] = []
        view = sanitize(raw, spans, control_tokens=True, injected_imperatives=True,
                        agent_addressed=self.policy.ingress_agentaddr, forged_turns_in_spans=True,
                        rolemark=self.policy.rolemark) if self.sanitize_returns else raw
        if spans and self.policy.injspan_recover:
            self.index.add_spans(spans)
        self._tool_texts.append(text_of(view))
        self._read(view)
        self._read(raw)
        return view

    # ---- egress ----------------------------------------------------------------------------------
    def check_call(self, name: str, args: Optional[dict]) -> Decision:
        """Admit, refuse, or (with a judge) re-examine one proposed call."""
        d = admit(name, args, self.user_task, self.trusted, self.tainted, self.index,
                  policy=self.policy, lexicon=self.lexicon,
                  tool_texts=tuple(self._tool_texts), fetch_tool_texts=tuple(self._fetch_tool_texts))
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
        if self.policy.short_target_guard:
            self._created_resources.record(name, args or {}, d.allowed)
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


