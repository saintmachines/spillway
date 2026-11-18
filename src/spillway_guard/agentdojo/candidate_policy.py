"""Opt-in 0.1.4 candidate flags at the actual reference gate call site.

Frozen reference files are not edited. The presence check uses the same helper as
the SDK and the reference's live role predicates, including AgentDyn extensions.
"""

from __future__ import annotations

import hashlib
import json
import os
from contextvars import ContextVar
from dataclasses import dataclass
from functools import wraps

from ..floor import (
    Policy,
    appears_in,
    grant_to_user_named_principal,
    is_taint_novel,
    iter_arg_values,
    known_domains,
    norm,
    refbind_user_task,
    significant_tokens,
    value_is_user_referent_prefixed,
)
from ..sanitizer import span_payload
from ..short_lineage import (
    CreationContracts,
    current_resource_identities,
    index_verified_query_identities,
    query_entailed_from_verified_identities,
    with_creation_receipts,
)
from ..short_targets import (
    index_short_resource_identities,
    short_resource_read_entailed,
    short_target_violations,
)
from ..source_known import delegated_domain_problem, strict_known_domains
from ..target_grounding import is_external_target_arg, ungrounded_targets, with_user_target_aliases
from ..typed_identity import index_typed_identity_leaves, index_typed_resource_identities


@dataclass(frozen=True, slots=True)
class _HostGroundedCall:
    operation: str
    args_sha256: str
    task_sha256: str
    destination: str
    destination_argument: str


# Minted only after the app's FlowProof checks, consumed by one exact call.
# This is presence evidence, never an addition to taint, trust or identities.
_host_grounded_call = ContextVar("spillway_host_grounded_call", default=None)


def _consume_host_grounded_target(name, args, user_task):
    record = _host_grounded_call.get()
    if (type(record) is not _HostGroundedCall or record.operation != name
            or type(args) is not dict or type(user_task) is not str
            or record.destination_argument != args.get("destination_path")):
        return None
    try:
        args_sha = hashlib.sha256(json.dumps(args, sort_keys=True, separators=(",", ":"),
                                            ensure_ascii=False).encode()).hexdigest()
        task_sha = hashlib.sha256(json.dumps(user_task, ensure_ascii=False).encode()).hexdigest()
    except (TypeError, ValueError):
        return None
    if record.args_sha256 != args_sha or record.task_sha256 != task_sha:
        return None
    _host_grounded_call.set(None)
    return record.destination


def candidate_policy() -> Policy:
    """The candidate CLI/environment switches. Target provenance (grounding and user aliases) is on by default in
    0.1.4; --no-target-provenance or SPW_GROUND_TARGETS=0 SPW_TRUSTED_TARGET_ALIASES=0 restores the 0.1.3 gate."""
    return Policy(
        ground_targets=os.environ.get("SPW_GROUND_TARGETS", "1") == "1",
        trusted_target_aliases=os.environ.get("SPW_TRUSTED_TARGET_ALIASES", "1") == "1",
        delegation_span_veto=os.environ.get("SPW_DELEGATION_SPAN_VETO", "0") == "1",
        refbind_whole_local=os.environ.get("SPW_REFBIND_WHOLE_LOCAL", "1") == "1",
        refbind_domain_known=os.environ.get("SPW_REFBIND_DOMAIN_KNOWN", "1") == "1",
        refbind_source_known=os.environ.get("SPW_REFBIND_SOURCE_KNOWN", "1") == "1",
        strict_fetch_provenance=os.environ.get("SPW_STRICT_FETCH_PROVENANCE", "1") == "1",
        payload_secret_guard=os.environ.get("SPW_PAYLOAD_SECRET_GUARD", "0") == "1",
        payload_partial_guard=os.environ.get("SPW_PAYLOAD_PARTIAL_GUARD", "0") == "1",
        short_target_guard=os.environ.get("SPW_SHORT_TARGET_GUARD", "1") == "1",
        typed_identity_only=os.environ.get("SPW_TYPED_IDENTITY_ONLY", "1") == "1",
    )


class _ReferenceRoles:
    """Delegate to the live gate vocabulary instead of guessing a suite or tool name."""

    def __init__(self, gate):
        self.gate = gate
        self.self_write_recipient_args = gate._SELF_WRITE_RECIPIENT_ARGS

    def tool_is_read_only(self, name):
        return self.gate.m30.tool_is_read_only(name)

    def is_target_arg(self, key):
        return self.gate.m30._is_target_arg(key)

    def agentdyn_id_field(self, field):
        return self.gate._agentdyn_id_field(field)

    def is_self_write_tool(self, name):
        return str(name).lower() in self.gate._SELF_WRITE_TOOLS

    def is_access_grant(self, name):
        return self.gate._is_access_grant(name)

    def is_principal_arg(self, key):
        return self.gate._is_principal_arg(key)

    def is_read_fetch_url(self, name, key):
        return self.gate._is_read_fetch_url(name, key)

    def is_read_fetch_url2(self, name, key):
        return self.gate._is_read_fetch_url2(name, key)

    def is_destructive(self, name):
        return self.gate.m30._is_destructive(name)

    def user_authorized_destruction(self, user_task):
        return self.gate.m30._user_authorized_destruction(user_task)

    def is_fetch_arg(self, key):
        return self.gate._is_fetch_arg(key)


_DELEGATION_LABELS = frozenset({
    "allow_referent_identity", "allow_user_task_referent_binding", "allow_refbind_delegated",
    "allow_grant_named_principal",
})


def _install_short_identity_indexer(gate, policy, resource_contracts=None):
    from contextvars import ContextVar

    current = getattr(gate, "index_identity_leaves", None)
    if current is None:
        return
    original = getattr(current, "_spw_original_short_indexer", current)
    query = getattr(gate, "_query_entailed", None)
    query_on = getattr(gate, "_queryentail_on", None)
    original_query = getattr(query, "_spw_original_short_query", query)
    original_query_on = getattr(query_on, "_spw_original_short_query_on", query_on)
    if not (policy.short_target_guard or policy.typed_identity_only):
        gate.index_identity_leaves = original
        if original_query is not None:
            gate._query_entailed = original_query
        if original_query_on is not None:
            gate._queryentail_on = original_query_on
        return

    # The real executor evaluates this immediately before indexing each READ.
    # Force hook invocation, but preserve the historical long-argument verdict
    # even when the caller explicitly disabled its original entailment switch.
    read_context = ContextVar("spillway_short_read_context", default=None)
    indexing = ContextVar("spillway_short_indexing", default=False)
    if policy.short_target_guard and original_query is not None and original_query_on is not None:
        @wraps(original_query)
        def query_entailed(args, tainted, trusted):
            allowed = original_query(args, tainted, trusted) if original_query_on() else True
            existing = current_resource_identities()
            if not allowed and existing is not None:
                allowed = query_entailed_from_verified_identities(
                    args, tainted, trusted, existing, lexicon=_ReferenceRoles(gate))
            read_context.set((dict(args or {}), trusted, tainted) if allowed else None)
            return allowed

        @wraps(original_query_on)
        def query_enabled():
            return True

        query_entailed._spw_original_short_query = original_query
        query_enabled._spw_original_short_query_on = original_query_on
        gate._query_entailed = query_entailed
        gate._queryentail_on = query_enabled
    else:
        if original_query is not None:
            gate._query_entailed = original_query
        if original_query_on is not None:
            gate._queryentail_on = original_query_on

    @wraps(original)
    def indexer(obj, identity_set, **kwargs):
        if indexing.get():
            return original(obj, identity_set, **kwargs)
        pending = read_context.get()
        read_context.set(None)
        allow_short = (pending is None or short_resource_read_entailed(
            pending[0], pending[1], identity_set, response=obj, tainted=pending[2]))
        # A read selected only by untrusted short text cannot mint ANY identity
        # authority, including ordinary short routing leaves such as "Bob".
        if policy.short_target_guard and not allow_short:
            return None
        token = indexing.set(True)
        try:
            if policy.typed_identity_only:
                index_typed_identity_leaves(
                    obj, identity_set, field_is_id_role=kwargs.get("field_is_id_role", False),
                    keys_are_id=kwargs.get("keys_are_id", False), lexicon=_ReferenceRoles(gate),
                )
            else:
                original(obj, identity_set, **kwargs)
        finally:
            indexing.reset(token)
        if policy.short_target_guard and allow_short:
            if policy.typed_identity_only:
                index_typed_resource_identities(obj, identity_set, lexicon=_ReferenceRoles(gate),
                                                resource_contracts=resource_contracts)
            else:
                index_short_resource_identities(obj, identity_set)
            index_verified_query_identities(
                obj, identity_set, roster=kwargs.get("field_is_id_role", False), lexicon=_ReferenceRoles(gate))

    indexer._spw_original_short_indexer = original
    gate.index_identity_leaves = indexer

def install_candidate_policy(gate, policy: Policy | None = None, *, source_contracts=None,
                             creation_contracts=None, resource_contracts=None) -> bool:
    """Patch the actual decision callable only when a candidate flag is enabled.

    Grounding runs before the original callable (hence before its voters). The
    delegation option vetoes only the existing delegation-allow labels, not all
    identity recovery. It uses the same span/co-residence predicate as the SDK.
    """
    policy = candidate_policy() if policy is None else policy
    from ..resource_contracts import ResourceContracts
    if resource_contracts is not None and type(resource_contracts) is not ResourceContracts:
        raise TypeError("resource_contracts must be trusted app configuration")
    # Both live reference modules historically inspect only the leading word.
    # Share the SDK's whole-value predicate before the ladder runs, so rejecting
    # this delegation still leaves the same subsequent recovery paths intact.
    predicate = getattr(gate, "_value_is_user_referent_prefixed", None)
    if predicate is not None:
        if not hasattr(gate, "_spw_original_user_referent_predicate"):
            gate._spw_original_user_referent_predicate = predicate
        gate._value_is_user_referent_prefixed = (
            value_is_user_referent_prefixed if policy.refbind_whole_local
            else gate._spw_original_user_referent_predicate
        )
    if source_contracts is None:
        from ..source_known import SourceContracts
        source_contracts = SourceContracts(no_redirect_tools=frozenset(
            value.strip() for value in os.environ.get("SPW_SOURCE_NO_REDIRECT_TOOLS", "").split(",") if value.strip()))
    if creation_contracts is None:
        creation_contracts = CreationContracts(fresh_tools=frozenset(
            value.strip() for value in os.environ.get("SPW_NEW_RESOURCE_TOOLS", "").split(",") if value.strip()))
    if not isinstance(creation_contracts, CreationContracts):
        raise TypeError("creation_contracts must be trusted CreationContracts, not response metadata")
    from .sensitive_context import current_sensitive_state, install_sensitive_capture
    install_sensitive_capture(gate, policy.payload_secret_guard)
    from .source_context import current_named_source_state, install_named_source_capture
    install_named_source_capture(gate, policy.refbind_source_known, source_contracts)
    from .sensitive_context import install_resource_capture
    install_resource_capture(gate, policy.short_target_guard, creation_contracts)
    _install_short_identity_indexer(gate, policy, resource_contracts)
    from .refusal_context import install_refusal_capture, prepare_decision
    install_refusal_capture(gate, policy.ground_targets)
    from .fetch_context import current_fetch_tool_texts, install_fetch_capture
    install_fetch_capture(gate, policy.strict_fetch_provenance)
    if not (policy.ground_targets or policy.trusted_target_aliases or policy.delegation_span_veto
            or policy.refbind_whole_local or policy.refbind_domain_known or policy.refbind_source_known or policy.payload_secret_guard or policy.short_target_guard or policy.typed_identity_only or policy.strict_fetch_provenance):
        current = getattr(gate, "gate_decision_v13b", None)
        if current is not None and hasattr(current, "_spw_original_gate"):
            gate.gate_decision_v13b = current._spw_original_gate
        return False
    original = getattr(gate.gate_decision_v13b, "_spw_original_gate", gate.gate_decision_v13b)
    roles = _ReferenceRoles(gate)

    @wraps(original)
    def decision(name, args, tainted, trusted, user_task, identity_set, **kw):
        active = policy.replace(
            selfwrite_integrity=gate._selfwrite_integrity_on(),
            selfwrite_recipients=gate._selfwrite_recipients_on(),
            readfetch=gate._readfetch_on(), readfetch2=gate._readfetch2_on(),
            access_grant=kw.get("access_grant", False),
        )
        tainted, kw = prepare_decision(tainted, kw, enabled=active.ground_targets)
        if active.trusted_target_aliases:
            trusted = with_user_target_aliases(trusted, user_task)
        source_state = current_named_source_state()
        source_addresses = (source_state.authorized(user_task)
                            if active.refbind_source_known and source_state is not None else set())
        if active.refbind_source_known:
            source_problem = delegated_domain_problem(name, args, user_task, trusted, identity_set, source_state,
                                                      policy=active, lexicon=roles)
            if source_problem:
                # App-owned continuation may defer only this source-evidence
                # check for an exact call. The underlying reference decision
                # and all subsequent hard checks still have to succeed.
                hooks = getattr(gate, "_spw_delegated_recovery_hooks", None)
                deferred = False
                if hooks is not None:
                    try:
                        deferred = hooks.defer_source_problem(
                            name, args, tainted, trusted, user_task, identity_set,
                            source_problem=source_problem, policy=active, lexicon=roles, flags=kw,
                        ) is True
                    except Exception:
                        deferred = False
                if not deferred:
                    return ("block", source_problem[0], source_problem[1], 0.0)
        if active.strict_fetch_provenance:
            from ..fetch_boundary import tool_observed_fetch_targets, unrequested_fetch_targets
            fetch_texts = current_fetch_tool_texts()
            if unrequested_fetch_targets(name, args, trusted, lexicon=roles, user_task=user_task,
                                         tool_return_texts=fetch_texts):
                return ("block", "block_fetch_provenance",
                        "network-read URL requires an exact user URL or an original executed-tool URL", 0.0)
            observed = tool_observed_fetch_targets(name, args, lexicon=roles, tool_return_texts=fetch_texts)
            if observed:
                tainted += " " + norm(" ".join(observed))
        if active.short_target_guard:
            short_bad = short_target_violations(name, args, trusted, user_task, identity_set,
                                                policy=active, lexicon=roles,
                                                injection_span=kw.get("injection_span") or "")
            if short_bad:
                return ("block", "block_short_target", "; ".join(short_bad)[:200], 0.0)
        if active.ground_targets:
            host_target = _consume_host_grounded_target(name, args, user_task)
            presence_text = tainted + "\n" + host_target if host_target is not None else tainted
            unknown = ungrounded_targets(name, args, trusted, presence_text, policy=active, lexicon=roles,
                                         user_task=user_task, original_tool_texts=current_fetch_tool_texts())
            if unknown:
                return ("block", "block_ungrounded_target",
                        "whole target value absent from the user's request and observed tool text; "
                        "confirm a grounded target before retrying: " + ", ".join(unknown)[:120], 0.0)
        if active.payload_secret_guard:
            from ..sensitive import SensitiveIndex, payload_problem
            problem = payload_problem(name, args, user_task, current_sensitive_state() or SensitiveIndex(),
                                      has_history=bool(tainted), policy=active, lexicon=roles)
            if problem:
                return ("block", problem[0], problem[1], 0.0)
        result = original(name, args, tainted, trusted, user_task, identity_set, **kw)
        if result[0] == "allow" and result[1] in {
            "allow_user_task_referent_binding", "allow_grant_named_principal",
        }:
            # The frozen reference uses its historical substring rule. Recheck
            # only its corresponding allow branch with the SDK's exact policy.
            novel = {
                token for key, value in iter_arg_values(args or {})
                if is_external_target_arg(name, key, policy=active, lexicon=roles)
                for token in significant_tokens(value)
                if appears_in(token, tainted) and not appears_in(token, trusted)
            }
            domains = (strict_known_domains(identity_set, user_task) if active.refbind_source_known
                       else (known_domains(identity_set, trusted) if active.refbind_domain_known else None))
            if result[1] == "allow_user_task_referent_binding":
                valid = refbind_user_task(novel, user_task, whole_local=active.refbind_whole_local,
                                         domains=domains, source_addresses=source_addresses)
            else:
                valid = grant_to_user_named_principal(
                    args, user_task, novel, roles,
                    whole_local=active.refbind_whole_local, domains=domains, source_addresses=source_addresses,
                )
            if not valid:
                hooks = getattr(gate, "_spw_delegated_recovery_hooks", None)
                if hooks is not None:
                    try:
                        valid = hooks.validate_refbind_remainder(
                            name, args, tainted, trusted, user_task, identity_set,
                            underlying_result=result, policy=active, lexicon=roles, flags=kw,
                        ) is True
                    except Exception:
                        valid = False
                if not valid:
                    return ("block", "block_refbind_policy",
                            "reference delegation failed the configured whole-local or domain-evidence rule", 0.0)
        if active.delegation_span_veto and result[0] == "allow" and result[1] in _DELEGATION_LABELS:
            span = span_payload(kw.get("injection_span") or "")
            cores = kw.get("taint_coresident")
            for key, value in iter_arg_values(args or {}):
                if not is_external_target_arg(name, key, policy=active, lexicon=roles):
                    continue
                if not is_taint_novel(value, tainted, trusted):
                    continue
                for token in significant_tokens(value) or {norm(value)}:
                    if (span and appears_in(token, span)) or (cores is not None and appears_in(token, cores)):
                        return ("block", "block_delegation_span_veto",
                                "delegation target occurred in removed text or free-text co-residence", 0.0)
        return result

    decision = with_creation_receipts(decision, enabled=policy.short_target_guard)
    decision._spw_original_gate = original
    decision._spw_candidate_policy = policy
    gate.gate_decision_v13b = decision
    return True
