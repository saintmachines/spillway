"""The reference wrapper must enforce the same policy as the SDK."""
import os
from types import SimpleNamespace
from unittest.mock import patch

import _path  # noqa: F401
from test_runner import TargetRecoveryRunnerTests as _RunnerHelper

from spillway_guard import Policy
from spillway_guard.agentdojo.candidate_policy import candidate_policy, install_candidate_policy
from spillway_guard.lexicon import DEFAULT_LEXICON as L


def gate_with_recorded_referent_allow():
    # A previously allowed reference result; the wrapper must independently
    # recheck the user-named local part and domain before returning it.
    return SimpleNamespace(
        gate_decision_v13b=lambda *a, **kw: ("allow", "allow_user_task_referent_binding", "reference", None),
        m30=SimpleNamespace(tool_is_read_only=L.tool_is_read_only, _is_target_arg=L.is_target_arg),
        _SELF_WRITE_RECIPIENT_ARGS=set(), _SELF_WRITE_TOOLS=set(),
        _is_access_grant=L.is_access_grant, _is_principal_arg=L.is_principal_arg,
        _is_read_fetch_url=lambda *a: False, _is_read_fetch_url2=lambda *a: False,
        _is_fetch_arg=lambda *a: False,
        _selfwrite_integrity_on=lambda: True, _selfwrite_recipients_on=lambda: True,
        _readfetch_on=lambda: False, _readfetch2_on=lambda: False,
    )


def test_reference_wrapper_ab_disagrees_only_on_unknown_domain():
    for strict, expected in ((False, "allow"), (True, "block")):
        gate = gate_with_recorded_referent_allow()
        install_candidate_policy(gate, Policy(refbind_domain_known=strict))
        result = gate.gate_decision_v13b(
            "send_email", {"recipients": ["carol@outside.example.invalid"]},
            "Carol is carol@outside.example.invalid", "Reply to Carol.", "Reply to Carol.", set(),
        )
        assert result[0] == expected


def test_reference_wrapper_rejects_the_old_substring_allow():
    gate = gate_with_recorded_referent_allow()
    install_candidate_policy(gate, Policy())
    result = gate.gate_decision_v13b(
        "send_email", {"recipients": ["carol.extra@outside.example.invalid"]},
        "Carol is carol.extra@outside.example.invalid", "Reply to Carol.", "Reply to Carol.", set(),
    )
    assert result[0] == "block"


def test_cli_domain_option_reaches_actual_candidate_policy_and_legacy_wins():
    helper = _RunnerHelper()
    forwarded, environment = helper.prepare_in_environment({}, ["--refbind-domain-known", "--self-test"])
    assert "--refbind-domain-known" not in forwarded
    with patch.dict(os.environ, environment, clear=True):
        assert candidate_policy().refbind_domain_known
        assert candidate_policy().refbind_whole_local
    for arguments in (["--paper", "--refbind-domain-known", "--self-test"],
                      ["--no-target-provenance", "--refbind-domain-known", "--self-test"]):
        _, environment = helper.prepare_in_environment({}, arguments)
        with patch.dict(os.environ, environment, clear=True):
            p = candidate_policy()
            assert not p.ground_targets
            assert not p.refbind_domain_known
            assert not p.refbind_whole_local
