"""Keep candidate delegation semantics shared without changing frozen files."""
import importlib.util
import sys
from pathlib import Path

import _path  # noqa: F401
import pytest

from spillway_guard import Guard, Policy
from spillway_guard.agentdojo.candidate_policy import install_candidate_policy
from spillway_guard.target_grounding import target_appears_in


@pytest.mark.parametrize("module", ["spillway_gate", "spillway_guarded"])
def test_live_reference_uses_whole_value_and_restores_historical_predicate(module):
    pytest.importorskip("agentdojo")
    reference = Path(__file__).resolve().parents[1] / "reference"
    for path in (reference, reference / "harness"):
        if str(path) not in sys.path:
            sys.path.insert(0, str(path))
    name = "alignment_" + module
    spec = importlib.util.spec_from_file_location(name, reference / (module + ".py"))
    gate = importlib.util.module_from_spec(spec)
    sys.modules[name] = gate
    spec.loader.exec_module(gate)
    old = gate._value_is_user_referent_prefixed
    value, referents = "External_team alice@evil.example", {"external"}
    assert old(value, referents)
    install_candidate_policy(gate, Policy())
    assert not gate._value_is_user_referent_prefixed(value, referents)
    assert gate._value_is_user_referent_prefixed("External_team", referents)
    install_candidate_policy(gate, Policy.legacy_013())
    assert gate._value_is_user_referent_prefixed is old
    assert old(value, referents)
    install_candidate_policy(gate, Policy())
    assert not gate._value_is_user_referent_prefixed(value, referents)


@pytest.mark.parametrize("ending", ["?", "? Please confirm.", '?"'])
def test_terminal_question_punctuation_preserves_explicit_email_evidence(ending):
    email = "owner@example.org"
    task = "Can you send the summary to " + email + ending
    assert target_appears_in(email, task)
    assert Guard(task).check_call("send_email", {"recipients": [email], "body": "Summary."}).allowed


@pytest.mark.parametrize("suffix", ["?cc=evil@example.org", "?next=https://evil.example", "?extra"])
def test_query_data_and_longer_identifiers_are_not_terminal_email_punctuation(suffix):
    email = "owner@example.org"
    assert not target_appears_in(email, "Send to " + email + suffix)
    assert not target_appears_in(email, "https://safe.example/?to=" + email)
    assert not target_appears_in("https://safe.example/read", "Read https://safe.example/read?token=secret")
