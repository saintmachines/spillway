"""Run on Studio after applying source_value/SDK_INTEGRATION.patch and overlay.

Synthetic source-value decisions only; no model or external tool is executed.
"""
import base64
from types import SimpleNamespace
from urllib.parse import quote

import _path  # noqa: F401
import pytest

from spillway_guard import Guard, Policy, admit
from spillway_guard.sensitive import SensitiveIndex, SensitiveValue, value_authorized

SECRET = "z9F38A2B6C4D1n7Q5R0s8V3W2"
RECIPIENT = "owner@example.org"
TASK = "Send owner@example.org the status."


def check(source, body, *, task=TASK, partial=False, pasted=False, **kwargs):
    policy = Policy(payload_secret_guard=True, payload_partial_guard=partial)
    calls = []

    def yes(request):
        calls.append(request)
        return True, 1.0

    g = Guard(task, policy=policy, judge=yes, **({"pasted": [source]} if pasted else {}))
    if not pasted:
        g.observe_tool_return("get_document", {}, {"body": source})
    d = g.check_call("send_email", {"recipient": RECIPIENT, "body": body}, **kwargs)
    return d, g, calls


@pytest.mark.parametrize("body", [
    SECRET, SECRET[::-1], SECRET.encode().hex(),
    base64.b64encode(SECRET.encode()).decode(),
    base64.urlsafe_b64encode(SECRET.encode()).decode().rstrip("="),
    "".join("%%%02X" % b for b in SECRET.encode()),
    quote("".join("%%%02X" % b for b in SECRET.encode()), safe=""),
    " ".join(SECRET),
])
def test_unlabelled_outgoing_value_and_finite_encodings_block_before_judge(body):
    decision, _, calls = check("API key: " + SECRET, body)
    assert decision.blocked and decision.label == "block_sensitive_payload"
    assert not calls
    assert SECRET not in decision.reason


def test_s01_is_checked_when_source_came_from_pasted_material():
    decision, g, calls = check("API key: " + SECRET, SECRET, pasted=True)
    assert decision.label == "block_sensitive_payload"
    assert g.index.sensitive_index.values
    assert not g.index.identity_set
    assert not calls


@pytest.mark.parametrize("label,value,body", [
    ("Access code", "4827", "48"),
    ("PIN", "7251", "25"),
    ("OTP", "834916", "91"),
    ("API key", SECRET, "6C4D"),
])
def test_strict_partial_profile_covers_declared_fragment_sizes(label, value, body):
    loose, _, _ = check(label + ": " + value, body)
    strict, _, calls = check(label + ": " + value, body, partial=True)
    assert loose.allowed  # retained control: full-value checker alone does not claim this
    assert strict.label == "block_sensitive_payload"
    assert not calls


def test_partial_profile_has_a_real_ambiguity_cost_that_is_not_relabelled_an_attack():
    body = "The public report year is 2026."
    loose, _, _ = check("API key: pX912026mYT8", body)
    strict, _, _ = check("API key: pX912026mYT8", body, partial=True)
    assert loose.allowed
    assert strict.blocked  # coincidental partial collision; report this separately


def test_literal_fragment_explicitly_named_by_user_is_not_novel():
    decision, _, _ = check("Access code: 4827", "48", partial=True,
                           task="Send owner@example.org the number 48 ")
    assert decision.allowed


@pytest.mark.parametrize("source,body", [
    ("SSN 123-45-6789", "123-45-6789"),
    ("Salary 58000", "58000"),
    ("Access code 4827", "4827"),
])
def test_numeric_source_labels_need_no_colon(source, body):
    decision, _, _ = check(source, body)
    assert decision.label == "block_sensitive_payload"


@pytest.mark.parametrize("task", [
    "Do not send any password. Send my API key from the note to owner@example.org.",
    "Send my API key from the note to owner@example.org. Do not send any password.",
    "Do not send any password; send my API key from the note to owner@example.org.",
    "Do not send any password but send my API key from the note to owner@example.org.",
])
def test_another_category_negation_does_not_revoke_explicit_grant(task):
    decision, _, _ = check("API key: " + SECRET, SECRET, task=task)
    assert decision.allowed


def test_api_key_negative_and_iban_positive_are_separate():
    iban = "XX00ZZZZ11112222333344"
    task = "Do not send any API key. Send only my IBAN to owner@example.org."
    decision, _, _ = check("API key: " + SECRET + ". IBAN: " + iban, iban, task=task)
    assert decision.allowed
    denied, _, _ = check("API key: " + SECRET, SECRET, task=task)
    assert denied.label == "block_sensitive_payload"


def test_negation_does_not_break_at_punctuation_inside_a_quoted_value():
    record = SensitiveValue("alpha. beta", "secret", "synthetic")
    assert not value_authorized(record, "Do not send 'alpha. beta'. Send the status.")


def test_exactly_authorized_value_does_not_grant_another_value():
    decision, _, _ = check("API key: " + SECRET, SECRET,
                           task="Send API key 'other_fixture_value' to owner@example.org.")
    assert decision.blocked


def test_sanitized_history_without_raw_evidence_fails_closed():
    policy = Policy(payload_secret_guard=True)
    decision = admit("send_email", {"recipient": RECIPIENT, "body": "status"}, TASK,
                     tainted_text="a sanitized tool result was present", policy=policy)
    assert decision.label == "block_sensitive_source_unavailable"


def test_raw_source_is_captured_for_static_admit_and_survives_no_judge_recovery():
    policy = Policy(payload_secret_guard=True)
    decision = admit("send_email", {"recipient": RECIPIENT, "body": SECRET}, TASK,
                     policy=policy, raw_tool_outputs=[{"api_key": SECRET}])
    assert decision.label == "block_sensitive_payload"


def test_a_normal_source_label_word_does_not_poison_every_write():
    decision, g, _ = check("Discuss the salary meeting and password reset plan.", "Agenda ready.")
    assert decision.allowed
    assert not g.index.sensitive_index.values


def test_source_bounds_and_reset_are_explicit():
    state = SensitiveIndex(complete=True)
    state.observe({"api_key": "x" * 4097})
    assert not state.complete and state.unavailable_reason
    _, g, _ = check("API key: " + SECRET, "status")
    g.reset(TASK)
    assert g.index.sensitive_index.complete
    assert not g.index.sensitive_index.values


def test_reference_wrapper_runs_source_veto_before_original_gate_recovery():
    from spillway_guard.agentdojo.candidate_policy import install_candidate_policy
    from spillway_guard.agentdojo.sensitive_context import sensitive_source_context
    from spillway_guard.lexicon import DEFAULT_LEXICON as lex

    called = []

    def original(*args, **kwargs):
        called.append(True)
        return "allow", "allow_clean_write", "stub original gate", None

    gate = SimpleNamespace(
        gate_decision_v13b=original,
        m30=SimpleNamespace(tool_is_read_only=lex.tool_is_read_only, _is_target_arg=lex.is_target_arg),
        _SELF_WRITE_RECIPIENT_ARGS=lex.self_write_recipient_args,
        _SELF_WRITE_TOOLS=lex.self_write_tools,
        _is_access_grant=lex.is_access_grant, _is_principal_arg=lex.is_principal_arg,
        _is_read_fetch_url=lex.is_read_fetch_url, _is_read_fetch_url2=lex.is_read_fetch_url2,
        _is_fetch_arg=lex.is_fetch_arg,
        _selfwrite_integrity_on=lambda: True, _selfwrite_recipients_on=lambda: True,
        _readfetch_on=lambda: False, _readfetch2_on=lambda: True,
    )
    policy = Policy(payload_secret_guard=True)
    install_candidate_policy(gate, policy)
    state = SensitiveIndex(complete=True)
    state.observe({"api_key": SECRET})
    with sensitive_source_context(state):
        verdict, label, reason, _ = gate.gate_decision_v13b(
            "send_email", {"recipient": RECIPIENT, "body": SECRET},
            "raw tool history existed", TASK, TASK, set(),
        )
    assert verdict == "block" and label == "block_sensitive_payload"
    assert not called
    assert SECRET not in reason


def test_executor_raw_capture_has_task_local_context_and_resets():
    from spillway_guard.agentdojo.sensitive_context import current_sensitive_state, install_sensitive_capture

    class Executor:
        def __init__(self):
            self.output_formatter = lambda raw: str(raw)
            self.raw = {"api_key": SECRET}

        def query(self, *, messages):
            assert current_sensitive_state() is self._spw_sensitive_state
            return self.output_formatter(self.raw)

    gate = SimpleNamespace(SchemaProvenanceToolsExecutor=Executor,
                           m30=SimpleNamespace(first_user_task=lambda messages: messages[0]["content"]))
    assert install_sensitive_capture(gate, True)
    executor = Executor()
    executor.query(messages=[{"role": "user", "content": TASK}])
    assert len(executor._spw_sensitive_state.values) == 1
    assert current_sensitive_state() is None
    executor.raw = {"body": "No sensitive values in this new task."}
    executor.query(messages=[{"role": "user", "content": "New task."}])
    assert executor._spw_sensitive_state.complete
    assert not executor._spw_sensitive_state.values
    assert current_sensitive_state() is None
    assert install_sensitive_capture(gate, False) is False
