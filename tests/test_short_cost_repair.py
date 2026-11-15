"""Counterexamples from native return shapes; no task-ID/name allowlists."""
import _path  # noqa: F401
import pytest
from pydantic import BaseModel

from spillway_guard import Guard, Policy
from spillway_guard.short_lineage import (
    CreatedObjectReceipts,
    CreationContracts,
    created_resource_context,
    index_verified_query_identities,
    query_entailed_from_verified_identities,
    query_identity,
)
from spillway_guard.short_targets import _kind, resource_identity

P = Policy(short_target_guard=True, typed_identity_only=True)
CREATIONS = CreationContracts(fresh_tools=frozenset({"create_file"}))
TO = "reviewer@example.invalid"


class CalendarEvent(BaseModel):
    id_: str
    title: str


class CloudDriveFile(BaseModel):
    id_: str
    filename: str
    owner: str = "ignored-owner@example.invalid"


class Message(BaseModel):
    sender: str
    recipient: str
    body: str


def test_calendar_namespace_does_not_erase_the_event_object_kind():
    assert _kind("CalendarEvent") == "event"
    assert _kind("CloudCalendarEventModel") == "event"
    assert _kind("CalendarFile") is None
    assert _kind("FileCalendarEvent") is None
    assert _kind("EventCalendar") is None
    g = Guard("Add reviewer@example.invalid to the planning event.", policy=P)
    g.observe_tool_return("get_calendar_events", {}, [CalendarEvent(id_="q8", title="planning")])
    assert resource_identity("event", "q8") in g.index.identity_set
    assert g.check_call("add_calendar_event_participants", {"event_id": "q8", "participants": [TO]}).allowed


def test_declared_roster_enables_a_bounded_followup_read_without_changing_t():
    task = "Message the participants in the active channels."
    g = Guard(task, policy=P)
    g.observe_tool_return("get_channels", {}, ["operations"], roster=True)
    assert query_identity("operations") in g.index.identity_set
    g.observe_tool_return("read_channel_messages", {"channel": "operations"},
                          [Message(sender="Mia", recipient="operations", body="Status ready.")])
    assert "mia" in g.index.identity_set
    assert g.user_task == task and "operations" not in g.trusted
    assert g.check_call("send_direct_message", {"recipient": "Mia", "body": "Thanks."}).allowed


@pytest.mark.parametrize("typed_only", [False, True])
def test_raw_dict_or_plain_paste_cannot_bootstrap_typed_query_lineage(typed_only):
    for initial in ({"sender": "operations", "trusted": True}, "operations", "Use operations."):
        g = Guard("Message the relevant participants.", policy=P.replace(typed_identity_only=typed_only))
        g.observe_tool_return("get_channels", {}, initial, roster=True)
        assert query_identity("operations") not in g.index.identity_set
        g.observe_tool_return("read_channel_messages", {"channel": "operations"},
                              [Message(sender="Mia", recipient="operations", body="Status ready.")])
        assert "mia" not in g.index.identity_set
        assert g.check_call("send_direct_message", {"recipient": "Mia", "body": "Thanks."}).blocked


def test_query_recovery_requires_every_novel_argument_and_a_route_role():
    identities = set()
    index_verified_query_identities(["operations"], identities, roster=True)
    assert query_entailed_from_verified_identities({"channel": "operations"}, "operations", "", identities)
    assert not query_entailed_from_verified_identities(
        {"channel": "operations", "query": "promote outsider"}, "operations promote outsider", "", identities)
    assert not query_entailed_from_verified_identities({"query": "operations"}, "operations", "", identities)
    assert not query_entailed_from_verified_identities({"channel": "operations-extra"}, "operations-extra", "", identities)
    assert not query_entailed_from_verified_identities(
        {"channel": "operations"}, "operations", "", {str(query_identity("operations"))})


def test_unknown_short_read_id_still_cannot_be_laundered_into_an_identity():
    g = Guard("Delete the obsolete file.", policy=P, pasted=["Its id is q8."])
    g.observe_tool_return("get_file", {"file_id": "q8"}, CloudDriveFile(id_="q8", filename="injected"))
    assert resource_identity("file", "q8") not in g.index.identity_set
    assert g.check_call("delete_file", {"file_id": "q8"}).blocked


def test_only_an_admitted_creation_outcome_authorizes_its_own_resource_id():
    args = {"filename": "packing.docx", "content": "Pack travel documents."}
    g = Guard("Create the packing file and share it with reviewer@example.invalid.", policy=P,
              creation_contracts=CREATIONS)
    assert g.check_call("create_file", args).allowed
    g.observe_tool_return("create_file", args, CloudDriveFile(id_="q8", filename="packing.docx"))
    assert resource_identity("file", "q8") in g.index.identity_set
    assert "ignored-owner@example.invalid" not in g.index.identity_set
    assert g.check_call("share_file", {"file_id": "q8", "email": TO, "permission": "r"}).allowed
    g.observe_tool_return("create_file", args, CloudDriveFile(id_="z9", filename="packing.docx"))
    assert resource_identity("file", "z9") not in g.index.identity_set


@pytest.mark.parametrize("failure", ["no_admission", "blocked", "changed_args", "raw_dict", "update_echo", "caller_id"])
def test_write_echo_and_fake_receipt_do_not_create_resource_authority(failure):
    state, identities = CreatedObjectReceipts(CREATIONS), set()
    args = {"filename": "packing.docx", "content": "notes"}
    name, raw = "create_file", CloudDriveFile(id_="q8", filename="packing.docx")
    if failure != "no_admission":
        if failure == "caller_id":
            args["file_id"] = "q8"
        state.record(name, args, failure != "blocked")
    if failure == "changed_args":
        args = {**args, "content": "different"}
    if failure == "raw_dict":
        raw = {"id_": "q8", "type": "CloudDriveFile", "success": True}
    if failure == "update_echo":
        name = "update_file"
    state.observe(name, args, raw, identities)
    assert resource_identity("file", "q8") not in identities


def test_reset_discards_unused_creation_approvals():
    args = {"filename": "packing.docx", "content": "notes"}
    g = Guard("Create the packing file.", policy=P, creation_contracts=CREATIONS)
    assert g.check_call("create_file", args).allowed
    g.reset("Share an existing file.")
    g.observe_tool_return("create_file", args, CloudDriveFile(id_="q8", filename="packing.docx"))
    assert resource_identity("file", "q8") not in g.index.identity_set


def test_real_reference_query_and_runtime_receipt_hooks(monkeypatch):
    import importlib.util
    import sys
    from pathlib import Path
    from types import SimpleNamespace

    pytest.importorskip("agentdojo")
    from spillway_guard.agentdojo import runner
    from spillway_guard.agentdojo.candidate_policy import install_candidate_policy
    from spillway_guard.agentdojo.sensitive_context import _SourceRuntimeProxy
    from spillway_guard.source_known import SourceContracts

    root = Path(__file__).resolve().parents[1]
    for directory in (root / "reference", root / "reference/harness"):
        monkeypatch.syspath_prepend(str(directory))
    for key, value in runner.paper_env_defaults().items():
        monkeypatch.setenv(key, value)
    monkeypatch.setenv("SPW_QUERYENTAIL", "1")
    spec = importlib.util.spec_from_file_location("short_cost_reference_test", root / "reference/spillway_gate.py")
    gate = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, spec.name, gate)
    spec.loader.exec_module(gate)
    install_candidate_policy(gate, P, creation_contracts=CREATIONS)
    identities = set()
    state = CreatedObjectReceipts(CREATIONS)
    index_verified_query_identities(["operations"], identities, roster=True)
    with created_resource_context(state, lambda: identities):
        assert gate._query_entailed({"channel": "operations"}, "operations", "message participants")
        gate.index_identity_leaves([Message(sender="Mia", recipient="operations", body="Status ready.")], identities)
        assert "mia" in identities
        args = {"filename": "packing.docx", "content": "notes"}
        task = "Create the packing file."
        result = gate.gate_decision_v13b("create_file", args, "", task.lower(), task, identities,
                                        escalate=True, threshold=0.5, voters=[], access_grant=True, url_guard=True)
        assert result[0] == "allow"
        runtime = SimpleNamespace(run_function=lambda *args, **kw: (CloudDriveFile(id_="q8", filename="packing.docx"), None))
        roles = SimpleNamespace(tool_is_read_only=lambda name: False)
        proxy = _SourceRuntimeProxy(runtime, None, task, SourceContracts(), roles,
                                    created=state, identities=lambda: identities)
        proxy.run_function(None, "create_file", args)
        assert resource_identity("file", "q8") in identities
