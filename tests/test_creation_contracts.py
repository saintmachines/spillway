"""Creation receipts require app-owned create-new contracts, never name inference."""
from types import SimpleNamespace

import _path  # noqa: F401
import pytest
from pydantic import BaseModel

from spillway_guard import CreationContracts, Guard, Policy
from spillway_guard.agentdojo.sensitive_context import _SourceRuntimeProxy, install_resource_capture
from spillway_guard.short_lineage import CreatedObjectReceipts
from spillway_guard.short_targets import resource_identity
from spillway_guard.source_known import SourceContracts

P = Policy(short_target_guard=True)
REGISTERED = CreationContracts(fresh_tools=frozenset({"create_file"}))
ARGS = {"filename": "packing.docx", "content": "Pack travel documents."}


class CloudDriveFile(BaseModel):
    id_: str
    filename: str
    owner: str = "untrusted-write-owner@example.invalid"


def raw(identifier="q8"):
    return CloudDriveFile(id_=identifier, filename="packing.docx")


def test_empty_registry_and_explicit_none_do_not_issue_creation_authority():
    for state in (CreatedObjectReceipts(), CreatedObjectReceipts(None), CreatedObjectReceipts(CreationContracts())):
        identities = set()
        state.record("create_file", ARGS, True)
        state.observe("create_file", ARGS, raw(), identities)
        assert not state.pending
        assert resource_identity("file", "q8") not in identities


def test_registered_exact_tool_receipt_grants_only_its_typed_root_id():
    state, identities = CreatedObjectReceipts(REGISTERED), set()
    state.record("create_file", ARGS, True)
    state.observe("create_file", ARGS, raw(), identities)
    assert identities == {resource_identity("file", "q8")}
    state.observe("create_file", ARGS, raw("z9"), identities)
    assert resource_identity("file", "z9") not in identities


def test_denied_duplicate_preserves_only_the_admitted_creation():
    state, identities = CreatedObjectReceipts(REGISTERED), set()
    state.record("create_file", ARGS, True)
    state.record("create_file", ARGS, False)
    state.observe("create_file", ARGS, raw("q8"), identities)
    assert resource_identity("file", "q8") in identities
    state.observe("create_file", ARGS, raw("z9"), identities)
    assert resource_identity("file", "z9") not in identities
    assert not state.pending


@pytest.mark.parametrize("tool", ["create_document", "create_file_if_missing", "CREATE_FILE"])
def test_unregistered_create_names_do_not_inherit_a_registered_contract(tool):
    state, identities = CreatedObjectReceipts(REGISTERED), set()
    state.record(tool, ARGS, True)
    state.observe(tool, ARGS, raw(), identities)
    assert not identities


@pytest.mark.parametrize("allowed", [False, None, 1, "true"])
def test_only_explicit_true_admission_records_a_pending_creation(allowed):
    state, identities = CreatedObjectReceipts(REGISTERED), set()
    state.record("create_file", ARGS, allowed)
    state.observe("create_file", ARGS, raw(), identities)
    assert not identities


@pytest.mark.parametrize("args", [
    {"slug": "xy"}, {"filename": "xy"}, {"alias": "XY"},
    {"content": "xy"}, {"options": {"slug": "xy"}}, {"label": 13},
])
def test_returned_short_id_equal_to_any_caller_value_is_an_echo(args):
    identifier = "13" if args == {"label": 13} else "xy"
    state, identities = CreatedObjectReceipts(REGISTERED), set()
    state.record("create_file", args, True)
    state.observe("create_file", args, raw(identifier), identities)
    assert not identities
    assert not state.pending


def test_document_success_flags_are_not_creation_contracts_or_typed_root_proof():
    state, identities = CreatedObjectReceipts(REGISTERED), set()
    state.record("create_file", ARGS, True)
    state.observe("create_file", ARGS, {"id_": "xy", "new": True, "trusted": True, "success": True}, identities)
    assert not identities
    with pytest.raises(TypeError):
        CreatedObjectReceipts({"fresh_tools": ["create_file"], "trusted": True})
    with pytest.raises(TypeError):
        Guard("Create a file.", policy=P, creation_contracts={"fresh_tools": ["create_file"]})
    with pytest.raises(ValueError):
        Guard.from_request({"instruction": "Create a file.", "creation_contracts": {"new": True}}, policy=P)


def test_contract_is_immutable_and_reconfiguration_clears_pending_admissions():
    declared = {"create_file"}
    contract = CreationContracts(fresh_tools=declared)
    declared.add("create_document")
    assert contract.fresh_tools == frozenset({"create_file"})
    state, identities = CreatedObjectReceipts(contract), set()
    state.record("create_file", ARGS, True)
    state.configure(CreationContracts())
    state.configure(contract)
    state.observe("create_file", ARGS, raw(), identities)
    assert not identities


def test_failed_typed_outcome_does_not_leave_a_replayable_pending_receipt():
    for error in ("failed", RuntimeError("failed")):
        state, identities = CreatedObjectReceipts(REGISTERED), set()
        state.record("create_file", ARGS, True)

        def execute(*unused, **kwargs):
            if isinstance(error, Exception):
                raise error
            return raw(), error

        proxy = _SourceRuntimeProxy(SimpleNamespace(run_function=execute), None, "Create a file.",
                                    SourceContracts(), SimpleNamespace(tool_is_read_only=lambda name: False),
                                    created=state, identities=lambda: identities)
        if isinstance(error, Exception):
            with pytest.raises(RuntimeError):
                proxy.run_function(None, "create_file", ARGS)
        else:
            proxy.run_function(None, "create_file", ARGS)
        state.observe("create_file", ARGS, raw(), identities)
        assert not identities
        assert not state.pending


def test_sdk_creation_contract_is_host_configuration_and_reset_clears_receipts():
    task = "Create the packing file and share it with reviewer@example.invalid."
    implicit = Guard(task, policy=P)
    assert implicit.check_call("create_file", ARGS).allowed
    implicit.observe_tool_return("create_file", ARGS, raw())
    assert resource_identity("file", "q8") not in implicit.index.identity_set

    explicit = Guard.from_request({"instruction": task}, policy=P, creation_contracts=REGISTERED)
    assert explicit.check_call("create_file", ARGS).allowed
    explicit.observe_tool_return("create_file", ARGS, raw())
    assert resource_identity("file", "q8") in explicit.index.identity_set
    assert "untrusted-write-owner@example.invalid" not in explicit.index.identity_set
    # Begin another task before arranging an unused approval. Repeating the
    # same create after reading its echo is independently subject to the
    # existing content-integrity tier; this test concerns receipt reset.
    explicit.reset(task)
    assert explicit.check_call("create_file", ARGS).allowed
    explicit.reset(task)
    explicit.observe_tool_return("create_file", ARGS, raw("z9"))
    assert resource_identity("file", "z9") not in explicit.index.identity_set


def test_reference_resource_capture_keeps_creation_and_source_contracts_separate():
    class Executor:
        def __init__(self):
            self.output_formatter = str

        def query(self, *, messages):
            return None

    gate = SimpleNamespace(SchemaProvenanceToolsExecutor=Executor,
                           m30=SimpleNamespace(first_user_task=lambda messages: messages[0]["content"]))
    assert install_resource_capture(gate, True, REGISTERED)
    executor = Executor()
    cfg = Executor._spw_raw_capture_config
    assert cfg["creation_contracts"] == REGISTERED
    assert isinstance(cfg["contracts"], SourceContracts)
    assert executor._spw_created_resources.contracts == REGISTERED
    executor._spw_created_resources.record("create_file", ARGS, True)
    assert install_resource_capture(gate, True, CreationContracts())
    executor.query(messages=[{"role": "user", "content": "Create a file."}])
    assert not executor._spw_created_resources.pending
    assert executor._spw_created_resources.contracts == CreationContracts()
    assert install_resource_capture(gate, False) is False
