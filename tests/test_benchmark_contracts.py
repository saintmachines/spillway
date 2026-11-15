"""Benchmark contract defaults must be verified and reach the real launcher."""
import json
import os
from unittest.mock import patch

import _path  # noqa: F401
import pytest

from spillway_guard import Guard
from spillway_guard.agentdojo import benchmark_contracts as bc


def test_general_sdk_never_trusts_tool_names_as_contracts():
    g = Guard("Create a file and share it with me.")
    assert not g.source_contracts.no_redirect_tools
    assert not g._created_resources.contracts.fresh_tools


def test_unknown_benchmark_version_or_suite_has_no_implicit_authority():
    assert not bc.verified_standard_contracts("workspace", "v99")["verified"]
    assert not bc.verified_standard_contracts("custom", "v1.2.2")["verified"]


def test_modified_tool_source_receives_no_implicit_contracts(tmp_path):
    source = tmp_path / "agentdojo"
    source.mkdir()
    for relative in bc.SOURCE_PINS:
        p = source / relative
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text("# a different implementation\n")
    with patch.object(bc.importlib.metadata, "version", return_value="0.1.35"), \
            patch.object(bc.importlib.util, "find_spec") as spec, \
            patch.dict(os.environ, {}, clear=True):
        spec.return_value.origin = str(source / "__init__.py")
        receipt = bc.configure_standard_contracts("workspace", "v1.2.2")
        assert not receipt["verified"]
        assert not receipt["defaulted"]
        assert "SPW_NEW_RESOURCE_TOOLS" not in os.environ


def test_new_agentdojo_version_needs_review_even_if_tools_keep_the_names():
    with patch.object(bc.importlib.metadata, "version", return_value="0.1.36"):
        assert not bc.verified_standard_contracts("workspace", "v1.2.2")["verified"]


def test_pinned_installed_benchmark_contracts_reach_prepare_without_flags():
    pytest.importorskip("agentdojo")
    from spillway_guard.agentdojo import runner
    with patch.dict(os.environ, {}, clear=True), patch.object(runner, "install_agent_shim", return_value=False):
        runner.prepare(["--paper", "--guarded", "--suite", "workspace", "--help"])
        receipt = json.loads(os.environ["SPW_BENCHMARK_CONTRACT_RECEIPT"])
        assert receipt["verified"], receipt
        assert receipt["sources"] == bc.SOURCE_PINS
        assert os.environ["SPW_SOURCE_NO_REDIRECT_TOOLS"] == "get_webpage"
        assert os.environ["SPW_NEW_RESOURCE_TOOLS"] == "create_file,create_calendar_event"


def test_explicit_host_configuration_including_empty_wins():
    with patch.object(bc, "verified_standard_contracts", return_value={"verified": True}), \
            patch.dict(os.environ, {"SPW_NEW_RESOURCE_TOOLS": "", "SPW_SOURCE_NO_REDIRECT_TOOLS": "app_read"}, clear=True):
        receipt = bc.configure_standard_contracts("workspace", "v1.2.2")
        assert not receipt["defaulted"]
        assert os.environ["SPW_NEW_RESOURCE_TOOLS"] == ""
        assert os.environ["SPW_SOURCE_NO_REDIRECT_TOOLS"] == "app_read"


def test_legacy_explicit_control_does_not_inherit_enhanced_contracts():
    from spillway_guard.agentdojo import runner
    with patch.dict(os.environ, {}, clear=True), patch.object(runner, "install_agent_shim", return_value=False):
        runner.prepare(["--paper", "--legacy-v1", "--help"])
        assert os.environ["SPW_NEW_RESOURCE_TOOLS"] == ""
        assert os.environ["SPW_SOURCE_NO_REDIRECT_TOOLS"] == ""

