"""Reviewed contracts for the byte-pinned, in-memory AgentDojo benchmark.

These defaults belong to this benchmark adapter, not to arbitrary tools with
the same names. The general SDK continues to require host-owned contracts.
Unknown versions or modified implementations receive no implicit contract.
"""
from __future__ import annotations

import hashlib
import importlib.metadata
import importlib.util
import os
from pathlib import Path

AGENTDOJO_VERSION = "0.1.35"
BENCHMARK_VERSION = "v1.2.2"
STANDARD_SUITES = frozenset({"banking", "slack", "travel", "workspace"})
SOURCE_PINS = {
    "default_suites/v1/tools/web.py":
        "246cc534a939ade2864bb62441d8452de7a840d007147c22391ad07bff91594c",
    "default_suites/v1/tools/cloud_drive_client.py":
        "19376d95731c46477037986319bc8522b4bc96f4924e730b11906df23fc00b93",
    "default_suites/v1/tools/calendar_client.py":
        "5d551339fb87237dd1414a003b26f4f851dbdd2b0826225025e44f16420add22",
}
DEFAULT_CONTRACTS = {
    "SPW_SOURCE_NO_REDIRECT_TOOLS": "get_webpage",
    "SPW_NEW_RESOURCE_TOOLS": "create_file,create_calendar_event",
}


def verified_standard_contracts(suite: str, benchmark_version: str) -> dict:
    """Return an audit receipt; do not infer semantics from a tool's name.

    The pinned web implementation is a dictionary lookup with no redirects.
    Both pinned create implementations allocate max(existing ids)+1 and return
    the new typed object. Existing receipt checks still bind the admitted
    call, exact arguments, success, resource kind and single consumption.
    """
    receipt = {"verified": False, "suite": suite, "benchmark_version": benchmark_version,
               "agentdojo_version": None, "sources": {}, "reason": "unsupported benchmark"}
    if suite not in STANDARD_SUITES or benchmark_version != BENCHMARK_VERSION:
        return receipt
    try:
        receipt["agentdojo_version"] = importlib.metadata.version("agentdojo")
        if receipt["agentdojo_version"] != AGENTDOJO_VERSION:
            receipt["reason"] = "unreviewed AgentDojo version"
            return receipt
        spec = importlib.util.find_spec("agentdojo")
        if spec is None or spec.origin is None:
            receipt["reason"] = "AgentDojo source is unavailable"
            return receipt
        root = Path(spec.origin).resolve().parent
        for relative, expected in SOURCE_PINS.items():
            digest = hashlib.sha256((root / relative).read_bytes()).hexdigest()
            receipt["sources"][relative] = digest
            if digest != expected:
                receipt["reason"] = "modified AgentDojo implementation: " + relative
                return receipt
    except (OSError, ImportError, ValueError, importlib.metadata.PackageNotFoundError) as exc:
        receipt["reason"] = "benchmark source verification unavailable: " + type(exc).__name__
        return receipt
    receipt.update(verified=True, reason="reviewed in-memory benchmark implementation")
    return receipt


def configure_standard_contracts(suite: str, benchmark_version: str) -> dict:
    """Install verified benchmark defaults, preserving explicit host settings.

    An explicitly empty registry also wins. Version/source drift leaves the
    registries empty rather than assigning semantics to unreviewed tools.
    """
    receipt = verified_standard_contracts(suite, benchmark_version)
    receipt["defaulted"] = {}
    if receipt["verified"]:
        for setting, value in DEFAULT_CONTRACTS.items():
            if setting not in os.environ:
                os.environ[setting] = value
                receipt["defaulted"][setting] = value
    receipt["effective"] = {key: os.environ.get(key, "") for key in DEFAULT_CONTRACTS}
    return receipt
