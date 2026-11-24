"""Frozen file policy v2.1 for tool proposals and host-resolved file paths."""

from ._file_policy_v21 import gate
from ._file_policy_v21_rules import mode_of
from .floor import BLOCK, Decision


def file_access_mode(path: str) -> str | None:
    """Return the v2.1 L0 mode for a path resolved by the host application."""
    return mode_of(path, "L0")


def file_call_refusal(name: str, args: dict | None) -> Decision | None:
    allowed, mode, _, _ = gate(name, args, "L0")
    if allowed:
        return None
    return Decision(BLOCK, f"block_file_policy_{mode}", "The host has restricted this file operation.", 0.0)
