"""AgentDojo adapter.

Runs the reference SPILLWAY gate (``reference/spillway_gate.py``, the final build the paper evaluated) as an
AgentDojo pipeline element with the paper's settings. The console script ``spillway-agentdojo`` forwards
the gate's own command line; see :mod:`spillway_guard.agentdojo.runner` and ``reproduce/README.md``.
"""

from spillway_guard.agentdojo.runner import (
    JUDGE_MODEL_ENV,
    JUDGE_URL_ENV,
    PAPER_FLAGS,
    PROMPT_SHA256,
    RECOVERY_SWITCHES,
    attack_model_name,
    main,
    paper_env_defaults,
)

__all__ = [
    "JUDGE_MODEL_ENV",
    "JUDGE_URL_ENV",
    "PAPER_FLAGS",
    "PROMPT_SHA256",
    "RECOVERY_SWITCHES",
    "attack_model_name",
    "main",
    "paper_env_defaults",
]
