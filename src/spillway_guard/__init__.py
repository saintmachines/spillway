"""SPILLWAY: an ingress sanitizer and a deterministic egress floor for tool-calling agents.

    from spillway_guard import Guard
    guard = Guard(user_task)
    text = guard.observe_tool_return(tool_name, tool_args, typed_return)   # the model reads this
    decision = guard.check_call(tool_name, tool_args)                      # before executing

The floor admits a side-effecting call only when every taint-novel target value occupies a typed
identity field of a read-only return the agent legitimately read (Sec. 3.1 and Algorithm 1 of the
paper), or a fixed delegation rule covers it. A judge may restore a refused call outside the
removed spans. Values the user named are never taint-novel. Scoped to identity targets on the
evaluated AgentDojo benchmarks. A spoofed typed field is out of scope.
"""

from .floor import (
                    ALLOW,
                    BLOCK,
                    REFER_TO_JUDGE,
                    Decision,
                    IdentityIndex,
                    JudgeRequest,
                    Policy,
                    admit,
                    index_identity_leaves,
                    taint_novel,
)
from .guard import Guard
from .file_policy import file_access_mode
from .e2gv2 import E2gV2Guard, E2VerdictRequest
from .ingress import PasteBoundaryError, split_pasted
from .judge import Judge
from .lexicon import Lexicon
from .resource_contracts import ResourceContracts, ResourceField
from .sanitizer import sanitize
from .short_lineage import CreationContracts

__version__ = "1.1.0"

__all__ = ["file_access_mode", "ResourceContracts", "ResourceField", "CreationContracts", "PasteBoundaryError", "split_pasted", "Guard", "E2gV2Guard", "E2VerdictRequest", "Decision", "sanitize", "IdentityIndex", "Lexicon", "Judge", "Policy",
           "JudgeRequest", "admit", "taint_novel", "index_identity_leaves",
           "ALLOW", "BLOCK", "REFER_TO_JUDGE", "__version__"]
