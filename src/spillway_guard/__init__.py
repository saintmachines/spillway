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
from .judge import Judge
from .lexicon import Lexicon
from .sanitizer import sanitize

__version__ = "0.1.1"

__all__ = ["Guard", "Decision", "sanitize", "IdentityIndex", "Lexicon", "Judge", "Policy",
           "JudgeRequest", "admit", "taint_novel", "index_identity_leaves",
           "ALLOW", "BLOCK", "REFER_TO_JUDGE", "__version__"]
