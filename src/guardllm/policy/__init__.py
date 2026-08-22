"""Policy backends that decide on the facts GuardLLM computes.

The library's own checks are not here: they live in ``guardllm.security`` and
always run first. This is the seam where an external policy language narrows an
already-permitted call.
"""

from guardllm.policy.rego import PolicyDecision, RegoPolicy, build_input, decide

__all__ = ["PolicyDecision", "RegoPolicy", "build_input", "decide"]
