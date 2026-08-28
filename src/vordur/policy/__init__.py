"""Policy backends that decide on the facts Vörður computes.

The library's own checks are not here: they live in ``vordur.security`` and
always run first. This is the seam where an external policy language narrows an
already-permitted call.
"""

from vordur.policy.rego import (
    POLICY_INPUT_VERSION,
    PolicyDecision,
    RegoPolicy,
    build_input,
    decide,
)

__all__ = [
    "POLICY_INPUT_VERSION",
    "PolicyDecision",
    "RegoPolicy",
    "build_input",
    "decide",
]
