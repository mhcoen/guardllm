"""Environment variables under the current name, and under the one before it.

The project was called GuardLLM and read ``GUARDLLM_*``. It is called Vörður and
reads ``VORDUR_*``. A rename that silently stopped honouring the old names would
not fail loudly: an operator's ``GUARDLLM_POLICY`` would simply stop being read
and the gateway would come up with no policy at all, which looks exactly like a
healthy start. So the old names are still read, once, with a warning naming the
replacement.

There is precedent in this codebase for keeping a legacy env var name working
rather than breaking a running deployment: ``EPISODIC_CANARY_SECRET`` predates
the project's current name and is still honoured.

The fallback is a migration aid, not a second supported spelling. It warns every
time it fires so an operator has something to grep for, and the deprecation is
recorded in the changelog rather than left to be discovered.
"""

from __future__ import annotations

import os
import warnings

__all__ = ["LEGACY_PREFIX", "PREFIX", "getenv", "names_set"]

#: The canonical prefix. Everything documented uses this.
PREFIX = "VORDUR_"

#: Read but never documented as current. Present so an upgrade does not silently
#: drop configuration that was working a moment earlier.
LEGACY_PREFIX = "GUARDLLM_"


def getenv(name: str, default: str | None = None) -> str | None:
    """Read ``VORDUR_<name>``, falling back to ``GUARDLLM_<name>``.

    ``name`` is the part after the prefix, so ``getenv("POLICY")`` reads
    ``VORDUR_POLICY`` and then ``GUARDLLM_POLICY``.

    An empty string counts as set. A deployment that deliberately blanks a
    variable is saying something, and treating that as absent would silently
    reinstate a default it was trying to clear.
    """
    current = os.environ.get(PREFIX + name)
    if current is not None:
        return current
    legacy = os.environ.get(LEGACY_PREFIX + name)
    if legacy is not None:
        warnings.warn(
            f"{LEGACY_PREFIX}{name} is read for compatibility and will stop being "
            f"read in a future release. Rename it to {PREFIX}{name}.",
            DeprecationWarning,
            stacklevel=2,
        )
        return legacy
    return default


def names_set() -> list[str]:
    """Names of set variables under either prefix, sorted, values never read.

    The diagnostic bundle reports these by name and presence only, because a
    value can carry a key inside a URL. Both prefixes appear so a bundle from a
    deployment mid-migration shows what is actually configuring it.
    """
    return sorted(k for k in os.environ if k.startswith((PREFIX, LEGACY_PREFIX)))
