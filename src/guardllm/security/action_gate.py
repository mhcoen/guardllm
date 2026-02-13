"""Part 3: Action gate — user confirmation for write operations.

Presents proposed actions to the user and requires explicit
confirmation before execution. The gate is the last line of defense
after all deterministic checks pass.

INV-MUSE-7 (Amendment B, Erratum 2): When conversation context
includes web-derived content, ALL tool calls (read, write, destructive)
require enhanced confirmation with a hardcoded warning.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict

from guardllm.security.types import SecurityContext


@dataclass
class ActionProposal:
    """A proposed action awaiting user confirmation."""

    tool_name: str
    args: Dict[str, Any]
    summary: str                   # Human-readable action summary
    context: Dict[str, Any]        # Additional context for display
    heightened_scrutiny: bool = False  # True if class_hiding_possible


# Hardcoded warning text — NOT LLM-generated (INV-MUSE-7)
_WEB_DERIVED_WARNING = (
    "\u26a0\ufe0f  Your conversation context includes content from web search."
)


class ActionGate:
    """User confirmation gate for write operations.

    See spec Part 3 for full requirements:
    - All write-capable tools require confirmation
    - Read-only tools skip the gate
    - Heightened scrutiny when class_hiding_possible
    - Cancelled actions are never executed
    - INV-MUSE-7: Enhanced confirmation for ALL tool calls when
      context_has_web_derived is True (gated on muse_escalation_gate config)
    """

    async def confirm(
        self,
        proposal: ActionProposal,
        ctx: SecurityContext,
        context_has_web_derived: bool = False,
    ) -> bool:
        """Present action to user and await confirmation.

        Returns True if user confirms, False if cancelled.
        Delegates to ctx.confirmation_handler if available;
        otherwise denies by default (safe fallback).

        Args:
            proposal: The action proposal to confirm
            ctx: Security context
            context_has_web_derived: If True, ALL tool calls require enhanced
                confirmation with hardcoded web-content warning (INV-MUSE-7)
        """
        if ctx.confirmation_handler is not None:
            context_dict: Dict[str, Any] = {
                **proposal.context,
                "summary": proposal.summary,
                "heightened_scrutiny": proposal.heightened_scrutiny,
            }

            # INV-MUSE-7: Enhanced confirmation when web-derived content present
            if (
                context_has_web_derived
                and ctx.policy.escalation_gate_enabled
            ):
                context_dict["web_derived_warning"] = _WEB_DERIVED_WARNING
                context_dict["enhanced_confirmation"] = True

            return await ctx.confirmation_handler.confirm(
                proposal.tool_name,
                proposal.args,
                context_dict,
            )

        # No handler configured — deny by default
        return False
