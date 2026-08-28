"""The Vörður gateway: an OpenAI-compatible proxy that runs the checks itself.

An application changes one line, ``base_url``, and makes no Vörður calls at
all. Everything the library inspects already crosses that connection: tool
results inbound, and the model's tool calls and final text outbound.

One rule governs the design, and it is the line between this and an ML
guardrail. **Provenance is derived from the channel, never from the content.**
A message's role, a tool's name, an HTTP header: each is a structural fact
about where bytes came from rather than a guess about what they mean. The
README's position that nothing is inferred from content survives the move from
code into a proxy because the proxy only ever reads structure.

Run it with ``python -m vordur.gateway`` or the container.
"""

from vordur.gateway.proxy import GatewayConfig, GatewayRefused, guard_chat_completion
from vordur.gateway.session import SessionStore

__all__ = ["GatewayConfig", "GatewayRefused", "SessionStore", "guard_chat_completion"]
