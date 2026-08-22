"""The HTTP shell around the gateway core. Standard library only.

No web framework, because the container's whole promise is one small image
that runs with ``docker run``. ``http.server`` and ``urllib`` carry it, and the
gateway core in ``proxy.py`` holds every decision worth testing, so this file
is only plumbing: read a body, call the core, pass the upstream key through
untouched, write a response.

Never take the upstream API key. The client's ``Authorization`` header is
forwarded verbatim and never read, stored, or logged. A proxy that demands its
own OpenAI key is a far harder sell and a liability we design away.
"""

from __future__ import annotations

import json
import sys
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from guardllm.gateway.proxy import GatewayConfig, GatewayRefused, guard_chat_completion
from guardllm.gateway.session import SessionStore

_SESSION_HEADER = "X-GuardLLM-Session"
_MAX_BODY_BYTES = 8 * 1024 * 1024  # a chat request past 8MB is not a real one


def _upstream_caller(cfg: GatewayConfig, auth_header: str | None):
    """Build the function the core calls to reach the model API.

    Closes over the client's Authorization header and forwards it unchanged.
    The gateway never supplies a key of its own.
    """

    url = cfg.upstream_base_url.rstrip("/") + "/chat/completions"
    # The upstream must be http(s). A file: or custom scheme in the configured
    # base URL would make the proxy read a local file instead of a model API,
    # so it is rejected at construction rather than reached at request time.
    if urllib.parse.urlparse(url).scheme not in ("http", "https"):
        raise ValueError(f"upstream must be an http(s) URL, got {cfg.upstream_base_url!r}")

    def call(body: dict[str, Any]) -> dict[str, Any]:
        data = json.dumps(body).encode("utf-8")
        headers = {"Content-Type": "application/json"}
        if auth_header:
            headers["Authorization"] = auth_header
        # The url's scheme is checked to be http(s) at construction, above, so
        # the file:/custom-scheme risk both linters flag here cannot occur.
        req = urllib.request.Request(url, data=data, headers=headers, method="POST")  # noqa: S310
        try:
            with urllib.request.urlopen(req, timeout=120) as resp:  # noqa: S310  # nosec B310
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            # The model API refused (bad key, rate limit). Surface its status
            # and body rather than dressing it as a gateway decision.
            raise GatewayRefused(
                "upstream", f"model API returned {exc.code}", status=exc.code
            ) from exc
        except urllib.error.URLError as exc:
            raise GatewayRefused(
                "upstream", f"model API unreachable: {exc.reason}", status=502
            ) from exc

    return call


class _Handler(BaseHTTPRequestHandler):
    # Set by make_server via a subclass; declared here for the type checker.
    store: SessionStore
    cfg: GatewayConfig

    def log_message(self, *_a: Any) -> None:
        # BaseHTTPRequestHandler logs every request to stderr with the client
        # address. The audit logger is the record we keep; this would only
        # duplicate it and leak addresses into container logs.
        pass

    def _send_json(self, status: int, payload: dict[str, Any]) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _error(self, status: int, message: str, *, stage: str | None = None) -> None:
        # OpenAI-shaped error envelope, so an OpenAI client surfaces it normally.
        err: dict[str, Any] = {"message": message, "type": "guardllm_gateway"}
        if stage is not None:
            err["stage"] = stage
        self._send_json(status, {"error": err})

    def do_GET(self) -> None:
        if self.path == "/healthz":
            self._send_json(200, {"status": "ok", "sessions": len(self.store)})
        else:
            self._error(404, "not found")

    def do_POST(self) -> None:
        if self.path.rstrip("/") != "/v1/chat/completions":
            self._error(404, "not found")
            return

        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0:
            self._error(400, "empty request body")
            return
        if length > _MAX_BODY_BYTES:
            self._error(413, "request body too large")
            return
        try:
            body = json.loads(self.rfile.read(length).decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            self._error(400, "request body is not valid JSON")
            return
        if not isinstance(body, dict):
            self._error(400, "request body is not a JSON object")
            return

        session_id = self.headers.get(_SESSION_HEADER)
        call = _upstream_caller(self.cfg, self.headers.get("Authorization"))
        try:
            decision = guard_chat_completion(
                body, session_id=session_id, store=self.store, cfg=self.cfg, call_upstream=call
            )
        except GatewayRefused as refused:
            # Fail closed and loud: the client gets an error, never an altered
            # or silently-passed completion. There is deliberately no fail-open
            # path, because the one thing a security proxy must never do is
            # forward traffic it could not inspect.
            self._error(refused.status, refused.reason, stage=refused.stage)
            return

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header(_SESSION_HEADER, decision.session_id)
        payload = json.dumps(decision.completion).encode("utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


def make_server(
    host: str, port: int, *, store: SessionStore, cfg: GatewayConfig
) -> ThreadingHTTPServer:
    """Build the HTTP server. Split from ``main`` so a test can drive it."""

    class Handler(_Handler):
        pass

    Handler.store = store
    Handler.cfg = cfg
    return ThreadingHTTPServer((host, port), Handler)


def main(argv: list[str] | None = None) -> int:
    import argparse
    import os
    import sys as _sys

    from guardllm import Guard
    from guardllm.config import load_policy
    from guardllm.security.audit import AuditLogger

    parser = argparse.ArgumentParser(prog="guardllm.gateway")
    # Binds all interfaces because a container publishes its port and reaches
    # the gateway from another network namespace; 127.0.0.1 would answer only
    # inside the container. Override with --host for a host-network deployment.
    parser.add_argument(
        "--host",
        default=os.environ.get("GUARDLLM_HOST", "0.0.0.0"),  # noqa: S104  # nosec B104
    )
    parser.add_argument("--port", type=int, default=int(os.environ.get("GUARDLLM_PORT", "8080")))
    parser.add_argument(
        "--upstream",
        default=os.environ.get("GUARDLLM_UPSTREAM", "https://api.openai.com/v1"),
        help="model API base URL, e.g. https://api.openai.com/v1",
    )
    parser.add_argument(
        "--policy",
        default=os.environ.get("GUARDLLM_POLICY"),
        help="path to a YAML policy file (optional)",
    )
    args = parser.parse_args(argv)

    policy = load_policy(args.policy) if args.policy else None
    cfg = GatewayConfig(upstream_base_url=args.upstream, policy=policy)

    audit = AuditLogger(stream=_sys.stdout)

    def make_guard() -> Guard:
        return Guard(audit_logger=audit)

    store = SessionStore(make_guard=make_guard)
    server = make_server(args.host, args.port, store=store, cfg=cfg)
    print(
        f"guardllm gateway on {args.host}:{args.port} -> {args.upstream} (fail closed)",
        file=_sys.stderr,
        flush=True,
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.shutdown()
    return 0


if __name__ == "__main__":
    sys.exit(main())
