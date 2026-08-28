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
import time
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from vordur.gateway.proxy import GatewayConfig, GatewayRefused, guard_chat_completion
from vordur.gateway.session import InvalidSessionId, SessionStore
from vordur.gateway.viewer import render_chain, render_index, render_missing
from vordur.support import UnsafeBundleError, build_bundle, render_bundle

_SESSION_HEADER = "X-Vordur-Session"
_MAX_BODY_BYTES = 8 * 1024 * 1024  # a chat request past 8MB is not a real one

#: The same cap for the upstream response. A model completion past this is not
#: a real one, and read() with no bound lets a compromised or malfunctioning
#: upstream allocate arbitrary gateway memory before a single check has run.
_MAX_UPSTREAM_BYTES = 8 * 1024 * 1024

#: Total wall clock allowed for one upstream exchange, connect through last
#: byte. urllib's ``timeout`` is a socket inactivity timeout, not a deadline, so
#: an upstream that delivers a byte often enough to keep resetting it holds the
#: connection indefinitely: a 124-byte response drip-fed one byte per second
#: completed in 123.9 seconds under a 120-second timeout. ThreadingHTTPServer
#: gives each request a thread, so that is a worker held per connection and an
#: availability failure in the component every request passes through.
_UPSTREAM_DEADLINE_SECONDS = 120.0

#: Read granularity for the bounded read below. Small enough that the deadline
#: is checked often against a slow sender, large enough not to matter otherwise.
_UPSTREAM_CHUNK_BYTES = 64 * 1024


class _NoRedirects(urllib.request.HTTPRedirectHandler):
    """Refuse every 3xx from the upstream instead of following it.

    urllib follows redirects by default and resends the request headers to the
    new location, so a 302 from the model API to an unrelated origin would
    carry the client's Authorization there. The gateway forwards a bearer token
    it does not own; letting a redirect choose where that token goes hands it
    to whoever controls the upstream's redirect target. A model completions
    endpoint has no legitimate reason to redirect, so this is refused rather
    than followed same-origin: the narrower rule is the one that cannot leak.
    """

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: N802
        raise urllib.error.HTTPError(
            req.full_url, code, f"upstream redirected to {newurl!r}; refused", headers, fp
        )


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

    _opener = urllib.request.build_opener(_NoRedirects)

    def call(body: dict[str, Any]) -> dict[str, Any]:
        data = json.dumps(body).encode("utf-8")
        headers = {"Content-Type": "application/json"}
        if auth_header:
            headers["Authorization"] = auth_header
        # The url's scheme is checked to be http(s) at construction, above, so
        # the file:/custom-scheme risk both linters flag here cannot occur.
        req = urllib.request.Request(url, data=data, headers=headers, method="POST")  # noqa: S310
        deadline = time.monotonic() + _UPSTREAM_DEADLINE_SECONDS
        try:
            with _opener.open(req, timeout=_UPSTREAM_DEADLINE_SECONDS) as resp:  # noqa: S310  # nosec B310
                # Chunked, with the deadline checked between chunks, because the
                # socket timeout alone is not a deadline: it resets on every
                # byte. read1 rather than read so a slow sender returns what it
                # has instead of blocking for a full chunk, which is what makes
                # the check between iterations meaningful.
                pieces: list[bytes] = []
                total = 0
                while True:
                    if time.monotonic() > deadline:
                        raise GatewayRefused(
                            "upstream",
                            f"model API exceeded the {_UPSTREAM_DEADLINE_SECONDS:.0f}s deadline",
                            status=504,
                        )
                    chunk = resp.read1(_UPSTREAM_CHUNK_BYTES)
                    if not chunk:
                        break
                    total += len(chunk)
                    # One byte past the cap is enough to know it is over: a body
                    # exactly at the cap is indistinguishable from a truncated
                    # one if the read stops at the cap itself.
                    if total > _MAX_UPSTREAM_BYTES:
                        raise GatewayRefused(
                            "upstream",
                            f"model API response exceeds {_MAX_UPSTREAM_BYTES} bytes",
                            status=502,
                        )
                    pieces.append(chunk)
                return json.loads(b"".join(pieces).decode("utf-8"))
        except urllib.error.HTTPError as exc:
            # The model API refused (bad key, rate limit), or a redirect was
            # refused above. Surface its status rather than dressing it as a
            # gateway decision.
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

    def _send_json(
        self, status: int, payload: dict[str, Any], *, session_id: str | None = None
    ) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        if session_id is not None:
            self.send_header(_SESSION_HEADER, session_id)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _error(
        self,
        status: int,
        message: str,
        *,
        stage: str | None = None,
        session_id: str | None = None,
    ) -> None:
        # OpenAI-shaped error envelope, so an OpenAI client surfaces it normally.
        err: dict[str, Any] = {"message": message, "type": "vordur_gateway"}
        if stage is not None:
            err["stage"] = stage
        if session_id is not None:
            # The session header goes on refusals too. A refusal is the case an
            # operator most wants to inspect, and without the id there is no
            # handle to look the chain up by, which made the viewer useless for
            # exactly the request that needed it.
            err["session_id"] = session_id
        self._send_json(status, {"error": err}, session_id=session_id)

    def _send_html(self, status: int, html: str) -> None:
        body = html.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        path = self.path.split("?", 1)[0].rstrip("/") or "/"
        if path == "/healthz":
            self._send_json(200, {"status": "ok", "sessions": len(self.store)})
            return
        if path == "/sessions":
            self._send_json(200, {"sessions": self.store.listing()})
            return
        if path.startswith("/sessions/"):
            session_id = urllib.parse.unquote(path[len("/sessions/") :])
            chain = self.store.chain(session_id)
            if chain is None:
                self._error(404, f"no live session {session_id!r}")
                return
            self._send_json(200, {"session_id": session_id, **chain.as_dict()})
            return
        if path == "/forensics":
            self._send_html(200, render_index(self.store.listing()))
            return
        if path.startswith("/forensics/"):
            session_id = urllib.parse.unquote(path[len("/forensics/") :])
            chain = self.store.chain(session_id)
            if chain is None:
                self._send_html(404, render_missing(session_id))
                return
            self._send_html(200, render_chain(session_id, chain))
            return
        if path == "/support" or path.startswith("/support/"):
            self._support(path)
            return
        self._error(404, "not found")

    def _support(self, path: str) -> None:
        """A diagnostic bundle, so a container can be diagnosed by curl.

        The operator running this gateway cannot be asked to reproduce a
        problem locally, and nobody here can reach their network. Everything
        support needs comes out of one request.

        A session id includes that session's decision chain, which is the part
        that explains a refusal several turns after the ingest that caused it.
        """
        chain = None
        if path.startswith("/support/"):
            session_id = urllib.parse.unquote(path[len("/support/") :])
            chain = self.store.chain(session_id)
            if chain is None:
                self._error(404, f"no live session {session_id!r}")
                return
        try:
            text = render_bundle(
                build_bundle(policy=self.cfg.policy, chain=chain, deployment="gateway")
            )
        except UnsafeBundleError as exc:
            # Refusing is the designed answer, so it is a 409 rather than a
            # 500: nothing failed, the bundle was declined because it could not
            # be cleaned.
            self._error(409, str(exc))
            return
        body = text.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

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

        # Resolved here rather than inside the guarded call, so the id exists on
        # every exit path including a refusal. store.get is idempotent for a
        # known id, so the call below returns this same session.
        try:
            resolved_id, _guard, _chain = self.store.get(self.headers.get(_SESSION_HEADER))
        except InvalidSessionId as exc:
            # A client error, not a security decision: the header is malformed.
            # Refused before the id becomes a stored key, a response header, or
            # a forensics row.
            self._error(400, str(exc))
            return
        call = _upstream_caller(self.cfg, self.headers.get("Authorization"))
        try:
            decision = guard_chat_completion(
                body, session_id=resolved_id, store=self.store, cfg=self.cfg, call_upstream=call
            )
        except GatewayRefused as refused:
            # Fail closed and loud: the client gets an error, never an altered
            # or silently-passed completion. There is deliberately no fail-open
            # path, because the one thing a security proxy must never do is
            # forward traffic it could not inspect.
            self._error(refused.status, refused.reason, stage=refused.stage, session_id=resolved_id)
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
    import sys as _sys

    from vordur import Guard, _env
    from vordur.config import load_policy
    from vordur.security.audit import AuditLogger

    parser = argparse.ArgumentParser(prog="vordur.gateway")
    # Binds all interfaces because a container publishes its port and reaches
    # the gateway from another network namespace; 127.0.0.1 would answer only
    # inside the container. Override with --host for a host-network deployment.
    parser.add_argument(
        "--host",
        default=_env.getenv("HOST", "0.0.0.0"),  # noqa: S104  # nosec B104
    )
    parser.add_argument("--port", type=int, default=int(_env.getenv("PORT", "8080")))
    parser.add_argument(
        "--upstream",
        default=_env.getenv("UPSTREAM", "https://api.openai.com/v1"),
        help="model API base URL, e.g. https://api.openai.com/v1",
    )
    parser.add_argument(
        "--policy",
        default=_env.getenv("POLICY"),
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
        f"vordur gateway on {args.host}:{args.port} -> {args.upstream} (fail closed)",
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
