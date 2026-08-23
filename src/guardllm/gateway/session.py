"""One Guard per session, kept in memory with TTL and LRU eviction.

Chat completions is stateless, so the gateway reconstructs the session itself.
A ``Guard`` is a few kilobytes (two booleans, a canary, a provenance tracker,
two capped deques), so an in-memory map holds thousands of them and Redis only
becomes necessary at multi-replica, which this tier is not.

Two failure directions, and they are not symmetric:

- Merging two callers' state is a security failure: one caller's contamination
  or escalation would gate another's tools, or worse, one caller's redacted
  provenance would be read against another's egress. So an absent or unusable
  session id yields a FRESH session, never a shared one.
- Losing a session to eviction is a correctness cost, not a security one: the
  next call rebuilds a clean Guard, which is stricter, not looser. So eviction
  is free to be aggressive.
"""

from __future__ import annotations

import threading
from collections import OrderedDict
from collections.abc import Callable

from guardllm import Guard
from guardllm.gateway.forensics import Chain


class SessionStore:
    """Thread-safe map of session id to Guard, with TTL and LRU eviction.

    ``time_source`` is injected so the tests do not sleep; it defaults to a
    monotonic clock, which cannot go backwards under an NTP step and turn a
    live session's age negative.
    """

    def __init__(
        self,
        *,
        make_guard: Callable[[], Guard],
        max_sessions: int = 10_000,
        ttl_seconds: float = 3600.0,
        time_source: Callable[[], float] | None = None,
    ) -> None:
        if max_sessions < 1:
            raise ValueError("max_sessions must be at least 1")
        self._make_guard = make_guard
        self._max = max_sessions
        self._ttl = ttl_seconds
        if time_source is None:
            import time

            time_source = time.monotonic
        self._now = time_source
        self._lock = threading.Lock()
        # id -> (guard, chain, last_used, session_lock). Ordered by recency;
        # oldest first. ``self._lock`` guards this map for the few microseconds
        # of a lookup. The fourth element is a different thing entirely: it
        # guards one session's Guard for the whole of one request, including
        # the upstream round trip. See ``lock_for``.
        self._entries: OrderedDict[str, tuple[Guard, Chain, float, threading.Lock]] = OrderedDict()

    def get(self, session_id: str | None) -> tuple[str, Guard, Chain]:
        """Return a live ``(session_id, Guard, Chain)``, creating it if needed.

        A ``None`` or empty id is a MISS, not a lookup key: it returns a fresh
        session under a generated id rather than a shared one, because a
        client that sends no id must never land in another client's state.
        The returned id is what the caller echoes back in the response header,
        so a fresh session becomes reusable on the next call.
        """
        now = self._now()
        if not session_id:
            return self._new(now)

        with self._lock:
            self._evict_expired(now)
            hit = self._entries.get(session_id)
            if hit is not None:
                guard, chain, _, session_lock = hit
                self._entries[session_id] = (guard, chain, now, session_lock)
                self._entries.move_to_end(session_id)
                return session_id, guard, chain
            # A client-supplied id that we do not hold is honoured as the id of
            # a NEW session, so the client keeps a stable handle across the TTL
            # gap. It is still a fresh Guard, never resurrected state.
            guard, chain = self._make_guard(), Chain()
            self._insert(session_id, guard, chain, now)
            return session_id, guard, chain

    def _new(self, now: float) -> tuple[str, Guard, Chain]:
        import uuid

        session_id = uuid.uuid4().hex
        guard, chain = self._make_guard(), Chain()
        with self._lock:
            self._evict_expired(now)
            self._insert(session_id, guard, chain, now)
        return session_id, guard, chain

    def _insert(self, session_id: str, guard: Guard, chain: Chain, now: float) -> None:
        # Caller holds the lock, except _new which takes it around this.
        self._entries[session_id] = (guard, chain, now, threading.Lock())
        self._entries.move_to_end(session_id)
        while len(self._entries) > self._max:
            self._entries.popitem(last=False)  # evict least-recently-used

    def _evict_expired(self, now: float) -> None:
        # Caller holds the lock. Entries are ordered oldest-use first, so the
        # expired ones are a prefix: stop at the first live entry instead of
        # scanning the whole map.
        ttl = self._ttl
        while self._entries:
            sid, (_guard, _chain, seen, _session_lock) = next(iter(self._entries.items()))
            if now - seen <= ttl:
                break
            del self._entries[sid]

    def lock_for(self, session_id: str) -> threading.Lock:
        """The lock that serializes one session's requests.

        A ``Guard`` mutates session state in place with no internal
        synchronization -- the remembered canary, contamination and escalation
        flags, DLP buffers, provenance, rate counters -- and
        ``docs/security.md`` states the contract: one pipeline per session,
        driven sequentially, and a host that may drive one concurrently holds a
        lock around it. The gateway runs on ``ThreadingHTTPServer``, so the
        gateway is that host. Two requests carrying the same
        ``X-GuardLLM-Session`` land on the same Guard in different threads and
        can interleave a contamination write with an egress read.

        Held across the upstream round trip as well, not just the two
        inspections. Contamination written by a tool result in a request has to
        be in force for the response that follows it; releasing over the
        network call would let a second request's ingest land between the
        first request's ingest and its egress check, which is precisely the
        session-risk loop the gateway exists to hold.

        The cost is that two concurrent requests naming one session serialize,
        including the time upstream. That is what a session is: a sequence.
        Different sessions never contend, so throughput scales with clients
        rather than with requests per client.

        An id the store no longer holds returns a fresh, uncontended lock. It
        cannot alias another session, because a caller in that position also
        has a different Guard.
        """
        with self._lock:
            hit = self._entries.get(session_id)
            return hit[3] if hit is not None else threading.Lock()

    def chain(self, session_id: str) -> Chain | None:
        """The decision chain for a live session, or None if it is not held.

        A lookup, never a create: the viewer must not conjure a session as a
        side effect of someone opening a URL.
        """
        with self._lock:
            # Swept here too. Expiry used to run only on the chat path, so an
            # idle gateway kept an expired session's decision chain readable
            # and listed for as long as nothing else arrived: a retention
            # window with no upper bound, in the one surface built for someone
            # to read a session back.
            self._evict_expired(self._now())
            hit = self._entries.get(session_id)
            return hit[1] if hit is not None else None

    def listing(self) -> list[dict[str, object]]:
        """Every live session, newest use first, for the viewer's index."""
        with self._lock:
            self._evict_expired(self._now())
            rows = [
                {
                    "session_id": sid,
                    "steps": len(chain),
                    "blocked": sum(1 for s in chain.steps if s.outcome == "blocked"),
                    "contaminated": chain.steps[-1].contaminated if len(chain) else False,
                    "escalated": chain.steps[-1].escalated if len(chain) else False,
                    "idle_seconds": round(self._now() - seen, 1),
                }
                for sid, (_guard, chain, seen, _session_lock) in self._entries.items()
            ]
        rows.reverse()  # most-recently-used first
        return rows

    def __len__(self) -> int:
        with self._lock:
            return len(self._entries)
