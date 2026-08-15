"""
Replay defense for agent-to-agent handoffs.

A provenance record is a TRUE statement about a past fetch. Its validity does not
expire when it is re-used: a holder can present the same valid record again,
later, in a new context, as if it were a fresh observation. `verify_handoff`
alone verifies a record's intrinsic validity and cannot, on its own, know it has
seen that record before.

A SeenStore gives a verifier that memory. It is OPT-IN -- pass one to
`verify_handoff` and a record presented a second time is flagged REPLAYED.

Honest limits (mirrored in SECURITY.md):
  - Per-verifier scope. The in-memory store stops replay to the SAME verifier,
    not across a fleet -- two independent verifiers each accept the record once.
    A shared backend (Redis, a DB) behind this same interface widens the scope.
  - Bounded by cache lifetime. With a TTL set, a record replayed after the TTL
    lapses is no longer remembered and will not be flagged.
  - REPLAYED is advisory, not proof of malice. A replayed record is still a
    genuine record of what was fetched; the property it defends is freshness of
    observation -- it stops an old, true record from being passed off as new.
"""
from __future__ import annotations

import time
from typing import Callable, Optional, Protocol, runtime_checkable


@runtime_checkable
class SeenStore(Protocol):
    """Minimal interface: has this key been seen, and remember that it has."""

    def seen(self, key: str) -> bool: ...
    def record(self, key: str) -> None: ...


class InMemorySeenStore:
    """Process-local SeenStore. An optional TTL bounds how long a record is
    remembered; without one, memory persists for the process lifetime.

    Deliberately not thread-safe and not shared across processes: a deployment
    that needs fleet-wide replay defense backs this interface with a shared
    store (e.g. Redis) rather than this default.
    """

    def __init__(self, ttl_seconds: Optional[float] = None,
                 clock: Callable[[], float] = time.time) -> None:
        self._ttl = ttl_seconds
        self._clock = clock
        self._seen: dict[str, float] = {}

    def seen(self, key: str) -> bool:
        first = self._seen.get(key)
        if first is None:
            return False
        if self._ttl is not None and (self._clock() - first) > self._ttl:
            del self._seen[key]      # expired -- forget it and treat as unseen
            return False
        return True

    def record(self, key: str) -> None:
        # Keep the FIRST-seen time so the TTL measures age from first sighting,
        # not from the most recent replay attempt.
        self._seen.setdefault(key, self._clock())

    def record_if_new(self, key: str) -> bool:
        """Test-and-set: record `key` and return True iff it was NOT already present.
        A single call, so a caller need not do a separate seen()+record() with a race
        window between them. A shared backend (e.g. Redis
        SETNX) implements this atomically; this in-memory version is single-op but, like
        the rest of the store, not thread-safe -- documented on the class."""
        if self.seen(key):
            return False
        self.record(key)
        return True
