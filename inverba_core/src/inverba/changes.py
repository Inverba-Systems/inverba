"""
Change detection (Phase A).

The shippable wedge: scrape a URL now, compare against the last signed
observation, and produce a ChangeReport backed by TWO provenance records
(before and after) so the change itself is cryptographically evidenced --
not just "the text looks different" but "here is signed proof of what the
page was at time T1 and what it became at time T2."

Buyers who feel this pain today: price monitoring, compliance/terms
tracking, competitive intel, journalism (was this edited after publ
after publication?). No regulatory bet required.

Built entirely on the semantic engine, so volatile per-request noise never
registers as a false-positive change, and changes are classified by
significance (a flipped price is MATERIAL even if 99% of the text is
unchanged).
"""

from __future__ import annotations

import json
import sqlite3
import time
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Optional

from .models import FetchResult, ProvenanceRecord
from .provenance import ProvenanceSigner, verify_record
from .semantic import SemanticNormalizer, SpectrumDiffer, DiffResult, DiffLevel, canonicalize_url


@dataclass
class Observation:
    """A single point-in-time snapshot: normalized content + its signed record."""
    url_canonical: str
    content_hash: str            # normalized content hash (semantic)
    raw_hash: str                 # raw bytes hash
    text: str
    observed_at: float
    provenance: ProvenanceRecord


@dataclass
class ChangeReport:
    url_canonical: str
    changed: bool
    level: str                          # DiffLevel value
    similarity: Optional[float]         # None on a first observation (nothing to compare)
    summary: str
    before_at: Optional[float]
    after_at: float
    before_hash: Optional[str]
    after_hash: str
    added_excerpt: Optional[str] = None
    removed_excerpt: Optional[str] = None
    before_provenance: Optional[dict] = None   # signed proof of prior state
    after_provenance: Optional[dict] = None     # signed proof of new state
    first_observation: bool = False              # no prior snapshot existed

    def to_dict(self) -> dict:
        return asdict(self)


# `seq` is a monotonic insertion counter and the ordering key. We deliberately do
# NOT order by observed_at: observed_at is a SIGNED, self-asserted timestamp taken
# from the fetching machine's clock, so it is neither trusted nor guaranteed
# monotonic. Ordering the change history by it would let a clock skew (rewind, or
# two fetches within one clock tick) silently mis-order or, under the old
# (url, observed_at) primary key + INSERT OR REPLACE, silently DROP a signed
# observation. Insertion order is the honest "order in which we observed."
_SCHEMA = """
CREATE TABLE IF NOT EXISTS observations (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    url_canonical TEXT NOT NULL,
    content_hash TEXT NOT NULL,
    raw_hash TEXT NOT NULL,
    text TEXT NOT NULL,
    observed_at REAL NOT NULL,
    provenance_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_obs_url ON observations(url_canonical, seq DESC);
"""


class ChangeStore:
    """Persists observations so 'what did this page look like last time' is
    answerable and evidenced."""

    def __init__(self, path: str | Path = "inverba_changes.db"):
        self.path = str(path)
        self._conn = sqlite3.connect(self.path)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(_SCHEMA)
        self._conn.commit()

    def close(self):
        self._conn.close()

    def __enter__(self): return self
    def __exit__(self, *exc): self.close()

    def latest(self, url_canonical: str) -> Optional[Observation]:
        # Order by insertion sequence, NOT observed_at -- see _SCHEMA note.
        row = self._conn.execute(
            "SELECT * FROM observations WHERE url_canonical = ? ORDER BY seq DESC LIMIT 1",
            (url_canonical,),
        ).fetchone()
        return self._row_to_obs(row) if row else None

    def history(self, url_canonical: str, limit: int = 50) -> list[Observation]:
        rows = self._conn.execute(
            "SELECT * FROM observations WHERE url_canonical = ? ORDER BY seq DESC LIMIT ?",
            (url_canonical, limit),
        ).fetchall()
        return [self._row_to_obs(r) for r in rows]

    def save(self, obs: Observation):
        # Plain INSERT (never REPLACE): every observation is retained. Two
        # observations with an identical observed_at must NOT clobber each other --
        # silently dropping a signed observation would corrupt the evidence trail.
        self._conn.execute(
            "INSERT INTO observations "
            "(url_canonical, content_hash, raw_hash, text, observed_at, provenance_json) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (obs.url_canonical, obs.content_hash, obs.raw_hash, obs.text,
             obs.observed_at, json.dumps(obs.provenance.to_dict())),
        )
        self._conn.commit()

    @staticmethod
    def _row_to_obs(row: sqlite3.Row) -> Observation:
        d = json.loads(row["provenance_json"])
        d["corroborations"] = [ProvenanceRecord(**c) for c in d.get("corroborations", [])]
        return Observation(
            url_canonical=row["url_canonical"],
            content_hash=row["content_hash"],
            raw_hash=row["raw_hash"],
            text=row["text"],
            observed_at=row["observed_at"],
            provenance=ProvenanceRecord(**d),
        )


class ChangeDetector:
    """
    Ties fetch -> normalize -> sign -> compare-to-last -> store into one call.

    The signer and a FetchResult come from the caller (so this works with a
    local single fetch OR a swarm-corroborated fetch). detect() returns a
    ChangeReport and persists the new observation as the new baseline.
    """

    def __init__(
        self,
        store: ChangeStore,
        signer: ProvenanceSigner,
        normalizer: Optional[SemanticNormalizer] = None,
        differ: Optional[SpectrumDiffer] = None,
    ):
        self.store = store
        self.signer = signer
        self.normalizer = normalizer or SemanticNormalizer()
        self.differ = differ or SpectrumDiffer()

    def detect(self, fetch_result: FetchResult) -> ChangeReport:
        normalized = self.normalizer.normalize(fetch_result.url, fetch_result.content)
        provenance = self.signer.sign(fetch_result)
        now = fetch_result.fetched_at or time.time()

        new_obs = Observation(
            url_canonical=normalized.url_canonical,
            content_hash=normalized.content_hash,
            raw_hash=normalized.raw_hash,
            text=normalized.text,
            observed_at=now,
            provenance=provenance,
        )

        prior = self.store.latest(normalized.url_canonical)
        self.store.save(new_obs)

        if prior is None:
            # A first observation has NOTHING to compare against. Do not report it
            # as level=identical/similarity=1.0 -- a caller ignoring the
            # first_observation flag would misread that as "unchanged." Use a
            # distinct level and similarity=None so it can never be confused with
            # a genuine no-change result.
            return ChangeReport(
                url_canonical=normalized.url_canonical,
                changed=False, level=DiffLevel.FIRST_OBSERVATION.value, similarity=None,
                summary="First observation of this URL; baseline recorded (no prior to compare).",
                before_at=None, after_at=now,
                before_hash=None, after_hash=normalized.content_hash,
                after_provenance=provenance.to_dict(),
                first_observation=True,
            )

        # Rebuild NormalizedContent shells for the differ from stored fields.
        from .semantic import NormalizedContent
        prior_nc = NormalizedContent(
            url_canonical=prior.url_canonical, text=prior.text,
            content_hash=prior.content_hash, raw_hash=prior.raw_hash,
        )
        new_nc = NormalizedContent(
            url_canonical=new_obs.url_canonical, text=new_obs.text,
            content_hash=new_obs.content_hash, raw_hash=new_obs.raw_hash,
        )
        diff: DiffResult = self.differ.diff(prior_nc, new_nc)

        return ChangeReport(
            url_canonical=normalized.url_canonical,
            changed=diff.changed, level=diff.level.value, similarity=diff.similarity,
            summary=diff.summary,
            before_at=prior.observed_at, after_at=now,
            before_hash=prior.content_hash, after_hash=normalized.content_hash,
            added_excerpt=diff.added_excerpt, removed_excerpt=diff.removed_excerpt,
            before_provenance=prior.provenance.to_dict(),
            after_provenance=provenance.to_dict(),
        )


def verify_change_report(report: ChangeReport) -> dict:
    """
    Independently verify that both provenance records in a change report are
    validly signed. This is what makes a change *evidenced*: a third party can
    confirm the before/after states were genuinely observed and signed, not
    fabricated.
    """
    result = {"before_valid": None, "after_valid": None}
    if report.before_provenance:
        d = dict(report.before_provenance)
        d["corroborations"] = [ProvenanceRecord(**c) for c in d.get("corroborations", [])]
        result["before_valid"] = verify_record(ProvenanceRecord(**d))
    if report.after_provenance:
        d = dict(report.after_provenance)
        d["corroborations"] = [ProvenanceRecord(**c) for c in d.get("corroborations", [])]
        result["after_valid"] = verify_record(ProvenanceRecord(**d))
    return result
