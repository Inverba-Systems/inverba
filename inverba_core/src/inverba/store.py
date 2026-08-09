"""
Job store.

SQLite by default -- deliberately not Redis. A single developer running
Inverba standalone shouldn't need to stand up and operate a Redis instance
just to track crawl jobs.

A separate distributed layer can swap in a different backing store for
multi-worker coordination without changing this module's interface.
"""

from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from dataclasses import asdict
from pathlib import Path
from typing import Iterator, Optional

from .models import (
    Job,
    JobStatus,
    FetchResult,
    FetchMethod,
    ExtractionResult,
    ProvenanceRecord,
)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS jobs (
    id TEXT PRIMARY KEY,
    url TEXT NOT NULL,
    status TEXT NOT NULL,
    schema_json TEXT,
    created_at REAL NOT NULL,
    updated_at REAL NOT NULL,
    fetch_result_json TEXT,
    extraction_result_json TEXT,
    provenance_json TEXT,
    error TEXT
);
CREATE INDEX IF NOT EXISTS idx_jobs_status ON jobs(status);
CREATE INDEX IF NOT EXISTS idx_jobs_url ON jobs(url);
"""


def _fetch_result_to_json(fr: Optional[FetchResult]) -> Optional[str]:
    if fr is None:
        return None
    d = asdict(fr)
    d["content"] = fr.content.decode("utf-8", errors="replace")  # store as text
    d["method"] = fr.method.value
    return json.dumps(d)


def _fetch_result_from_json(s: Optional[str]) -> Optional[FetchResult]:
    if s is None:
        return None
    d = json.loads(s)
    d["content"] = d["content"].encode("utf-8")
    d["method"] = FetchMethod(d["method"])
    return FetchResult(**d)


def _extraction_result_to_json(er: Optional[ExtractionResult]) -> Optional[str]:
    return json.dumps(asdict(er)) if er is not None else None


def _extraction_result_from_json(s: Optional[str]) -> Optional[ExtractionResult]:
    return ExtractionResult(**json.loads(s)) if s is not None else None


def _provenance_to_json(pr: Optional[ProvenanceRecord]) -> Optional[str]:
    return json.dumps(pr.to_dict()) if pr is not None else None


def _provenance_from_json(s: Optional[str]) -> Optional[ProvenanceRecord]:
    if s is None:
        return None
    d = json.loads(s)
    d["corroborations"] = [ProvenanceRecord(**c) for c in d.get("corroborations", [])]
    return ProvenanceRecord(**d)


class JobStore:
    def __init__(self, path: str | Path = "inverba.db"):
        self.path = str(path)
        self._conn = sqlite3.connect(self.path)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(_SCHEMA)
        self._conn.commit()

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> "JobStore":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def save(self, job: Job) -> None:
        self._conn.execute(
            """
            INSERT INTO jobs (id, url, status, schema_json, created_at, updated_at,
                               fetch_result_json, extraction_result_json, provenance_json, error)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                url=excluded.url,
                status=excluded.status,
                schema_json=excluded.schema_json,
                updated_at=excluded.updated_at,
                fetch_result_json=excluded.fetch_result_json,
                extraction_result_json=excluded.extraction_result_json,
                provenance_json=excluded.provenance_json,
                error=excluded.error
            """,
            (
                job.id,
                job.url,
                job.status.value,
                json.dumps(job.schema) if job.schema is not None else None,
                job.created_at,
                job.updated_at,
                _fetch_result_to_json(job.fetch_result),
                _extraction_result_to_json(job.extraction_result),
                _provenance_to_json(job.provenance),
                job.error,
            ),
        )
        self._conn.commit()

    def get(self, job_id: str) -> Optional[Job]:
        row = self._conn.execute("SELECT * FROM jobs WHERE id = ?", (job_id,)).fetchone()
        return self._row_to_job(row) if row else None

    def list(self, status: Optional[JobStatus] = None, limit: int = 100) -> list[Job]:
        if status is not None:
            rows = self._conn.execute(
                "SELECT * FROM jobs WHERE status = ? ORDER BY created_at DESC LIMIT ?",
                (status.value, limit),
            ).fetchall()
        else:
            rows = self._conn.execute(
                "SELECT * FROM jobs ORDER BY created_at DESC LIMIT ?", (limit,)
            ).fetchall()
        return [self._row_to_job(r) for r in rows]

    @staticmethod
    def _row_to_job(row: sqlite3.Row) -> Job:
        return Job(
            id=row["id"],
            url=row["url"],
            status=JobStatus(row["status"]),
            schema=json.loads(row["schema_json"]) if row["schema_json"] else None,
            created_at=row["created_at"],
            updated_at=row["updated_at"],
            fetch_result=_fetch_result_from_json(row["fetch_result_json"]),
            extraction_result=_extraction_result_from_json(row["extraction_result_json"]),
            provenance=_provenance_from_json(row["provenance_json"]),
            error=row["error"],
        )
