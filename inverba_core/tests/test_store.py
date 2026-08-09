import tempfile
import time
from pathlib import Path

from inverba.models import Job, JobStatus, FetchResult, FetchMethod, ExtractionResult
from inverba.provenance import ProvenanceSigner
from inverba.store import JobStore


def make_job() -> Job:
    fr = FetchResult(
        url="https://example.com",
        final_url="https://example.com",
        status_code=200,
        content=b"<html><body>hi</body></html>",
        content_type="text/html",
        method=FetchMethod.HTTP,
        fetched_at=time.time(),
    )
    er = ExtractionResult(url=fr.url, markdown="hi")
    signer = ProvenanceSigner.generate()
    provenance = signer.sign(fr)
    return Job(
        url=fr.url,
        status=JobStatus.DONE,
        fetch_result=fr,
        extraction_result=er,
        provenance=provenance,
    )


def test_save_and_get_roundtrip():
    with tempfile.TemporaryDirectory() as tmp:
        db_path = Path(tmp) / "test.db"
        job = make_job()
        with JobStore(db_path) as store:
            store.save(job)
            fetched = store.get(job.id)

        assert fetched is not None
        assert fetched.url == job.url
        assert fetched.status == JobStatus.DONE
        assert fetched.fetch_result.content == job.fetch_result.content
        assert fetched.extraction_result.markdown == "hi"
        assert fetched.provenance.content_hash == job.provenance.content_hash


def test_list_filters_by_status():
    with tempfile.TemporaryDirectory() as tmp:
        db_path = Path(tmp) / "test.db"
        with JobStore(db_path) as store:
            done_job = make_job()
            failed_job = make_job()
            failed_job.status = JobStatus.FAILED
            failed_job.error = "timeout"

            store.save(done_job)
            store.save(failed_job)

            done_jobs = store.list(status=JobStatus.DONE)
            failed_jobs = store.list(status=JobStatus.FAILED)

        assert len(done_jobs) == 1
        assert done_jobs[0].id == done_job.id
        assert len(failed_jobs) == 1
        assert failed_jobs[0].error == "timeout"


def test_update_existing_job():
    with tempfile.TemporaryDirectory() as tmp:
        db_path = Path(tmp) / "test.db"
        job = make_job()
        with JobStore(db_path) as store:
            store.save(job)
            job.status = JobStatus.ESCALATED
            job.updated_at = time.time()
            store.save(job)
            fetched = store.get(job.id)

        assert fetched.status == JobStatus.ESCALATED
