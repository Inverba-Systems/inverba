"""
Tests for the LangChain / LlamaIndex integrations.

The differentiating claim: provenance survives into the vector store, so a
retrieved chunk can be RE-VERIFIED rather than merely trusted. These lock that
in, including the case that matters -- a chunk whose text was tampered with
after retrieval must fail verification.
"""

import json
import time

import pytest

from inverba.models import FetchResult, FetchMethod
from inverba.provenance import ProvenanceSigner
from inverba.backends import CallableBackend, NativeBackend
from inverba.integrations import (
    InverbaLoader, verify_document_metadata, _record_metadata,
)

pytest.importorskip("langchain_core")

PAGE = (b"<html><body><article><h1>Widget</h1>"
        b"<p>Price: $49.99. In stock and ready to ship today.</p>"
        b"</article></body></html>")


def fake_backend(content=PAGE, name="native"):
    async def fn(url):
        return content, 200, "text/html"
    if name == "native":
        class _B:
            name = "native"
            async def fetch(self, url):
                return FetchResult(url=url, final_url=url, status_code=200,
                                   content=content, content_type="text/html",
                                   method=FetchMethod.HTTP, fetched_at=time.time(),
                                   fetched_by="native")
        return _B()
    return CallableBackend(name, fn)


def test_loader_returns_documents_with_provenance():
    loader = InverbaLoader(["https://example.com/p"], backend=fake_backend())
    docs = loader.load()
    assert len(docs) == 1
    md = docs[0].metadata
    assert md["source"] == "https://example.com/p"
    assert len(md["content_sha256"]) == 64
    assert md["fetched_by"] == "native"
    assert md["independent_observation"] is True
    assert "inverba_record" in md


def test_document_text_is_extracted_markdown():
    loader = InverbaLoader(["https://example.com/p"], backend=fake_backend())
    docs = loader.load()
    assert "Widget" in docs[0].page_content


def test_raw_mode_returns_original_html():
    loader = InverbaLoader(["https://example.com/p"], backend=fake_backend(), mode="raw")
    docs = loader.load()
    assert "<html>" in docs[0].page_content


def test_metadata_is_flat_and_json_serializable():
    """Vector stores silently drop nested metadata -- it must survive json."""
    loader = InverbaLoader(["https://example.com/p"], backend=fake_backend())
    md = loader.load()[0].metadata
    json.dumps(md)   # must not raise
    for v in md.values():
        assert isinstance(v, (str, int, float, bool)), f"non-flat metadata: {v!r}"


def test_relayed_fetch_is_marked_in_metadata():
    loader = InverbaLoader(["https://example.com/p"],
                           backend=fake_backend(name="firecrawl"))
    md = loader.load()[0].metadata
    assert md["fetched_by"] == "firecrawl"
    assert md["independent_observation"] is False


def test_retrieved_chunk_can_be_reverified():
    """The payoff: a chunk out of a vector store is checkable, not just trusted."""
    loader = InverbaLoader(["https://example.com/p"], backend=fake_backend())
    md = loader.load()[0].metadata
    result = verify_document_metadata(md, content=PAGE)
    assert result["signature_valid"] is True
    assert result["trusted"] is True


def test_tampered_chunk_fails_reverification():
    loader = InverbaLoader(["https://example.com/p"], backend=fake_backend())
    md = loader.load()[0].metadata
    tampered = PAGE.replace(b"49.99", b"39.99")
    result = verify_document_metadata(md, content=tampered)
    assert result["trusted"] is False
    assert result["verdict"] == "content_mismatch"


def test_forged_record_in_metadata_fails():
    loader = InverbaLoader(["https://example.com/p"], backend=fake_backend())
    md = dict(loader.load()[0].metadata)
    rec = json.loads(md["inverba_record"])
    rec["signature"] = "00" * 64
    md["inverba_record"] = json.dumps(rec)
    result = verify_document_metadata(md, content=PAGE)
    assert result["trusted"] is False


def test_chunk_without_provenance_reports_honestly():
    result = verify_document_metadata({"source": "https://x.com"})
    assert result["trusted"] is False
    assert result["verdict"] == "no_record"


def test_multiple_urls_load():
    loader = InverbaLoader(
        ["https://example.com/a", "https://example.com/b"], backend=fake_backend()
    )
    docs = loader.load()
    assert len(docs) == 2


def test_continue_on_failure_skips_bad_url():
    class Broken:
        name = "native"
        async def fetch(self, url):
            return FetchResult(url=url, final_url=url, status_code=500,
                               content=b"", content_type="", method=FetchMethod.HTTP,
                               error="boom", fetched_by="native")
    loader = InverbaLoader(["https://example.com/x"], backend=Broken(),
                           continue_on_failure=True)
    assert loader.load() == []


def test_raises_when_continue_on_failure_false():
    class Broken:
        name = "native"
        async def fetch(self, url):
            return FetchResult(url=url, final_url=url, status_code=500,
                               content=b"", content_type="", method=FetchMethod.HTTP,
                               error="boom", fetched_by="native")
    loader = InverbaLoader(["https://example.com/x"], backend=Broken(),
                           continue_on_failure=False)
    with pytest.raises(RuntimeError):
        loader.load()
