"""
LangChain / LlamaIndex integrations.

Why this exists: AI developers do not adopt a scraper by reading its docs --
they adopt it because it drops into the framework they already use in three
lines. Firecrawl's LangChain and LlamaIndex loaders are a large part of why it
became the default RAG crawler. Without an equivalent, Inverba is invisible to
that audience regardless of how good the trust layer is.

What makes these different from every other loader: the Document metadata
carries the PROVENANCE. Once a chunk is embedded in a vector store, you can
still answer "where did this come from, when, who fetched it, and can I prove
it?" -- which is exactly what nobody can answer today about their RAG corpus.

    Every other loader gives your RAG pipeline text.
    Inverba's gives it text you can prove.

The record travels with the chunk, so provenance survives retrieval. That is
the training-data / compliance use case falling out of the RAG use case for
free.

Both integrations are OPTIONAL extras. The imports are deferred and the classes
degrade with a clear error if the framework isn't installed, so the core package
never takes a hard dependency on either.
"""

from __future__ import annotations

import json
from typing import Any, Iterator, Optional, Sequence

from .models import ProvenanceRecord


def _record_metadata(record: ProvenanceRecord, extra: Optional[dict] = None) -> dict:
    """Provenance fields attached to every Document.

    Kept flat and JSON-serializable because vector stores vary wildly in what
    metadata types they accept -- nested objects get silently dropped by some.
    The full signed record is carried as a JSON string so it survives round-trips
    and can be re-verified after retrieval.
    """
    meta = {
        "source": record.url,
        "content_sha256": record.content_hash,
        "fetched_at": record.fetched_at,
        "fetched_by": record.fetched_by,
        "independent_observation": record.fetched_by == "native",
        "signed_by": record.worker_public_key,
        "corroborations": len(record.corroborations),
        # full record, re-verifiable after retrieval
        "inverba_record": json.dumps(record.to_dict()),
    }
    if extra:
        meta.update(extra)
    return meta


def verify_document_metadata(metadata: dict, content: Optional[bytes] = None) -> dict:
    """
    Re-verify a chunk's provenance AFTER it comes back out of a vector store.

    This is the payoff: a retrieved chunk can be checked, not just trusted.
    Returns the same verdict shape as the agent trust layer.
    """
    from .agent_trust import verify_handoff

    raw = metadata.get("inverba_record")
    if not raw:
        return {"verdict": "no_record", "trusted": False,
                "reasons": ["chunk carries no Inverba provenance record"]}

    data = json.loads(raw) if isinstance(raw, str) else raw
    data = dict(data)
    data["corroborations"] = [ProvenanceRecord(**c) for c in data.get("corroborations", [])]
    record = ProvenanceRecord(**data)
    return verify_handoff(record, claimed_content=content).to_dict()


# --------------------------------------------------------------------------
# LangChain
# --------------------------------------------------------------------------

def _require_langchain():
    try:
        from langchain_core.documents import Document
        from langchain_core.document_loaders import BaseLoader
        return Document, BaseLoader
    except ImportError as e:  # pragma: no cover - env-dependent
        raise ImportError(
            "LangChain integration requires langchain-core. "
            "Install with: pip install inverba-core[langchain]"
        ) from e


class InverbaLoader:
    """
    LangChain document loader that returns provenance-carrying Documents.

        from inverba.integrations import InverbaLoader

        loader = InverbaLoader(["https://example.com/pricing"])
        docs = loader.load()
        docs[0].metadata["content_sha256"]   # provable
        docs[0].metadata["fetched_by"]        # 'native' or e.g. 'firecrawl'

    Use any backend -- rent Firecrawl's anti-bot coverage and still get a
    signed record:

        loader = InverbaLoader(urls, backend=FirecrawlBackend(api_key="fc-..."))
    """

    def __init__(
        self,
        urls: Sequence[str] | str,
        *,
        backend=None,
        signer=None,
        mode: str = "markdown",     # "markdown" | "raw"
        continue_on_failure: bool = True,
    ):
        self.urls = [urls] if isinstance(urls, str) else list(urls)
        self.mode = mode
        self.continue_on_failure = continue_on_failure

        if backend is None:
            from .backends import NativeBackend
            backend = NativeBackend()
        self.backend = backend

        if signer is None:
            from .provenance import ProvenanceSigner
            signer = ProvenanceSigner.generate()
        self.signer = signer

    def lazy_load(self) -> Iterator[Any]:
        import asyncio
        Document, _ = _require_langchain()

        for url in self.urls:
            try:
                fetch_result = asyncio.run(self.backend.fetch(url))
                if not fetch_result.ok:
                    raise RuntimeError(fetch_result.error or f"fetch failed for {url}")
                record = self.signer.sign(fetch_result)
                text = self._to_text(fetch_result)
            except Exception:
                if self.continue_on_failure:
                    continue
                raise
            yield Document(page_content=text, metadata=_record_metadata(record))

    def load(self) -> list[Any]:
        return list(self.lazy_load())

    def _to_text(self, fetch_result) -> str:
        if self.mode == "raw":
            return fetch_result.content.decode("utf-8", errors="ignore")
        from .extract import ExtractionPipeline
        html = fetch_result.content.decode("utf-8", errors="ignore")
        try:
            import trafilatura
            md = trafilatura.extract(html, output_format="markdown", favor_recall=True)
            if md:
                return md
        except Exception:
            pass
        return html


def as_langchain_loader(*args, **kwargs) -> InverbaLoader:
    """Alias matching the naming other providers use."""
    return InverbaLoader(*args, **kwargs)


# --------------------------------------------------------------------------
# LlamaIndex
# --------------------------------------------------------------------------

class InverbaReader:
    """
    LlamaIndex reader that returns provenance-carrying Documents.

        from inverba.integrations import InverbaReader

        reader = InverbaReader()
        docs = reader.load_data(["https://example.com/pricing"])

    Mirrors the LlamaIndex reader convention (`load_data`) so it drops into an
    existing pipeline unchanged.
    """

    def __init__(self, *, backend=None, signer=None, mode: str = "markdown"):
        self._loader_kwargs = {"backend": backend, "signer": signer, "mode": mode}

    def load_data(self, urls: Sequence[str] | str) -> list[Any]:
        try:
            from llama_index.core import Document as LIDocument
        except ImportError as e:  # pragma: no cover - env-dependent
            raise ImportError(
                "LlamaIndex integration requires llama-index-core. "
                "Install with: pip install inverba-core[llamaindex]"
            ) from e

        import asyncio
        from .backends import NativeBackend
        from .provenance import ProvenanceSigner

        backend = self._loader_kwargs["backend"] or NativeBackend()
        signer = self._loader_kwargs["signer"] or ProvenanceSigner.generate()
        mode = self._loader_kwargs["mode"]

        url_list = [urls] if isinstance(urls, str) else list(urls)
        docs = []
        for url in url_list:
            fetch_result = asyncio.run(backend.fetch(url))
            if not fetch_result.ok:
                continue
            record = signer.sign(fetch_result)
            helper = InverbaLoader([], mode=mode, backend=backend, signer=signer)
            text = helper._to_text(fetch_result)
            docs.append(LIDocument(text=text, metadata=_record_metadata(record)))
        return docs
