"""
Extraction pipeline.

Fast path (always available, no model required):
    raw HTML -> clean markdown, via trafilatura. Matches competitor
    baseline performance for the common "give me clean readable text" case.

Structured path (optional, requires a model backend):
    raw HTML + a JSON schema -> structured data, via a pluggable
    `ModelBackend`. The open core ships a single-backend path; a
    multi-model consensus backend is available separately as a
    commercial add-on and plugs into the same `ModelBackend` protocol.

The ModelBackend protocol is intentionally minimal so a local Ollama
model, a hosted API, or a future ensemble wrapper can all satisfy
it without extract.py needing to change.
"""

from __future__ import annotations

import json
from typing import Any, Optional, Protocol

import trafilatura

from .models import FetchResult, ExtractionResult


class ModelBackend(Protocol):
    """Anything that can turn (html, schema) into structured data satisfies this."""

    name: str

    def extract(self, html: str, schema: dict[str, Any]) -> dict[str, Any]:
        ...


class OllamaBackend:
    """
    Minimal local-model backend using an Ollama server's /api/generate
    endpoint. No cloud dependency -- this is the default structured-
    extraction path so Inverba never requires a hosted API key to work.
    """

    def __init__(self, model: str = "llama3.2", host: str = "http://localhost:11434"):
        self.name = model
        self.host = host

    def extract(self, html: str, schema: dict[str, Any]) -> dict[str, Any]:
        import httpx as _httpx  # local import: this backend is optional at runtime

        prompt = self._build_prompt(html, schema)
        resp = _httpx.post(
            f"{self.host}/api/generate",
            json={"model": self.name, "prompt": prompt, "stream": False, "format": "json"},
            timeout=120.0,
        )
        resp.raise_for_status()
        raw = resp.json().get("response", "{}")
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return {"_error": "model did not return valid JSON", "_raw": raw}

    @staticmethod
    def _build_prompt(html: str, schema: dict[str, Any]) -> str:
        # Truncate defensively -- callers should pre-clean HTML via the
        # markdown fast path before handing it to structured extraction
        # where possible, to keep prompts small.
        truncated = html[:20000]
        return (
            "Extract data matching this JSON schema from the page content below. "
            "Respond with ONLY valid JSON matching the schema, no other text.\n\n"
            f"SCHEMA:\n{json.dumps(schema)}\n\n"
            f"PAGE CONTENT:\n{truncated}"
        )


class ExtractionPipeline:
    def __init__(self, model_backend: Optional[ModelBackend] = None):
        self.model_backend = model_backend

    def to_markdown(self, fetch_result: FetchResult) -> Optional[str]:
        html = fetch_result.content.decode("utf-8", errors="ignore")
        return trafilatura.extract(
            html,
            output_format="markdown",
            include_links=True,
            include_images=True,
            favor_recall=True,
        )

    def extract(
        self,
        fetch_result: FetchResult,
        schema: Optional[dict[str, Any]] = None,
    ) -> ExtractionResult:
        markdown = self.to_markdown(fetch_result)

        structured = None
        model_used = None
        if schema is not None:
            if self.model_backend is None:
                raise ValueError(
                    "A schema was provided but no model_backend is configured. "
                    "Pass a ModelBackend (e.g. OllamaBackend()) to ExtractionPipeline()."
                )
            html = fetch_result.content.decode("utf-8", errors="ignore")
            structured = self.model_backend.extract(html, schema)
            model_used = self.model_backend.name

        return ExtractionResult(
            url=fetch_result.url,
            markdown=markdown,
            structured=structured,
            schema_used=schema,
            model_used=model_used,
            # confidence is left None here -- populated once the
            # multi-model consensus engine is wired in.
        )
