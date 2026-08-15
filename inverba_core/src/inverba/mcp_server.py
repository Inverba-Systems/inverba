"""
MCP server.

Exposes Inverba's core capabilities as MCP tools so any MCP client (Claude
Desktop, Claude Code, agent frameworks) can drive it:

    inverba_scrape   -- fetch + markdown extraction + signed provenance
    inverba_extract  -- fetch + schema-driven structured extraction
    inverba_verify   -- verify a provenance record

Runs over stdio. Requires the optional `mcp` extra:
    pip install "inverba-core[mcp]"

This is deliberately thin -- it wires the existing core modules to MCP
rather than reimplementing anything, so behavior is identical to the CLI.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Optional

from .fetch import FetchEngine
from .extract import ExtractionPipeline, OllamaBackend
from .homedir import inverba_home
from .provenance import ProvenanceSigner, verify_with_corroborations
from .models import ProvenanceRecord


def _load_signer(key_path: Path) -> ProvenanceSigner:
    if key_path.exists():
        return ProvenanceSigner.from_private_bytes(bytes.fromhex(key_path.read_text().strip()))
    signer = ProvenanceSigner.generate()
    key_path.parent.mkdir(parents=True, exist_ok=True)
    key_path.write_text(signer.private_bytes().hex())
    key_path.chmod(0o600)
    return signer


def build_server(key_path: Optional[Path] = None):
    """
    Construct the MCP server. Imported lazily so `mcp` is only required
    when the server is actually run.
    """
    from mcp.server.fastmcp import FastMCP

    key_path = key_path or (inverba_home() / "worker.key")
    signer = _load_signer(key_path)
    engine = FetchEngine()

    mcp = FastMCP("inverba")

    @mcp.tool()
    async def inverba_scrape(url: str) -> str:
        """Fetch a URL, extract clean markdown, and return it with a signed
        provenance record proving what content was observed."""
        fetch_result = await engine.fetch(url)
        if not fetch_result.ok:
            return json.dumps({"error": fetch_result.error or f"status {fetch_result.status_code}"})
        pipeline = ExtractionPipeline()
        extraction = pipeline.extract(fetch_result)
        provenance = signer.sign(fetch_result)
        return json.dumps({
            "url": url,
            "markdown": extraction.markdown,
            "provenance": provenance.to_dict(),
        }, indent=2)

    @mcp.tool()
    async def inverba_extract(url: str, schema_json: str, model: str = "llama3.2") -> str:
        """Fetch a URL and extract structured data matching the given JSON
        schema, using a local Ollama model. Returns the structured result
        plus a signed provenance record."""
        fetch_result = await engine.fetch(url)
        if not fetch_result.ok:
            return json.dumps({"error": fetch_result.error or f"status {fetch_result.status_code}"})
        schema = json.loads(schema_json)
        backend = OllamaBackend(model=model)
        pipeline = ExtractionPipeline(model_backend=backend)
        extraction = pipeline.extract(fetch_result, schema=schema)
        provenance = signer.sign(fetch_result)
        return json.dumps({
            "url": url,
            "structured": extraction.structured,
            "provenance": provenance.to_dict(),
        }, indent=2)

    @mcp.tool()
    def inverba_verify(record_json: str) -> str:
        """Verify a Inverba provenance record. Returns validity and, if
        corroborations are present, whether independent workers agreed on
        the content."""
        from .models import load_record_json
        try:
            data = load_record_json(record_json)   # size-bounded, fail-closed
            record = ProvenanceRecord.from_dict(data)   # fail-closed on unexpected record types
        except (ValueError, TypeError) as e:
            return json.dumps({"valid": False, "error": f"invalid record: {e}"}, indent=2)
        return json.dumps(verify_with_corroborations(record), indent=2)

    return mcp


def main():
    server = build_server()
    server.run()


if __name__ == "__main__":
    main()
