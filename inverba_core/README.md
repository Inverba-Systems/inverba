# inverba-core

Sovereign, verifiable, swarm-distributable web extraction engine.

This is the **Phase 0 standalone core** — everything here runs on one
machine with zero mandatory cloud dependency. The swarm/trust layer
(`inverba-swarm`) and the hosted commercial product (Inverba Cloud) are
separate, optional add-ons described in the architecture spec; nothing in
this package requires them.

## What's here

| Module | Responsibility |
|---|---|
| `fetch.py` | Async HTTP fetch (httpx), with optional Playwright fallback for JS-heavy pages, triggered by a heuristic rather than always-on headless browsing |
| `extract.py` | Markdown fast path (trafilatura, no model required) + schema-driven structured extraction via a pluggable `ModelBackend` (default: local Ollama, no API key needed) |
| `provenance.py` | Content-hash + Ed25519 signed attestation of every fetch. Records are portable — verifiable with just the public key, independent of Inverba itself |
| `store.py` | SQLite-backed job store. Deliberately not Redis — no infra to stand up for local/single-machine use |
| `cli.py` | `inverba scrape`, `inverba verify`, `inverba jobs` |

## Install

```bash
pip install -e .
# optional: browser fallback for JS-heavy pages
pip install -e ".[browser]" && playwright install chromium
# optional: structured extraction needs a local Ollama server running
```

## Usage

```bash
# Fetch + extract to markdown, sign a provenance record
inverba scrape https://example.com

# Structured extraction against a JSON schema, via a local Ollama model
inverba scrape https://example.com --schema product_schema.json --model llama3.2

# Verify a standalone provenance record (works with no Inverba install --
# only needs the record's embedded public key)
inverba verify record.json

# List jobs from the local store
inverba jobs
```

## Why the provenance layer exists

Every other crawler gives you data and asks you to trust the process that
produced it. `inverba scrape` also emits a signed claim:

```json
{
  "url": "https://example.com/page",
  "content_hash": "2547...a324",
  "fetched_at": 1783833956.0,
  "worker_public_key": "54dc...bc90e",
  "signature": "94a8...5d5103",
  "fetched_by": "native",
  "status_code": 200,
  "final_url": "",
  "content_type": "text/html",
  "corroborations": []
}
```

Anyone holding this JSON and the worker's public key can verify — without
running Inverba — that this exact content was observed at this exact URL
at this exact time, by a worker holding this specific private key. When
`inverba-swarm` is used, `corroborations` gets populated with independent
signed observations of the same URL from other workers, so you can also
verify that multiple independent parties agree on what they saw.

## License

Apache-2.0. See `LICENSE`. The commercial layer (managed swarm hosting,
verification registry, trust-ledger service) is a separate product —
nothing in this package is feature-gated toward it.

## Roadmap

This package is the open-core engine. A multi-model consensus extraction
backend is available separately as a commercial add-on and plugs into
`extract.py`'s `ModelBackend` protocol without changing this package's
public interface.
