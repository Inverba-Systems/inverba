# Inverba

**Use any scraper. Prove exactly what it got — cryptographically, verifiable offline, with zero trust in us.**

Every web scraper hands you data. None of them let you *prove* what the page
actually returned. Inverba signs every fetch with an Ed25519 signature, so anyone
— you, a collaborator, an auditor, a future version of you — can verify exactly
what was retrieved and when, offline, without trusting Inverba, without an account,
without a server.

It's not a scraper. It layers on top of whatever scraper you already use.

> ⚠️ **Status: early, in active development.** The cryptographic core is solid and
> heavily tested (241 tests in this open core), but this is a young project. APIs may change. See
> [What Inverba does and doesn't prove](#what-inverba-does-and-doesnt-prove) before
> relying on it for anything that matters.

## What it's for

Two concrete jobs:

1. **Agent-to-agent handoff verification** — one agent proves to another exactly
   what it fetched, so the receiver trusts the data on cryptographic grounds, not
   faith (and a replayed record is caught). See it:
   `python inverba_core/examples/handoff_demo.py`.
2. **Provenance for scraped or collected data** — document a corpus, answer a
   dispute, or stand behind a dataset later, with signed, offline-verifiable proof
   of exactly what each URL returned. Try it: `inverba solo <url>` then
   `inverba verify record.json`.

## Verify it yourself (30 seconds)

Don't take our word for it — that's the whole point. After installing (below):

```bash
# 1. Fetch a URL and sign what came back into a portable record
inverba solo https://example.com --out record.json

# 2. Verify the record — offline, no account, no network, no trust in us
inverba verify record.json
#   ✓ VALID
#   signature  valid

# 3. Now tamper: change ANY single character in record.json (e.g. one hex
#    digit of "content_hash") in your editor, save, and verify again:
inverba verify record.json
#   ✗ INVALID
#   signature  INVALID — record forged or altered
```

That last step is the point: change a single character of a signed record and
verification fails. The signature proves the record is exactly what was fetched,
untouched.

### Agent-to-agent handoff

One agent hands a signed record to another; the receiver verifies it — and a
*replayed* record is caught, not silently re-trusted:

```bash
python inverba_core/examples/handoff_demo.py
#   1. fresh handoff     -> TRUSTED
#   2. same record again -> REPLAYED
#   3. tampered record   -> UNVERIFIED
```

## Why

Provenance for web data has been the last "just trust me" layer in the stack.
Everywhere else, self-attestation got replaced by independent verification — but
scraped data still arrives with nothing but the collector's word for what it was.
That's a problem for reproducible research (was the dataset *really* this?), for
anyone building on scraped corpora, and for data you may need to stand behind
later.

Inverba makes web-data provenance **independently verifiable**: the proof travels
with the data and checks out on any machine, offline, forever, with no dependency
on us.

## What you get

- **Sign any fetch** — produce a signed `ProvenanceRecord` for what a URL returned.
- **Verify offline** — check any record with no account, no network, no trust in
  Inverba. Verification is always free and always will be.
- **Use any scraper** — pluggable backends; layer Inverba on your existing pipeline.
- **Change detection** — prove whether a page changed between two fetches.
- **Corpus manifests** — bundle many signed records into one signed, verifiable
  manifest with membership proofs. Prove your whole dataset, self-hosted.
- **Bot-wall honesty** — detects when a fetch hit a CAPTCHA/block and signs *that*,
  instead of pretending a block page was the real content.
- **Agent-to-agent verification** — one agent can verify another agent's data
  handoff cryptographically.
- **C2PA export**, **RFC 3161 timestamping**, **LangChain/LlamaIndex loaders**.

A signed record contains exactly these fields — nothing invented, nothing hidden:
`url`, `content_hash` (SHA-256 of the content), `fetched_at`, `worker_public_key`,
`signature` (Ed25519), `fetched_by`, `status_code`, `final_url`, `content_type`,
and any `corroborations`.

## What Inverba does and doesn't prove

Being honest about the boundaries is part of a provenance tool's job.

**It proves:** that the holder of a specific key fetched specific content from a
specific URL at a specific time, and that the record hasn't been altered since. The
proof is independently verifiable offline.

**It does not prove:**
- That you had the *legal right* to collect the data (origin ≠ authority).
- That *every* visitor to that URL saw the same thing (sites vary by geo, auth,
  time — Inverba proves what *your fetch* got, not universal truth).
- The *exact* wall-clock time as certified fact. `fetched_at` is self-asserted; the
  optional RFC 3161 timestamp proves an *upper bound* ("existed at or before T"),
  not exact time.

If a claim isn't in that first list, Inverba doesn't make it.

## Install

Requires Python 3.10+.

```bash
pip install inverba
```

Published as `inverba` (the meta package) and `inverba-core` (the engine). That
gives you the `inverba` command used in the examples above. Optional extras on the
core: `pip install "inverba-core[temporal]"` (RFC 3161 timestamping), `[browser]`
(JS rendering), `[mcp]` (MCP server), `[langchain]` / `[llamaindex]`.

**From source** instead:

```bash
git clone https://github.com/Inverba-Systems/inverba
cd inverba
python -m venv .venv
source .venv/bin/activate     # Windows: .venv\Scripts\activate
pip install -e ./inverba_core
```

## Open core

Inverba is **open core**. This repository — the entire engine you see here — is
free and **Apache-2.0, permanently**. Prove your own data, self-host everything,
verify offline, forever, at no cost. That's not a trial; it's the product.

There's also a commercial layer (advanced compliance/governance features, and
hosted services) for organizations that need it — that's how the project sustains
itself. But everything in this repo is free and open, and the core promise —
sign, verify, prove your own data, offline, self-hosted — will never be paywalled.

If you want the commercial details, see [inverba.dev](https://inverba.dev). If you
just want to prove your web data, you already have everything you need right here.

## License

Apache-2.0. See [LICENSE](LICENSE).

## Contributing / contact

This is an early, solo-built project — issues and feedback are welcome. Please
[open an issue](https://github.com/Inverba-Systems/inverba/issues); that's the best way to
reach the project.
