# Verification run — Inverba flagship flow

Evidence that the core flow works end-to-end in a fresh environment: install →
fetch → notarize (sign) → offline verify → agent-to-agent handoff, timed and
adversarially tested. Reproducible from this repository alone (see the end).

**Date:** 2026-08-09 · **Verdict:** ✅ **PASS** — every criterion met, **total
wall-clock 52.90 s**, zero manual intervention.

## The bar

A fresh environment must go from install → fetch → notarize → offline verify →
`verify_handoff` between two agents in **under 10 minutes with no manual
intervention**, the full test suite must be green, and an adversarial pass must
hold: a **tampered record is rejected** and a **replayed handoff is rejected**.

## Environment

- Windows 10, fresh `python -m venv` (no prior state carried over).
- The app's home directory was pointed at a throwaway location, so no
  pre-existing local data influenced the run.
- Installed **`inverba-core` only** — the open-core package. The entire flagship
  flow (CLI, fetch, sign, offline verify, `verify_handoff`, replay defense)
  resolved from that one package; no other package was required.
- Ed25519 verify path: `cryptography` 49.0.0 / OpenSSL 4.0.1 (RFC 8032; rejects
  non-canonical `S`, so a malleated signature cannot verify — see `SECURITY.md`).

## Criteria — pass/fail

| # | Criterion | Result |
|---|---|---|
| 1 | Fresh-environment install, no manual steps | ✅ PASS |
| 2 | Fetch a live URL (`https://example.com`) | ✅ PASS |
| 3 | Notarize = produce a signed provenance record | ✅ PASS |
| 4 | Offline verify → VALID | ✅ PASS |
| 5 | `verify_handoff` between two agents → TRUSTED | ✅ PASS |
| 6 | Under 10 minutes, zero manual intervention | ✅ PASS (52.90 s) |
| 7 | Full test suite green | ✅ PASS (375 passed / 3 skipped) |
| 8 | Adversarial: tampered record rejected | ✅ PASS (→ INVALID) |
| 9 | Adversarial: replayed handoff rejected | ✅ PASS (→ REPLAYED) |

## Timings (wall-clock seconds)

| Step | Seconds |
|---|---|
| 1. install (fresh venv + `inverba-core`) | 46.93 |
| 2. `inverba --version` | 1.39 |
| 3. fetch + notarize (`inverba scrape … --json-out`) | 2.01 |
| 4. offline verify (`inverba verify`) | 0.83 |
| 5. tamper → INVALID (adversarial) | 0.93 |
| 6. `verify_handoff` A→B + replay (adversarial) | 0.80 |
| **TOTAL** | **52.90** |

Install dominates (≈89% of total) — resolving/building `cryptography` and deps.
Everything after install is **< 6 s combined**; from an already-installed
environment, time-to-first-verify is effectively instant.

## Adversarial detail

- **Tamper:** flipping the signed `content_hash` on the record makes
  `inverba verify` return INVALID (non-zero exit).
- **Replay:** a verifier holding a `SeenStore` accepts a record once (`TRUSTED`)
  and rejects the identical re-presentation (`REPLAYED`, `trusted=False`). Replay
  defense and its honest limits are documented in `SECURITY.md`.

## Notes

- **Install is the whole cost** (~47 s), unattended. A prebuilt wheel / `pipx`
  path would shorten it further.
- **Fetch requires network.** A fully offline environment cannot perform the
  fetch step; `inverba demo` provides a no-network taste of sign/verify.
- **"Notarize"** here is the local signing step — the notarization of what was
  fetched. The optional hosted notary corroboration needs live infrastructure and
  is not part of this offline flow.

## Reproduce it

```bash
python -m venv .venv
. .venv/Scripts/activate                      # bash on Windows; or source .venv/bin/activate
pip install ./inverba_core

inverba scrape https://example.com --json-out > record.json
inverba verify record.json                    # ✓ VALID
# flip one character of content_hash in record.json, then:
inverba verify record.json                    # ✗ INVALID — record forged or altered

python inverba_core/examples/handoff_demo.py  # TRUSTED -> REPLAYED -> UNVERIFIED
pytest inverba_core/tests                      # full core suite green
```
