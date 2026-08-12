# Verifier test fixture

A committed, reproducible record used by the `js-verifier` CI job (and handy for
trying `verify.mjs` by hand).

- `record.json` — a valid Inverba record.
- `content.bin` — the exact bytes the record attests to (so `content_hash` matches).
- `record-badsig.json` — the same record with one signature byte flipped; its
  signature is invalid and a correct verifier must reject it.

The record is signed with a **fixed throwaway test key** (seed = bytes `00..1f`),
never a real signing key. Ed25519 is deterministic, so anyone can regenerate this
fixture byte-for-byte. `fetched_at` is deliberately an integer-valued float
(`1700000000.0`) — the exact case a naive `JSON.stringify` mis-serializes — so the
fixture guards that edge, not just the easy path.

Check it yourself:

```
node verifiers/verify.mjs verifiers/testdata/record.json verifiers/testdata/content.bin   # -> VALID (exit 0)
node verifiers/verify.mjs verifiers/testdata/record-badsig.json verifiers/testdata/content.bin  # -> INVALID (exit 1)
```
