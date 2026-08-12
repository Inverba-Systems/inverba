# Independent verifiers

A signed Inverba record is meant to be checkable by anyone, in any language, with
no Inverba install. This directory holds small standalone verifiers that prove it.

| File | Language | Dependencies |
|---|---|---|
| `verify.mjs` | JavaScript (Node) | none — Node standard library only |

They join the two implementations shipped elsewhere in the repo:

- **Python** — `inverba.provenance.verify_record` (the reference the package uses).
- **Rust** — `inverba-core-rs`, whose generated test vectors are checked
  byte-for-byte against the spec.

Three independent implementations agreeing on the same records is what makes
"checkable in any language" a demonstrated claim rather than a slogan.

## `verify.mjs`

```
node verifiers/verify.mjs <record.json> [content-file]
```

Reconstructs the signed payload, verifies the Ed25519 signature against the
record's own public key, and — if you pass the content — confirms the bytes hash
to the signed `content_hash`. Exit code 0 = valid, non-zero = rejected.

The signed payload is canonical JSON (sorted keys, no whitespace). One detail
worth stating: `fetched_at` is a float, and the shipped format serializes it the
way Python does (a trailing `.0` when the value is integer-valued). `verify.mjs`
reproduces that exactly, so it agrees with Python even on that edge. IRF/1's
deterministic CBOR is the exact, language-neutral answer to number encoding; this
verifier targets the JSON record the package ships today.
