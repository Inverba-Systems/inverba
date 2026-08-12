# Adversarial security battery

Inverba's whole value is a record that is honest about what it does and does not
prove. This document reports an adversarial battery run against that honesty
architecture: a set of attacks, each trying to make a record verify or mislead
where it should not — plus the boundaries where an attack lands on a limitation
that is *already documented*, which is the architecture behaving correctly.

Every result here is reproducible. The battery is source code:

```
pytest inverba_core/tests/test_adversarial_battery.py
```

**83 attacks, 0 findings.** No attack produced a record that verified when it
should not have, or a claim the documentation does not disclose. The boundaries
that exist are the ones already stated in the docs — named again below, honestly,
rather than buried under a green check.

## How to read this

- **Rejected / flagged** — the attack was caught: the signature failed, the
  content did not match, the verdict was `UNVERIFIED` / `CONTENT_MISMATCH` /
  `REPLAYED` / `STALE`, or the malicious input raised.
- **Documented limit** — the attack "succeeds" only in the sense that it reaches
  a boundary Inverba openly documents (e.g. an inclusion proof does not bind a
  corpus's total size). The record does not lie; the limit is disclosed. These
  are marked so a reader can judge them directly instead of taking a claim on
  faith. Naming a limit is the point — a provenance tool that oversells is worse
  than one that is precise about its edges.

A **finding** would be an attack that succeeds in a way the docs do not disclose.
There are none. If you find one, see "Try to break it" at the end.

---

## 1. Malicious-but-authentic fetcher

The signer's key is real; the signer lies about provenance. This is run first
because it is where a real product most plausibly leaks trust.

| Attack | Result |
|---|---|
| Relay a third party's fetch (`fetched_by != native`) as if first-hand | Rejected/flagged — the handoff verdict surfaces that the origin was not observed; `require_independent_observation` rejects it outright |
| Edit `fetched_by` from a relay label to `native` to launder a relay into a first-hand claim | Rejected — `fetched_by` is inside the signed payload; editing it breaks the signature |
| Sign a CAPTCHA / "just a moment…" interstitial (HTTP 200, junk body) as content | Flagged — the signature is valid, but the handoff verdict raises `suspected_block` from the signed metadata and the body |
| Present a signed redirect to a challenge endpoint with no body | Flagged — the signed `final_url` alone trips the bot-wall check |
| Hand fabricated content alongside a valid relay record | Rejected — `CONTENT_MISMATCH` (the relay label does not weaken content binding) |
| Self-corroborate with a second key held by the same operator (Sybil) | **Documented limit** — corroboration proves distinct *keys* signed and agreed on content; it does not, and cannot locally, prove the signers are independent real-world entities. Disclosed in the provenance docs. |

## 2. Replay & handoff

A valid record is a true statement about a *past* fetch. The attack is passing an
old true record off as a fresh observation.

| Attack | Result |
|---|---|
| Re-present a record a verifier already accepted | Rejected — `REPLAYED` (opt-in `SeenStore`) |
| Pre-seed a verifier's memory with a forged record to suppress a genuine one later | Rejected — a forged record is thrown out before the replay check and never recorded |
| Present a valid record with the wrong content, hoping to poison the replay cache | Rejected — `CONTENT_MISMATCH` returns before recording, so a later correct presentation still verifies |
| Slip a replay through by malleating the signature into a different string | Rejected — a malleated signature fails verification (canonical `S` enforced) before the replay check keys on it |
| Replay the same record to two independent verifiers | **Documented limit** — the in-memory store is per-verifier; fleet-wide defense needs a shared backend behind the same interface. Disclosed on `SeenStore`. |
| Replay after the cache TTL lapses | **Documented limit** — a TTL-bounded store forgets; disclosed on `SeenStore`. |

## 3. Canonicalization & encoding

Two distinct inputs collapsing to one signed payload, or a tampered record
verifying.

- An earlier signing-payload ambiguity (a delimiter-joined format where two
  different field tuples could produce identical signed bytes) is **closed**: the
  payload is canonical JSON with one keyed field each, so those tuples now sign
  differently.
- Tampering **any** signed field — URL, content hash, timestamp, status code,
  final URL, content type — breaks the signature. Bot-wall evidence (status,
  redirect) cannot be stripped after signing.
- Content is hashed as **raw bytes with no normalization**. NFC vs NFD encodings
  of the same text, a trailing byte, or a BOM produce different records. This is a
  **documented limit**: Inverba binds exact bytes, not semantic equivalence.
- A homoglyph URL (Cyrillic `а` vs Latin `a`) is a different byte string and
  signs differently — a **documented limit**: Inverba binds the exact URL;
  detecting visual confusability is out of scope.
- Invalid UTF-8 and empty content sign and verify without incident.

## 4. Signature malleability & crypto edge

Non-canonical `S` (`S+L`, `S+2L`, high-bit set), flipped bits, truncated,
oversized, empty, all-zero, and non-hex signatures are **all rejected**. A valid
signature lifted from one record does not verify another, even under the same
key. Wrong-length, non-hex, and mismatched public keys are rejected. The
canonical-`S` enforcement (RFC 8032) is what makes signature-keyed replay defense
safe.

## 5. Key-history & lifecycle

The distinction that matters: **rotation is not compromise.**

- A record signed **before** a routine rotation stays valid forever; the battery
  confirms rotation never invalidates honest history.
- A record signed **inside** a key's compromise window is rejected against the
  keyring; one signed **before** the window stays trusted.
- Unknown keys, records predating a key's creation, forged rotation
  authorizations, and revocations attested by an outside key are all caught by
  the keyring chain check. A self-attested compromise is **warned**, not silently
  trusted.
- **Documented limit:** without a keyring, verification checks only the signature
  math — a compromised-window record reads as trusted. Supplying the keyring is
  what upgrades the check to lifecycle-aware; this is disclosed.

## 6. URL / redirect / fetch-boundary (notary SSRF)

The notary fetches attacker-supplied URLs, so SSRF is critical. Defense validates
the **resolved address**, never a blacklist of URL string formats.

- Cloud-metadata, loopback, private, and link-local targets are blocked —
  including the decimal-encoded (`http://2852039166/`) and IPv4-mapped-IPv6 forms
  of the metadata address, because the resolved address is what is checked.
- A host resolving to **both** a public and a private address is blocked entirely.
- **Documented limit:** a residual DNS-rebinding TOCTOU window remains because the
  HTTP client re-resolves on connect. The validated IPs are returned so a caller
  that can connect-by-IP may pin and close it; where it cannot, network-layer
  egress controls are the backstop. Disclosed in the SSRF module.

## 7. Manifest / Merkle / corpus

RFC 6962-style tree. Tampering a leaf hash, an audit-path sibling, a path side, or
the root — and reusing a proof across trees — are **all rejected**. Domain
separation (leaves prefixed `0x00`, internal nodes `0x01`) blocks a second-preimage
attack that would pass a node off as a leaf. Empty and single-leaf roots are
well-defined.

- **Documented limit:** an inclusion proof proves a leaf is *in* a tree with a
  given root; it does not, by itself, bind the tree's total **size**. Binding
  size and append-only history is the job of a consistency proof against a
  published log, not a single inclusion proof. Disclosed.

## 8. Temporal / RFC 3161

- The temporal anchor hashes a record's **signature**, so backdating (which means
  re-signing) changes the anchor — an old timestamp token cannot cover a rewritten
  record.
- A record with no signature cannot be anchored; a manifest root that is not a
  32-byte digest is rejected; an unknown token format is rejected; a malformed
  token fails verification.
- **Documented limit:** an RFC 3161 timestamp proves a hash existed **at or
  before** the authority's time — an upper bound, never the exact observation
  time. `fetched_at` remains self-asserted. This is stated plainly, not glossed.

---

## Try to break it

The battery is the proof; this writeup is the narrative. Both are public.

- **Reproduce it:** `pytest inverba_core/tests/test_adversarial_battery.py`.
- **Extend it:** if you can write an attack the battery misses — a record that
  verifies when it should not, or a claim in the docs that turns out false — open
  an issue with a reproducing test. That is the most useful contribution possible
  to a provenance tool, and it is exactly what this document invites.

No bounty, no gate — the same message either way: a tool whose job is trust should
be the easiest one in your stack to check.
