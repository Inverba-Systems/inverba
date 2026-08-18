# Inverba Record Format, version 1 (IRF/1)

**Status:** IRF/1 is the **target wire format** for Inverba records — the long-term,
`COSE_Sign`-based envelope defined below — with a **Rust reference implementation**
(`inverba-core-rs`) verified against the normative test vectors.

**What ships today is not yet IRF/1.** The current Python package
(`pip install inverba`) produces a simpler record: a canonical-JSON payload signed
with raw Ed25519. IRF/1 is the format the project is migrating to; the record format
is a provenance system's ABI, so it is settled first — in this document, with test
vectors — and the implementation is fitted to it (see §0). Until the Python core
emits IRF/1, read this as the *specification of record*, not a description of the
current `inverba-core` wire format.

**Date:** 25 July 2026
**Normative test vectors:** `vectors.json`, reproduced independently by `reference_check.py`

Key words MUST, MUST NOT, SHOULD, MAY are per RFC 2119.

---

## 0. Why this document exists before the code

The record format is the ABI of a provenance system. Once a third party signs an
evidentiary record with IRF/1, that format must be verifiable for as long as the
record has value — which for the buyers Inverba is aimed at means decades. A
format break is indistinguishable from data loss for an archive.

So the format gets settled first, in a document, with test vectors, and the
implementation is fitted to it. Not the other way around.

Two consequences shape every decision below:

1. **Nothing is invented that a standard already covers.** The envelope is COSE
   (RFC 9052), the encoding is deterministic CBOR (RFC 8949 §4.2.1), the tree is
   RFC 6962, the algorithm identifiers come from the IANA COSE registry. Inventing
   any of these would mean maintaining them, and being illegible to every
   procurement process that already speaks them.
2. **Every extension point that will be needed later exists now.** Post-quantum
   co-signatures, third-party witnesses, and RFC 4998 re-timestamping are all the
   *same mechanism* — an additional entry in the COSE signatures array — so none
   of them requires a version bump when it ships.

---

## 1. What a record claims, and what it does not

This is the most important section in the document.

An IRF record asserts exactly this:

> The holder of key *K*, identifying itself as observer *O*, states that at time
> *T* it retrieved *L* bytes from URI *U*, and that those bytes hash to *H*.

It does **not** assert:

- that the origin server genuinely served those bytes;
- that the bytes were unmodified in transit by anything between origin and observer;
- that *O* is honest, or that *O* is who it says it is beyond control of *K*;
- that *U* resolved to any particular host.

A digital signature cannot establish any of those. Signing proves *integrity
since capture*, never *fidelity to source*. Anyone evaluating Inverba for
evidentiary use will find this gap in the first conversation, so the format
states it in the signed payload itself: the `scope` field travels with every
record and cannot be dropped by restating the marketing.

Fidelity is strengthened — never proved — by mechanisms outside the signature:
independent witnesses observing the same URI (§7), external timestamp anchoring
(§9), and transparency-log inclusion. Each raises the cost of a false record.
None converts an observation into a proof of what the origin served.

---

## 2. Encoding: the dCBOR profile

All IRF byte strings are deterministic CBOR per RFC 8949 §4.2.1, **restricted**
further as follows. Encoders MUST NOT emit, and decoders MUST reject:

| Forbidden | Rationale |
|---|---|
| Floating-point (major 7, ai 25/26/27) | IEEE-754 normalisation — negative zero, exponent boundaries, NaN payloads — is the most error-prone part of any canonicalisation implementation. IRF has no need for floats. The bug class is removed rather than managed. |
| Semantic tags (major 6) | A second interpretation layer over identical bytes. |
| Indefinite-length items (ai 31) | Multiple encodings of one value. |
| `undefined` (major 7, ai 23) | No meaning in this format. |
| Non-minimal integer heads | `0x18 0x05` and `0x05` would otherwise both mean 5. |
| Unsorted or duplicated map keys | See below. |
| Trailing bytes after the top-level item | Prevents smuggling. |

Map keys MUST be sorted ascending by their **encoded bytes**, bytewise. Note the
consequence, which trips up most implementations: `"z"` sorts *before* `"aa"`,
because the length is part of the head byte. Integer keys sort before text keys
for the same reason. See vector `map_key_order_by_encoded_bytes`.

**Decoders MUST reject non-canonical input rather than re-canonicalising it.**
Re-canonicalising attacker-supplied bytes is precisely how "same bytes, different
meaning" bugs are born: the verifier ends up checking a signature over bytes the
signer never produced.

Decoders MUST enforce a nesting-depth limit (RECOMMENDED 32) and MUST reject a
declared array or map length exceeding the remaining input length.

---

## 3. Domain separation

Every signature is bound to exactly one context. The context tag is carried in
the COSE `external_aad` field, which is the idiomatic COSE mechanism and is
length-delimited by CBOR's own `bstr` encoding — so there is no delimiter to
inject and no ambiguity about field boundaries.

| Domain | Tag (ASCII) |
|---|---|
| Record | `inverba/1/record` |
| Manifest | `inverba/1/manifest` |
| Anchor | `inverba/1/anchor` |
| Witness | `inverba/1/witness` |
| Renewal | `inverba/1/renewal` |

Tags include the format major version, so an IRF/2 signature can never collide
with an IRF/1 one. Verifiers MUST reject an unrecognised tag. Tags MUST NOT be
treated as extensible by deployment: a private tag is a fork of the format.

Merkle hashing uses the RFC 6962 prefixes: `0x00` for leaves, `0x01` for internal
nodes (§8).

---

## 4. Envelope: `COSE_Sign`

IRF uses `COSE_Sign` — the **multi-signer** variant — even when there is exactly
one signature.

```cddl
IRF_Envelope = [
  protected   : bstr .cbor irf_body_header,
  unprotected : {},                          ; MUST be empty
  payload     : bstr,                        ; dCBOR claim set, §6
  signatures  : [1*64 IRF_Signature]
]

IRF_Signature = [
  protected   : bstr .cbor irf_signer_header,
  unprotected : {},                          ; MUST be empty
  signature   : bstr .size (1..)
]

irf_body_header   = { "irf" => [major : uint, minor : uint] }
irf_signer_header = { 1 => int,               ; alg, IANA COSE Algorithms
                      4 => bstr .size (1..) } ; kid
```

Rationale for `COSE_Sign` over `COSE_Sign1`, which is what C2PA uses: a format
that starts single-signer and later grows a second signer has to change shape,
which is a v1→v2 break in an archive that exists to outlive breaks. Starting
multi-signer costs a handful of bytes and buys hybrid signatures, witnesses, and
timestamp renewal with no future break. IRF remains a compatible superset of the
`COSE_Sign1` shape C2PA expects for interop purposes.

The unprotected header MUST be empty in both positions. An unprotected header is
by definition unauthenticated; permitting content there invites a downgrade.

The signed preimage is the standard COSE `Sig_structure`:

```
Sig_structure = [
  "Signature",        ; context, fixed
  body_protected,     ; bstr
  sign_protected,     ; bstr
  external_aad,       ; bstr = domain tag from §3
  payload             ; bstr
]
```

There MUST be exactly one preimage-construction routine in an implementation,
shared by signer and verifier. Two routines drift; one cannot.

---

## 5. Algorithms

### 5.1 Signature algorithms

Values are IANA COSE Algorithms registry codepoints. ML-DSA is permanently
registered with Recommended status, so these are real identifiers, not
private-use placeholders needing later migration.

| Algorithm | COSE `alg` | Public key | Signature | Role |
|---|---|---|---|---|
| Ed25519 (EdDSA) | `-8` | 32 B | 64 B | classical half of the hybrid pair |
| ML-DSA-44 | `-48` | 1312 B | 2420 B | optional, lower size cost |
| ML-DSA-65 | `-49` | 1952 B | 3309 B | **PQC half of the default pair** |
| ML-DSA-87 | `-50` | 2592 B | 4627 B | CNSA 2.0's mandated parameter set |

Reserved for the anchor tier, not implemented in v1.0 (§9): SLH-DSA and
LMS/XMSS. The codepoint slot exists; the implementation is deferred. Note that
CNSA 2.0 does **not** approve SLH-DSA for national security systems while
civilian guidance does permit it as a hash-based fallback — so a defence-adjacent
deployment needs ML-DSA-87 or LMS/XMSS at the anchor, not SLH-DSA.

Verifiers MUST reject an unknown `alg` value. They MUST NOT skip an
unrecognised signer and continue: skipping is how a hybrid policy silently
degrades into no policy at all.

### 5.2 Content-hash algorithms

RFC 9054 codepoints: SHA-256 `-16`, SHA-384 `-43`, SHA-512 `-44`. The algorithm
identifier is carried in the signed payload, so a future migration to a stronger
hash does not require a format change.

### 5.3 Signature policy — the hybrid semantic

A verifier is configured with a policy naming required algorithms. The default
IRF/1 policy is `RequireAll([Ed25519, ML-DSA-65])`.

**`RequireAll` means all of them must be present and verify.** A verifier that
accepts *either* half of a hybrid pair is strictly **weaker** than either
primitive used alone, because an attacker simply presents whichever one is
broken. This is the single most dangerous misimplementation available in this
spec, and it is why the policy type has no "any-of" variant.

Additionally: **any signature present in the envelope MUST verify, whether or not
the policy required it.** An envelope carrying a broken signature is not a valid
envelope. Tolerating extra failing signatures gives an attacker a free probing
channel.

Rationale for hybridisation rather than PQC alone: ANSSI requires it, BSI and UK
NCSC favour it, and the IETF composite-signature work exists because the security
argument is dual — a break of *either* primitive alone does not yield a forgery.
Against that, NIST IR 8547 deprecates RSA and ECC in 2030 and disallows them in
2035, so a classical-only archive signed today is already on a clock. A
provenance record whose whole value is decades-long non-repudiation MUST NOT ship
classical-only by default.

---

## 6. Payload claim sets

### 6.1 Observation (domain `record`)

```cddl
observation = {
  "uri"         => tstr .size (1..),
  "hash_alg"    => int,          ; §5.2
  "hash"        => bstr .size (1..),
  "len"         => uint,
  "media_type"  => tstr,
  "observed_at" => uint,         ; seconds since Unix epoch, UTC
  "observed_by" => bstr .size (1..),
  "scope"       => tstr          ; "observation" in v1
}
```

Encoded map-key order follows §2, which for this key set is:
`hash`, `hash_alg`, `len`, `media_type`, `observed_at`, `observed_by`, `scope`,
`uri`. See vector `record.payload` (166 bytes for the reference fixture).

`scope` is mandatory and carries the §1 limitation inside the signature.

### 6.2 Manifest (domain `manifest`)

```cddl
manifest = {
  "root"       => bstr .size 32,
  "size"       => uint .gt 0,
  "created_at" => uint
}
```

`root` and `size` are bound together inside the signed bytes. This is
load-bearing: see §8 for why `size` alone proves nothing at proof-verification
time, and why the authoritative `size` must come from here.

### 6.3 Anchor, witness, renewal

Reserved. Their domain tags are allocated and their envelope shape is identical;
their claim sets are not specified in v1.0. Implementations MUST reject payloads
under these domains until specified, rather than accepting an unvalidated shape.

---

## 7. Witnesses — a trust list, not consensus

Multiple parties may independently observe the same URI and co-sign. Each is an
additional entry in the signatures array with its own `kid`.

**IRF makes no consensus claim and provides no Sybil resistance.** It cannot: the
format has no way to establish that two witness keys are operated by independent
parties. Independence is a *deployment* property, and in a self-hosted
product it is exactly the property that cannot be assumed.

The model is therefore Certificate Transparency's, not a Byzantine agreement
protocol's. The verifier holds a local list of witness keys it is willing to
believe and a threshold; quorum is the verifier's policy decision, not a protocol
guarantee. Distinct `kid` values count once each — two signatures from one key are
one witness.

Implementations and marketing MUST NOT use the words "consensus", "quorum",
"Byzantine", or "trustless" to describe this. An undefined consensus claim is a
liability, not a feature: it is the first thing an adversarial reviewer will ask
you to formalise, and there is no formalisation available.

---

## 8. Merkle trees

RFC 6962 / RFC 9162 construction:

```
MTH({})   = SHA-256()
MTH({d0}) = SHA-256(0x00 || d0)
MTH(D[n]) = SHA-256(0x01 || MTH(D[0:k]) || MTH(D[k:n]))
            where k = largest power of two STRICTLY less than n
```

Three properties, each addressing a documented historical failure:

- **Leaf/node domain separation** (`0x00`/`0x01`) prevents presenting an internal
  node as a leaf — the flaw hit by early OpenZeppelin implementations and several
  IPFS variants.
- **No lonely-leaf duplication.** The RFC 6962 split binds tree shape to `n`.
  Bitcoin duplicates an odd trailing node, which is CVE-2012-2459: two distinct
  leaf multisets yield one root. Impossible here.
- **`(root, size)` is one commitment.** Every proof API takes `size`.

`k` is the largest power of two **strictly** less than `n`. Computing it from the
high bit of `n` rather than `n - 1` returns `n` itself for powers of two, which
makes the tree recursion split into (everything, nothing) and never terminate.
This was a live bug in the reference implementation, caught by the consistency
test as a stack overflow. Implementations SHOULD include a test asserting
`split_point(8) == 4`.

### 8.1 Inclusion proofs — a stated limitation

Audit paths are emitted **leaf-to-root**. Verifiers must therefore record the
descent decisions from the root down, then replay them in reverse against the
proof. Consuming the proof root-first is a natural and silent error; the vectors
in `merkle[]` catch it.

`size` selects the audit-path *shape*, and distinct sizes can produce the same
shape for a given index — index 3 in trees of size 7 and 8 both take
`[left, right, right]`. An honest proof therefore verifies under either claimed
size.

**This is not a forgery**, because the proof still resolves to the same `root`,
and a root commits to one leaf multiset. But it means `size` prevents nothing on
its own. The actual protection is that `size` is bound to `root` inside the
signed manifest (§6.2). **Verifiers MUST take `size` from the signed manifest and
MUST NOT accept it from an untrusted caller.** Do not claim that `size` prevents
cross-tree proof reuse; it does not.

### 8.2 Consistency proofs

Inclusion proofs alone let an operator silently rewrite history by publishing a
fresh tree. Consistency proofs (RFC 6962 §2.1.2) are what make the log
append-only, which is the property an evidentiary archive actually needs.
Implementations MUST provide them, not only inclusion proofs.

The binding that matters when verifying is `reconstructed_root_n == root_n`,
where `root_n` came from a signed manifest. Collision resistance of SHA-256 is
what prevents an attacker choosing a bogus `root_m` that still chains to `root_n`.

### 8.3 Anchoring

**A Merkle root that is not independently anchored proves nothing about time.**
An inclusion proof against a root you also control is a statement about your own
bookkeeping. Anchoring is therefore not optional for evidentiary use:

- multiple independent RFC 3161 TSAs (single-TSA trust is a single point of failure);
- a public transparency log or OpenTimestamps, which additionally stops *you*
  from backdating and is the cheapest large credibility gain available;
- RFC 4998 Evidence Record Syntax timestamp renewal and hash-tree renewal, so
  the archive survives the eventual weakening of SHA-256 and Ed25519.

v1.0 defines the envelope slot for these (§6.3) and does not implement renewal.
That deferral is safe **only** because the multi-signer envelope means renewal
adds signers rather than changing shape.

---

## 9. Verification rules (normative)

A verifier MUST return one of exactly two results. There is no third state, no
"valid but", and no default-allow path. The result type SHOULD NOT be a boolean,
so that no defaulted or zero-initialised value is truthy.

A verifier MUST return INVALID if any of the following holds:

1. The input is not canonical per §2, at any nesting level.
2. There are trailing bytes.
3. The envelope shape does not match §4 exactly, including non-empty unprotected headers.
4. `major` in the body header is not a version this build implements. Unknown majors are refused, never best-effort parsed.
5. The signatures array is empty, or exceeds the implementation limit.
6. Any signer header is missing `alg` or `kid`, or `kid` is empty.
7. Any `alg` is not implemented by this build.
8. **Any** signature present fails to verify.
9. A required algorithm per policy is absent.
10. An observer `kid` is not in the trust list, where one is configured.
11. The count of distinct trusted witness `kid`s is below the configured threshold.
12. The `external_aad` domain does not match the context the caller is verifying for.
13. Any parse, arithmetic, or allocation error occurs anywhere.

Error reporting: the reason for INVALID MUST NOT cross a trust boundary.
Distinguishing "malformed" from "bad signature" to an untrusted caller is an
oracle. Implementations SHOULD carry a detailed reason internally for operator
tooling and tests, and expose a single opaque value remotely.

Verifiers MUST bound their own work: cap signer count, proof length, nesting
depth, and total input size before doing cryptographic work.

---

## 10. Versioning and migration

`major` bumps are hard breaks; a verifier MUST refuse an unknown major.

`minor` bumps are additive only. Unknown fields in the core claim sets of §6 MUST
be rejected, not ignored. "Ignore what you don't recognise" is a footgun in a
signature format: it lets an attacker add a field that a *newer* verifier treats
as meaningful while an older one silently discards, and both call it VALID.
Extension data, when it is specified, will live in an explicitly-marked extension
map with defined ignore semantics — not scattered through the claim set.

Algorithm migration does **not** require a version bump, by design: add the new
`alg` to the registry table in §5, add signers for it, and tighten the policy.
Records already signed remain verifiable, because the algorithm identifier is
inside each signer's protected header.

---

## 11. Conformance

An implementation conforms to IRF/1 if it reproduces every vector in
`vectors.json` byte-for-byte, rejects every input in `dcbor_must_reject`, and
satisfies every MUST in §9.

The reference set is currently reproduced by two independent implementations —
the Rust core and `reference_check.py`, written separately against this document —
agreeing on 63 checks including a 1328-mutation single-bit tamper sweep with zero
survivors. A format spec that only one implementation has ever satisfied has not
been tested; it has been described.

---

## 12. Deliberate non-goals

Stated here so they are not mistaken for oversights:

- **No encryption.** IRF signs; it does not conceal. Confidentiality is a
  transport and storage concern.
- **No key distribution or PKI.** A self-hosted deployment has no
  trusted CA by construction. Trust roots are self-anchored and distributed out
  of band, which makes the anchor key and its external corroboration the entire
  trust foundation. This is a real limitation, not a feature.
- **No revocation semantics in v1.** Key rotation MUST NOT invalidate previously
  signed records — that would destroy the archive, which is the opposite of the
  product's purpose. This is exactly why ERS re-timestamping (§8.3) is the
  mechanism for aging keys rather than revocation.
- **No content parsing, no network I/O, no proof of fidelity to origin.** See §1.
