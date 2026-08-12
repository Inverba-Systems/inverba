# Inverba Security & Trust Model

This document states plainly what Inverba's trust and corroboration layer
does and does **not** guarantee. It exists because the honest failure mode
for a "verifiable, multi-party" system is implying stronger guarantees than
the design actually provides. We would rather under-claim.

## Reporting a vulnerability

Email **Info@inverba.dev** with the details and, if you have one, a proof of
concept. Please report privately first rather than opening a public issue, and
allow a reasonable window to ship a fix before public disclosure. This is an
early, solo-built project; security reports are taken seriously and credited if
you'd like.

## Adversarial battery

An adversarial test battery runs a suite of attacks against everything described
below — signature malleability, replay, canonicalization, key-lifecycle, notary
SSRF, Merkle, and temporal abuse — and reports each result, including the
boundaries that land on an already-documented limit. See
**[SECURITY-BATTERY.md](SECURITY-BATTERY.md)**. It is reproducible:
`pytest inverba_core/tests/test_adversarial_battery.py`.

## What provenance guarantees (strong)

Ed25519 signatures over `(url, content_hash, fetched_at)` are
cryptographically sound. If a provenance record verifies against a public
key, then the holder of that key's **private** key signed exactly that
claim. This is not an assumption — it is standard public-key cryptography.

A third party can verify any record with only the public key and a standard
Ed25519 implementation. No trust in Inverba required.

**Limit:** a valid signature proves *who signed* and *that the bytes hash to
this value*. It does **not** prove the worker fetched honestly, that the
content is truthful, or that the URL wasn't serving that worker manipulated
content. Signatures bind identity to a claim; they don't make the claim
true.

## What corroboration guarantees (conditional)

When multiple workers fetch the same URL and their **semantically
normalized** content agrees, you get evidence that independent parties
observed the same content. The trust scorer rewards agreement and penalizes
being the outlier.

This is only as strong as its assumptions, stated here explicitly:

### Assumption 1: Honest majority among corroborating workers

Corroboration uses majority agreement on normalized content hash. **If an
adversary controls a majority of the workers assigned to a URL, they can
make a lie look like consensus.** Inverba is **not** Byzantine-fault-tolerant
in the formal sense. It assumes that, among the workers corroborating a
given URL, more than half are honest.

Mitigations that raise the bar (but do not eliminate the assumption):
- Unproven workers are always paired with **proven** corroborators, so a new
  worker cannot unilaterally establish "truth."
- Trust is earned slowly (+3 per agreement) and lost fast (-8 per
  disagreement), so a worker must behave honestly for a sustained period
  before it carries weight.
- Corroborators are drawn preferentially from the proven pool.

### Assumption 2: Sybil resistance is external

Nothing in the core stops an adversary from generating many keypairs and
registering many workers (a Sybil attack). Worker identity is just an
Ed25519 key; keys are free.

Inverba's answer is **deliberately not** proof-of-work or stake (those
conflict with the sovereign/local-first ethos). Instead, Sybil resistance
is an **operator policy** decision at the registry boundary:
- In a **private swarm** (the common case — your own workers), you
  control who registers. Sybil is a non-issue; you admit workers you run.
- In an **open swarm**, the registry operator must gate admission (invite,
  vouching, out-of-band identity, rate limits). Inverba provides the trust
  mechanics; it does not provide open-enrollment Sybil resistance out of the
  box, and does not pretend to.

We surface this rather than bury it: an open, permissionless Inverba swarm
with no admission control is **not** secure against a resourced adversary.
A private or admission-controlled swarm is.

### Assumption 3: Corroboration detects divergence, not intent

The cloaking detector reports that workers saw different content and how
different. It **cannot alone** tell benign personalization/A-B testing apart
from malicious cloaking — that needs context (were the workers meant to be
equivalent? different geos? logged-in vs anonymous?). Reports carry an
explicit confidence level and never claim certainty. The verdict
`suspected_cloaking` is a signal for human review, not a proof.

## Semantic normalization: reduces false positives, not zero

Normalization strips volatile scaffolding (nonces, timestamps, tracking
params, build hashes) so honest workers aren't flagged for trivial byte
differences. This dramatically reduces false disagreement, but:

- Aggressive personalization (per-user content, not just per-user tokens)
  will still normalize differently. That is correctly surfaced as MATERIAL
  variation — a real signal, not a bug.
- Normalization is heuristic. It can over-strip (hiding a real change) or
  under-strip (surfacing a non-change). The spectrum + confidence framing is
  designed so these degrade gracefully rather than producing false
  certainty.

## Registry integrity (commercial layer)

The hosted verification registry stores records durably. In the reference
implementation it is a database; the transparency-log upgrade (append-only
Merkle log, Certificate-Transparency style) is what makes the registry
itself tamper-evident. Until that ships, the registry operator is trusted to
not alter stored records. This is called out as a known gap, not glossed.

## Notary SSRF posture (hosted notary — NOT production-ready yet)

A word on the term: Inverba's "notary" (and any talk of "notarizing" a fetch) means
**cryptographic attestation, not legal notarization**. No authority certifies that
the *content is true* — only that a specific identity attested to *observing* it.
"Notary" is the component name; it corroborates an observation, it does not
certify facts.

The optional notary fetches user-supplied URLs from Inverba-operated
infrastructure, so it is an SSRF target. The code-level vectors are closed:
address validation resolves the hostname and rejects any resolved
private/loopback/link-local/reserved/multicast/metadata address (IPv4, IPv6,
IPv4-mapped) rather than blacklisting URL string formats; this runs once up front
before ANY outbound (including the robots.txt preflight), redirects are followed
hop-by-hop with per-hop validation, and the notary forces redirect-disabled
fetching so it can't be made unsafe by an engine's config.

**One residual remains and is not yet closed:** a DNS-rebinding TOCTOU window
between our resolution check and the HTTP client's connect-time re-resolution.
Closing it requires connection-pinning (connect-by-IP) or network-layer egress
controls at deploy time. **Until that lands, the hosted notary is gated and not
production-ready.** Local, offline use (signing + offline verification) does not
involve the notary and is unaffected.

## Replay defense (agent handoffs)

A provenance record is a *true statement about a past fetch*. Its validity does
not expire when the record is re-used: a holder can present the same valid record
again, later, in a new context, as if it were a fresh observation.
`verify_handoff` on its own verifies a record's intrinsic validity and cannot
know it has seen that record before.

Passing a `SeenStore` (see `inverba.seen`) gives a verifier that memory: a record
presented a second time returns the `REPLAYED` verdict (`trusted=False`). This is
**opt-in** — callers that supply no store keep the prior behavior. Its limits,
stated in the same register as the rest of this model:

- **Per-verifier scope.** The in-memory store stops replay to the *same*
  verifier, not across a fleet — two independent verifiers each accept the record
  once. A shared backend (e.g. Redis) behind the same interface widens the scope.
- **Bounded by cache lifetime.** With a TTL configured, a record replayed after
  the TTL lapses is no longer remembered and will not be flagged.
- **`REPLAYED` is advisory, not proof of malice.** A replayed record is still a
  genuine record of what was fetched. The property it defends is *freshness of
  observation* — it stops an old, true record from being passed off as a new one.

Cross-verifier, one-time-use binding (a verifier-issued challenge the record must
commit to) is deliberately **not** in the offline core; it is future work for the
hosted enforcement layer, where shared state already exists.

## Summary table

| Claim | Strength | Depends on |
|---|---|---|
| "This key signed this content hash" | Cryptographic | Ed25519 soundness only |
| "This handoff hasn't been replayed to me" | Conditional | A `SeenStore` is supplied; per-verifier, TTL-bounded (see above) |
| "...at this claimed time (`fetched_at`)" | Self-asserted | Signer's honesty + clock; the signature proves the *claim* was signed, not that the time is true. A notary corroboration or external timestamp authority is what anchors time. |
| "Independent workers agreed on content" | Conditional | Honest majority among corroborators |
| "This worker is trustworthy" | Heuristic | Sustained corroboration history |
| "This site is cloaking" | Signal, not proof | Human judgment + worker context |
| "The registry hasn't been altered" | Operator-trusted (today) | Transparency log (future) closes this |

## Design principle

Where a guarantee is cryptographic, we say so. Where it rests on an
assumption, we name the assumption. Where it's a heuristic signal, we label
confidence and refuse to claim certainty. A security story that over-promises
is worse than one that under-promises, because users build on what you claim.
