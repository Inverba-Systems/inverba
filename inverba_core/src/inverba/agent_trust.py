"""
Agent-to-agent data trust (the novel layer).

The problem nobody has solved: as autonomous agents increasingly consume web
data to make decisions, agent B must trust data that agent A fetched -- without
having fetched it itself. Today the answer is "just believe agent A." Inverba's
answer is a verifiable one.

Flow:
    Agent A fetches a page with Inverba -> gets a signed provenance record.
    Agent A hands (data + record) to Agent B.
    Agent B calls verify_handoff(record, claimed_content) -> a verdict:
        - is the record's signature valid?
        - does the claimed content actually hash to what the record attests?
        - was it corroborated by independent workers?
        - how fresh is it?
    Agent B now trusts (or rejects) the data on cryptographic grounds, not faith.

This is designed for MACHINE consumption: structured verdicts, explicit trust
signals, no prose to parse. It serves all four verticals (a monitoring agent, a
compliance agent, a training-data agent, and a general research agent all need
to trust upstream data), which is why it's the horizontal capability under the
agent-to-agent beachhead.
"""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, asdict, field
from enum import Enum
from typing import Optional

from .provenance import verify_record, verify_with_corroborations
from .models import ProvenanceRecord


class TrustVerdict(str, Enum):
    TRUSTED = "trusted"              # valid sig + content matches + fresh enough
    TRUSTED_CORROBORATED = "trusted_corroborated"  # + independent workers agreed
    STALE = "stale"                  # valid but older than the caller's freshness bound
    CONTENT_MISMATCH = "content_mismatch"  # record is valid but doesn't describe THIS data
    REPLAYED = "replayed"            # valid record re-presented to a verifier that already saw it
    UNVERIFIED = "unverified"        # signature invalid / record forged
    NO_RECORD = "no_record"          # no provenance record supplied


@dataclass
class HandoffVerdict:
    verdict: str
    trusted: bool                     # simple boolean for quick agent branching
    signature_valid: bool
    content_matches: Optional[bool]
    corroborated: Optional[bool]
    corroborator_count: int
    age_seconds: Optional[float]
    url: Optional[str]
    reasons: list[str]
    # Who actually retrieved the bytes, and whether the signer observed the
    # origin itself. A relayed record ("this is what Firecrawl gave me") is a
    # weaker claim than a first-hand observation, and an agent deciding whether
    # to act on data deserves to know which it's holding.
    fetched_by: Optional[str] = None
    independent_observation: Optional[bool] = None
    # Bot-wall / soft-block signals. A record can be validly signed and describe
    # a CAPTCHA page (HTTP 200 with junk). These surface that so a verifier isn't
    # misled by a perfect signature over garbage.
    suspected_block: Optional[bool] = None
    block_confidence: Optional[str] = None
    block_signals: list = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


def verify_handoff(
    record: Optional[ProvenanceRecord],
    claimed_content: Optional[bytes] = None,
    *,
    max_age_seconds: Optional[float] = None,
    require_corroboration: bool = False,
    require_independent_observation: bool = False,
    keyring=None,
    seen=None,
    now: Optional[float] = None,
) -> HandoffVerdict:
    """
    The core agent-to-agent trust primitive. Given a provenance record (and,
    ideally, the actual bytes the record is supposed to describe), return a
    machine-actionable verdict.

    claimed_content: the data agent B actually received. If provided, we confirm
        the record genuinely describes THIS content (not just that the record is
        internally valid). This closes the "valid record for different data"
        attack -- an agent can't hand you a real record for page X alongside
        fabricated content for page Y.
    max_age_seconds: if set, records older than this are STALE.
    require_corroboration: if True, an uncorroborated (single-worker) record is
        not considered fully trusted.
    require_independent_observation: if True, reject records where the signer
        merely relayed a third-party fetch (fetched_by != "native") rather than
        observing the origin itself. Use when independence is the point.
    keyring: an optional KeyRing. When supplied, the signing key's LIFECYCLE is
        checked, not just its math -- a cryptographically perfect signature made
        by a key that was in an attacker's hands is rejected. Without a keyring
        we can only check the math, which is strictly weaker.
    seen: an optional SeenStore (see inverba.seen). When supplied, a record this
        verifier has already accepted is rejected as REPLAYED on re-presentation.
        A valid record is a true statement about a PAST fetch; replay defense
        stops an old one being passed off as a fresh observation. Opt-in, so
        default behavior is unchanged. Honest limits (per-verifier scope,
        TTL-bounded, advisory-not-malice) are documented on SeenStore.
    """
    now = now or time.time()
    reasons: list[str] = []

    def stamp(v: HandoffVerdict) -> HandoffVerdict:
        if record is not None:
            v.fetched_by = getattr(record, "fetched_by", "native")
            v.independent_observation = (v.fetched_by == "native")
            # Bot-wall check from the record's signed metadata (+ content if given).
            from .blockcheck import check_record_for_block
            bc = check_record_for_block(record, claimed_content)
            v.suspected_block = bc.is_suspicious
            v.block_confidence = bc.confidence
            v.block_signals = bc.signals
            if bc.is_suspicious and bc.signals:
                v.reasons = v.reasons + [
                    f"fetch may be a bot-wall/soft-block ({bc.confidence} confidence): "
                    f"{bc.signals[0]}"
                ]
        return v

    if record is None:
        return HandoffVerdict(
            verdict=TrustVerdict.NO_RECORD.value, trusted=False,
            signature_valid=False, content_matches=None, corroborated=None,
            corroborator_count=0, age_seconds=None, url=None,
            reasons=["no provenance record supplied; data is unverifiable"],
        )

    # 1. Signature.
    sig_ok = verify_record(record)
    if not sig_ok:
        return stamp(HandoffVerdict(
            verdict=TrustVerdict.UNVERIFIED.value, trusted=False,
            signature_valid=False, content_matches=None, corroborated=None,
            corroborator_count=len(record.corroborations),
            age_seconds=now - record.fetched_at, url=record.url,
            reasons=["provenance signature is invalid -- record forged or altered"],
        ))

    # 2. Content binding: does the record actually describe the data handed over?
    content_matches = None
    if claimed_content is not None:
        actual = hashlib.sha256(claimed_content).hexdigest()
        content_matches = (actual == record.content_hash)
        if not content_matches:
            return stamp(HandoffVerdict(
                verdict=TrustVerdict.CONTENT_MISMATCH.value, trusted=False,
                signature_valid=True, content_matches=False, corroborated=None,
                corroborator_count=len(record.corroborations),
                age_seconds=now - record.fetched_at, url=record.url,
                reasons=["record is validly signed but does NOT describe this content -- "
                         "possible bait-and-switch (real record, fabricated data)"],
            ))
        reasons.append("content hash matches the signed record")

    # 2.2 Key lifecycle. A signature can be mathematically perfect and still
    # untrustworthy, because the key was in an attacker's hands when it was
    # made. Only checkable when the caller supplies a keyring.
    if keyring is not None:
        from .keys import verify_record_with_keyring
        key_trust = verify_record_with_keyring(record, keyring)
        if not key_trust.trusted:
            return stamp(HandoffVerdict(
                verdict=TrustVerdict.UNVERIFIED.value, trusted=False,
                signature_valid=True, content_matches=content_matches,
                corroborated=None, corroborator_count=len(record.corroborations),
                age_seconds=now - record.fetched_at, url=record.url,
                reasons=reasons + key_trust.reasons,
            ))
        reasons.extend(key_trust.reasons)

    # 2.5 Observation vs relay. If the signer merely relayed a third party's
    # fetch, they did not observe the origin -- surface it, and reject if the
    # caller demanded independence.
    fetched_by = getattr(record, "fetched_by", "native")
    if fetched_by != "native":
        reasons.append(
            f"signer did not observe the origin -- bytes were retrieved by "
            f"'{fetched_by}' and relayed; this attests only to what {fetched_by} returned"
        )
        if require_independent_observation:
            return stamp(HandoffVerdict(
                verdict=TrustVerdict.UNVERIFIED.value, trusted=False,
                signature_valid=True, content_matches=content_matches,
                corroborated=None, corroborator_count=len(record.corroborations),
                age_seconds=now - record.fetched_at, url=record.url,
                reasons=reasons + ["caller requires an independent observation"],
            ))

    # 3. Corroboration.
    corr = verify_with_corroborations(record)
    corroborated = corr["corroborations_agree"] if corr["corroboration_count"] > 0 else False
    corr_count = corr["corroboration_count"]
    if require_corroboration and not corroborated:
        return stamp(HandoffVerdict(
            verdict=TrustVerdict.UNVERIFIED.value, trusted=False,
            signature_valid=True, content_matches=content_matches, corroborated=False,
            corroborator_count=corr_count, age_seconds=now - record.fetched_at, url=record.url,
            reasons=["caller requires corroboration but record is single-source/uncorroborated"],
        ))

    # 4. Freshness.
    age = now - record.fetched_at
    if max_age_seconds is not None and age > max_age_seconds:
        return stamp(HandoffVerdict(
            verdict=TrustVerdict.STALE.value, trusted=False,
            signature_valid=True, content_matches=content_matches,
            corroborated=corroborated, corroborator_count=corr_count,
            age_seconds=age, url=record.url,
            reasons=[f"record is {age:.0f}s old, exceeds caller's freshness bound "
                     f"of {max_age_seconds:.0f}s"],
        ))

    # 5. Replay. A record can be valid, matching, and fresh, and STILL be a
    # re-presentation of one this verifier already accepted. Only checkable when
    # the caller supplies a SeenStore; keyed on the signature (unique per record,
    # and authentic by this point). Keying on the signature is safe because
    # verify_record enforces Ed25519 canonical S (RFC 8032: S < L), so a
    # malleated variant of a valid signature cannot verify under a different key
    # and thus cannot slip a replay past this check. That invariant is pinned by
    # test_malleated_signature_rejected_keeps_seen_key_stable. Recorded only on
    # acceptance, so rejected records never poison the store. Opt-in -- callers
    # without a store are unaffected.
    if seen is not None and record.signature:
        if seen.seen(record.signature):
            return stamp(HandoffVerdict(
                verdict=TrustVerdict.REPLAYED.value, trusted=False,
                signature_valid=True, content_matches=content_matches,
                corroborated=corroborated, corroborator_count=corr_count,
                age_seconds=age, url=record.url,
                reasons=reasons + [
                    "this record has already been presented to this verifier -- "
                    "replayed; it is a true record of a past fetch, not a fresh "
                    "observation"],
            ))
        seen.record(record.signature)

    # Trusted. Corroborated is the stronger grade.
    if corroborated:
        reasons.append(f"{corr_count} independent worker(s) corroborated the content")
        verdict = TrustVerdict.TRUSTED_CORROBORATED
    else:
        verdict = TrustVerdict.TRUSTED

    return stamp(HandoffVerdict(
        verdict=verdict.value, trusted=True,
        signature_valid=True, content_matches=content_matches,
        corroborated=corroborated, corroborator_count=corr_count,
        age_seconds=age, url=record.url, reasons=reasons,
    ))
