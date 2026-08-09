"""
Tests for key lifecycle -- rotation, revocation, compromise windows.

This module existed untested. Untested cryptographic code is assumed broken
until proven otherwise, so these are written to ATTACK it, not to confirm it.

The property that matters most: a compromised key does not retroactively
invalidate the honest work it did before the compromise. Getting that wrong in
either direction is a real failure -- too strict destroys genuine evidence, too
loose trusts an attacker's signatures.
"""

import json
import time

import pytest

from inverba.provenance import ProvenanceSigner
from inverba.models import FetchResult, FetchMethod
from inverba.keys import (
    KeyRing, KeyEntry, Revocation, RevocationReason, KeyStatus,
    verify_record_with_keyring, _verify_sig,
)


def rec(signer, at, url="https://example.com/p"):
    fr = FetchResult(url=url, final_url=url, status_code=200,
                     content=f"<html>{at}</html>".encode(), content_type="text/html",
                     method=FetchMethod.HTTP, fetched_at=at)
    return signer.sign(fr)


T0 = 1_000_000.0
DAY = 86400.0


@pytest.fixture
def ring():
    return KeyRing("worker-a")


# ---- roots and unknown keys ----

def test_root_key_is_active(ring):
    s = ProvenanceSigner.generate()
    entry = ring.add_root(s, created_at=T0)
    assert entry.status == KeyStatus.ACTIVE
    assert entry.trusted_at(T0 + DAY) is True


def test_record_predating_key_creation_is_rejected(ring):
    """Backdating defence: a record cannot precede the key that signed it."""
    s = ProvenanceSigner.generate()
    ring.add_root(s, created_at=T0)
    r = rec(s, T0 - DAY)          # signed "before" the key existed
    trust = verify_record_with_keyring(r, ring)
    assert trust.signature_valid is True     # math is fine...
    assert trust.trusted is False             # ...but the lifecycle says no


def test_unknown_key_is_not_trusted_but_not_called_forged(ring):
    s = ProvenanceSigner.generate()
    r = rec(s, T0)
    trust = verify_record_with_keyring(r, ring)   # key never registered
    assert trust.signature_valid is True
    assert trust.key_known is False
    assert trust.trusted is False
    assert "unknown identity" in " ".join(trust.reasons)


def test_forged_record_fails_before_lifecycle_is_consulted(ring):
    s = ProvenanceSigner.generate()
    ring.add_root(s, created_at=T0)
    r = rec(s, T0 + DAY)
    r.signature = "00" * 64
    trust = verify_record_with_keyring(r, ring)
    assert trust.signature_valid is False
    assert trust.trusted is False


# ---- rotation: must NOT invalidate history ----

def test_rotation_preserves_old_records(ring):
    old, new = ProvenanceSigner.generate(), ProvenanceSigner.generate()
    ring.add_root(old, created_at=T0)
    old_record = rec(old, T0 + DAY)
    ring.rotate(old, new, at=T0 + 2 * DAY)

    trust = verify_record_with_keyring(old_record, ring)
    assert trust.trusted is True, "rotation must not invalidate prior honest work"
    assert "remains valid" in " ".join(trust.reasons)


def test_rotated_key_marked_rotated_not_revoked(ring):
    old, new = ProvenanceSigner.generate(), ProvenanceSigner.generate()
    ring.add_root(old, created_at=T0)
    ring.rotate(old, new, at=T0 + DAY)
    assert ring.find(old.public_key_hex()).status == KeyStatus.ROTATED
    assert ring.find(new.public_key_hex()).status == KeyStatus.ACTIVE


def test_rotation_is_cross_signed_for_continuity(ring):
    """Both keys sign, proving the same party controls both."""
    old, new = ProvenanceSigner.generate(), ProvenanceSigner.generate()
    ring.add_root(old, created_at=T0)
    entry = ring.rotate(old, new, at=T0 + DAY)
    assert entry.predecessor == old.public_key_hex()
    assert entry.predecessor_signature
    assert entry.successor_signature

    from inverba.keys import _rotation_payload
    payload = _rotation_payload(old.public_key_hex(), new.public_key_hex(), T0 + DAY)
    assert _verify_sig(old.public_key_hex(), entry.predecessor_signature, payload)
    assert _verify_sig(new.public_key_hex(), entry.successor_signature, payload)


def test_forged_rotation_proof_does_not_verify(ring):
    old, new = ProvenanceSigner.generate(), ProvenanceSigner.generate()
    ring.add_root(old, created_at=T0)
    entry = ring.rotate(old, new, at=T0 + DAY)
    entry.predecessor_signature = "00" * 64
    from inverba.keys import _rotation_payload
    payload = _rotation_payload(old.public_key_hex(), new.public_key_hex(), T0 + DAY)
    assert _verify_sig(old.public_key_hex(), entry.predecessor_signature, payload) is False


def test_cannot_rotate_unknown_key(ring):
    old, new = ProvenanceSigner.generate(), ProvenanceSigner.generate()
    with pytest.raises(ValueError):
        ring.rotate(old, new)      # old was never added


def test_cannot_rotate_already_revoked_key(ring):
    old, new = ProvenanceSigner.generate(), ProvenanceSigner.generate()
    ring.add_root(old, created_at=T0)
    ring.revoke(old.public_key_hex(), RevocationReason.COMPROMISED,
                effective_at=T0 + DAY, attesting_signer=old)
    with pytest.raises(ValueError):
        ring.rotate(old, new, at=T0 + 2 * DAY)


# ---- compromise: the window is the whole point ----

def test_records_before_compromise_stay_trusted(ring):
    """Two years of honest work is not erased by a theft on Tuesday."""
    s = ProvenanceSigner.generate()
    ring.add_root(s, created_at=T0)
    honest = rec(s, T0 + 10 * DAY)
    ring.revoke(s.public_key_hex(), RevocationReason.COMPROMISED,
                effective_at=T0 + 100 * DAY, attesting_signer=s)

    trust = verify_record_with_keyring(honest, ring)
    assert trust.trusted is True


def test_records_after_compromise_are_suspect(ring):
    s = ProvenanceSigner.generate()
    ring.add_root(s, created_at=T0)
    ring.revoke(s.public_key_hex(), RevocationReason.COMPROMISED,
                effective_at=T0 + 100 * DAY, attesting_signer=s)
    tainted = rec(s, T0 + 101 * DAY)

    trust = verify_record_with_keyring(tainted, ring)
    assert trust.trusted is False
    assert "compromise window" in " ".join(trust.reasons)


def test_compromise_boundary_is_inclusive(ring):
    """A record signed exactly AT effective_at must be suspect, not trusted --
    the attacker may have acted at that instant."""
    s = ProvenanceSigner.generate()
    ring.add_root(s, created_at=T0)
    eff = T0 + 50 * DAY
    ring.revoke(s.public_key_hex(), RevocationReason.COMPROMISED,
                effective_at=eff, attesting_signer=s)
    assert ring.find(s.public_key_hex()).trusted_at(eff) is False
    assert ring.find(s.public_key_hex()).trusted_at(eff - 1) is True


def test_lost_key_does_not_invalidate_history(ring):
    """Losing a key means you can't sign NEW things -- it says nothing about
    whether past signatures were honest."""
    s = ProvenanceSigner.generate()
    ring.add_root(s, created_at=T0)
    past = rec(s, T0 + DAY)
    successor = ProvenanceSigner.generate()
    ring.revoke(s.public_key_hex(), RevocationReason.LOST,
                effective_at=T0 + 2 * DAY, attesting_signer=successor)
    assert verify_record_with_keyring(past, ring).trusted is True


def test_retired_key_does_not_invalidate_history(ring):
    s = ProvenanceSigner.generate()
    ring.add_root(s, created_at=T0)
    past = rec(s, T0 + DAY)
    ring.revoke(s.public_key_hex(), RevocationReason.RETIRED,
                effective_at=T0 + 2 * DAY, attesting_signer=s)
    assert verify_record_with_keyring(past, ring).trusted is True


def test_compromised_key_can_be_revoked_by_successor(ring):
    """A stolen key cannot be trusted to revoke itself -- the attacker holds it.
    A successor must be able to attest the revocation."""
    old, new = ProvenanceSigner.generate(), ProvenanceSigner.generate()
    ring.add_root(old, created_at=T0)
    ring.add_root(new, created_at=T0 + DAY)
    ring.revoke(old.public_key_hex(), RevocationReason.COMPROMISED,
                effective_at=T0 + 5 * DAY, attesting_signer=new)
    entry = ring.find(old.public_key_hex())
    assert entry.status == KeyStatus.REVOKED
    assert entry.revocation.attested_by == new.public_key_hex()


def test_revocation_is_signed(ring):
    s = ProvenanceSigner.generate()
    ring.add_root(s, created_at=T0)
    ring.revoke(s.public_key_hex(), RevocationReason.COMPROMISED,
                effective_at=T0 + DAY, attesting_signer=s)
    rev = ring.find(s.public_key_hex()).revocation
    assert rev.signature
    assert _verify_sig(rev.attested_by, rev.signature, rev.payload(s.public_key_hex()))


def test_tampering_with_effective_at_breaks_revocation_signature(ring):
    """The attack: move the compromise window later so tainted records look
    honest."""
    s = ProvenanceSigner.generate()
    ring.add_root(s, created_at=T0)
    ring.revoke(s.public_key_hex(), RevocationReason.COMPROMISED,
                effective_at=T0 + 10 * DAY, attesting_signer=s)
    rev = ring.find(s.public_key_hex()).revocation
    rev.effective_at = T0 + 999 * DAY      # forge a later window
    assert _verify_sig(rev.attested_by, rev.signature,
                       rev.payload(s.public_key_hex())) is False


# ---- the wiring: lifecycle must actually reach the trust layer ----

def test_agent_handoff_rejects_compromised_key_record(ring):
    """verify_handoff with a keyring must catch what signature math cannot."""
    from inverba.agent_trust import verify_handoff
    s = ProvenanceSigner.generate()
    ring.add_root(s, created_at=T0)
    ring.revoke(s.public_key_hex(), RevocationReason.COMPROMISED,
                effective_at=T0 + 10 * DAY, attesting_signer=s)

    tainted = rec(s, T0 + 20 * DAY)
    content = f"<html>{T0 + 20 * DAY}</html>".encode()

    # without a keyring: the math is fine, so it passes -- strictly weaker
    assert verify_handoff(tainted, claimed_content=content, now=T0 + 21 * DAY).trusted is True
    # with a keyring: caught
    v = verify_handoff(tainted, claimed_content=content, keyring=ring, now=T0 + 21 * DAY)
    assert v.trusted is False
    assert "compromise" in " ".join(v.reasons)


def test_agent_handoff_accepts_pre_compromise_record(ring):
    from inverba.agent_trust import verify_handoff
    s = ProvenanceSigner.generate()
    ring.add_root(s, created_at=T0)
    honest = rec(s, T0 + DAY)
    content = f"<html>{T0 + DAY}</html>".encode()
    ring.revoke(s.public_key_hex(), RevocationReason.COMPROMISED,
                effective_at=T0 + 10 * DAY, attesting_signer=s)

    v = verify_handoff(honest, claimed_content=content, keyring=ring, now=T0 + 20 * DAY)
    assert v.trusted is True


def test_dataset_excludes_compromised_key_records(ring):
    """A corpus must not vouch for records an attacker signed."""
    from inverba.dataset import DatasetBuilder
    s = ProvenanceSigner.generate()
    ring.add_root(s, created_at=T0)
    honest = rec(s, T0 + DAY, url="https://honest.com")
    ring.revoke(s.public_key_hex(), RevocationReason.COMPROMISED,
                effective_at=T0 + 10 * DAY, attesting_signer=s)
    tainted = rec(s, T0 + 20 * DAY, url="https://tainted.com")

    b = DatasetBuilder("c", ProvenanceSigner.generate(), keyring=ring)
    assert b.add(honest) is True
    assert b.add(tainted) is False
    report = b.build()
    assert report.accepted == 1
    assert report.rejected == 1
    assert "tainted.com" in report.rejected_reasons[0]
