"""
Key lifecycle: rotation, revocation, and compromise.

The boring, catastrophic part of any cryptographic product. Inverba rests
entirely on Ed25519 keys that users hold, and until now there was no story for:
what happens when a key is lost, rotated, or stolen?

THE CENTRAL DISTINCTION -- ROTATION IS NOT COMPROMISE:

  ROTATED    -- routine hygiene. The old key was never in an attacker's hands,
                so every record it signed REMAINS VALID FOREVER. Invalidating
                them would be wrong and would destroy honest history.

  COMPROMISED -- an attacker held the private key from some point in time. Every
                record signed by that key AFTER `compromised_at` is suspect,
                because the attacker could have signed anything. Records signed
                BEFORE that moment are still trustworthy.

Collapsing these two is the classic mistake: treat rotation like compromise and
you throw away valid history; treat compromise like rotation and you launder
forged records into a corpus. So revocation carries a REASON and an
EFFECTIVE TIME, and verification is evaluated against the moment of signing.

CONTINUITY (why you can trust that key B replaced key A):
A rotation statement is signed by BOTH the old and the new key. The old key's
signature proves "I authorized this successor" (only its holder could) and the
new key's signature proves "I accept". A third party can then follow the chain
from a known-good key to the current one without trusting us.

A compromised key cannot be trusted to authorize its own successor, so a
compromise revocation may be attested by the successor alone -- and that
weakness is reported honestly rather than hidden.

WHAT THIS CANNOT DO:
Nothing recovers a LOST key. Records it signed remain verifiable forever (the
public key is enough to verify), but you can never sign as that identity again
-- rotate to a new key and cross-sign if you still hold the old one, or start a
new identity if you don't. There is no key escrow. That is the cost of nobody
being able to sign as you.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Optional

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey,
)
from cryptography.exceptions import InvalidSignature

from .models import ProvenanceRecord
from .provenance import ProvenanceSigner, verify_record


KEYRING_FORMAT = "inverba-keyring/1.0"


class RevocationReason(str, Enum):
    ROTATED = "rotated"          # routine; prior signatures stay valid
    COMPROMISED = "compromised"   # attacker held it; signatures after the fact are suspect
    RETIRED = "retired"           # decommissioned identity; prior signatures stay valid
    LOST = "lost"                 # no longer holdable; prior signatures stay valid


# Reasons under which signatures made before the effective time remain trusted.
_NON_INVALIDATING = {RevocationReason.ROTATED, RevocationReason.RETIRED, RevocationReason.LOST}


class KeyStatus(str, Enum):
    ACTIVE = "active"
    ROTATED = "rotated"
    REVOKED = "revoked"


@dataclass
class Revocation:
    reason: RevocationReason
    # When the revocation takes effect. For COMPROMISED this is the earliest
    # time the key may have been in an attacker's hands -- NOT when you noticed.
    # Signatures at or after this instant are suspect.
    effective_at: float
    declared_at: float
    note: Optional[str] = None
    # Signature over the revocation statement. May be from the key itself
    # (self-revocation) or from its successor (when the key is compromised or
    # lost and cannot sign).
    attested_by: str = ""
    signature: str = ""

    def payload(self, public_key: str) -> bytes:
        return json.dumps({
            "type": "revocation",
            "public_key": public_key,
            "reason": self.reason.value,
            "effective_at": self.effective_at,
            "declared_at": self.declared_at,
            "note": self.note,
        }, sort_keys=True, separators=(",", ":")).encode()


@dataclass
class KeyEntry:
    public_key: str
    created_at: float
    label: Optional[str] = None
    revocation: Optional[Revocation] = None
    # Cross-signature from the predecessor authorizing this key as successor.
    predecessor: Optional[str] = None
    predecessor_signature: str = ""
    successor_signature: str = ""

    @property
    def status(self) -> KeyStatus:
        if self.revocation is None:
            return KeyStatus.ACTIVE
        if self.revocation.reason in _NON_INVALIDATING:
            return KeyStatus.ROTATED
        return KeyStatus.REVOKED

    def trusted_at(self, when: float) -> bool:
        """Was a signature made at `when` by this key trustworthy?"""
        if when < self.created_at - 1:      # 1s slack for clock jitter
            return False
        if self.revocation is None:
            return True
        if self.revocation.reason in _NON_INVALIDATING:
            # Rotation/retirement/loss never invalidates prior work. The key
            # simply stops being used going forward.
            return True
        # COMPROMISED: only signatures strictly before the compromise window.
        return when < self.revocation.effective_at


def _rotation_payload(old_key: str, new_key: str, created_at: float) -> bytes:
    return json.dumps({
        "type": "rotation",
        "predecessor": old_key,
        "successor": new_key,
        "created_at": created_at,
    }, sort_keys=True, separators=(",", ":")).encode()


class KeyRing:
    """
    The signed history of one identity's keys.

    Ships alongside records (or is published) so a verifier can answer: was this
    key trusted at the moment it signed this record?
    """

    def __init__(self, identity: str):
        self.identity = identity
        self.keys: list[KeyEntry] = []

    # -- construction --

    def add_root(self, signer: ProvenanceSigner, label: Optional[str] = None,
                 created_at: Optional[float] = None) -> KeyEntry:
        entry = KeyEntry(public_key=signer.public_key_hex(),
                         created_at=created_at or time.time(), label=label)
        self.keys.append(entry)
        return entry

    def rotate(self, old_signer: ProvenanceSigner, new_signer: ProvenanceSigner,
               *, at: Optional[float] = None, note: Optional[str] = None,
               label: Optional[str] = None) -> KeyEntry:
        """Routine rotation. Cross-signed by both keys to prove continuity.

        Prior records signed by the old key REMAIN VALID -- rotation is hygiene,
        not a statement that the old key was ever untrustworthy.
        """
        at = at or time.time()
        old_pub, new_pub = old_signer.public_key_hex(), new_signer.public_key_hex()
        old_entry = self.find(old_pub)
        if old_entry is None:
            raise ValueError("cannot rotate a key that is not in this keyring")
        if old_entry.revocation is not None:
            raise ValueError("cannot rotate an already-revoked key")

        payload = _rotation_payload(old_pub, new_pub, at)
        new_entry = KeyEntry(
            public_key=new_pub, created_at=at, label=label,
            predecessor=old_pub,
            predecessor_signature=old_signer._private_key.sign(payload).hex(),
            successor_signature=new_signer._private_key.sign(payload).hex(),
        )
        self.keys.append(new_entry)

        rev = Revocation(reason=RevocationReason.ROTATED, effective_at=at,
                         declared_at=at, note=note, attested_by=old_pub)
        rev.signature = old_signer._private_key.sign(rev.payload(old_pub)).hex()
        old_entry.revocation = rev
        return new_entry

    def revoke(self, public_key: str, reason: RevocationReason, *,
               effective_at: float, attesting_signer: ProvenanceSigner,
               note: Optional[str] = None) -> Revocation:
        """Revoke a key.

        For COMPROMISED, `effective_at` must be the EARLIEST time the key may
        have been exposed -- not when you noticed. Everything signed at or after
        that instant becomes suspect, so guessing late silently trusts forged
        records.

        `attesting_signer` may be the key itself (self-revocation) or another key
        in the ring (necessary when the key is lost or compromised).
        """
        entry = self.find(public_key)
        if entry is None:
            raise ValueError("unknown key")
        rev = Revocation(reason=reason, effective_at=effective_at,
                         declared_at=time.time(), note=note,
                         attested_by=attesting_signer.public_key_hex())
        rev.signature = attesting_signer._private_key.sign(rev.payload(public_key)).hex()
        entry.revocation = rev
        return rev

    # -- queries --

    def find(self, public_key: str) -> Optional[KeyEntry]:
        return next((k for k in self.keys if k.public_key == public_key), None)

    @property
    def active_key(self) -> Optional[KeyEntry]:
        return next((k for k in self.keys if k.status == KeyStatus.ACTIVE), None)

    def trusted_at(self, public_key: str, when: float) -> bool:
        entry = self.find(public_key)
        return bool(entry and entry.trusted_at(when))

    # -- verification --

    def verify_chain(self) -> dict:
        """Verify cross-signatures and revocation attestations.

        Returns a report rather than a bool: a chain can be structurally sound
        but contain a compromise, and callers need to tell those apart.
        """
        problems: list[str] = []
        warnings: list[str] = []

        for entry in self.keys:
            if entry.predecessor:
                payload = _rotation_payload(entry.predecessor, entry.public_key, entry.created_at)
                if not _verify_sig(entry.predecessor, entry.predecessor_signature, payload):
                    problems.append(
                        f"{entry.public_key[:12]}: predecessor did not authorize this successor"
                    )
                if not _verify_sig(entry.public_key, entry.successor_signature, payload):
                    problems.append(f"{entry.public_key[:12]}: successor did not accept rotation")

            rev = entry.revocation
            if rev:
                if not _verify_sig(rev.attested_by, rev.signature, rev.payload(entry.public_key)):
                    problems.append(f"{entry.public_key[:12]}: revocation attestation invalid")
                elif rev.attested_by != entry.public_key and self.find(rev.attested_by) is None:
                    problems.append(
                        f"{entry.public_key[:12]}: revoked by a key outside this ring"
                    )
                if rev.reason == RevocationReason.COMPROMISED:
                    if rev.attested_by == entry.public_key:
                        warnings.append(
                            f"{entry.public_key[:12]}: compromise self-attested -- a "
                            "compromised key cannot be trusted to describe its own compromise"
                        )
                    warnings.append(
                        f"{entry.public_key[:12]}: COMPROMISED; signatures at/after "
                        f"{rev.effective_at} are not trusted"
                    )

        return {"valid": not problems, "problems": problems, "warnings": warnings,
                "key_count": len(self.keys)}

    # -- serialization --

    def to_dict(self) -> dict:
        return {
            "fmt": KEYRING_FORMAT,
            "identity": self.identity,
            "keys": [
                {**asdict(k),
                 "revocation": (
                     {**asdict(k.revocation), "reason": k.revocation.reason.value}
                     if k.revocation else None
                 ),
                 "status": k.status.value}
                for k in self.keys
            ],
        }

    @classmethod
    def from_dict(cls, d: dict) -> "KeyRing":
        ring = cls(d["identity"])
        for kd in d["keys"]:
            kd = dict(kd)
            kd.pop("status", None)
            rev = kd.pop("revocation", None)
            entry = KeyEntry(**kd)
            if rev:
                rev = dict(rev)
                rev["reason"] = RevocationReason(rev["reason"])
                entry.revocation = Revocation(**rev)
            ring.keys.append(entry)
        return ring


def _verify_sig(public_key_hex: str, signature_hex: str, payload: bytes) -> bool:
    try:
        pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key_hex))
        pub.verify(bytes.fromhex(signature_hex), payload)
        return True
    except (InvalidSignature, ValueError):
        return False


@dataclass
class RecordTrust:
    signature_valid: bool
    key_known: bool
    key_trusted_at_signing: bool
    trusted: bool
    status: Optional[str]
    reasons: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


def verify_record_with_keyring(record: ProvenanceRecord, keyring: KeyRing) -> RecordTrust:
    """
    Verify a record against a key's lifecycle, not just its math.

    This is the difference that matters: a signature can be cryptographically
    perfect and still untrustworthy, because the key was in an attacker's hands
    when it was made.
    """
    reasons: list[str] = []
    sig_ok = verify_record(record)
    if not sig_ok:
        return RecordTrust(False, False, False, False, None,
                           ["signature invalid -- record forged or altered"])

    entry = keyring.find(record.worker_public_key)
    if entry is None:
        return RecordTrust(True, False, False, False, None,
                           ["signature valid but the signing key is not in this keyring -- "
                            "unknown identity"])

    trusted_at = entry.trusted_at(record.fetched_at)
    if not trusted_at:
        rev = entry.revocation
        if rev and rev.reason == RevocationReason.COMPROMISED:
            reasons.append(
                f"key was compromised as of {rev.effective_at}; this record was signed "
                f"at {record.fetched_at}, inside the compromise window -- an attacker "
                "could have produced it"
            )
        else:
            reasons.append("record predates the key's creation")
    else:
        if entry.revocation and entry.revocation.reason in _NON_INVALIDATING:
            reasons.append(
                f"key was later {entry.revocation.reason.value}, but this record predates "
                "that and remains valid"
            )

    return RecordTrust(
        signature_valid=True, key_known=True, key_trusted_at_signing=trusted_at,
        trusted=trusted_at, status=entry.status.value, reasons=reasons,
    )
