"""
Dataset manifests -- corpus-level provenance.

WHY THIS EXISTS:
Per-URL records answer "what was on this page?" Compliance asks a different
question: "what is in this training corpus, where did it come from, and can you
prove it?" (EU AI Act GPAI obligations require a sufficiently detailed summary
of training-data content; high-risk systems require data governance and
provenance documentation.)

Nobody's auditor wants four million record.json files. They want ONE object:

    dataset web-corpus-2026q2
      4,182,004 records
      merkle root a41c...09be
      collected 2026-04-01 .. 2026-06-30
      signed by <key>
      -> verify any single record's membership with an inclusion proof

The Merkle root commits to every record, so:
  - the manifest cannot be edited after signing without detection
  - a record's membership is provable WITHOUT shipping the whole corpus
  - a record cannot be quietly added to or removed from a published dataset

THE HONEST PART:
A manifest that hid how the corpus was collected would be provenance laundering
-- it would let someone relay four million pages through a third party and
present the result as independently verified. So the manifest reports
composition truthfully and prominently:

  - how many records are independent observations vs relayed from a third party
  - which backends were used, and in what proportion
  - how many records are corroborated
  - how many failed verification at build time (these are REJECTED, not counted)

`independence_ratio` is computed, not asserted. An auditor reading a manifest
must be able to see "92% of this corpus was fetched by firecrawl and relayed"
because that materially changes what the signature is worth.
"""

from __future__ import annotations

import json
import time
from collections import Counter
from dataclasses import dataclass, field, asdict
from typing import Iterable, Optional

from .models import ProvenanceRecord
from .merkle import MerkleTree, InclusionProof, verify_inclusion
from .provenance import ProvenanceSigner, verify_record


MANIFEST_FORMAT = "inverba-dataset/1.0"


@dataclass
class DatasetComposition:
    """How the corpus was actually collected. Computed from the records, never
    asserted by the caller."""
    record_count: int = 0
    independent_observations: int = 0     # fetched_by == "native"
    relayed: int = 0                       # fetched by a third party
    corroborated: int = 0                  # >=1 corroborating worker agreed
    backends: dict[str, int] = field(default_factory=dict)
    unique_urls: int = 0
    earliest_fetch: Optional[float] = None
    latest_fetch: Optional[float] = None

    @property
    def independence_ratio(self) -> float:
        if not self.record_count:
            return 0.0
        return self.independent_observations / self.record_count

    @property
    def corroboration_ratio(self) -> float:
        if not self.record_count:
            return 0.0
        return self.corroborated / self.record_count


@dataclass
class DatasetManifest:
    """A signed, corpus-level provenance object."""
    dataset_id: str
    name: str
    created_at: float
    merkle_root: str
    composition: DatasetComposition
    signer_public_key: str = ""
    signature: str = ""
    fmt: str = MANIFEST_FORMAT
    notes: Optional[str] = None

    def signing_payload(self) -> bytes:
        """Deterministic bytes covered by the signature.

        Composition is INSIDE the payload: if it weren't, someone could sign a
        manifest and then edit 'relayed: 4,000,000' down to zero. The whole
        point is that composition is not editable after the fact.
        """
        body = {
            "fmt": self.fmt,
            "dataset_id": self.dataset_id,
            "name": self.name,
            "created_at": self.created_at,
            "merkle_root": self.merkle_root,
            "composition": asdict(self.composition),
            "notes": self.notes,
        }
        return json.dumps(body, sort_keys=True, separators=(",", ":")).encode()

    def to_dict(self) -> dict:
        d = {
            "fmt": self.fmt,
            "dataset_id": self.dataset_id,
            "name": self.name,
            "created_at": self.created_at,
            "merkle_root": self.merkle_root,
            "composition": asdict(self.composition),
            "notes": self.notes,
            "signer_public_key": self.signer_public_key,
            "signature": self.signature,
        }
        # surface derived ratios for humans/auditors reading the JSON directly
        d["composition"]["independence_ratio"] = round(self.composition.independence_ratio, 4)
        d["composition"]["corroboration_ratio"] = round(self.composition.corroboration_ratio, 4)
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "DatasetManifest":
        comp = dict(d["composition"])
        comp.pop("independence_ratio", None)   # derived, not stored
        comp.pop("corroboration_ratio", None)
        return cls(
            dataset_id=d["dataset_id"], name=d["name"], created_at=d["created_at"],
            merkle_root=d["merkle_root"], composition=DatasetComposition(**comp),
            signer_public_key=d.get("signer_public_key", ""),
            signature=d.get("signature", ""), fmt=d.get("fmt", MANIFEST_FORMAT),
            notes=d.get("notes"),
        )

    def summary(self) -> str:
        c = self.composition
        lines = [
            f"dataset {self.name} ({self.dataset_id})",
            f"  {c.record_count:,} records · {c.unique_urls:,} unique URLs",
            f"  merkle root {self.merkle_root[:16]}...",
        ]
        if c.earliest_fetch and c.latest_fetch:
            lines.append(
                f"  collected {time.strftime('%Y-%m-%d', time.gmtime(c.earliest_fetch))}"
                f" .. {time.strftime('%Y-%m-%d', time.gmtime(c.latest_fetch))}"
            )
        lines.append(
            f"  {c.independent_observations:,} independently observed "
            f"({c.independence_ratio:.0%}) · {c.relayed:,} relayed"
        )
        if c.backends:
            parts = ", ".join(f"{k}={v:,}" for k, v in sorted(c.backends.items()))
            lines.append(f"  backends: {parts}")
        lines.append(f"  {c.corroborated:,} corroborated ({c.corroboration_ratio:.0%})")
        return "\n".join(lines)


@dataclass
class BuildReport:
    manifest: DatasetManifest
    accepted: int
    rejected: int
    rejected_reasons: list[str] = field(default_factory=list)


class DatasetBuilder:
    """
    Assembles verified records into a signed dataset manifest.

    Records are VERIFIED at build time. A record with a bad signature is
    rejected, not silently counted -- a corpus manifest that vouches for records
    it never checked is worse than no manifest, because it launders unverified
    data into something that looks audited.
    """

    def __init__(self, name: str, signer: ProvenanceSigner,
                 dataset_id: Optional[str] = None, keyring=None):
        """
        keyring: optional KeyRing. When supplied, records are checked against
            the signing key's LIFECYCLE, so a record signed by a key that was
            compromised at the time is kept out of the corpus. Without it we can
            only check signature math -- a corpus could then contain records an
            attacker signed with a stolen key, and the manifest would vouch for
            them.
        """
        self.name = name
        self.signer = signer
        self.keyring = keyring
        self.dataset_id = dataset_id or f"ds_{int(time.time())}_{abs(hash(name)) % 10**8:08d}"
        self._tree = MerkleTree()
        self._records: list[ProvenanceRecord] = []
        self._rejected: list[str] = []

    @staticmethod
    def _leaf_bytes(record: ProvenanceRecord) -> bytes:
        """Canonical leaf for a record. Uses the record's own signed fields, so
        the tree commits to exactly what was signed."""
        return json.dumps({
            "url": record.url,
            "content_hash": record.content_hash,
            "fetched_at": record.fetched_at,
            "worker_public_key": record.worker_public_key,
            "signature": record.signature,
            "fetched_by": record.fetched_by,
        }, sort_keys=True, separators=(",", ":")).encode()

    def add(self, record: ProvenanceRecord) -> bool:
        """Add one record. Returns False (and records a reason) if it fails
        verification or its key was not trustworthy when it signed."""
        if not verify_record(record):
            self._rejected.append(f"{record.url}: invalid signature")
            return False

        if self.keyring is not None:
            from .keys import verify_record_with_keyring
            trust = verify_record_with_keyring(record, self.keyring)
            if not trust.trusted:
                reason = trust.reasons[0] if trust.reasons else "key not trusted at signing"
                self._rejected.append(f"{record.url}: {reason}")
                return False

        self._tree.append(self._leaf_bytes(record))
        self._records.append(record)
        return True

    def add_all(self, records: Iterable[ProvenanceRecord]) -> int:
        return sum(1 for r in records if self.add(r))

    def _composition(self) -> DatasetComposition:
        comp = DatasetComposition(record_count=len(self._records))
        if not self._records:
            return comp
        backends = Counter()
        urls = set()
        times = []
        for r in self._records:
            fb = getattr(r, "fetched_by", "native")
            backends[fb] += 1
            if fb == "native":
                comp.independent_observations += 1
            else:
                comp.relayed += 1
            if r.corroborations:
                comp.corroborated += 1
            urls.add(r.url)
            times.append(r.fetched_at)
        comp.backends = dict(backends)
        comp.unique_urls = len(urls)
        comp.earliest_fetch = min(times)
        comp.latest_fetch = max(times)
        return comp

    def build(self, notes: Optional[str] = None) -> BuildReport:
        composition = self._composition()
        manifest = DatasetManifest(
            dataset_id=self.dataset_id,
            name=self.name,
            created_at=time.time(),
            merkle_root=self._tree.root_hex(),
            composition=composition,
            notes=notes,
        )
        sig = self.signer._private_key.sign(manifest.signing_payload())
        manifest.signature = sig.hex()
        manifest.signer_public_key = self.signer.public_key_hex()
        return BuildReport(
            manifest=manifest, accepted=len(self._records),
            rejected=len(self._rejected), rejected_reasons=list(self._rejected),
        )

    def inclusion_proof(self, index: int) -> InclusionProof:
        """Prove record #index is in this dataset, without shipping the corpus."""
        return self._tree.inclusion_proof(index)

    def proof_for(self, record: ProvenanceRecord) -> Optional[InclusionProof]:
        leaf = self._leaf_bytes(record)
        from .merkle import leaf_hash
        target = leaf_hash(leaf).hex()
        for i in range(self._tree.size):
            if self._tree.inclusion_proof(i).leaf_hash == target:
                return self._tree.inclusion_proof(i)
        return None


def verify_manifest(manifest: DatasetManifest) -> dict:
    """Verify a manifest's signature. Returns a status dict rather than a bool
    so a caller can distinguish 'forged' from 'unsigned'."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.exceptions import InvalidSignature

    result = {"valid_signature": False, "record_count": manifest.composition.record_count,
              "independence_ratio": round(manifest.composition.independence_ratio, 4),
              "merkle_root": manifest.merkle_root}
    if not manifest.signature or not manifest.signer_public_key:
        result["reason"] = "manifest is unsigned"
        return result
    try:
        pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(manifest.signer_public_key))
        pub.verify(bytes.fromhex(manifest.signature), manifest.signing_payload())
        result["valid_signature"] = True
    except (InvalidSignature, ValueError):
        result["reason"] = "signature invalid -- manifest forged or altered after signing"
    return result


def verify_membership(proof: InclusionProof, manifest: DatasetManifest) -> bool:
    """Confirm a record belongs to the dataset the manifest describes."""
    return verify_inclusion(proof, manifest.merkle_root)
