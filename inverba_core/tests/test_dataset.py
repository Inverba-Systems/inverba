"""
Tests for corpus-level dataset manifests.

The compliance product. These lock in the properties an auditor depends on:
  - the manifest cannot be edited after signing (composition is signed)
  - composition is COMPUTED, so a relayed corpus cannot present as independent
  - membership is provable without shipping the whole corpus
  - records that fail verification are REJECTED, not silently counted
"""

import json
import time

import pytest

from inverba.provenance import ProvenanceSigner
from inverba.models import FetchResult, FetchMethod
from inverba.dataset import (
    DatasetBuilder, DatasetManifest, verify_manifest, verify_membership,
)


def make_record(signer, url="https://example.com/p", content=b"<html>x</html>",
                fetched_by="native", at=None):
    fr = FetchResult(url=url, final_url=url, status_code=200, content=content,
                     content_type="text/html", method=FetchMethod.HTTP,
                     fetched_at=at or time.time(), fetched_by=fetched_by)
    return signer.sign(fr)


@pytest.fixture
def signer():
    return ProvenanceSigner.generate()


# ---- basic build ----

def test_build_produces_signed_manifest(signer):
    b = DatasetBuilder("web-corpus-2026q2", signer)
    for i in range(5):
        b.add(make_record(signer, url=f"https://example.com/{i}"))
    report = b.build()
    assert report.accepted == 5
    assert verify_manifest(report.manifest)["valid_signature"] is True
    assert report.manifest.composition.record_count == 5


def test_manifest_reports_unique_urls_and_date_range(signer):
    b = DatasetBuilder("c", signer)
    b.add(make_record(signer, url="https://a.com", at=1000))
    b.add(make_record(signer, url="https://a.com", at=2000))   # dupe URL
    b.add(make_record(signer, url="https://b.com", at=3000))
    m = b.build().manifest
    assert m.composition.record_count == 3
    assert m.composition.unique_urls == 2
    assert m.composition.earliest_fetch == 1000
    assert m.composition.latest_fetch == 3000


# ---- the honest part: composition can't be laundered ----

def test_composition_reports_relayed_records_truthfully(signer):
    b = DatasetBuilder("mostly-relayed", signer)
    b.add(make_record(signer, url="https://a.com", fetched_by="native"))
    for i in range(9):
        b.add(make_record(signer, url=f"https://r{i}.com", fetched_by="firecrawl"))
    m = b.build().manifest
    assert m.composition.independent_observations == 1
    assert m.composition.relayed == 9
    assert m.composition.independence_ratio == pytest.approx(0.1)
    assert m.composition.backends == {"native": 1, "firecrawl": 9}


def test_editing_composition_after_signing_breaks_signature(signer):
    """The laundering attack: sign a relayed corpus, then edit the numbers to
    claim independence."""
    b = DatasetBuilder("c", signer)
    for i in range(4):
        b.add(make_record(signer, url=f"https://r{i}.com", fetched_by="firecrawl"))
    m = b.build().manifest
    assert verify_manifest(m)["valid_signature"] is True

    m.composition.relayed = 0
    m.composition.independent_observations = 4
    assert verify_manifest(m)["valid_signature"] is False


def test_editing_merkle_root_breaks_signature(signer):
    b = DatasetBuilder("c", signer)
    b.add(make_record(signer))
    m = b.build().manifest
    m.merkle_root = "00" * 32
    assert verify_manifest(m)["valid_signature"] is False


def test_editing_record_count_breaks_signature(signer):
    b = DatasetBuilder("c", signer)
    b.add(make_record(signer))
    m = b.build().manifest
    m.composition.record_count = 1_000_000
    assert verify_manifest(m)["valid_signature"] is False


def test_corroboration_counted(signer):
    b = DatasetBuilder("c", signer)
    r = make_record(signer, url="https://a.com")
    other = ProvenanceSigner.generate()
    r.corroborations.append(make_record(other, url="https://a.com"))
    b.add(r)
    b.add(make_record(signer, url="https://b.com"))
    m = b.build().manifest
    assert m.composition.corroborated == 1
    assert m.composition.corroboration_ratio == pytest.approx(0.5)


# ---- unverified records are rejected, not counted ----

def test_invalid_record_is_rejected_not_counted(signer):
    b = DatasetBuilder("c", signer)
    good = make_record(signer, url="https://good.com")
    bad = make_record(signer, url="https://bad.com")
    bad.signature = "00" * 64
    assert b.add(good) is True
    assert b.add(bad) is False
    report = b.build()
    assert report.accepted == 1
    assert report.rejected == 1
    assert report.manifest.composition.record_count == 1
    assert "bad.com" in report.rejected_reasons[0]


def test_forged_attribution_record_is_rejected(signer):
    """A record whose fetched_by was edited fails verification, so it can't
    enter a corpus and inflate the independence ratio."""
    b = DatasetBuilder("c", signer)
    r = make_record(signer, fetched_by="firecrawl")
    r.fetched_by = "native"          # forge independence
    assert b.add(r) is False
    assert b.build().manifest.composition.record_count == 0


# ---- membership proofs ----

def test_membership_provable_without_shipping_corpus(signer):
    b = DatasetBuilder("big", signer)
    records = [make_record(signer, url=f"https://example.com/{i}") for i in range(50)]
    b.add_all(records)
    m = b.build().manifest

    proof = b.proof_for(records[17])
    assert proof is not None
    assert verify_membership(proof, m) is True
    # the proof is logarithmic, not the whole corpus
    assert len(proof.audit_path) < 10


def test_membership_proof_fails_against_other_dataset(signer):
    b1 = DatasetBuilder("d1", signer)
    r = make_record(signer, url="https://a.com")
    b1.add(r)
    m1 = b1.build().manifest

    b2 = DatasetBuilder("d2", signer)
    b2.add(make_record(signer, url="https://different.com"))
    m2 = b2.build().manifest

    proof = b1.proof_for(r)
    assert verify_membership(proof, m1) is True
    assert verify_membership(proof, m2) is False


def test_record_not_in_dataset_has_no_proof(signer):
    b = DatasetBuilder("d", signer)
    b.add(make_record(signer, url="https://in.com"))
    b.build()
    outsider = make_record(signer, url="https://out.com")
    assert b.proof_for(outsider) is None


def test_all_leaves_provable(signer):
    b = DatasetBuilder("d", signer)
    records = [make_record(signer, url=f"https://e.com/{i}") for i in range(11)]
    b.add_all(records)
    m = b.build().manifest
    for i in range(11):
        assert verify_membership(b.inclusion_proof(i), m) is True


# ---- serialization ----

def test_manifest_json_roundtrip_preserves_signature(signer):
    b = DatasetBuilder("c", signer)
    b.add(make_record(signer, fetched_by="firecrawl"))
    m = b.build().manifest
    restored = DatasetManifest.from_dict(json.loads(json.dumps(m.to_dict())))
    assert verify_manifest(restored)["valid_signature"] is True
    assert restored.composition.relayed == 1


def test_manifest_dict_surfaces_ratios_for_auditors(signer):
    b = DatasetBuilder("c", signer)
    b.add(make_record(signer, fetched_by="firecrawl"))
    d = b.build().manifest.to_dict()
    assert "independence_ratio" in d["composition"]
    assert d["composition"]["independence_ratio"] == 0.0


def test_summary_is_human_readable(signer):
    b = DatasetBuilder("web-corpus-2026q2", signer)
    b.add(make_record(signer, fetched_by="native"))
    b.add(make_record(signer, url="https://b.com", fetched_by="firecrawl"))
    s = b.build().manifest.summary()
    assert "web-corpus-2026q2" in s
    assert "relayed" in s
    assert "firecrawl" in s


def test_unsigned_manifest_reports_honestly():
    m = DatasetManifest(dataset_id="x", name="n", created_at=time.time(),
                        merkle_root="ab" * 32,
                        composition=__import__("inverba.dataset", fromlist=["DatasetComposition"]).DatasetComposition())
    result = verify_manifest(m)
    assert result["valid_signature"] is False
    assert "unsigned" in result["reason"]


def test_empty_dataset_builds(signer):
    report = DatasetBuilder("empty", signer).build()
    assert report.accepted == 0
    assert verify_manifest(report.manifest)["valid_signature"] is True
    assert report.manifest.composition.independence_ratio == 0.0
