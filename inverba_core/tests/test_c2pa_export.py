import json
import tempfile
from pathlib import Path

from inverba.models import FetchResult, FetchMethod
from inverba.provenance import ProvenanceSigner, verify_record
from inverba.c2pa_export import (
    build_manifest, export_manifest_json, verify_manifest_binding,
    TrainingMiningControl, CAWG_TRAINING_MINING, C2PA_HASH_DATA,
)


def make_record(content=b"<html>dataset content</html>", url="https://data.com/page"):
    signer = ProvenanceSigner.generate()
    fr = FetchResult(url=url, final_url=url, status_code=200, content=content,
                     content_type="text/html", method=FetchMethod.HTTP)
    return signer.sign(fr), content


def test_manifest_has_required_assertions():
    record, _ = make_record()
    m = build_manifest(record)
    labels = [a["label"] for a in m["assertions"]]
    assert C2PA_HASH_DATA in labels           # content binding
    assert CAWG_TRAINING_MINING in labels      # training/mining consent
    assert "c2pa.actions" in labels             # provenance action
    assert "inverba.source" in labels           # source URL


def test_content_binding_matches_bytes():
    record, content = make_record()
    m = build_manifest(record)
    result = verify_manifest_binding(m, content)
    assert result["has_binding"] is True
    assert result["binding_matches"] is True


def test_content_binding_detects_tampering():
    record, _ = make_record()
    m = build_manifest(record)
    result = verify_manifest_binding(m, b"different bytes entirely")
    assert result["binding_matches"] is False


def test_training_mining_control_defaults_to_not_allowed():
    record, _ = make_record()
    m = build_manifest(record)
    tm = next(a for a in m["assertions"] if a["label"] == CAWG_TRAINING_MINING)
    entries = tm["data"]["entries"]
    assert entries["cawg.ai_training"]["use"] == "notAllowed"
    assert entries["cawg.ai_generative_training"]["use"] == "notAllowed"


def test_training_mining_control_can_allow():
    record, _ = make_record()
    tm = TrainingMiningControl(ai_training="allowed", data_mining="allowed")
    m = build_manifest(record, training_mining=tm)
    entries = next(a for a in m["assertions"]
                   if a["label"] == CAWG_TRAINING_MINING)["data"]["entries"]
    assert entries["cawg.ai_training"]["use"] == "allowed"


def test_signature_info_references_ed25519_source_of_truth():
    record, _ = make_record()
    m = build_manifest(record)
    sig = m["signature_info"]
    assert sig["alg"] == "ed25519"
    assert sig["issuer"] == record.worker_public_key
    assert sig["signature"] == record.signature
    # honest labeling of cert status
    assert sig["cert_status"] == "self-signed"


def test_semantic_hash_binding_when_provided():
    record, _ = make_record()
    m = build_manifest(record, normalized_content_hash="a" * 64)
    labels = [a["label"] for a in m["assertions"]]
    assert "inverba.semantic_hash" in labels


def test_corroboration_assertion_when_present():
    record, _ = make_record()
    corr, _ = make_record()
    record.corroborations.append(corr)
    m = build_manifest(record)
    corr_assertion = next(a for a in m["assertions"] if a["label"] == "inverba.corroboration")
    assert corr_assertion["data"]["corroborator_count"] == 1


def test_export_to_file_roundtrips():
    record, content = make_record()
    with tempfile.TemporaryDirectory() as tmp:
        path = str(Path(tmp) / "content.json.c2pa")
        export_manifest_json(record, path)
        loaded = json.load(open(path))
        assert verify_manifest_binding(loaded, content)["binding_matches"] is True


def test_derived_view_does_not_break_source_record():
    # building a manifest must not mutate the authoritative Ed25519 record
    record, _ = make_record()
    assert verify_record(record) is True
    build_manifest(record)
    assert verify_record(record) is True   # still valid after derivation
