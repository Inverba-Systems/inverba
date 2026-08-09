import time

from inverba.models import FetchResult, FetchMethod
from inverba.provenance import (
    ProvenanceSigner,
    verify_record,
    verify_with_corroborations,
    hash_content,
)


def make_fetch_result(content: bytes = b"<html>hello</html>") -> FetchResult:
    return FetchResult(
        url="https://example.com/page",
        final_url="https://example.com/page",
        status_code=200,
        content=content,
        content_type="text/html",
        method=FetchMethod.HTTP,
        fetched_at=time.time(),
    )


def test_sign_and_verify_roundtrip():
    signer = ProvenanceSigner.generate()
    fr = make_fetch_result()
    record = signer.sign(fr)

    assert record.content_hash == hash_content(fr.content)
    assert verify_record(record) is True


def test_tampered_hash_fails_verification():
    signer = ProvenanceSigner.generate()
    record = signer.sign(make_fetch_result())
    record.content_hash = "0" * 64
    assert verify_record(record) is False


def test_tampered_signature_fails_verification():
    signer = ProvenanceSigner.generate()
    record = signer.sign(make_fetch_result())
    record.signature = "00" * 64
    assert verify_record(record) is False


def test_wrong_public_key_fails_verification():
    signer_a = ProvenanceSigner.generate()
    signer_b = ProvenanceSigner.generate()
    record = signer_a.sign(make_fetch_result())
    record.worker_public_key = signer_b.public_key_hex()
    assert verify_record(record) is False


def test_key_roundtrip_via_private_bytes():
    signer = ProvenanceSigner.generate()
    raw = signer.private_bytes()
    restored = ProvenanceSigner.from_private_bytes(raw)
    assert restored.public_key_hex() == signer.public_key_hex()


def test_corroboration_agreement():
    signer_a = ProvenanceSigner.generate()
    signer_b = ProvenanceSigner.generate()
    fr = make_fetch_result(b"same content")

    primary = signer_a.sign(fr)
    corroborator = signer_b.sign(fr)
    primary.corroborations.append(corroborator)

    result = verify_with_corroborations(primary)
    assert result["primary_valid"] is True
    assert result["corroboration_count"] == 1
    assert result["corroborations_agree"] is True


def test_corroboration_disagreement_detected():
    signer_a = ProvenanceSigner.generate()
    signer_b = ProvenanceSigner.generate()

    primary = signer_a.sign(make_fetch_result(b"version one"))
    corroborator = signer_b.sign(make_fetch_result(b"version two -- different!"))
    primary.corroborations.append(corroborator)

    result = verify_with_corroborations(primary)
    assert result["primary_valid"] is True
    assert result["corroborations_agree"] is False


def test_signing_payload_is_canonical_no_delimiter_collision():
    """B2 regression: the signature must bind each field independently. A
    field-boundary shift between final_url and content_type must NOT verify
    (the old '|'-joined payload let two records share one signature)."""
    import copy
    signer = ProvenanceSigner.generate()
    fr = FetchResult(url="https://origin.example/p",
                     final_url="https://origin.example/a", status_code=200,
                     content=b"body", content_type="b|text/html",
                     method=FetchMethod.HTTP, fetched_at=1000.0)
    rec_a = signer.sign(fr)
    assert verify_record(rec_a) is True

    # boundary shift: move the '|' across the final_url/content_type split.
    rec_b = copy.deepcopy(rec_a)
    rec_b.final_url = "https://origin.example/a|b"
    rec_b.content_type = "text/html"
    rec_b.signature = rec_a.signature  # attacker re-presents A's signature
    assert (rec_a.final_url, rec_a.content_type) != (rec_b.final_url, rec_b.content_type)
    assert verify_record(rec_b) is False, "delimiter collision still possible"


def test_signing_payload_distinguishes_all_freeform_field_shifts():
    """Any boundary shift among the free-form signed fields must break verify."""
    import copy
    signer = ProvenanceSigner.generate()
    fr = FetchResult(url="https://o/p", final_url="https://o/p", status_code=200,
                     content=b"x", content_type="a", method=FetchMethod.HTTP, fetched_at=1.0)
    rec = signer.sign(fr)
    for field, val in [("fetched_by", "native|200"), ("content_type", "a|b|c"),
                       ("url", "https://o/p|extra")]:
        m = copy.deepcopy(rec)
        setattr(m, field, val)
        assert verify_record(m) is False, f"shifting {field} verified"
