"""
Tests for RFC 3161 temporal proof (temporal.py).

TSA calls are mocked: a self-signed test TSA mints valid tokens offline, so the
storage + verification logic is exercised without a network. Live-TSA
verification against a real server is a manual step (see TEMPORAL_PROOF.md).
"""
import hashlib
from datetime import datetime, timezone

import pytest

from inverba.models import FetchResult, FetchMethod
from inverba.provenance import ProvenanceSigner
from inverba import temporal
from inverba.temporal import (
    TimestampToken, TimestampVerification, verify_timestamp, request_timestamp,
    digest_for_record, digest_for_manifest_root, TemporalConfig,
    OpenTimestampsAnchor, TemporalError,
)


# --------------------------------------------------------------------------
# Offline self-signed TSA that mints RFC 3161 tokens (no network)
# --------------------------------------------------------------------------

def _make_tsa():
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import rsa
    import datetime as dt
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test TSA")])
    cert = (x509.CertificateBuilder()
            .subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(12345).not_valid_before(dt.datetime(2020, 1, 1))
            .not_valid_after(dt.datetime(2035, 1, 1))
            .sign(key, hashes.SHA256()))
    return key, cert


def _mint_token(digest, gen_time, key, cert, *, imprint_algo="sha256"):
    """Build a valid RFC 3161 TimeStampToken (CMS ContentInfo DER) over `digest`."""
    from asn1crypto import tsp, cms, algos, x509 as ax509, core
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding

    acert = ax509.Certificate.load(cert.public_bytes(serialization.Encoding.DER))

    tst = tsp.TSTInfo({
        "version": 1,
        "policy": "1.2.3.4.1",
        "message_imprint": tsp.MessageImprint({
            "hash_algorithm": algos.DigestAlgorithm({"algorithm": imprint_algo}),
            "hashed_message": digest,
        }),
        "serial_number": 1,
        "gen_time": gen_time,
    })
    econtent = tst.dump()

    signed_attrs = cms.CMSAttributes([
        cms.CMSAttribute({"type": "content_type", "values": ["tst_info"]}),
        cms.CMSAttribute({"type": "message_digest",
                          "values": [hashlib.sha256(econtent).digest()]}),
    ])
    attrs_der = bytearray(signed_attrs.dump())
    attrs_der[0] = 0x31  # SET OF for signing
    signature = key.sign(bytes(attrs_der), padding.PKCS1v15(), hashes.SHA256())

    signer_info = cms.SignerInfo({
        "version": 1,
        "sid": cms.SignerIdentifier({"issuer_and_serial_number": cms.IssuerAndSerialNumber({
            "issuer": acert.issuer, "serial_number": acert.serial_number})}),
        "digest_algorithm": algos.DigestAlgorithm({"algorithm": "sha256"}),
        "signed_attrs": signed_attrs,
        "signature_algorithm": algos.SignedDigestAlgorithm({"algorithm": "rsassa_pkcs1v15"}),
        "signature": signature,
    })
    signed_data = cms.SignedData({
        "version": "v3",
        "digest_algorithms": [algos.DigestAlgorithm({"algorithm": "sha256"})],
        "encap_content_info": cms.EncapsulatedContentInfo({
            "content_type": "tst_info",
            "content": core.ParsableOctetString(econtent),
        }),
        "certificates": [acert],
        "signer_infos": [signer_info],
    })
    ci = cms.ContentInfo({"content_type": "signed_data", "content": signed_data})
    return ci.dump()


class MockTSA:
    """A TSAClient that mints a valid token offline for whatever digest it's asked."""
    url = "http://mock.tsa.local"
    def __init__(self, gen_time=None):
        self.key, self.cert = _make_tsa()
        self.gen_time = gen_time or datetime(2026, 7, 21, 10, 0, 0, tzinfo=timezone.utc)
    def get_response(self, request_der):
        from asn1crypto import tsp
        req = tsp.TimeStampReq.load(request_der)
        digest = req["message_imprint"]["hashed_message"].native
        token_der = _mint_token(digest, self.gen_time, self.key, self.cert)
        from asn1crypto import cms
        resp = tsp.TimeStampResp({
            "status": tsp.PKIStatusInfo({"status": "granted"}),
            "time_stamp_token": cms.ContentInfo.load(token_der),
        })
        return resp.dump()


def _record():
    signer = ProvenanceSigner.generate()
    fr = FetchResult(url="https://x/p", final_url="https://x/p", status_code=200,
                     content=b"data", content_type="text/html",
                     method=FetchMethod.HTTP, fetched_at=1.0)
    return signer.sign(fr)


# --------------------------------------------------------------------------
# Tests
# --------------------------------------------------------------------------

def test_request_and_verify_valid_token():
    rec = _record()
    digest = digest_for_record(rec)
    token = request_timestamp(digest, MockTSA())
    v = verify_timestamp(token, digest)
    assert v.valid is True
    assert v.imprint_matches and v.signature_valid
    assert v.timestamp == datetime(2026, 7, 21, 10, 0, 0, tzinfo=timezone.utc)


def test_verification_is_explicitly_upper_bound_not_exact():
    rec = _record()
    token = request_timestamp(digest_for_record(rec), MockTSA())
    v = verify_timestamp(token, digest_for_record(rec))
    assert v.is_upper_bound is True
    d = v.to_dict()
    assert "at or BEFORE" in d["proves"]        # cannot be read as exact time
    assert "upper bound" in d["proves"].lower()


def test_token_stored_and_retrievable_roundtrip():
    rec = _record()
    token = request_timestamp(digest_for_record(rec), MockTSA())
    restored = TimestampToken.from_dict(token.to_dict())
    assert restored.token_der == token.token_der
    assert verify_timestamp(restored, digest_for_record(rec)).valid is True


def test_tampered_expected_digest_fails():
    rec = _record()
    token = request_timestamp(digest_for_record(rec), MockTSA())
    v = verify_timestamp(token, b"\x00" * 32)   # wrong digest
    assert v.valid is False and v.imprint_matches is False


def test_tampered_token_bytes_fail():
    rec = _record()
    token = request_timestamp(digest_for_record(rec), MockTSA())
    bad = bytearray(token.token_der)
    bad[-10] ^= 0xFF                             # corrupt the signature region
    v = verify_timestamp(TimestampToken(bytes(bad)), digest_for_record(rec))
    assert v.valid is False


def test_forged_time_fails_signature():
    # An attacker re-signs a token with a different genTime using their OWN key;
    # verification against the (real) embedded cert must fail. Here we mint with a
    # test TSA, then swap the TSTInfo genTime and re-dump WITHOUT re-signing.
    from asn1crypto import cms, tsp, core
    rec = _record()
    token = request_timestamp(digest_for_record(rec), MockTSA())
    ci = cms.ContentInfo.load(token.token_der)
    sd = ci["content"]
    tst = tsp.TSTInfo.load(sd["encap_content_info"]["content"].parsed.dump())
    tst["gen_time"] = datetime(1999, 1, 1, tzinfo=timezone.utc)   # backdate
    sd["encap_content_info"]["content"] = core.ParsableOctetString(tst.dump())
    forged = TimestampToken(ci.dump())
    v = verify_timestamp(forged, digest_for_record(rec))
    assert v.valid is False and v.signature_valid is False


def test_manifest_root_anchoring():
    from inverba.dataset import DatasetBuilder
    signer = ProvenanceSigner.generate()
    b = DatasetBuilder("corpus", signer)
    b.add_all([_record_for(signer, i) for i in range(3)])
    rep = b.build()
    token = temporal.timestamp_manifest(rep.manifest, MockTSA())
    v = verify_timestamp(token, digest_for_manifest_root(rep.manifest.merkle_root))
    assert v.valid is True


def _record_for(signer, i):
    fr = FetchResult(url=f"https://x/{i}", final_url=f"https://x/{i}", status_code=200,
                     content=f"c{i}".encode(), content_type="text/html",
                     method=FetchMethod.HTTP, fetched_at=1.0)
    return signer.sign(fr)


def test_timestamped_record_keeps_signed_record_unchanged():
    rec = _record()
    before = rec.to_dict()
    tr = temporal.timestamp_record(rec, MockTSA())
    assert tr.record.to_dict() == before          # signed record untouched
    assert tr.verify_temporal().valid is True
    assert "temporal_proof" in tr.to_dict()


def test_blockchain_anchoring_is_off_by_default():
    cfg = TemporalConfig()
    assert cfg.blockchain_enabled is False
    assert cfg.blockchain_active() is False
    # even flipping the flag without an anchor stays inactive
    assert TemporalConfig(blockchain_enabled=True).blockchain_active() is False


def test_opentimestamps_is_a_disabled_stub():
    anchor = OpenTimestampsAnchor()
    assert anchor.enabled is False
    with pytest.raises(TemporalError):
        anchor.submit(b"\x00" * 32)
