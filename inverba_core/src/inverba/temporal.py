"""
Temporal proof — RFC 3161 trusted timestamping (optional, additive).

`fetched_at` on a provenance record is SELF-ASSERTED: the signer's own claim about
when they observed something. This module adds an *independent* temporal anchor by
submitting a record's (or a manifest root's) hash to an RFC 3161 Timestamping
Authority (TSA) and storing the returned signed token ALONGSIDE the record. That
token proves the hash existed **at or before** the TSA's timestamp — an
un-backdatable UPPER BOUND, not the exact time.

What it proves vs. what it does not:
  - PROVES: "this hash was submitted to the TSA no later than T" (upper bound),
    verifiable offline against the TSA's certificate.
  - DOES NOT prove exact observation time; `fetched_at` stays self-asserted.
  - The trust shifts from "trust the fetcher's clock" to "trust a standard,
    court-accepted third party (the TSA)" — a different and weaker assumption than
    trusting the fetcher, which is the whole point.

Design constraints (deliberate):
  - The signed provenance record and `_signing_payload` are NOT modified. The token
    is attached alongside (the record was signed BEFORE it could be timestamped —
    that ordering is correct).
  - TSA calls are live network but injectable (`TSAClient`), so tests stay offline.
  - Requires the optional `[temporal]` extra (asn1crypto); imported lazily.
"""
from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, Protocol


class TemporalError(Exception):
    """Temporal-proof construction/verification error."""


def _require_asn1():
    try:
        from asn1crypto import tsp, cms, algos, core, x509  # noqa
    except ImportError as e:  # pragma: no cover - env-dependent
        raise TemporalError(
            "RFC 3161 temporal proof needs the optional dependency asn1crypto. "
            "Install it with:  pip install 'inverba-core[temporal]'"
        ) from e
    from asn1crypto import tsp, cms, algos, core, x509
    return tsp, cms, algos, core, x509


# --------------------------------------------------------------------------
# Digests to anchor
# --------------------------------------------------------------------------

def digest_for_record(record) -> bytes:
    """The 32-byte sha256 anchor for a signed provenance record.

    Hashes the record's signature (which itself covers every signed field), so the
    timestamp binds THIS exact signed record, not merely its content."""
    sig = getattr(record, "signature", None)
    if not sig:
        raise TemporalError("record has no signature to anchor")
    return hashlib.sha256(bytes.fromhex(sig)).digest()


def digest_for_manifest_root(merkle_root_hex: str) -> bytes:
    """The 32-byte anchor for a dataset manifest: its Merkle root (already a
    sha256). We timestamp the root directly, per common Merkle-anchoring practice."""
    raw = bytes.fromhex(merkle_root_hex)
    if len(raw) != 32:
        raise TemporalError("merkle_root is not a 32-byte sha256 hex digest")
    return raw


# --------------------------------------------------------------------------
# TSA client (injectable so tests stay offline)
# --------------------------------------------------------------------------

# A well-known free RFC 3161 TSA. Swappable: point at your own for sovereignty.
DEFAULT_TSA_URL = "http://timestamp.digicert.com"


class TSAClient(Protocol):
    """Sends a DER TimeStampReq, returns the DER TimeStampResp bytes."""
    def get_response(self, request_der: bytes) -> bytes: ...


@dataclass
class HTTPTSAClient:
    """Real RFC 3161 client over HTTP. Injected in production; tests mock it."""
    url: str = DEFAULT_TSA_URL
    timeout: float = 20.0

    def get_response(self, request_der: bytes) -> bytes:
        import httpx
        r = httpx.post(
            self.url, content=request_der,
            headers={"Content-Type": "application/timestamp-query"},
            timeout=self.timeout,
        )
        r.raise_for_status()
        return r.content


def build_timestamp_request(digest: bytes, *, hash_algo: str = "sha256",
                            nonce: Optional[int] = None, cert_req: bool = True) -> bytes:
    """Build a DER-encoded RFC 3161 TimeStampReq for a 32-byte digest."""
    tsp, cms, algos, core, x509 = _require_asn1()
    if len(digest) != hashlib.new(hash_algo).digest_size:
        raise TemporalError(f"digest length {len(digest)} != {hash_algo} size")
    req = tsp.TimeStampReq({
        "version": 1,
        "message_imprint": tsp.MessageImprint({
            "hash_algorithm": algos.DigestAlgorithm({"algorithm": hash_algo}),
            "hashed_message": digest,
        }),
        "cert_req": cert_req,
    })
    if nonce is not None:
        req["nonce"] = nonce
    return req.dump()


# --------------------------------------------------------------------------
# Token: the stored proof
# --------------------------------------------------------------------------

@dataclass
class TimestampToken:
    """An RFC 3161 TimeStampToken (a CMS ContentInfo), stored alongside a record."""
    token_der: bytes
    tsa_url: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "format": "rfc3161",
            "token_b64": base64.b64encode(self.token_der).decode("ascii"),
            "tsa_url": self.tsa_url,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "TimestampToken":
        if d.get("format") != "rfc3161":
            raise TemporalError(f"unknown temporal-proof format: {d.get('format')}")
        return cls(token_der=base64.b64decode(d["token_b64"]), tsa_url=d.get("tsa_url"))

    # -- parsed views --
    def _signed_data(self):
        tsp, cms, algos, core, x509 = _require_asn1()
        ci = cms.ContentInfo.load(self.token_der)
        if ci["content_type"].native != "signed_data":
            raise TemporalError("token is not a CMS SignedData")
        return ci["content"]

    def tst_info(self):
        sd = self._signed_data()
        eci = sd["encap_content_info"]
        if eci["content_type"].native != "tst_info":
            raise TemporalError("encapsulated content is not a TSTInfo")
        tsp, cms, algos, core, x509 = _require_asn1()
        return tsp.TSTInfo.load(eci["content"].parsed.dump())

    def gen_time(self) -> datetime:
        return self.tst_info()["gen_time"].native

    def message_imprint(self) -> bytes:
        return self.tst_info()["message_imprint"]["hashed_message"].native


def request_timestamp(digest: bytes, client: TSAClient, *,
                      tsa_url: Optional[str] = None) -> TimestampToken:
    """Anchor a digest: send a request, return the TimeStampToken. Live network
    happens inside `client`; pass a mock in tests."""
    tsp, cms, algos, core, x509 = _require_asn1()
    request_der = build_timestamp_request(digest)
    resp_der = client.get_response(request_der)
    resp = tsp.TimeStampResp.load(resp_der)
    status = resp["status"]["status"].native
    if status not in ("granted", "granted_with_mods"):
        raise TemporalError(f"TSA refused the timestamp: status={status}")
    token = resp["time_stamp_token"]
    return TimestampToken(token_der=token.dump(),
                          tsa_url=tsa_url or getattr(client, "url", None))


# --------------------------------------------------------------------------
# Verification (offline, given the token; only NEW tokens need the TSA)
# --------------------------------------------------------------------------

@dataclass
class TimestampVerification:
    """Result of verifying a timestamp token. `is_upper_bound` is ALWAYS True:
    the timestamp proves the data existed AT OR BEFORE `timestamp`, never the
    exact time. Read `trusted` only together with that caveat."""
    valid: bool
    timestamp: Optional[datetime]
    imprint_matches: bool
    signature_valid: bool
    is_upper_bound: bool = True
    reason: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "valid": self.valid,
            "proves": "hash existed at or BEFORE this time (upper bound, not exact)",
            "timestamp_upper_bound": self.timestamp.isoformat() if self.timestamp else None,
            "imprint_matches": self.imprint_matches,
            "signature_valid": self.signature_valid,
            "is_upper_bound": self.is_upper_bound,
            "reason": self.reason,
        }


def _signer_cert(signed_data, signer_info, x509):
    """Find the signer's certificate in the token by issuer+serial."""
    sid = signer_info["sid"]
    if sid.name != "issuer_and_serial_number":
        return None
    want_issuer = sid.chosen["issuer"]
    want_serial = sid.chosen["serial_number"].native
    for choice in signed_data["certificates"]:
        cert = choice.chosen
        if (cert.issuer == want_issuer and
                cert["tbs_certificate"]["serial_number"].native == want_serial):
            return cert
    return None


def _verify_signature(cert_der: bytes, signed_attrs_der: bytes, signature: bytes,
                      digest_algo: str) -> bool:
    from cryptography import x509 as cx509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding, rsa, ec, ed25519
    from cryptography.exceptions import InvalidSignature
    cert = cx509.load_der_x509_certificate(cert_der)
    pub = cert.public_key()
    halg = {"sha256": hashes.SHA256(), "sha384": hashes.SHA384(),
            "sha512": hashes.SHA512(), "sha1": hashes.SHA1()}.get(digest_algo)
    if halg is None:
        raise TemporalError(f"unsupported digest algorithm: {digest_algo}")
    try:
        if isinstance(pub, rsa.RSAPublicKey):
            pub.verify(signature, signed_attrs_der, padding.PKCS1v15(), halg)
        elif isinstance(pub, ec.EllipticCurvePublicKey):
            pub.verify(signature, signed_attrs_der, ec.ECDSA(halg))
        elif isinstance(pub, ed25519.Ed25519PublicKey):
            pub.verify(signature, signed_attrs_der)
        else:
            raise TemporalError(f"unsupported TSA key type: {type(pub).__name__}")
        return True
    except InvalidSignature:
        return False


def verify_timestamp(token: TimestampToken, expected_digest: bytes) -> TimestampVerification:
    """Verify an RFC 3161 token offline. Confirms (a) the token's message imprint
    is `expected_digest`, and (b) the TSA's signature over the token is valid, so
    the genTime is an authentic UPPER BOUND on when `expected_digest` existed.

    NOTE: this verifies the token's own signature against the embedded TSA cert. It
    does NOT perform full X.509 chain validation to a trusted root — supply and
    pin the TSA root out of band for that. Stated plainly, not glossed."""
    tsp, cms, algos, core, x509 = _require_asn1()
    try:
        sd = token._signed_data()
        eci = sd["encap_content_info"]
        tst = tsp.TSTInfo.load(eci["content"].parsed.dump())
        imprint = tst["message_imprint"]["hashed_message"].native
        gen_time = tst["gen_time"].native
    except Exception as e:
        return TimestampVerification(False, None, False, False, reason=f"malformed token: {e}")

    imprint_matches = (imprint == expected_digest)

    # Verify the CMS signature over the signed attributes.
    sig_valid = False
    reason = None
    try:
        signer_info = sd["signer_infos"][0]
        signed_attrs = signer_info["signed_attrs"]
        if not signed_attrs or len(signed_attrs) == 0:
            reason = "token has no signed attributes"
        else:
            # message-digest signed attr must equal hash(eContent)
            digest_algo = signer_info["digest_algorithm"]["algorithm"].native
            econtent = eci["content"].parsed.dump()
            md_attr = next((a for a in signed_attrs if a["type"].native == "message_digest"), None)
            ct_attr = next((a for a in signed_attrs if a["type"].native == "content_type"), None)
            content_hash = hashlib.new(digest_algo, econtent).digest()
            md_ok = md_attr is not None and md_attr["values"][0].native == content_hash
            ct_ok = ct_attr is not None and ct_attr["values"][0].native == "tst_info"
            if not md_ok:
                reason = "message-digest attribute does not match the TSTInfo content"
            elif not ct_ok:
                reason = "content-type attribute is not tst_info"
            else:
                # signature is over the DER SET-OF of signed attrs (tag 0x31),
                # not the [0] IMPLICIT tag (0xA0) they carry in the structure.
                attrs_der = bytearray(signed_attrs.dump())
                attrs_der[0] = 0x31
                cert = _signer_cert(sd, signer_info, x509)
                if cert is None:
                    reason = "signer certificate not present in the token"
                else:
                    sig_valid = _verify_signature(
                        cert.dump(), bytes(attrs_der),
                        signer_info["signature"].native, digest_algo)
                    if not sig_valid:
                        reason = "TSA signature is invalid"
    except Exception as e:
        reason = f"signature verification error: {e}"

    valid = imprint_matches and sig_valid
    if valid:
        reason = "authentic TSA timestamp; proves the hash existed at or before genTime"
    elif not imprint_matches and reason is None:
        reason = "token's message imprint does not match the expected digest"
    return TimestampVerification(
        valid=valid, timestamp=gen_time, imprint_matches=imprint_matches,
        signature_valid=sig_valid, reason=reason,
    )


# --------------------------------------------------------------------------
# Attaching proof alongside records / manifests (NOT into the signed payload)
# --------------------------------------------------------------------------

def timestamp_record(record, client: TSAClient) -> "TimestampedRecord":
    """Anchor a signed record's identity and return it wrapped with the token
    alongside — the signed record is unchanged."""
    token = request_timestamp(digest_for_record(record), client)
    return TimestampedRecord(record=record, token=token)


def timestamp_manifest(manifest, client: TSAClient) -> TimestampToken:
    """Anchor a dataset manifest's Merkle root. Returns the token to store
    alongside the manifest (the manifest is unchanged)."""
    return request_timestamp(digest_for_manifest_root(manifest.merkle_root), client)


@dataclass
class TimestampedRecord:
    """A provenance record plus an RFC 3161 token, stored side by side. The record
    itself is byte-for-byte the original signed record."""
    record: object
    token: TimestampToken

    def to_dict(self) -> dict:
        return {"record": self.record.to_dict(), "temporal_proof": self.token.to_dict()}

    def verify_temporal(self) -> TimestampVerification:
        return verify_timestamp(self.token, digest_for_record(self.record))


# --------------------------------------------------------------------------
# Blockchain anchoring — pluggable interface, DEFAULT OFF (no coin, no keys)
# --------------------------------------------------------------------------

class BlockchainAnchor(Protocol):
    """Interface for anchoring a root hash to a public chain (e.g. Bitcoin via
    OpenTimestamps) for the fully-trustless case. Intentionally NOT wired on by
    default — RFC 3161 is the real path; this is a future option that must never
    put crypto/coin/key handling into the default experience."""
    def submit(self, digest: bytes) -> bytes: ...
    def verify(self, digest: bytes, proof: bytes) -> bool: ...


@dataclass
class TemporalConfig:
    """Temporal-proof configuration. Blockchain anchoring is OFF by default and
    stays off unless a caller both flips the flag AND supplies an anchor."""
    tsa_url: str = DEFAULT_TSA_URL
    blockchain_enabled: bool = False
    blockchain_anchor: Optional[BlockchainAnchor] = None

    def blockchain_active(self) -> bool:
        return bool(self.blockchain_enabled and self.blockchain_anchor is not None)


class OpenTimestampsAnchor:
    """STUB. OpenTimestamps (Bitcoin) anchor — interface only, deliberately not
    implemented. Building it means no coin, no keys, no wallet in this codebase;
    it stays a documented future option so the grift-perception risk stays out of
    the default experience."""
    enabled = False

    def submit(self, digest: bytes) -> bytes:
        raise TemporalError(
            "OpenTimestamps anchoring is not implemented — RFC 3161 is the "
            "supported path. Blockchain anchoring is a future, opt-in option.")

    def verify(self, digest: bytes, proof: bytes) -> bool:
        raise TemporalError("OpenTimestamps anchoring is not implemented.")
