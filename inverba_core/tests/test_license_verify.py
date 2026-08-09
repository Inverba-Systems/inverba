import json
import time

from inverba.license_verify import verify_license_token


def make_token(tier="managed", duration_days=365, issuer_pub=None, sign_with=None):
    """Build a signed token using cryptography directly (no cloud dependency)."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization

    sk = sign_with or Ed25519PrivateKey.generate()
    pub = sk.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    ).hex()
    now = time.time()
    lic = {
        "tier": tier, "issued_at": now,
        "expires_at": 0.0 if duration_days <= 0 else now + duration_days * 86400,
        "license_id": "test-id", "quota": None, "holder": None,
        "payment_ref": None, "fmt": "inverba-license/1.0",
    }
    canonical = json.dumps(lic, sort_keys=True, separators=(",", ":")).encode()
    sig = sk.sign(canonical).hex()
    token = json.dumps({"license": lic, "signature": sig, "issuer_public_key": pub})
    return token, pub, sk


def test_valid_license_usable():
    token, pub, _ = make_token()
    result = verify_license_token(token, trusted_issuer_public_key=pub)
    assert result.valid_signature is True
    assert result.issuer_trusted is True
    assert result.usable is True


def test_wrong_issuer_untrusted():
    token, _, _ = make_token()
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization
    other = Ed25519PrivateKey.generate().public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    ).hex()
    result = verify_license_token(token, trusted_issuer_public_key=other)
    assert result.valid_signature is True
    assert result.issuer_trusted is False
    assert result.usable is False


def test_tampered_tier_invalid():
    token, pub, _ = make_token()
    d = json.loads(token)
    d["license"]["tier"] = "enterprise"
    tampered = json.dumps(d)
    result = verify_license_token(tampered, trusted_issuer_public_key=pub)
    assert result.valid_signature is False
    assert result.usable is False


def test_expired_not_usable():
    token, pub, sk = make_token(duration_days=1)
    # verify far in the future
    result = verify_license_token(token, trusted_issuer_public_key=pub, now=time.time() + 10 * 86400)
    assert result.valid_signature is True
    assert result.expired is True
    assert result.usable is False


def test_perpetual_license():
    token, pub, _ = make_token(duration_days=0)
    result = verify_license_token(token, trusted_issuer_public_key=pub)
    assert result.expired is False
    assert result.days_remaining is None
    assert result.usable is True
