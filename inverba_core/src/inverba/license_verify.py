"""
Offline license verification (client side).

Verifying a license needs only the issuer PUBLIC key and stdlib crypto, so it
lives in the open core -- anyone can verify a license offline without any
commercial component. Issuing licenses (the private-key side) is a separate
commercial concern; this module is verify-only.

A Inverba build bakes in the trusted issuer public key. `inverba license
verify` checks a token against it (or against a key you pass explicitly),
entirely offline -- no network, no license server.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from typing import Optional

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature


# The issuer public key baked into this build. Replace at release time with the
# real Harrington Crest issuer key. None => verification reports issuer_trusted
# as null (signature is still checked).
BAKED_IN_ISSUER_PUBLIC_KEY: Optional[str] = None


@dataclass
class LicenseCheck:
    valid_signature: bool
    issuer_trusted: Optional[bool]
    expired: Optional[bool]
    tier: Optional[str]
    days_remaining: Optional[float]
    usable: bool
    scope: Optional[str] = None            # "hosted" | "software"
    major_version: Optional[str] = None


def _canonical_bytes(license_dict: dict) -> bytes:
    return json.dumps(license_dict, sort_keys=True, separators=(",", ":")).encode()


def verify_license_token(
    token: str,
    trusted_issuer_public_key: Optional[str] = None,
    now: Optional[float] = None,
) -> LicenseCheck:
    """
    Verify a license token string offline. `trusted_issuer_public_key` defaults
    to the build's baked-in key; pass one explicitly to override.
    """
    if trusted_issuer_public_key is None:
        trusted_issuer_public_key = BAKED_IN_ISSUER_PUBLIC_KEY

    payload = json.loads(token)
    lic = payload["license"]
    signature = payload["signature"]
    issuer_pub = payload["issuer_public_key"]

    check = LicenseCheck(
        valid_signature=False, issuer_trusted=None, expired=None,
        tier=lic.get("tier"), days_remaining=None, usable=False,
        scope=lic.get("scope"), major_version=lic.get("major_version"),
    )

    # 1. signature against the embedded issuer key
    try:
        pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(issuer_pub))
        pub.verify(bytes.fromhex(signature), _canonical_bytes(lic))
        check.valid_signature = True
    except (InvalidSignature, ValueError, KeyError):
        return check

    # 2. is it OUR issuer?
    if trusted_issuer_public_key is not None:
        check.issuer_trusted = (issuer_pub == trusted_issuer_public_key)

    # 3. expiry
    now = now or time.time()
    expires_at = lic.get("expires_at", 0)
    if expires_at == 0:
        check.expired = False
        check.days_remaining = None
    else:
        check.expired = now >= expires_at
        check.days_remaining = max(0.0, (expires_at - now) / 86400.0)

    trusted_ok = check.issuer_trusted in (True, None)
    check.usable = check.valid_signature and trusted_ok and not check.expired
    return check
