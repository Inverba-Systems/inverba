"""
Adversarial test battery.

Every test here is an ATTACK on the honesty architecture: an attempt to make a
record verify, or mislead, where it should not -- or to show a documented limit
actually holding. The battery is the proof behind SECURITY-BATTERY.md; anyone can
run it (`pytest inverba_core/tests/test_adversarial_battery.py`) and reproduce
every result.

Outcome taxonomy (see vault/Adversarial/battery-plan.md):
  - PASS  -- the attack is rejected/flagged, OR it lands on an ALREADY-DOCUMENTED
             limitation (the honesty architecture holding). A test named
             ``*_documented_limit`` asserts the boundary behaviour and states the
             limit in its docstring -- that boundary is a feature, not a defect.
  - FINDING -- an attack that succeeds in a way the docs do not disclose. There
             are none in this file; a FINDING would be a failing assertion, which
             we fix (or honestly re-document) rather than assert around.

Build/report order follows the approved plan: category 6 (malicious-but-authentic
fetcher) and category 5 (replay/handoff) first, as the most likely to surface
P0/P1, then 1, 2, 3, 4, 7, 8. Category numbers are kept for traceability.
"""

from __future__ import annotations

import hashlib

import pytest

from inverba.models import FetchResult, FetchMethod, ProvenanceRecord
from inverba.provenance import (
    ProvenanceSigner,
    verify_record,
    verify_with_corroborations,
    hash_content,
    _signing_payload,
)
from inverba.agent_trust import verify_handoff, TrustVerdict
from inverba.seen import InMemorySeenStore
from inverba.keys import KeyRing, RevocationReason, verify_record_with_keyring
from inverba.merkle import MerkleTree, verify_inclusion, leaf_hash, node_hash
from inverba.ssrf import validate_public_url, is_disallowed_ip, SSRFError
from inverba.blockcheck import detect_block, BlockVerdict


# Ed25519 group order L (RFC 8032). A canonical signature has S < L; verifiers
# MUST reject S >= L. We use it to synthesise non-canonical (malleated) sigs.
ED25519_L = 2 ** 252 + 27742317777372353535851937790883648493


def make_fetch(
    content: bytes = b"<html>hello</html>",
    url: str = "https://example.com/page",
    *,
    status_code: int = 200,
    final_url: str | None = None,
    content_type: str = "text/html",
    fetched_by: str = "native",
    fetched_at: float = 1_700_000_000.0,
) -> FetchResult:
    return FetchResult(
        url=url,
        final_url=final_url if final_url is not None else url,
        status_code=status_code,
        content=content,
        content_type=content_type,
        method=FetchMethod.HTTP,
        fetched_at=fetched_at,
        fetched_by=fetched_by,
    )


def signed_record(signer: ProvenanceSigner | None = None, **kw):
    signer = signer or ProvenanceSigner.generate()
    return signer.sign(make_fetch(**kw)), signer


def _malleate_S(signature_hex: str, addend: int) -> str:
    """Return the record's signature with S replaced by S+addend (mod nothing) --
    a non-canonical encoding of the SAME signature that a correct verifier rejects."""
    sig = bytes.fromhex(signature_hex)
    R, S = sig[:32], sig[32:]
    s2 = int.from_bytes(S, "little") + addend
    assert s2 < 2 ** 256, "malleated S must still fit in 32 bytes for this test"
    return (R + s2.to_bytes(32, "little")).hex()


# ===========================================================================
# CATEGORY 6 -- MALICIOUS-BUT-AUTHENTIC FETCHER  (sequenced first)
# A legitimately-keyed signer that lies about provenance: relaying as first-hand,
# signing a block page as content, or self-corroborating (Sybil).
# ===========================================================================

def test_relay_is_disclosed_not_hidden():
    """A relayed fetch (fetched_by != native) verifies, but the handoff verdict
    surfaces that the signer did NOT observe the origin."""
    rec, _ = signed_record(fetched_by="firecrawl")
    assert verify_record(rec) is True
    v = verify_handoff(rec, rec_content := b"<html>hello</html>" if False else None)  # no content
    v = verify_handoff(rec)
    assert v.independent_observation is False
    assert any("relay" in r or "did not observe" in r for r in v.reasons)


def test_require_independent_observation_rejects_relay():
    """When the caller demands first-hand observation, a relay is UNVERIFIED."""
    rec, _ = signed_record(fetched_by="firecrawl")
    v = verify_handoff(rec, require_independent_observation=True)
    assert v.verdict == TrustVerdict.UNVERIFIED.value
    assert v.trusted is False


def test_relay_cannot_be_upgraded_to_native_without_resigning():
    """The attack: edit fetched_by from a relay label to 'native' to launder a
    relay into a claimed first-hand fetch. fetched_by is signed, so this breaks
    the signature. (P0 surface: this is the field whose meaning matters most.)"""
    rec, _ = signed_record(fetched_by="firecrawl")
    rec.fetched_by = "native"
    assert verify_record(rec) is False


def test_signed_captcha_page_is_flagged_despite_valid_signature():
    """A signer signs a Cloudflare interstitial (HTTP 200, junk body). The math is
    perfect; the content is a lie. verify_handoff must surface the suspected block."""
    captcha = b"<html><title>Just a moment...</title>checking your browser before accessing</html>"
    rec, _ = signed_record(content=captcha)
    assert verify_record(rec) is True
    v = verify_handoff(rec, captcha)
    assert v.suspected_block is True
    assert v.block_signals


def test_signed_block_via_redirect_flagged_from_metadata_alone():
    """Even without the body, a signed redirect to a challenge endpoint is a
    tamper-evident tell the downstream verifier can see."""
    rec, _ = signed_record(final_url="https://example.com/cdn-cgi/challenge/x")
    v = verify_handoff(rec)
    assert v.suspected_block is True


def test_hard_block_non2xx_is_not_clean():
    """A signed 403 must never read as a clean success."""
    bc = detect_block(b"forbidden", status_code=403, url="https://x/", final_url="https://x/")
    assert bc.verdict == BlockVerdict.HARD_BLOCK.value
    assert bc.is_suspicious is True


def test_relay_record_still_binds_content():
    """A relay label does not weaken content binding: fabricated content against a
    valid relay record is CONTENT_MISMATCH."""
    rec, _ = signed_record(content=b"real", fetched_by="firecrawl")
    v = verify_handoff(rec, b"fabricated")
    assert v.verdict == TrustVerdict.CONTENT_MISMATCH.value


def test_self_corroboration_sybil_is_not_proven_independence_documented_limit():
    """DOCUMENTED LIMIT: corroboration proves distinct KEYS signed and agreed on
    content -- NOT that the signers are distinct real-world entities. One operator
    holding two keys can self-corroborate. Inverba surfaces the agreement; it does
    not (and cannot, locally) assert operator independence. That is stated in the
    provenance docs, so this is the architecture holding, not a finding."""
    content = b"<html>same page observed twice</html>"
    primary, _ = signed_record(content=content)
    sybil, _ = signed_record(content=content)          # same operator, second key
    primary.corroborations = [sybil]
    summary = verify_with_corroborations(primary)
    assert summary["primary_valid"] is True
    assert summary["corroboration_count"] == 1
    assert summary["corroborations_agree"] is True     # keys agree on content...
    # ...but the two public keys are simply different; nothing here proves two
    # independent operators. The limit is real and disclosed.
    assert primary.worker_public_key != sybil.worker_public_key


def test_corroboration_with_different_content_does_not_agree():
    """A corroborator that signed DIFFERENT content is reported as not agreeing,
    so collusion can't manufacture false agreement over mismatched bytes."""
    primary, _ = signed_record(content=b"page A")
    other, _ = signed_record(content=b"page B")
    primary.corroborations = [other]
    summary = verify_with_corroborations(primary)
    assert summary["corroborations_agree"] is False


# ===========================================================================
# CATEGORY 5 -- REPLAY & HANDOFF  (sequenced second)
# A valid record is a TRUE statement about a PAST fetch; the attack is passing an
# old true record off as a fresh observation.
# ===========================================================================

def test_first_presentation_trusted_replay_flagged():
    rec, _ = signed_record()
    content = b"<html>hello</html>"
    store = InMemorySeenStore()
    v1 = verify_handoff(rec, content, seen=store)
    assert v1.trusted is True
    v2 = verify_handoff(rec, content, seen=store)
    assert v2.verdict == TrustVerdict.REPLAYED.value
    assert v2.trusted is False


def test_replay_across_two_verifiers_each_accept_once_documented_limit():
    """DOCUMENTED LIMIT: the in-memory store is per-verifier. Two independent
    verifiers each accept the record once; fleet-wide replay defense needs a
    shared backend behind the same interface. Disclosed on SeenStore."""
    rec, _ = signed_record()
    a, b = InMemorySeenStore(), InMemorySeenStore()
    assert verify_handoff(rec, seen=a).trusted is True
    assert verify_handoff(rec, seen=b).trusted is True   # second verifier, first sight


def test_replay_after_ttl_is_forgotten_documented_limit():
    """DOCUMENTED LIMIT: with a TTL, a record replayed after the TTL lapses is no
    longer remembered. Disclosed on SeenStore."""
    clock = {"t": 0.0}
    store = InMemorySeenStore(ttl_seconds=100, clock=lambda: clock["t"])
    rec, _ = signed_record()
    assert verify_handoff(rec, seen=store, now=0.0).trusted is True
    clock["t"] = 500.0
    v = verify_handoff(rec, seen=store, now=rec.fetched_at + 10)
    assert v.verdict != TrustVerdict.REPLAYED.value      # forgotten -> not flagged


def test_forged_record_does_not_poison_the_seen_store():
    """A rejected (forged) record must NOT be recorded as seen -- otherwise an
    attacker could pre-seed a verifier's memory to later suppress a genuine one."""
    rec, _ = signed_record()
    rec.signature = _malleate_S(rec.signature, ED25519_L)   # now invalid
    store = InMemorySeenStore()
    v = verify_handoff(rec, seen=store)
    assert v.verdict == TrustVerdict.UNVERIFIED.value
    assert store.seen(rec.signature) is False


def test_content_mismatch_does_not_poison_the_seen_store():
    """A valid record presented with the WRONG content is rejected before the
    replay check, so it never gets recorded -- a later correct presentation of the
    same record is not falsely flagged as a replay."""
    rec, _ = signed_record(content=b"real")
    store = InMemorySeenStore()
    assert verify_handoff(rec, b"wrong", seen=store).verdict == TrustVerdict.CONTENT_MISMATCH.value
    assert verify_handoff(rec, b"real", seen=store).trusted is True   # first real sighting


def test_stale_record_flagged_and_not_recorded():
    """Freshness is checked before replay: a stale record is STALE and is not
    recorded as seen."""
    rec, _ = signed_record(fetched_at=1_000.0)
    store = InMemorySeenStore()
    v = verify_handoff(rec, seen=store, max_age_seconds=10, now=1_000_000.0)
    assert v.verdict == TrustVerdict.STALE.value
    assert store.seen(rec.signature) is False


def test_malleated_signature_cannot_slip_a_replay_past_the_seen_key():
    """The seen store keys on record.signature. A malleated variant of a valid
    signature is a DIFFERENT string, but it fails verify_record (canonical-S
    enforced), so it is rejected before the replay check and cannot register as a
    distinct record. Pins the invariant the seen-cache safety argument relies on."""
    rec, _ = signed_record()
    good_sig = rec.signature
    rec.signature = _malleate_S(good_sig, ED25519_L)
    assert rec.signature != good_sig
    assert verify_record(rec) is False


# ===========================================================================
# CATEGORY 1 -- CANONICALIZATION & ENCODING ABUSE
# Two distinct inputs -> one signed payload, or a tampered record verifies.
# ===========================================================================

def test_field_separator_ambiguity_is_closed():
    """The historical B2 bug: a delimiter-joined payload let (final_url='a',
    content_type='b') and (final_url='a|b', content_type='') sign identical bytes.
    The keyed-JSON payload gives them distinct bytes."""
    p1 = _signing_payload("https://x", "h", 1.0, "native", 200, "a", "b")
    p2 = _signing_payload("https://x", "h", 1.0, "native", 200, "a|b", "")
    assert p1 != p2


def test_no_content_normalization_nfc_vs_nfd_documented_limit():
    """DOCUMENTED: content is hashed as raw bytes, no Unicode normalization. NFC
    and NFD encodings of the same text are DIFFERENT bytes and produce different
    records -- a record for one does not verify the other. Inverba binds exact
    bytes; it does not claim semantic equivalence."""
    nfc = "café".encode("utf-8")            # é as U+00E9
    nfd = "café".encode("utf-8")      # e + combining acute
    assert nfc != nfd
    rec, _ = signed_record(content=nfc)
    assert verify_handoff(rec, nfc).trusted is True
    assert verify_handoff(rec, nfd).verdict == TrustVerdict.CONTENT_MISMATCH.value


def test_url_homoglyph_produces_a_distinct_record_documented_limit():
    """DOCUMENTED: a Cyrillic-'а' URL and a Latin-'a' URL are different byte
    strings and sign differently. Inverba binds the exact URL bytes; detecting
    visual homoglyph confusability is out of scope, stated plainly."""
    latin = _signing_payload("https://exampla.com", "h", 1.0, "native", 200, "", "")
    cyr = _signing_payload("https://exаmpla.com", "h", 1.0, "native", 200, "", "")
    assert latin != cyr


def test_trailing_byte_changes_the_hash():
    a = hash_content(b"<html>x</html>")
    b = hash_content(b"<html>x</html>\n")
    assert a != b


def test_bom_prefix_changes_the_hash():
    assert hash_content(b"hi") != hash_content(b"\xef\xbb\xbfhi")


def test_tamper_url_breaks_signature():
    rec, _ = signed_record()
    rec.url = "https://evil.example.com/page"
    assert verify_record(rec) is False


def test_tamper_content_hash_breaks_signature():
    rec, _ = signed_record()
    rec.content_hash = hashlib.sha256(b"different").hexdigest()
    assert verify_record(rec) is False


def test_tamper_fetched_at_breaks_signature():
    rec, _ = signed_record()
    rec.fetched_at = rec.fetched_at + 1
    assert verify_record(rec) is False


def test_tamper_status_code_breaks_signature():
    """Bot-wall evidence (status) is signed and cannot be stripped."""
    rec, _ = signed_record(status_code=403)
    rec.status_code = 200
    assert verify_record(rec) is False


def test_tamper_final_url_breaks_signature():
    rec, _ = signed_record(final_url="https://example.com/cdn-cgi/challenge/x")
    rec.final_url = ""
    assert verify_record(rec) is False


def test_tamper_content_type_breaks_signature():
    rec, _ = signed_record(content_type="text/html")
    rec.content_type = "application/json"
    assert verify_record(rec) is False


def test_invalid_utf8_content_hashes_and_verifies():
    """Raw bytes are hashed; invalid UTF-8 must not crash signing or verification."""
    rec, _ = signed_record(content=b"\xff\xfe\x00\x80not utf8")
    assert verify_record(rec) is True


def test_empty_content_signs_and_verifies():
    rec, _ = signed_record(content=b"")
    assert verify_record(rec) is True
    assert rec.content_hash == hashlib.sha256(b"").hexdigest()


def test_signing_payload_is_deterministic():
    """Same inputs -> identical signed bytes (canonical JSON, sorted keys)."""
    a = _signing_payload("https://x", "h", 1.5, "native", 200, "", "text/html")
    b = _signing_payload("https://x", "h", 1.5, "native", 200, "", "text/html")
    assert a == b


def test_numeric_form_of_fetched_at_is_part_of_signed_bytes():
    """int vs float fetched_at serialize differently, so they are distinct signed
    payloads. (The JSON payload's number form is why IRF/1 moves to deterministic
    CBOR for cross-language exactness; noted in the spec.)"""
    assert _signing_payload("u", "h", 1700000000, "native", 200, "", "") != \
        _signing_payload("u", "h", 1700000000.0, "native", 200, "", "")


# ===========================================================================
# CATEGORY 2 -- SIGNATURE MALLEABILITY & CRYPTO EDGE
# ===========================================================================

def test_noncanonical_S_plus_L_rejected():
    rec, _ = signed_record()
    rec.signature = _malleate_S(rec.signature, ED25519_L)
    assert verify_record(rec) is False


def test_noncanonical_S_plus_2L_rejected():
    rec, _ = signed_record()
    rec.signature = _malleate_S(rec.signature, 2 * ED25519_L)
    assert verify_record(rec) is False


def test_high_bit_set_in_S_rejected():
    rec, _ = signed_record()
    sig = bytearray(bytes.fromhex(rec.signature))
    sig[63] |= 0x80                      # forces S >= 2^255 > L -> non-canonical
    rec.signature = bytes(sig).hex()
    assert verify_record(rec) is False


def test_flipped_bit_in_signature_rejected():
    rec, _ = signed_record()
    sig = bytearray(bytes.fromhex(rec.signature))
    sig[0] ^= 0x01
    rec.signature = bytes(sig).hex()
    assert verify_record(rec) is False


def test_truncated_signature_rejected():
    rec, _ = signed_record()
    rec.signature = rec.signature[:-4]
    assert verify_record(rec) is False


def test_oversized_signature_rejected():
    rec, _ = signed_record()
    rec.signature = rec.signature + "00"
    assert verify_record(rec) is False


def test_empty_signature_rejected():
    rec, _ = signed_record()
    rec.signature = ""
    assert verify_record(rec) is False


def test_all_zero_signature_rejected():
    rec, _ = signed_record()
    rec.signature = "00" * 64
    assert verify_record(rec) is False


def test_non_hex_signature_rejected():
    rec, _ = signed_record()
    rec.signature = "zz" * 64
    assert verify_record(rec) is False


def test_wrong_public_key_rejected():
    rec, _ = signed_record()
    other = ProvenanceSigner.generate()
    rec.worker_public_key = other.public_key_hex()
    assert verify_record(rec) is False


def test_non_hex_public_key_rejected():
    rec, _ = signed_record()
    rec.worker_public_key = "nothex"
    assert verify_record(rec) is False


def test_wrong_length_public_key_rejected():
    rec, _ = signed_record()
    rec.worker_public_key = "00" * 16      # 16 bytes, not 32
    assert verify_record(rec) is False


def test_signature_from_another_record_rejected():
    """A valid signature lifted from record A does not verify record B, even under
    the same key -- the signature binds the payload, not just the key."""
    signer = ProvenanceSigner.generate()
    a, _ = signed_record(signer, content=b"page A")
    b, _ = signed_record(signer, content=b"page B")
    b.signature = a.signature
    assert verify_record(b) is False


# ===========================================================================
# CATEGORY 3 -- KEY-HISTORY / LIFECYCLE ATTACKS
# ===========================================================================

def _ring_with_key(signer, created_at):
    ring = KeyRing("identity")
    ring.add_root(signer, created_at=created_at)
    return ring


def test_rotated_key_prior_records_stay_valid():
    """Rotation is hygiene, not compromise: records signed before rotation remain
    trusted forever."""
    old = ProvenanceSigner.generate()
    ring = _ring_with_key(old, created_at=100.0)
    rec, _ = signed_record(old, fetched_at=150.0)
    new = ProvenanceSigner.generate()
    ring.rotate(old, new, at=200.0)
    trust = verify_record_with_keyring(rec, ring)
    assert trust.trusted is True


def test_compromised_key_signature_inside_window_rejected():
    """A signature made at/after the compromise instant could have been forged by
    the attacker -- not trusted."""
    key = ProvenanceSigner.generate()
    ring = _ring_with_key(key, created_at=10.0)
    rec, _ = signed_record(key, fetched_at=100.0)
    ring.revoke(key.public_key_hex(), RevocationReason.COMPROMISED,
                effective_at=50.0, attesting_signer=key)
    trust = verify_record_with_keyring(rec, ring)
    assert trust.trusted is False
    assert trust.signature_valid is True     # math fine; lifecycle is the problem


def test_compromised_key_signature_before_window_trusted():
    key = ProvenanceSigner.generate()
    ring = _ring_with_key(key, created_at=10.0)
    rec, _ = signed_record(key, fetched_at=40.0)
    ring.revoke(key.public_key_hex(), RevocationReason.COMPROMISED,
                effective_at=50.0, attesting_signer=key)
    assert verify_record_with_keyring(rec, ring).trusted is True


def test_unknown_key_not_trusted():
    key = ProvenanceSigner.generate()
    empty = KeyRing("identity")
    rec, _ = signed_record(key)
    trust = verify_record_with_keyring(rec, empty)
    assert trust.key_known is False
    assert trust.trusted is False


def test_record_predating_key_creation_rejected():
    key = ProvenanceSigner.generate()
    ring = _ring_with_key(key, created_at=1_000.0)
    rec, _ = signed_record(key, fetched_at=500.0)     # before the key existed
    assert verify_record_with_keyring(rec, ring).trusted is False


def test_valid_rotation_chain_verifies():
    old = ProvenanceSigner.generate()
    ring = _ring_with_key(old, created_at=100.0)
    new = ProvenanceSigner.generate()
    ring.rotate(old, new, at=200.0)
    report = ring.verify_chain()
    assert report["valid"] is True


def test_forged_rotation_predecessor_signature_detected():
    old = ProvenanceSigner.generate()
    ring = _ring_with_key(old, created_at=100.0)
    new = ProvenanceSigner.generate()
    ring.rotate(old, new, at=200.0)
    new_entry = ring.find(new.public_key_hex())
    new_entry.predecessor_signature = "00" * 64      # forged authorization
    report = ring.verify_chain()
    assert report["valid"] is False
    assert any("predecessor" in p for p in report["problems"])


def test_revocation_attested_by_outside_key_flagged():
    key = ProvenanceSigner.generate()
    ring = _ring_with_key(key, created_at=10.0)
    stranger = ProvenanceSigner.generate()           # not in the ring
    ring.revoke(key.public_key_hex(), RevocationReason.COMPROMISED,
                effective_at=50.0, attesting_signer=stranger)
    report = ring.verify_chain()
    assert report["valid"] is False


def test_compromise_self_attested_warns():
    """A compromised key cannot be trusted to describe its own compromise; the
    chain report warns rather than silently trusting it."""
    key = ProvenanceSigner.generate()
    ring = _ring_with_key(key, created_at=10.0)
    ring.revoke(key.public_key_hex(), RevocationReason.COMPROMISED,
                effective_at=50.0, attesting_signer=key)
    report = ring.verify_chain()
    assert any("self-attested" in w for w in report["warnings"])


def test_verify_handoff_with_keyring_rejects_compromised_window_record():
    key = ProvenanceSigner.generate()
    ring = _ring_with_key(key, created_at=10.0)
    rec, _ = signed_record(key, content=b"data", fetched_at=100.0)
    ring.revoke(key.public_key_hex(), RevocationReason.COMPROMISED,
                effective_at=50.0, attesting_signer=key)
    v = verify_handoff(rec, b"data", keyring=ring)
    assert v.verdict == TrustVerdict.UNVERIFIED.value


def test_without_keyring_only_math_is_checked_documented_limit():
    """DOCUMENTED LIMIT: without a keyring, verify_handoff can only check the
    signature math -- a compromised-window record still reads as TRUSTED. Supplying
    a keyring is what upgrades the check to lifecycle-aware; disclosed in the docs."""
    key = ProvenanceSigner.generate()
    rec, _ = signed_record(key, content=b"data", fetched_at=100.0)
    v = verify_handoff(rec, b"data")     # no keyring
    assert v.trusted is True


# ===========================================================================
# CATEGORY 4 -- URL / REDIRECT / FETCH-BOUNDARY ABUSE (incl. notary SSRF)
# ===========================================================================

def _resolver(*ips):
    return lambda host: list(ips)


def test_ssrf_blocks_cloud_metadata_ip():
    with pytest.raises(SSRFError):
        validate_public_url("http://metadata.example/", resolver=_resolver("169.254.169.254"))


def test_ssrf_blocks_decimal_encoded_metadata():
    """http://2852039166/ is the decimal form of 169.254.169.254. Validating the
    RESOLVED address catches every string-encoding, not a blacklist of formats."""
    with pytest.raises(SSRFError):
        validate_public_url("http://2852039166/", resolver=_resolver("169.254.169.254"))


def test_ssrf_blocks_ipv4_mapped_ipv6():
    with pytest.raises(SSRFError):
        validate_public_url("http://x/", resolver=_resolver("::ffff:169.254.169.254"))


def test_ssrf_blocks_loopback():
    with pytest.raises(SSRFError):
        validate_public_url("http://x/", resolver=_resolver("127.0.0.1"))


def test_ssrf_blocks_private_ranges():
    for ip in ("10.0.0.5", "192.168.250.250", "172.16.0.1"):
        with pytest.raises(SSRFError):
            validate_public_url("http://x/", resolver=_resolver(ip))


def test_ssrf_blocks_link_local():
    with pytest.raises(SSRFError):
        validate_public_url("http://x/", resolver=_resolver("169.254.1.1"))


def test_ssrf_any_private_in_a_set_blocks_the_whole_url():
    """If a host resolves to BOTH a public and a private address, it is blocked --
    a DNS trick can't smuggle a private target behind one public answer."""
    with pytest.raises(SSRFError):
        validate_public_url("http://x/", resolver=_resolver("8.8.8.8", "10.0.0.1"))


def test_ssrf_missing_host_rejected():
    with pytest.raises(SSRFError):
        validate_public_url("not-a-url", resolver=_resolver("8.8.8.8"))


def test_ssrf_allows_genuinely_public_address():
    ips = validate_public_url("http://x/", resolver=_resolver("8.8.8.8"))
    assert ips == ["8.8.8.8"]


def test_ssrf_exposes_validated_ips_for_pinning_documented_limit():
    """DOCUMENTED LIMIT: a residual DNS-rebinding TOCTOU window exists because the
    HTTP client re-resolves on connect. validate_public_url RETURNS the validated
    IPs so a caller that can connect-by-IP may pin and close the window; where it
    can't, network-layer egress controls are the backstop. Disclosed in ssrf.py."""
    ips = validate_public_url("http://x/", resolver=_resolver("8.8.8.8"))
    assert ips == ["8.8.8.8"]      # the caller has what it needs to pin


def test_ipv4_mapped_metadata_detected_directly():
    assert is_disallowed_ip("::ffff:169.254.169.254") is True
    assert is_disallowed_ip("8.8.8.8") is False


def test_redirect_to_challenge_endpoint_detected():
    bc = detect_block(b"<html>ok</html>", status_code=200,
                      url="https://site/", final_url="https://site/cdn-cgi/challenge/1")
    assert bc.is_suspicious is True


# ===========================================================================
# CATEGORY 7 -- MANIFEST / MERKLE / CORPUS ABUSE
# ===========================================================================

def _tree(*leaves):
    t = MerkleTree()
    for l in leaves:
        t.append(l)
    return t


def test_inclusion_proofs_verify_for_every_leaf():
    leaves = [f"record-{i}".encode() for i in range(7)]
    t = _tree(*leaves)
    root = t.root_hex()
    for i in range(len(leaves)):
        assert verify_inclusion(t.inclusion_proof(i), root) is True


def test_tampered_leaf_hash_fails():
    t = _tree(b"a", b"b", b"c", b"d")
    proof = t.inclusion_proof(2)
    proof.leaf_hash = leaf_hash(b"forged").hex()
    assert verify_inclusion(proof, t.root_hex()) is False


def test_tampered_audit_path_fails():
    t = _tree(b"a", b"b", b"c", b"d")
    proof = t.inclusion_proof(1)
    proof.audit_path[0] = leaf_hash(b"forged").hex()
    assert verify_inclusion(proof, t.root_hex()) is False


def test_flipped_path_side_fails():
    t = _tree(b"a", b"b", b"c", b"d")
    proof = t.inclusion_proof(1)
    proof.path_sides[0] = not proof.path_sides[0]
    assert verify_inclusion(proof, t.root_hex()) is False


def test_wrong_root_fails():
    t = _tree(b"a", b"b", b"c")
    other = _tree(b"x", b"y", b"z")
    assert verify_inclusion(t.inclusion_proof(0), other.root_hex()) is False


def test_cross_tree_proof_reuse_fails():
    t1 = _tree(b"a", b"b", b"c", b"d")
    t2 = _tree(b"a", b"b", b"c", b"e")    # differs only in last leaf
    assert verify_inclusion(t1.inclusion_proof(3), t2.root_hex()) is False


def test_leaf_cannot_masquerade_as_internal_node_second_preimage():
    """RFC 6962 domain separation: leaves are prefixed 0x00, internal nodes 0x01.
    An attacker cannot present the concatenation of two children as a single leaf
    whose hash equals their parent node."""
    la, lb = leaf_hash(b"a"), leaf_hash(b"b")
    parent = node_hash(la, lb)
    assert leaf_hash(la + lb) != parent


def test_empty_and_single_leaf_roots_well_defined():
    assert MerkleTree().root() == hashlib.sha256(b"").digest()
    single = _tree(b"only")
    assert single.root() == leaf_hash(b"only")
    assert single.inclusion_proof(0).audit_path == []


def test_inclusion_proof_does_not_bind_tree_size_documented_limit():
    """DOCUMENTED LIMIT: an inclusion proof proves a leaf is IN a tree with a given
    root; it does not, by itself, bind the tree's total SIZE (verify_inclusion
    recomputes the root and ignores the claimed tree_size). Binding size/append-
    only history is the job of a consistency proof against a published log, which
    the transparency log provides -- not a single inclusion proof. Disclosed."""
    t = _tree(b"a", b"b", b"c", b"d")
    proof = t.inclusion_proof(1)
    proof.tree_size = 999999             # lie about the corpus size
    assert verify_inclusion(proof, t.root_hex()) is True   # still structurally valid


# ===========================================================================
# CATEGORY 8 -- TEMPORAL / RFC 3161 ABUSE
# ===========================================================================

from inverba.temporal import (           # noqa: E402  (grouped with its category)
    digest_for_record,
    digest_for_manifest_root,
    TimestampToken,
    TemporalError,
    TimestampVerification,
)


def test_temporal_anchor_binds_the_exact_signature():
    """The temporal digest hashes the record's SIGNATURE (which covers every signed
    field). Backdating a record means re-signing it, which changes the signature
    and therefore the anchor -- an old token cannot cover a rewritten record."""
    a, signer = signed_record(fetched_at=1000.0)
    b, _ = signed_record(signer, fetched_at=2000.0)    # "backdated"/re-signed
    assert digest_for_record(a) != digest_for_record(b)


def test_temporal_record_without_signature_cannot_anchor():
    rec, _ = signed_record()
    rec.signature = ""
    with pytest.raises(TemporalError):
        digest_for_record(rec)


def test_manifest_root_must_be_32_bytes():
    with pytest.raises(TemporalError):
        digest_for_manifest_root(("00" * 31))          # 31 bytes


def test_manifest_root_accepts_valid_sha256():
    root = hashlib.sha256(b"root").hexdigest()
    assert len(digest_for_manifest_root(root)) == 32


def test_timestamp_token_from_dict_rejects_unknown_format():
    with pytest.raises(TemporalError):
        TimestampToken.from_dict({"format": "not-rfc3161", "token_b64": ""})


def test_timestamp_verification_is_always_an_upper_bound_documented_limit():
    """DOCUMENTED LIMIT: an RFC 3161 token proves a hash existed AT OR BEFORE the
    TSA's genTime -- an upper bound, never the exact observation time; fetched_at
    stays self-asserted. is_upper_bound is structurally always True."""
    v = TimestampVerification(valid=True, timestamp=None, imprint_matches=True,
                              signature_valid=True)
    assert v.is_upper_bound is True
    assert "BEFORE" in v.to_dict()["proves"]


def test_malformed_timestamp_token_rejected():
    """A garbage token is rejected, not accepted as a valid anchor. Needs the
    optional [temporal] extra (asn1crypto)."""
    pytest.importorskip("asn1crypto")
    from inverba.temporal import verify_timestamp
    result = verify_timestamp(TimestampToken(token_der=b"not a real token"),
                              expected_digest=hashlib.sha256(b"x").digest())
    assert result.valid is False
