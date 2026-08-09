import time

from inverba.provenance import ProvenanceSigner
from inverba.models import FetchResult, FetchMethod
from inverba.agent_trust import verify_handoff, TrustVerdict


def make_record(content=b"<html>real data</html>", url="https://x.com", at=None):
    signer = ProvenanceSigner.generate()
    fr = FetchResult(url=url, final_url=url, status_code=200, content=content,
                     content_type="text/html", method=FetchMethod.HTTP,
                     fetched_at=at or time.time())
    return signer.sign(fr), content


def test_no_record_is_untrusted():
    v = verify_handoff(None)
    assert v.verdict == TrustVerdict.NO_RECORD.value
    assert v.trusted is False


def test_valid_record_with_matching_content_is_trusted():
    record, content = make_record()
    v = verify_handoff(record, claimed_content=content)
    assert v.verdict == TrustVerdict.TRUSTED.value
    assert v.trusted is True
    assert v.content_matches is True


def test_forged_signature_unverified():
    record, content = make_record()
    record.signature = "00" * 64
    v = verify_handoff(record, claimed_content=content)
    assert v.verdict == TrustVerdict.UNVERIFIED.value
    assert v.trusted is False


def test_bait_and_switch_detected():
    # attacker hands a REAL record for page X but FABRICATED content
    record, _ = make_record(content=b"<html>the real page A saw</html>")
    fake_content = b"<html>fabricated data B is being tricked into trusting</html>"
    v = verify_handoff(record, claimed_content=fake_content)
    assert v.verdict == TrustVerdict.CONTENT_MISMATCH.value
    assert v.trusted is False
    assert v.content_matches is False
    assert any("bait-and-switch" in r for r in v.reasons)


def test_stale_record_flagged():
    record, content = make_record(at=time.time() - 3600)  # 1 hour old
    v = verify_handoff(record, claimed_content=content, max_age_seconds=60)
    assert v.verdict == TrustVerdict.STALE.value
    assert v.trusted is False


def test_fresh_record_within_bound_trusted():
    record, content = make_record(at=time.time() - 10)
    v = verify_handoff(record, claimed_content=content, max_age_seconds=60)
    assert v.trusted is True


def test_require_corroboration_rejects_single_source():
    record, content = make_record()   # no corroborations
    v = verify_handoff(record, claimed_content=content, require_corroboration=True)
    assert v.trusted is False
    assert "corroboration" in " ".join(v.reasons).lower()


def test_corroborated_record_gets_stronger_verdict():
    record, content = make_record()
    corr, _ = make_record(content=content)  # independent worker, same content
    record.corroborations.append(corr)
    v = verify_handoff(record, claimed_content=content)
    assert v.verdict == TrustVerdict.TRUSTED_CORROBORATED.value
    assert v.corroborated is True
    assert v.corroborator_count == 1


def test_verdict_without_content_still_checks_signature():
    # agent B may not have the raw bytes, only the record -- still useful
    record, _ = make_record()
    v = verify_handoff(record)  # no claimed_content
    assert v.signature_valid is True
    assert v.content_matches is None   # couldn't check
    assert v.trusted is True            # sig valid, no freshness/corr requirement


def test_replayed_record_is_rejected():
    from inverba.seen import InMemorySeenStore
    store = InMemorySeenStore()
    record, content = make_record()
    first = verify_handoff(record, claimed_content=content, seen=store)
    assert first.verdict == TrustVerdict.TRUSTED.value
    assert first.trusted is True
    # same record, re-presented to the same verifier -> REPLAYED
    second = verify_handoff(record, claimed_content=content, seen=store)
    assert second.verdict == TrustVerdict.REPLAYED.value
    assert second.trusted is False
    assert any("replayed" in r.lower() for r in second.reasons)


def test_no_seen_store_means_no_replay_check():
    # backward compatibility: without a store, re-presentation stays trusted
    record, content = make_record()
    assert verify_handoff(record, claimed_content=content).trusted is True
    assert verify_handoff(record, claimed_content=content).trusted is True


def test_seen_store_forgets_after_ttl():
    from inverba.seen import InMemorySeenStore
    clock = {"t": 1000.0}
    store = InMemorySeenStore(ttl_seconds=60, clock=lambda: clock["t"])
    record, content = make_record(at=1000.0)
    assert verify_handoff(record, claimed_content=content, seen=store,
                          now=1000.0).trusted is True
    clock["t"] += 120  # past the cache TTL
    # forgotten -> accepted again, NOT flagged replayed
    again = verify_handoff(record, claimed_content=content, seen=store, now=1120.0)
    assert again.verdict == TrustVerdict.TRUSTED.value


def test_malleated_signature_rejected_keeps_seen_key_stable():
    # The seen-cache keys on record.signature. That is only safe if a
    # malleated-but-"valid" variant of a signature cannot verify -- otherwise an
    # attacker could re-present the same record under a different signature hex
    # and slip past the cache. Ed25519 (RFC 8032) requires S < L and
    # verify_record enforces it; this pins that invariant so a future crypto-lib
    # change can't silently weaken the replay defense.
    from inverba.provenance import verify_record
    L = 2**252 + 27742317777372353535851937790883648493
    record, _ = make_record()
    assert verify_record(record) is True
    sig = bytes.fromhex(record.signature)
    R, S = sig[:32], int.from_bytes(sig[32:], "little")
    record.signature = (R + (S + L).to_bytes(32, "little")).hex()  # non-canonical S
    assert verify_record(record) is False


def test_rejected_record_does_not_poison_seen_store():
    # a forged record is rejected and must NOT be recorded as seen; a later
    # genuine presentation of a DIFFERENT valid record is unaffected
    from inverba.seen import InMemorySeenStore
    store = InMemorySeenStore()
    bad, content = make_record()
    bad.signature = "00" * 64
    assert verify_handoff(bad, claimed_content=content, seen=store).trusted is False
    good, gcontent = make_record()
    assert verify_handoff(good, claimed_content=gcontent, seen=store).trusted is True
