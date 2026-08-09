"""
Tests for the bot-wall honesty fix.

The bug: a CAPTCHA/challenge page returns HTTP 200 with junk, gets signed, and
verification passes over garbage. The fix has two layers -- signed fetch
metadata (status_code/final_url/content_type, tamper-evident) and content
heuristics -- and these lock in both.
"""

import json
import time

import pytest

from inverba.provenance import ProvenanceSigner, verify_record
from inverba.models import FetchResult, FetchMethod, ProvenanceRecord
from inverba.blockcheck import detect_block, check_record_for_block, BlockVerdict
from inverba.agent_trust import verify_handoff


REAL_PAGE = b"<html><body><article><h1>Product</h1><p>Price: $49.99</p></article></body></html>"
CF_CHALLENGE = (b"<html><head><title>Just a moment...</title></head><body>"
                b"<div>Checking your browser before accessing the site. "
                b"cf_chl_ Enable JavaScript and cookies to continue</div></body></html>")


def make_record(signer, content=REAL_PAGE, url="https://example.com/p",
                status=200, final_url="", ctype="text/html"):
    fr = FetchResult(url=url, final_url=final_url or url, status_code=status,
                     content=content, content_type=ctype, method=FetchMethod.HTTP,
                     fetched_at=time.time())
    return signer.sign(fr)


@pytest.fixture
def signer():
    return ProvenanceSigner.generate()


# ---- signed fetch metadata survives and is covered by the signature ----

def test_status_and_content_type_are_signed(signer):
    r = make_record(signer, status=200, ctype="text/html")
    assert verify_record(r) is True
    assert r.status_code == 200
    assert r.content_type == "text/html"


def test_tampering_status_code_breaks_signature(signer):
    r = make_record(signer, status=200)
    r.status_code = 403          # forge a different status
    assert verify_record(r) is False


def test_tampering_final_url_breaks_signature(signer):
    r = make_record(signer, url="https://x.com/p",
                    final_url="https://x.com/cdn-cgi/challenge")
    assert verify_record(r) is True          # redirect legitimately recorded
    r.final_url = "https://x.com/p"           # forge away the redirect
    assert verify_record(r) is False


def test_metadata_survives_json_roundtrip(signer):
    r = make_record(signer, status=200, final_url="https://x.com/challenge",
                    url="https://x.com/p", ctype="application/json")
    data = json.loads(json.dumps(r.to_dict()))
    data["corroborations"] = []
    restored = ProvenanceRecord(**data)
    assert verify_record(restored) is True
    assert restored.status_code == 200
    assert restored.final_url == "https://x.com/challenge"
    assert restored.content_type == "application/json"


def test_minimal_record_signs_and_verifies_consistently(signer):
    """A record fetched with only defaults (empty content_type, no redirect)
    signs and verifies consistently. Since there are zero pre-existing records,
    strict signing of the new fields is correct -- the signer and verifier just
    have to agree, which they do."""
    fr = FetchResult(url="https://x.com", final_url="https://x.com", status_code=200,
                     content=REAL_PAGE, content_type="", method=FetchMethod.HTTP)
    r = signer.sign(fr)
    assert verify_record(r) is True
    assert r.content_type == ""
    # round-trips too
    data = json.loads(json.dumps(r.to_dict()))
    data["corroborations"] = []
    assert verify_record(ProvenanceRecord(**data)) is True


def test_was_redirected_flag(signer):
    r = make_record(signer, url="https://x.com/p", final_url="https://x.com/sorry/")
    assert r.was_redirected is True
    r2 = make_record(signer, url="https://x.com/p")
    assert r2.was_redirected is False


# ---- content heuristics ----

def test_clean_page_is_clean():
    bc = detect_block(REAL_PAGE, status_code=200)
    assert bc.verdict == BlockVerdict.CLEAN.value
    assert bc.is_suspicious is False


def test_cloudflare_challenge_detected():
    bc = detect_block(CF_CHALLENGE, status_code=200)
    assert bc.is_suspicious is True
    assert bc.verdict == BlockVerdict.SUSPECTED_BLOCK.value
    assert bc.confidence in ("medium", "high")


def test_non_2xx_is_hard_block():
    bc = detect_block(b"<html>Forbidden</html>", status_code=403)
    assert bc.verdict == BlockVerdict.HARD_BLOCK.value
    assert bc.confidence == "high"


def test_redirect_to_challenge_endpoint_flagged():
    bc = detect_block(b"<html>x</html>", status_code=200,
                      url="https://x.com/product",
                      final_url="https://x.com/cdn-cgi/challenge-platform/x")
    assert bc.is_suspicious is True
    assert any("challenge endpoint" in s for s in bc.signals)


def test_recaptcha_widget_detected():
    body = b"<html><body><script src='https://www.google.com/recaptcha/api.js'></script></body></html>"
    bc = detect_block(body, status_code=200)
    assert bc.is_suspicious is True


def test_page_merely_mentioning_captcha_not_over_flagged():
    """A blog post about CAPTCHAs shouldn't hard-trip -- markers are specific
    phrases challenge pages render, not the word 'captcha' alone."""
    body = (b"<html><body><article>Today we discuss how CAPTCHA systems work "
            b"and why they matter for security.</article></body></html>")
    bc = detect_block(body, status_code=200)
    assert bc.verdict == BlockVerdict.CLEAN.value


# ---- surfaced through the record + verify_handoff ----

def test_check_record_uses_signed_metadata(signer):
    # a record whose SIGNED final_url shows a challenge redirect is flagged even
    # without the original bytes
    r = make_record(signer, url="https://x.com/p",
                    final_url="https://x.com/cdn-cgi/challenge", content=b"x")
    bc = check_record_for_block(r)   # no content passed
    assert bc.is_suspicious is True


def test_verify_handoff_surfaces_suspected_block(signer):
    r = make_record(signer, content=CF_CHALLENGE)
    v = verify_handoff(r, claimed_content=CF_CHALLENGE)
    assert v.suspected_block is True
    assert v.block_confidence in ("medium", "high")
    assert any("bot-wall" in reason for reason in v.reasons)


def test_verify_handoff_clean_page_no_block_flag(signer):
    r = make_record(signer, content=REAL_PAGE)
    v = verify_handoff(r, claimed_content=REAL_PAGE)
    assert v.suspected_block is False
    assert v.trusted is True


def test_block_check_still_lets_signature_verify(signer):
    """A suspected block does NOT make the record invalid -- the signature is
    real; the point is to flag WHAT was signed, not to reject it."""
    r = make_record(signer, content=CF_CHALLENGE)
    assert verify_record(r) is True
    v = verify_handoff(r, claimed_content=CF_CHALLENGE)
    assert v.signature_valid is True
    assert v.suspected_block is True


def test_status_zero_is_a_failed_fetch_never_clean():
    """status_code 0 = the fetch never got an HTTP response (network/DNS/TLS
    error). It must be flagged suspicious, never fall through to 'clean' -- a
    failed fetch reading as clean is a success-on-failed-data honesty bug."""
    bc = detect_block(b"", status_code=0, url="https://x/y", final_url="https://x/y", content_type="")
    assert bc.is_suspicious is True
    assert bc.verdict == BlockVerdict.HARD_BLOCK.value


AMAZON_CAPTCHA = (b"<html><head><title>Amazon.com</title></head><body>"
                  b"<h4>Enter the characters you see below</h4>"
                  b"<p>Sorry, we just need to make sure you're not a robot.</p>"
                  b"<p>To discuss automated access to Amazon data please contact "
                  b"api-services-support@amazon.com</p></body></html>")

def test_amazon_captcha_is_flagged():
    """Amazon's anti-bot CAPTCHA returns HTTP 200 and must be flagged -- it's one
    of the most common e-commerce bot-walls."""
    bc = detect_block(AMAZON_CAPTCHA, status_code=200, url="https://www.amazon.com/dp/X",
                      final_url="https://www.amazon.com/dp/X", content_type="text/html")
    assert bc.is_suspicious is True

def test_page_merely_mentioning_captcha_is_not_a_false_positive():
    """A normal article that talks about CAPTCHAs must NOT be flagged."""
    article = (b"<html><body><article><h1>How CAPTCHA systems work</h1>"
               b"<p>A CAPTCHA is a challenge used to tell humans and bots apart. "
               b"This article explains the history and design of these systems in "
               b"depth for practitioners building accessible websites.</p>"
               b"</article></body></html>")
    bc = detect_block(article, status_code=200, url="https://blog.example/captcha",
                      final_url="https://blog.example/captcha", content_type="text/html")
    assert bc.is_suspicious is False
