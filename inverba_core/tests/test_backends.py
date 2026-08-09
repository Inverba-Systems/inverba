"""
Tests for pluggable fetch backends and signed fetch attribution.

The strategic bet: Inverba doesn't need to win the anti-bot/proxy arms race if
it can verify content anyone fetched. But that only works if the trust model
stays honest about WHO fetched -- otherwise "independent verification" becomes
a lie told over someone else's bytes.

These lock in the honest part:
  - attribution is COVERED BY THE SIGNATURE (can't be edited after the fact)
  - a relayed record cannot be upgraded to a claimed first-hand observation
  - verify_handoff surfaces observation-vs-relay to the consuming agent
  - a third-party backend cannot claim the 'native' attribution
"""

import json
import time

import pytest

from inverba.provenance import ProvenanceSigner, verify_record
from inverba.models import FetchResult, FetchMethod
from inverba.agent_trust import verify_handoff
from inverba.backends import (
    NativeBackend, CallableBackend, FirecrawlBackend, is_independent_observation, NATIVE,
)


PAGE = b"<html><body><p>Price: $49.99</p></body></html>"


def fr(content=PAGE, url="https://example.com/p", fetched_by="native"):
    return FetchResult(url=url, final_url=url, status_code=200, content=content,
                       content_type="text/html", method=FetchMethod.HTTP,
                       fetched_at=time.time(), fetched_by=fetched_by)


class FakeEngine:
    def __init__(self, content=PAGE):
        self.content = content

    async def fetch(self, url):
        return fr(self.content, url=url)


# ---- attribution is signed, not metadata ----

def test_attribution_is_covered_by_signature():
    signer = ProvenanceSigner.generate()
    record = signer.sign(fr(fetched_by="firecrawl"))
    assert verify_record(record) is True
    assert record.fetched_by == "firecrawl"


def test_relayed_record_cannot_be_upgraded_to_native():
    """The attack: edit fetched_by to claim you observed the origin yourself."""
    signer = ProvenanceSigner.generate()
    record = signer.sign(fr(fetched_by="firecrawl"))
    record.fetched_by = "native"          # attacker forges independence
    assert verify_record(record) is False  # signature breaks


def test_native_record_cannot_be_downgraded_silently():
    signer = ProvenanceSigner.generate()
    record = signer.sign(fr(fetched_by="native"))
    record.fetched_by = "firecrawl"
    assert verify_record(record) is False


def test_attribution_survives_json_roundtrip():
    signer = ProvenanceSigner.generate()
    record = signer.sign(fr(fetched_by="crawl4ai"))
    from inverba.models import ProvenanceRecord
    data = json.loads(json.dumps(record.to_dict()))
    data["corroborations"] = []
    restored = ProvenanceRecord(**data)
    assert restored.fetched_by == "crawl4ai"
    assert verify_record(restored) is True


# ---- the trust layer distinguishes observation from relay ----

def test_verify_handoff_surfaces_relay():
    signer = ProvenanceSigner.generate()
    record = signer.sign(fr(fetched_by="firecrawl"))
    v = verify_handoff(record, claimed_content=PAGE)
    assert v.fetched_by == "firecrawl"
    assert v.independent_observation is False
    assert any("did not observe the origin" in r for r in v.reasons)


def test_verify_handoff_marks_native_as_independent():
    signer = ProvenanceSigner.generate()
    record = signer.sign(fr(fetched_by="native"))
    v = verify_handoff(record, claimed_content=PAGE)
    assert v.independent_observation is True
    assert v.trusted is True


def test_require_independent_observation_rejects_relay():
    signer = ProvenanceSigner.generate()
    record = signer.sign(fr(fetched_by="firecrawl"))
    v = verify_handoff(record, claimed_content=PAGE,
                       require_independent_observation=True)
    assert v.trusted is False
    assert any("requires an independent observation" in r for r in v.reasons)


def test_relayed_record_still_trusted_by_default():
    """Relay is a weaker claim, not an invalid one -- default stays usable."""
    signer = ProvenanceSigner.generate()
    record = signer.sign(fr(fetched_by="firecrawl"))
    v = verify_handoff(record, claimed_content=PAGE)
    assert v.signature_valid is True
    assert v.trusted is True      # usable, but the caveat is in reasons/flags


def test_bait_and_switch_still_caught_on_relayed_record():
    signer = ProvenanceSigner.generate()
    record = signer.sign(fr(fetched_by="firecrawl"))
    v = verify_handoff(record, claimed_content=b"<html>fabricated</html>")
    assert v.verdict == "content_mismatch"
    assert v.trusted is False


# ---- backends ----

@pytest.mark.asyncio
async def test_native_backend_attributes_native():
    backend = NativeBackend(engine=FakeEngine())
    result = await backend.fetch("https://example.com/p")
    assert result.fetched_by == NATIVE
    assert is_independent_observation(result.fetched_by) is True


@pytest.mark.asyncio
async def test_callable_backend_wraps_any_fetcher():
    async def my_fetch(url):
        return b"<html>from my own stack</html>", 200, "text/html"

    backend = CallableBackend("crawl4ai", my_fetch)
    result = await backend.fetch("https://example.com/p")
    assert result.fetched_by == "crawl4ai"
    assert result.content == b"<html>from my own stack</html>"
    assert is_independent_observation(result.fetched_by) is False


@pytest.mark.asyncio
async def test_callable_backend_reports_errors_without_faking_content():
    async def broken(url):
        raise RuntimeError("proxy exploded")

    backend = CallableBackend("someproxy", broken)
    result = await backend.fetch("https://example.com/p")
    assert result.ok is False
    assert "proxy exploded" in result.error
    assert result.content == b""    # never invent bytes


def test_third_party_backend_cannot_claim_native():
    async def f(url):
        return b"", 200, "text/html"
    with pytest.raises(ValueError):
        CallableBackend("native", f)


def test_firecrawl_backend_declares_its_attribution():
    backend = FirecrawlBackend(api_key="test-key")
    assert backend.name == "firecrawl"
    assert is_independent_observation(backend.name) is False


def test_absent_attribution_is_not_treated_as_independent():
    # absence of a claim is not a claim of independence
    assert is_independent_observation(None) is False
