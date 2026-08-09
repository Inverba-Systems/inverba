"""
Tests for notary policy enforcement -- the legal-posture layer.

When the notary fetches, Inverba is the party scraping, from Inverba
infrastructure. These tests lock in the defensible lane established by the
2026 case law: public logged-out pages only, robots.txt ENFORCED, no login
walls, never hammering, never a proxy into private networks. Every refusal is
explicit and reasoned, because a documented refusal is itself good-faith
evidence.
"""

import time

import pytest

from inverba.models import FetchResult, FetchMethod, ProvenanceRecord
from inverba.notary import (
    NotaryService, NotaryPolicy, NotaryRefusal, NotaryClient,
    InProcessNotaryTransport, _looks_login_walled, _is_private_address,
)
from inverba.provenance import ProvenanceSigner


class FakeEngine:
    def __init__(self, content=b"<html>ok</html>", status=200):
        self.content, self.status = content, status
        self.calls = []

    async def fetch(self, url):
        self.calls.append(url)
        return FetchResult(url=url, final_url=url, status_code=self.status,
                           content=self.content, content_type="text/html",
                           method=FetchMethod.HTTP, fetched_at=time.time())


class FakeRobots:
    """Controllable robots checker so enforcement is testable offline."""
    def __init__(self, allowed=True):
        self.allowed = allowed
        self.checked = []

    async def check(self, url):
        self.checked.append(url)
        from inverba.robots import RobotsVerdict
        return RobotsVerdict(url=url, robots_url="https://x.com/robots.txt",
                             allowed=self.allowed, checked_at=time.time(),
                             user_agent="InverbaNotary", robots_found=True)


def public_resolver(host):
    """Resolver stub -> a public address, so SSRF validation passes offline.
    SSRF-specific tests pass their own resolver to exercise the guard."""
    return ["93.184.216.34"]


def svc(engine=None, policy=None, robots=None, resolver=public_resolver):
    return NotaryService(fetch_engine=engine or FakeEngine(),
                         policy=policy, robots_checker=robots, resolver=resolver)


async def observe(service, url):
    return await service.observe(url)


# ---- robots: enforced, not just recorded ----

@pytest.mark.asyncio
async def test_robots_disallow_refuses_fetch():
    engine = FakeEngine()
    service = svc(engine=engine, robots=FakeRobots(allowed=False))
    result = await observe(service, "https://example.com/private-path")
    assert isinstance(result, NotaryRefusal)
    assert result.reason_code == "robots_disallowed"
    assert engine.calls == []          # never even fetched


@pytest.mark.asyncio
async def test_robots_allow_permits_fetch():
    service = svc(robots=FakeRobots(allowed=True))
    result = await observe(service, "https://example.com/public")
    assert isinstance(result, ProvenanceRecord)


@pytest.mark.asyncio
async def test_robots_enforcement_can_be_disabled_for_self_hosters():
    # a self-hoster on their own infra may choose otherwise; the DEFAULT is enforced
    policy = NotaryPolicy(enforce_robots=False)
    service = svc(policy=policy, robots=FakeRobots(allowed=False))
    result = await observe(service, "https://example.com/anything")
    assert isinstance(result, ProvenanceRecord)


def test_default_policy_is_the_safe_lane():
    p = NotaryPolicy()
    assert p.enforce_robots is True
    assert p.refuse_login_walled is True
    assert p.allow_private_networks is False


# ---- login walls: the lane where scrapers lose ----

@pytest.mark.asyncio
async def test_login_hint_urls_refused():
    service = svc()
    for url in ("https://x.com/login", "https://x.com/account/settings",
                "https://x.com/page?session=abc"):
        result = await observe(service, url)
        assert isinstance(result, NotaryRefusal)
        assert result.reason_code == "login_walled"


@pytest.mark.asyncio
async def test_403_response_is_honored_not_retried():
    """A 401/403 is the site declining. The notary does not try harder --
    'trying harder' is exactly the DMCA-1201 circumvention theory."""
    engine = FakeEngine(status=403)
    service = svc(engine=engine, robots=FakeRobots(allowed=True))
    result = await observe(service, "https://example.com/public")
    assert isinstance(result, NotaryRefusal)
    assert result.reason_code == "login_walled"
    assert "does not attempt" in result.detail


def test_login_wall_heuristic():
    assert _looks_login_walled("https://x.com/login") is True
    assert _looks_login_walled("https://x.com/blog/post") is False
    assert _looks_login_walled("https://x.com/blog", status_code=403) is True


# ---- rate limiting: a notary never hammers ----

@pytest.mark.asyncio
async def test_per_domain_rate_limit():
    policy = NotaryPolicy(per_domain_min_interval=60.0, enforce_robots=False)
    service = svc(policy=policy)
    first = await observe(service, "https://example.com/a")
    assert isinstance(first, ProvenanceRecord)
    second = await observe(service, "https://example.com/b")   # same host, immediately
    assert isinstance(second, NotaryRefusal)
    assert second.reason_code == "rate_limited"


@pytest.mark.asyncio
async def test_rate_limit_is_per_domain_not_global():
    policy = NotaryPolicy(per_domain_min_interval=60.0, enforce_robots=False)
    service = svc(policy=policy)
    await observe(service, "https://a.com/x")
    other = await observe(service, "https://b.com/y")   # different host -> fine
    assert isinstance(other, ProvenanceRecord)


# ---- private networks: never an SSRF proxy ----

@pytest.mark.asyncio
async def test_private_addresses_refused():
    service = svc()
    for url in ("http://127.0.0.1/admin", "http://10.0.0.5/", "http://192.168.1.1/",
                "http://localhost/x", "http://169.254.169.254/latest/meta-data"):
        result = await observe(service, url)
        assert isinstance(result, NotaryRefusal), url
        assert result.reason_code == "private_network"


def test_private_address_detection():
    assert _is_private_address("http://127.0.0.1/") is True
    assert _is_private_address("http://10.1.2.3/") is True
    assert _is_private_address("http://169.254.169.254/") is True     # cloud metadata
    assert _is_private_address("https://example.com/") is False


# ---- structural ----

@pytest.mark.asyncio
async def test_non_http_refused():
    service = svc()
    result = await observe(service, "file:///etc/passwd")
    assert isinstance(result, NotaryRefusal)
    assert result.reason_code == "invalid_url"


# ---- refusals surface honestly through the client ----

def test_refusal_reaches_the_user_with_reason():
    engine = FakeEngine()
    service = svc(engine=engine, robots=FakeRobots(allowed=False))
    client = NotaryClient(InProcessNotaryTransport(service))

    signer = ProvenanceSigner.generate()
    fr = FetchResult(url="https://example.com/private-path",
                     final_url="https://example.com/private-path", status_code=200,
                     content=b"<html>x</html>", content_type="text/html",
                     method=FetchMethod.HTTP)
    record = signer.sign(fr)

    result = client.notarize(record, b"<html>x</html>")
    assert result.corroborated is False
    assert result.agreement == "refused"
    assert "robots_disallowed" in result.detail
