"""
B1 regression: SSRF-safe notary fetch.

The fix validates the RESOLVED address, not the URL string, so every string
encoding of an internal address is caught once resolved. These tests prove the
address-level logic and the notary's per-hop redirect validation.
"""
import pytest

from inverba.ssrf import is_disallowed_ip, validate_public_url, SSRFError
from inverba.notary import NotaryService, NotaryPolicy, NotaryRefusal
from inverba.models import FetchResult, FetchMethod


# ---- address classifier ----------------------------------------------------

@pytest.mark.parametrize("ip", [
    "127.0.0.1", "10.0.0.5", "192.168.1.1", "172.16.0.1",     # private/loopback
    "169.254.169.254", "fd00:ec2::254",                        # cloud metadata
    "0.0.0.0", "::1", "::ffff:127.0.0.1", "::ffff:169.254.169.254",  # unspec/v6/mapped
    "224.0.0.1",                                               # multicast
])
def test_disallowed_addresses(ip):
    assert is_disallowed_ip(ip) is True

@pytest.mark.parametrize("ip", ["93.184.216.34", "8.8.8.8", "2001:4860:4860::8888", "1.1.1.1"])
def test_public_addresses_allowed(ip):
    assert is_disallowed_ip(ip) is False


# ---- resolution-based validation closes the ENCODING class -----------------
# A resolver stub returns what the OS resolver would for each encoding; the
# point is that the RESOLVED address is validated, so encoding is irrelevant.

_ENCODINGS = {
    "http://2130706433/": ["127.0.0.1"],        # decimal loopback
    "http://0177.0.0.1/": ["127.0.0.1"],          # octal
    "http://0x7f000001/": ["127.0.0.1"],          # hex
    "http://127.1/": ["127.0.0.1"],               # short form
    "http://2852039166/": ["169.254.169.254"],    # decimal -> metadata
    "http://[::ffff:127.0.0.1]/": ["::ffff:127.0.0.1"],
    "http://internal.example/": ["10.0.0.9"],     # hostname -> private A record
}

@pytest.mark.parametrize("url,resolved", list(_ENCODINGS.items()))
def test_encoded_and_hostname_targets_refused(url, resolved):
    def resolver(host):
        return resolved
    with pytest.raises(SSRFError):
        validate_public_url(url, resolver=resolver)

def test_public_url_passes():
    assert validate_public_url("https://example.com/", resolver=lambda h: ["93.184.216.34"]) == ["93.184.216.34"]

def test_real_resolver_refuses_loopback_and_metadata_literals():
    # deterministic + portable: these literals resolve to themselves
    for url in ("http://127.0.0.1/", "http://169.254.169.254/"):
        with pytest.raises(SSRFError):
            validate_public_url(url)


# ---- notary per-hop redirect validation ------------------------------------

class RedirectEngine:
    """First call returns a 302 to `redirect_to`; never fetches it if refused."""
    def __init__(self, redirect_to):
        self.redirect_to = redirect_to
        self.calls = []
    async def fetch(self, url):
        self.calls.append(url)
        if url != self.redirect_to:
            return FetchResult(url=url, final_url=url, status_code=302, content=b"",
                               content_type="text/html", method=FetchMethod.HTTP,
                               fetched_at=1.0, headers={"location": self.redirect_to})
        return FetchResult(url=url, final_url=url, status_code=200, content=b"internal!",
                           content_type="text/html", method=FetchMethod.HTTP, fetched_at=1.0)

class AllowRobots:
    def __init__(self): self.allowed = True
    async def check(self, url):
        from inverba.robots import RobotsVerdict
        import time
        return RobotsVerdict(url=url, robots_url="r", allowed=True, checked_at=time.time(),
                             user_agent="InverbaNotary", robots_found=True)

@pytest.mark.asyncio
async def test_redirect_toward_metadata_refused_at_the_hop():
    engine = RedirectEngine("http://169.254.169.254/latest/meta-data/")
    def resolver(host):
        return ["93.184.216.34"] if host == "public.example" else ["169.254.169.254"]
    svc = NotaryService(fetch_engine=engine, robots_checker=AllowRobots(),
                        resolver=resolver, policy=NotaryPolicy(per_domain_min_interval=0))
    result = await svc.observe("http://public.example/start")
    assert isinstance(result, NotaryRefusal)
    assert result.reason_code == "private_network"
    # the metadata address must NEVER have been fetched
    assert "http://169.254.169.254/latest/meta-data/" not in engine.calls

@pytest.mark.asyncio
async def test_normal_public_fetch_still_succeeds():
    class OK:
        async def fetch(self, url):
            return FetchResult(url=url, final_url=url, status_code=200, content=b"<html>hi</html>",
                               content_type="text/html", method=FetchMethod.HTTP, fetched_at=1.0)
    svc = NotaryService(fetch_engine=OK(), robots_checker=AllowRobots(),
                        resolver=lambda h: ["93.184.216.34"],
                        policy=NotaryPolicy(per_domain_min_interval=0))
    result = await svc.observe("https://example.com/page")
    from inverba.models import ProvenanceRecord
    assert isinstance(result, ProvenanceRecord)


# ---- Fix 1: upfront gate — NO outbound (robots OR content) before validation --

class SpyEngine:
    def __init__(self): self.calls = []
    async def fetch(self, url):
        self.calls.append(url)
        return FetchResult(url=url, final_url=url, status_code=200, content=b"x",
                           content_type="text/html", method=FetchMethod.HTTP, fetched_at=1.0)

class SpyRobots:
    def __init__(self): self.calls = []
    async def check(self, url):
        self.calls.append(url)
        import time as _t
        from inverba.robots import RobotsVerdict
        return RobotsVerdict(url=url, robots_url=url, allowed=True, checked_at=_t.time(),
                             user_agent="InverbaNotary", robots_found=True)

@pytest.mark.parametrize("url,resolved", [
    ("http://2852039166/", ["169.254.169.254"]),   # decimal -> metadata
    ("http://0x7f000001/", ["127.0.0.1"]),           # hex -> loopback
    ("http://[::ffff:127.0.0.1]/", ["::ffff:127.0.0.1"]),  # IPv4-mapped IPv6
])
@pytest.mark.asyncio
async def test_no_outbound_before_ssrf_validation(url, resolved):
    engine, robots = SpyEngine(), SpyRobots()
    svc = NotaryService(fetch_engine=engine, robots_checker=robots,
                        resolver=lambda h: resolved,
                        policy=NotaryPolicy(per_domain_min_interval=0))
    result = await svc.observe(url)
    assert isinstance(result, NotaryRefusal)
    assert result.reason_code == "private_network"
    # the notary refused BEFORE any outbound of any kind fired
    assert robots.calls == [], f"robots preflight fired against {url}"
    assert engine.calls == [], f"content fetch fired against {url}"


# ---- Fix 2: notary forces redirect-disabled fetching (owns redirect behavior) --

class ConfigurableRedirectEngine:
    """Mimics a real FetchEngine: follow_redirects=True auto-follows a 302 to
    metadata INTERNALLY; =False surfaces the 302 for the caller to handle."""
    def __init__(self):
        self.follow_redirects = True          # production default -- the danger
        self.fetched = []
        self.meta = "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
    async def fetch(self, url):
        self.fetched.append(url)
        if url != self.meta:  # the public start URL
            if self.follow_redirects:
                self.fetched.append(self.meta)   # internal auto-follow -> SSRF fires
                return FetchResult(url=url, final_url=self.meta, status_code=200,
                                   content=b"CREDS", content_type="text/plain",
                                   method=FetchMethod.HTTP, fetched_at=1.0)
            return FetchResult(url=url, final_url=url, status_code=302, content=b"",
                               content_type="text/html", method=FetchMethod.HTTP,
                               fetched_at=1.0, headers={"location": self.meta})
        return FetchResult(url=url, final_url=url, status_code=200, content=b"CREDS",
                           content_type="text/plain", method=FetchMethod.HTTP, fetched_at=1.0)

@pytest.mark.asyncio
async def test_notary_forces_redirects_off_metadata_never_requested():
    engine = ConfigurableRedirectEngine()
    assert engine.follow_redirects is True     # injected with the dangerous default
    def resolver(host):
        return ["93.184.216.34"] if host == "public.example" else ["169.254.169.254"]
    svc = NotaryService(fetch_engine=engine, robots_checker=AllowRobots(),
                        resolver=resolver, policy=NotaryPolicy(per_domain_min_interval=0))
    # the notary took ownership and forced auto-follow OFF at construction
    assert engine.follow_redirects is False
    result = await svc.observe("http://public.example/redirect-to-metadata")
    assert isinstance(result, NotaryRefusal)
    assert result.reason_code == "private_network"
    # the metadata address must NEVER have been requested (not even internally)
    assert engine.meta not in engine.fetched
