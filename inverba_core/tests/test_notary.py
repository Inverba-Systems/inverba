import time

from inverba.provenance import ProvenanceSigner
from inverba.models import FetchResult, FetchMethod
from inverba.notary import (
    NotaryService, NotaryClient, InProcessNotaryTransport, NotaryResult,
)


class FakeFetchEngine:
    """Returns a controllable FetchResult so the notary is testable offline."""
    def __init__(self, content: bytes, ok: bool = True):
        self._content = content
        self._ok = ok

    async def fetch(self, url):
        return FetchResult(
            url=url, final_url=url, status_code=200 if self._ok else 500,
            content=self._content, content_type="text/html",
            method=FetchMethod.HTTP, fetched_at=time.time(),
        )


class AllowRobots:
    """An allowing robots checker so these corroboration tests run offline.

    The notary now ENFORCES robots.txt (see test_notary_policy.py); without an
    injected checker it would build a real network RobotsChecker. These tests
    exercise corroboration/signing, not robots policy, so they assume allowed.
    """
    def __init__(self, allowed: bool = True):
        self.allowed = allowed

    async def check(self, url):
        from inverba.robots import RobotsVerdict
        return RobotsVerdict(url=url, robots_url="https://x.com/robots.txt",
                             allowed=self.allowed, checked_at=time.time(),
                             user_agent="InverbaNotary", robots_found=True)


def public_resolver(host):
    """A resolver stub returning a public address so SSRF validation passes
    offline. These tests exercise corroboration/signing, not SSRF policy."""
    return ["93.184.216.34"]  # example.com's public IP


def user_record(content=b"<html>page</html>", url="https://x.com"):
    signer = ProvenanceSigner.generate()
    fr = FetchResult(url=url, final_url=url, status_code=200, content=content,
                     content_type="text/html", method=FetchMethod.HTTP)
    return signer.sign(fr), content


def test_notary_corroborates_matching_content():
    content = b"<html>identical page</html>"
    record, user_content = user_record(content=content)
    # notary sees the SAME content from its own vantage
    service = NotaryService(fetch_engine=FakeFetchEngine(content), robots_checker=AllowRobots(), resolver=public_resolver)
    client = NotaryClient(InProcessNotaryTransport(service))

    result = client.notarize(record, user_content)
    assert result.corroborated is True
    assert result.agreement == "match"
    # the user's record is now two-party corroborated at N=1
    assert len(record.corroborations) == 1
    assert record.corroborations[0].worker_public_key == service.public_key


def test_notary_reports_mismatch_on_different_content():
    record, user_content = user_record(content=b"<html>what the user saw</html>")
    # notary sees DIFFERENT content (cloaking, or page changed)
    service = NotaryService(fetch_engine=FakeFetchEngine(b"<html>totally different</html>"), robots_checker=AllowRobots(), resolver=public_resolver)
    client = NotaryClient(InProcessNotaryTransport(service))

    result = client.notarize(record, user_content)
    assert result.corroborated is False
    assert result.agreement == "mismatch"
    assert len(record.corroborations) == 0   # nothing folded in


def test_notary_unreachable_is_handled():
    record, user_content = user_record()
    # fetch fails -> notary returns no observation
    service = NotaryService(fetch_engine=FakeFetchEngine(b"", ok=False), robots_checker=AllowRobots(), resolver=public_resolver)
    client = NotaryClient(InProcessNotaryTransport(service))

    result = client.notarize(record, user_content)
    assert result.corroborated is False
    assert result.agreement == "unreachable"


def test_notary_record_is_independently_signed():
    content = b"<html>page</html>"
    record, user_content = user_record(content=content)
    service = NotaryService(fetch_engine=FakeFetchEngine(content), robots_checker=AllowRobots(), resolver=public_resolver)
    client = NotaryClient(InProcessNotaryTransport(service))
    client.notarize(record, user_content)

    # the corroboration is signed by the NOTARY, not the user -> independent
    notary_corr = record.corroborations[0]
    assert notary_corr.worker_public_key == service.public_key
    from inverba.provenance import verify_record
    assert verify_record(notary_corr) is True


def test_solo_user_goes_from_zero_to_two_party():
    content = b"<html>solo user first fetch</html>"
    record, user_content = user_record(content=content)
    assert len(record.corroborations) == 0   # solo: single-source

    service = NotaryService(fetch_engine=FakeFetchEngine(content), robots_checker=AllowRobots(), resolver=public_resolver)
    client = NotaryClient(InProcessNotaryTransport(service))
    client.notarize(record, user_content)

    # now corroborated without the user running any swarm of their own
    assert len(record.corroborations) == 1
