import pytest
import httpx

from inverba.robots import RobotsChecker, RobotsVerdict


def patched_checker(robots_body, status=200):
    """A RobotsChecker whose HTTP layer returns a fixed robots.txt."""
    checker = RobotsChecker(user_agent="Inverba")

    async def fake_check(url):
        import urllib.robotparser, time
        from urllib.parse import urlparse
        parsed = urlparse(url)
        robots_url = f"{parsed.scheme}://{parsed.netloc}/robots.txt"
        parser = urllib.robotparser.RobotFileParser()
        robots_found = status == 200
        if status == 200:
            parser.parse(robots_body.splitlines())
        else:
            parser.parse([])
        allowed = parser.can_fetch("Inverba", url)
        return RobotsVerdict(url=url, robots_url=robots_url, allowed=allowed,
                             checked_at=time.time(), user_agent="Inverba",
                             robots_found=robots_found)
    checker.check = fake_check
    return checker


@pytest.mark.asyncio
async def test_allowed_path():
    checker = patched_checker("User-agent: *\nDisallow: /private/")
    verdict = await checker.check("https://site.com/public/page")
    assert verdict.allowed is True
    assert verdict.robots_found is True


@pytest.mark.asyncio
async def test_disallowed_path():
    checker = patched_checker("User-agent: *\nDisallow: /private/")
    verdict = await checker.check("https://site.com/private/secret")
    assert verdict.allowed is False


@pytest.mark.asyncio
async def test_no_robots_means_allowed():
    checker = patched_checker("", status=404)
    verdict = await checker.check("https://site.com/anything")
    assert verdict.allowed is True
    assert verdict.robots_found is False


@pytest.mark.asyncio
async def test_verdict_produces_assertion():
    checker = patched_checker("User-agent: *\nDisallow: /private/")
    verdict = await checker.check("https://site.com/public")
    assertion = verdict.to_assertion()
    assert assertion["label"] == "inverba.robots_compliance"
    assert assertion["data"]["allowed"] is True
    assert "checked_at" in assertion["data"]
