"""
Ethical-scraping attestation.

Signed, verifiable proof that at fetch time the crawler checked and respected
robots.txt. Small feature, real enterprise value: "prove your crawler
behaved" is increasingly a legal-defensibility question as scraping
litigation grows. Because Inverba already signs provenance, adding a
robots-compliance assertion to the record makes good behavior *provable*, not
just claimed.

Slots into the C2PA assertion set as an additional assertion, and
stands alone as a checkable field on the provenance side.

HONEST SCOPE: this attests that Inverba fetched and evaluated robots.txt for
the URL and recorded the verdict. It is a record of the crawler's own
behavior. It does not adjudicate whether a given path *should* be allowed —
it records what robots.txt said and whether Inverba honored it.
"""

from __future__ import annotations

import time
import urllib.robotparser
from dataclasses import dataclass
from typing import Optional
from urllib.parse import urlparse

import httpx


@dataclass
class RobotsVerdict:
    url: str
    robots_url: str
    allowed: bool
    checked_at: float
    user_agent: str
    robots_found: bool          # False if site had no robots.txt (=> allowed)
    error: Optional[str] = None

    def to_assertion(self) -> dict:
        """As a C2PA-style assertion for inclusion in a manifest."""
        return {
            "label": "inverba.robots_compliance",
            "data": {
                "robots_url": self.robots_url,
                "allowed": self.allowed,
                "robots_found": self.robots_found,
                "user_agent": self.user_agent,
                "checked_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(self.checked_at)),
            },
        }


class RobotsChecker:
    """
    Checks robots.txt for a URL and returns a verdict. Caches parsed
    robots.txt per host for the lifetime of the instance.
    """

    def __init__(self, user_agent: str = "Inverba", timeout: float = 10.0,
                 follow_redirects: bool = False):
        self.user_agent = user_agent
        self.timeout = timeout
        # Default OFF: a robots.txt that 302s elsewhere is unusual, and for the
        # hosted notary an unfollowed redirect must never become an SSRF outbound
        # to a redirected (possibly internal) address. Treating a redirect as
        # "no robots" is the conservative reading.
        self.follow_redirects = follow_redirects
        self._cache: dict[str, urllib.robotparser.RobotFileParser] = {}

    async def check(self, url: str) -> RobotsVerdict:
        parsed = urlparse(url)
        robots_url = f"{parsed.scheme}://{parsed.netloc}/robots.txt"
        now = time.time()

        parser = self._cache.get(parsed.netloc)
        robots_found = True
        error = None

        if parser is None:
            parser = urllib.robotparser.RobotFileParser()
            try:
                async with httpx.AsyncClient(timeout=self.timeout,
                                             follow_redirects=self.follow_redirects) as client:
                    resp = await client.get(robots_url)
                if resp.status_code == 200:
                    parser.parse(resp.text.splitlines())
                else:
                    # No robots.txt (404 etc.) -> everything allowed by convention.
                    robots_found = False
                    parser.parse([])
            except httpx.HTTPError as e:
                # Network failure fetching robots.txt -> record error, default
                # to disallow (conservative: don't claim compliance we can't verify).
                error = str(e)
                parser.parse([])
                self._cache[parsed.netloc] = parser
                return RobotsVerdict(
                    url=url, robots_url=robots_url, allowed=False, checked_at=now,
                    user_agent=self.user_agent, robots_found=False, error=error,
                )
            self._cache[parsed.netloc] = parser

        allowed = parser.can_fetch(self.user_agent, url)
        return RobotsVerdict(
            url=url, robots_url=robots_url, allowed=allowed, checked_at=now,
            user_agent=self.user_agent, robots_found=robots_found, error=error,
        )
