"""
Pluggable fetch backends.

The strategic point: verification is fetch-agnostic. A signed record over
content someone ELSE retrieved is just as cryptographically valid as one over
content we retrieved ourselves. So Inverba does not need to win the
anti-bot/proxy/scale arms race -- it can sit on top of whoever already won it.

    "Use whatever scraper you like. Inverba proves what it got."

This turns competitors (Firecrawl, Crawl4AI, ScrapingBee, your own stack) into
FETCH INFRASTRUCTURE rather than rivals, and inherits their coverage instead of
rebuilding it.

THE HONEST PART -- READ THIS BEFORE USING A THIRD-PARTY BACKEND:

Who fetched the bytes changes what a signature MEANS.

  - fetched_by="native": we retrieved the page ourselves from our own vantage.
    The record attests "I observed this at this URL."

  - fetched_by="firecrawl" (or any third party): a third party retrieved it and
    handed us bytes. We can only attest "this is what <backend> gave me."
    We did NOT independently observe the origin. If that backend is compromised,
    lies, or is itself served cloaked content, our signature faithfully attests
    to a falsehood.

That distinction is load-bearing for Inverba's whole pitch (independent
verification), so `fetched_by` is COVERED BY THE SIGNATURE -- it is not
mutable metadata. A consumer can always tell whether the signer was the
observer or merely a relay, and `verify_handoff` surfaces it in its verdict.

Corroboration is what recovers strength here: two backends with different
vantages agreeing is meaningful evidence even when neither is us.
"""

from __future__ import annotations

import time
from typing import Optional, Protocol

from .models import FetchResult, FetchMethod


# Attribution for a fetch performed by us, from our own vantage.
NATIVE = "native"


class FetchBackend(Protocol):
    """Anything that can turn a URL into raw bytes + metadata.

    Implementations MUST set `fetched_by` on the returned FetchResult to a
    stable identifier for the retrieving party, and MUST NOT mutate the bytes
    before returning them -- the provenance layer hashes exactly what comes back.
    """

    @property
    def name(self) -> str:
        """Stable identifier recorded as `fetched_by` (e.g. 'firecrawl')."""
        ...

    async def fetch(self, url: str) -> FetchResult:
        ...


class NativeBackend:
    """Inverba's own fetcher (httpx + optional Playwright fallback).

    The only backend that supports a genuine "I observed this" claim, because
    we control the vantage. Zero third-party dependency; works air-gapped
    against reachable hosts.
    """

    name = NATIVE

    def __init__(self, engine=None, **kwargs):
        from .fetch import FetchEngine
        self.engine = engine or FetchEngine(**kwargs)

    async def fetch(self, url: str) -> FetchResult:
        result = await self.engine.fetch(url)
        result.fetched_by = NATIVE
        return result


class FirecrawlBackend:
    """
    Fetch via Firecrawl's API, then sign what it returns.

    Why: Firecrawl ships anti-bot bypass, residential proxy rotation, stealth
    mode and real-Chromium rendering with ~96% web coverage. Rebuilding that is
    years of work we would lose. Renting it is one HTTP call.

    Trust caveat (see module docstring): records produced here are attributed
    `fetched_by="firecrawl"`. The signature then means "this is what Firecrawl
    returned to me," NOT "I independently observed the origin." Use corroboration
    (e.g. a native fetch or a second backend) when independence matters.

    Requires a Firecrawl API key. Live HTTP; not exercised in offline tests.
    """

    name = "firecrawl"

    def __init__(self, api_key: str, base_url: str = "https://api.firecrawl.dev",
                 timeout: float = 60.0, formats: Optional[list[str]] = None):
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        # rawHtml keeps the bytes closest to what the origin served, which is
        # what we want to hash. Markdown is a derived view.
        self.formats = formats or ["rawHtml"]

    async def fetch(self, url: str) -> FetchResult:
        import httpx

        started = time.time()
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.post(
                    f"{self.base_url}/v2/scrape",
                    headers={"Authorization": f"Bearer {self.api_key}",
                             "Content-Type": "application/json"},
                    json={"url": url, "formats": self.formats},
                )
        except httpx.HTTPError as e:
            return FetchResult(
                url=url, final_url=url, status_code=0, content=b"",
                content_type="", method=FetchMethod.HTTP, fetched_at=started,
                error=f"firecrawl transport error: {e}", fetched_by=self.name,
            )

        if resp.status_code != 200:
            return FetchResult(
                url=url, final_url=url, status_code=resp.status_code, content=b"",
                content_type="", method=FetchMethod.HTTP, fetched_at=started,
                error=f"firecrawl returned {resp.status_code}", fetched_by=self.name,
            )

        payload = resp.json()
        data = payload.get("data", {})
        body = data.get("rawHtml") or data.get("html") or data.get("markdown") or ""
        meta = data.get("metadata", {}) or {}

        return FetchResult(
            url=url,
            final_url=meta.get("sourceURL", url),
            status_code=int(meta.get("statusCode", 200)),
            content=body.encode("utf-8"),
            content_type=meta.get("contentType", "text/html"),
            method=FetchMethod.HTTP,
            fetched_at=started,
            fetched_by=self.name,
        )


class CallableBackend:
    """
    Wrap any user-supplied fetch function as a backend.

    Escape hatch so someone using Crawl4AI, ScrapingBee, Bright Data, a
    corporate proxy, or their own Playwright stack can feed Inverba without us
    shipping an adapter for each. They provide bytes; we provide the trust layer.

        async def my_fetch(url) -> tuple[bytes, int, str]:
            ...  # returns (content, status_code, content_type)

        backend = CallableBackend("crawl4ai", my_fetch)
    """

    def __init__(self, name: str, fn):
        if name == NATIVE:
            raise ValueError(
                "a third-party backend may not claim the 'native' attribution -- "
                "'native' means Inverba observed the origin itself"
            )
        self._name = name
        self._fn = fn

    @property
    def name(self) -> str:
        return self._name

    async def fetch(self, url: str) -> FetchResult:
        started = time.time()
        try:
            content, status_code, content_type = await self._fn(url)
        except Exception as e:
            return FetchResult(
                url=url, final_url=url, status_code=0, content=b"",
                content_type="", method=FetchMethod.HTTP, fetched_at=started,
                error=f"{self._name} backend error: {e}", fetched_by=self._name,
            )
        return FetchResult(
            url=url, final_url=url, status_code=status_code, content=content,
            content_type=content_type, method=FetchMethod.HTTP,
            fetched_at=started, fetched_by=self._name,
        )


def is_independent_observation(fetched_by: Optional[str]) -> bool:
    """True only if Inverba itself observed the origin.

    Used by the trust layer to distinguish "I saw this" from "I was told this."
    A None attribution is treated as NOT independent: absence of a claim is not
    a claim of independence.
    """
    return fetched_by == NATIVE
