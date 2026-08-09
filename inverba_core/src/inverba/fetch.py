"""
Fetch engine.

Fast path: httpx async GET, no JS execution -- handles the large majority
of pages and matches competitor baseline throughput.

Fallback: playwright-rendered fetch, triggered only when the fast path
looks like it returned an empty/JS-shell page (heuristic, not always-on
headless browsing -- keeps the standalone core lightweight by default).

Playwright is an optional extra (`pip install inverba-core[browser]`).
Importing it is deferred so the core package has zero hard dependency on
a browser binary being installed.
"""

from __future__ import annotations

import re
from typing import Optional

import httpx

from .models import FetchResult, FetchMethod

DEFAULT_HEADERS = {
    "User-Agent": "Inverba/0.1 (+https://github.com/inverba-project/inverba-core)"
}

# Heuristic signals that a page is a JS shell and needs browser rendering.
_SPA_MARKERS = (
    re.compile(r'<div\s+id=["\']root["\']\s*>\s*</div>', re.IGNORECASE),
    re.compile(r'<div\s+id=["\']app["\']\s*>\s*</div>', re.IGNORECASE),
    re.compile(r'<noscript>.*you need to enable javascript', re.IGNORECASE | re.DOTALL),
)
_MIN_BODY_LEN_FOR_STATIC = 200  # bytes; below this + SPA markers, escalate to browser


def _looks_like_js_shell(html: str) -> bool:
    if len(html) < _MIN_BODY_LEN_FOR_STATIC:
        return True
    return any(pattern.search(html) for pattern in _SPA_MARKERS)


class FetchEngine:
    """
    Fetches a URL and returns a FetchResult with raw bytes intact.

    Raw bytes are never mutated before hashing -- the provenance layer
    hashes exactly what this class returns in `FetchResult.content`.
    """

    def __init__(
        self,
        timeout: float = 20.0,
        headers: Optional[dict[str, str]] = None,
        allow_browser_fallback: bool = True,
        follow_redirects: bool = True,
    ):
        self.timeout = timeout
        self.headers = {**DEFAULT_HEADERS, **(headers or {})}
        self.allow_browser_fallback = allow_browser_fallback
        self.follow_redirects = follow_redirects

    async def fetch(self, url: str) -> FetchResult:
        result = await self._fetch_http(url)

        if not result.ok:
            return result

        if self.allow_browser_fallback and result.content_type.startswith("text/html"):
            try:
                text = result.content.decode("utf-8", errors="ignore")
            except Exception:
                text = ""
            if _looks_like_js_shell(text):
                browser_result = await self._fetch_browser(url)
                if browser_result is not None:
                    return browser_result
                # Browser fallback unavailable (e.g. playwright not installed,
                # or browser binaries not downloaded) -- return the http
                # result rather than failing the whole job.

        return result

    async def _fetch_http(self, url: str) -> FetchResult:
        try:
            async with httpx.AsyncClient(
                timeout=self.timeout,
                follow_redirects=self.follow_redirects,
                headers=self.headers,
            ) as client:
                resp = await client.get(url)
                return FetchResult(
                    url=url,
                    final_url=str(resp.url),
                    status_code=resp.status_code,
                    content=resp.content,
                    content_type=resp.headers.get("content-type", ""),
                    method=FetchMethod.HTTP,
                    headers=dict(resp.headers),
                )
        except httpx.HTTPError as e:
            return FetchResult(
                url=url,
                final_url=url,
                status_code=0,
                content=b"",
                content_type="",
                method=FetchMethod.HTTP,
                error=str(e),
            )

    async def _fetch_browser(self, url: str) -> Optional[FetchResult]:
        try:
            from playwright.async_api import async_playwright
        except ImportError:
            return None

        try:
            async with async_playwright() as pw:
                browser = await pw.chromium.launch(headless=True)
                try:
                    page = await browser.new_page()
                    resp = await page.goto(url, timeout=self.timeout * 1000, wait_until="networkidle")
                    html = await page.content()
                    return FetchResult(
                        url=url,
                        final_url=page.url,
                        status_code=resp.status if resp else 0,
                        content=html.encode("utf-8"),
                        content_type="text/html",
                        method=FetchMethod.BROWSER,
                    )
                finally:
                    await browser.close()
        except Exception as e:
            return FetchResult(
                url=url,
                final_url=url,
                status_code=0,
                content=b"",
                content_type="",
                method=FetchMethod.BROWSER,
                error=str(e),
            )
