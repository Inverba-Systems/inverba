import pytest
import httpx

from inverba.fetch import FetchEngine, _looks_like_js_shell


@pytest.mark.asyncio
async def test_fetch_static_html_via_mock_transport():
    async def handler(request):
        return httpx.Response(200, content=b"<html><body>real content here</body></html>",
                               headers={"content-type": "text/html"})

    transport = httpx.MockTransport(handler)

    # Patch AsyncClient to use our mock transport for this test.
    class PatchedEngine(FetchEngine):
        async def _fetch_http(self, url):
            async with httpx.AsyncClient(transport=transport) as client:
                resp = await client.get(url)
                from inverba.models import FetchResult, FetchMethod
                return FetchResult(
                    url=url,
                    final_url=str(resp.url),
                    status_code=resp.status_code,
                    content=resp.content,
                    content_type=resp.headers.get("content-type", ""),
                    method=FetchMethod.HTTP,
                    headers=dict(resp.headers),
                )

    engine = PatchedEngine(allow_browser_fallback=False)
    result = await engine.fetch("https://example.com")
    assert result.ok
    assert b"real content here" in result.content


def test_js_shell_detection_empty_root_div():
    assert _looks_like_js_shell('<html><body><div id="root"></div></body></html>') is True


def test_js_shell_detection_normal_page():
    long_html = "<html><body><p>" + ("real content " * 50) + "</p></body></html>"
    assert _looks_like_js_shell(long_html) is False


def test_js_shell_detection_short_body():
    assert _looks_like_js_shell("<html></html>") is True
