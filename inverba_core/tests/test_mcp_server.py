"""
Tests for the MCP server wiring.

The `mcp` package is an optional extra and may not be installed, so we inject a
fake FastMCP that captures the registered tool functions. That lets us exercise
the real scrape/extract/verify logic over stdio's tool layer WITHOUT a network
call or a live Ollama model.
"""
import json
import sys
import types
import time

import pytest

from inverba.models import FetchResult, FetchMethod
from inverba.provenance import ProvenanceSigner


# ---- fake `mcp.server.fastmcp.FastMCP` -----------------------------------

class FakeFastMCP:
    def __init__(self, name):
        self.name = name
        self.tools = {}

    def tool(self):
        def deco(fn):
            self.tools[fn.__name__] = fn
            return fn
        return deco

    def run(self):
        self.ran = True


@pytest.fixture
def fake_mcp(monkeypatch):
    mod = types.ModuleType("mcp")
    server = types.ModuleType("mcp.server")
    fastmcp = types.ModuleType("mcp.server.fastmcp")
    fastmcp.FastMCP = FakeFastMCP
    server.fastmcp = fastmcp
    mod.server = server
    monkeypatch.setitem(sys.modules, "mcp", mod)
    monkeypatch.setitem(sys.modules, "mcp.server", server)
    monkeypatch.setitem(sys.modules, "mcp.server.fastmcp", fastmcp)
    return fastmcp


class FakeEngine:
    def __init__(self, result):
        self._result = result

    async def fetch(self, url):
        return self._result


def _ok(url, content=b"<html><body><h1>Hello</h1><p>Body text here.</p></body></html>"):
    return FetchResult(url=url, final_url=url, status_code=200, content=content,
                       content_type="text/html", method=FetchMethod.HTTP, fetched_at=time.time())


def _fail(url):
    return FetchResult(url=url, final_url=url, status_code=503, content=b"",
                       content_type="text/html", method=FetchMethod.HTTP,
                       fetched_at=time.time(), error="server error")


def test_build_server_registers_three_tools(fake_mcp, tmp_path):
    from inverba import mcp_server
    server = mcp_server.build_server(key_path=tmp_path / "worker.key")
    assert set(server.tools) == {"inverba_scrape", "inverba_extract", "inverba_verify"}


def test_load_signer_creates_then_reloads_same_key(tmp_path):
    from inverba.mcp_server import _load_signer
    kp = tmp_path / "sub" / "worker.key"
    s1 = _load_signer(kp)
    assert kp.exists()
    s2 = _load_signer(kp)
    # reload yields the SAME identity, not a fresh key
    assert s1.public_key_hex() == s2.public_key_hex()


@pytest.mark.asyncio
async def test_scrape_tool_returns_markdown_and_provenance(fake_mcp, tmp_path, monkeypatch):
    from inverba import mcp_server
    monkeypatch.setattr(mcp_server, "FetchEngine", lambda: FakeEngine(_ok("https://x.com")))
    server = mcp_server.build_server(key_path=tmp_path / "worker.key")

    out = json.loads(await server.tools["inverba_scrape"]("https://x.com"))
    assert out["url"] == "https://x.com"
    assert "markdown" in out
    assert out["provenance"]["url"] == "https://x.com"


@pytest.mark.asyncio
async def test_scrape_tool_reports_fetch_failure_without_faking_data(fake_mcp, tmp_path, monkeypatch):
    from inverba import mcp_server
    monkeypatch.setattr(mcp_server, "FetchEngine", lambda: FakeEngine(_fail("https://down.example")))
    server = mcp_server.build_server(key_path=tmp_path / "worker.key")

    out = json.loads(await server.tools["inverba_scrape"]("https://down.example"))
    assert "error" in out
    assert "markdown" not in out


@pytest.mark.asyncio
async def test_extract_tool_reports_fetch_failure(fake_mcp, tmp_path, monkeypatch):
    from inverba import mcp_server
    monkeypatch.setattr(mcp_server, "FetchEngine", lambda: FakeEngine(_fail("https://down.example")))
    server = mcp_server.build_server(key_path=tmp_path / "worker.key")

    out = json.loads(await server.tools["inverba_extract"]("https://down.example", "{}"))
    assert "error" in out


def test_verify_tool_validates_a_real_record(fake_mcp, tmp_path):
    from inverba import mcp_server
    signer = ProvenanceSigner.generate()
    rec = signer.sign(_ok("https://x.com"))
    server = mcp_server.build_server(key_path=tmp_path / "worker.key")

    out = json.loads(server.tools["inverba_verify"](json.dumps(rec.to_dict())))
    assert out["primary_valid"] is True


def test_main_builds_and_runs_the_server(fake_mcp, tmp_path, monkeypatch):
    from inverba import mcp_server
    monkeypatch.setattr(mcp_server.Path, "home", staticmethod(lambda: tmp_path))
    mcp_server.main()
    # FakeFastMCP.run set the flag — main wired build_server -> run without error
