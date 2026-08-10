"""
Tests for the onboarding surface.

The CLI is the first thing a new user touches, so its behavior is a product
guarantee, not a convenience. These lock in:
  - `inverba demo` works with no network, no key, no setup
  - `inverba verify` gives a human verdict and correct exit codes
  - tampering is caught (the aha moment actually fires)
  - the notary is OFF by default and never contacted unless enabled
"""

import json
import time
from pathlib import Path

from click.testing import CliRunner

from inverba.cli import main
from inverba.provenance import ProvenanceSigner
from inverba.models import FetchResult, FetchMethod


PAGE = b"<html><body><article><h1>Item</h1><p>Price: $49.99.</p></article></body></html>"


def write_record(tmp: Path, content: bytes = PAGE):
    """Create a real signed record + content pair on disk, like `solo` does."""
    signer = ProvenanceSigner.generate()
    fr = FetchResult(url="https://example.com/p", final_url="https://example.com/p",
                     status_code=200, content=content, content_type="text/html",
                     method=FetchMethod.HTTP, fetched_at=time.time())
    record = signer.sign(fr)
    rec_path = tmp / "record.json"
    rec_path.write_text(json.dumps(record.to_dict(), indent=2))
    (tmp / "record.content").write_bytes(content)
    return rec_path


# ---- demo: the zero-friction taste ----

def test_demo_runs_with_no_network_or_setup():
    result = CliRunner().invoke(main, ["demo"])
    assert result.exit_code == 0
    # it must actually show the tamper failing -- that's the whole point
    assert "CONTENT_MISMATCH" in result.output
    assert "signature invalid" in result.output


def test_demo_ends_with_a_next_step():
    result = CliRunner().invoke(main, ["demo"])
    assert "inverba solo" in result.output


# ---- verify: the aha moment ----

def test_verify_valid_record_exits_zero():
    runner = CliRunner()
    with runner.isolated_filesystem() as tmp:
        rec = write_record(Path(tmp))
        result = runner.invoke(main, ["verify", str(rec)])
        assert result.exit_code == 0
        assert "VALID" in result.output
        assert "matches the signed hash" in result.output


def test_verify_catches_tampered_content():
    runner = CliRunner()
    with runner.isolated_filesystem() as tmp:
        rec = write_record(Path(tmp))
        # flip one character in the content
        c = Path(tmp) / "record.content"
        c.write_bytes(PAGE.replace(b"49.99", b"39.99"))
        result = runner.invoke(main, ["verify", str(rec)])
        assert result.exit_code == 1
        assert "INVALID" in result.output
        assert "DOES NOT MATCH" in result.output


def test_verify_catches_forged_signature():
    runner = CliRunner()
    with runner.isolated_filesystem() as tmp:
        rec = write_record(Path(tmp))
        data = json.loads(rec.read_text())
        data["signature"] = "00" * 64
        rec.write_text(json.dumps(data))
        result = runner.invoke(main, ["verify", str(rec)])
        assert result.exit_code == 1
        assert "INVALID" in result.output


def test_verify_distinguishes_bad_sig_from_bad_content():
    """A valid signature with mismatched content is a DIFFERENT failure than a
    forged signature. Collapsing them would lose the bait-and-switch signal."""
    runner = CliRunner()
    with runner.isolated_filesystem() as tmp:
        rec = write_record(Path(tmp))
        (Path(tmp) / "record.content").write_bytes(b"totally different bytes")
        result = runner.invoke(main, ["verify", str(rec)])
        assert "signature  valid" in result.output      # sig is fine...
        assert "DOES NOT MATCH" in result.output          # ...content is not


def test_verify_json_output_is_machine_readable():
    runner = CliRunner()
    with runner.isolated_filesystem() as tmp:
        rec = write_record(Path(tmp))
        result = runner.invoke(main, ["verify", str(rec), "--json-out"])
        assert result.exit_code == 0
        payload = json.loads(result.output)
        assert payload["primary_valid"] is True


def test_verify_without_content_warns_not_checked():
    """A record separated from its .content must not read as fully verified: the
    signature is valid, but verify loudly flags that content was NOT CHECKED so the
    downgrade to signature-only can't happen silently."""
    runner = CliRunner()
    with runner.isolated_filesystem() as tmp:
        rec = write_record(Path(tmp))
        (Path(tmp) / "record.content").unlink()      # separate record from its content
        result = runner.invoke(main, ["verify", str(rec)])
        assert result.exit_code == 0
        assert "VALID" in result.output
        assert "NOT CHECKED" in result.output


def test_verify_json_always_reports_content_matches():
    """--json-out must always include content_matches (null when unchecked), so a
    machine consumer never mistakes a missing key for a content pass."""
    runner = CliRunner()
    with runner.isolated_filesystem() as tmp:
        rec = write_record(Path(tmp))
        (Path(tmp) / "record.content").unlink()
        result = runner.invoke(main, ["verify", str(rec), "--json-out"])
        payload = json.loads(result.output)
        assert "content_matches" in payload
        assert payload["content_matches"] is None


# ---- notary: off by default, never silent ----

def test_notary_status_defaults_to_disabled(tmp_path, monkeypatch):
    monkeypatch.setenv("INVERBA_HOME", str(tmp_path))
    import importlib
    from inverba import solo as solo_mod
    importlib.reload(solo_mod)
    result = CliRunner().invoke(main, ["notary", "status"])
    assert result.exit_code == 0
    assert "disabled" in result.output.lower()


def test_notary_enable_declined_stays_local(tmp_path, monkeypatch):
    monkeypatch.setenv("INVERBA_HOME", str(tmp_path))
    import importlib
    from inverba import solo as solo_mod
    importlib.reload(solo_mod)
    # answer "no" to the confirm prompt
    result = CliRunner().invoke(main, ["notary", "enable"], input="n\n")
    assert result.exit_code == 0
    assert "100% local" in result.output


def test_verify_accepts_scrape_jsonout_wrapped_record(tmp_path, monkeypatch):
    """The documented `inverba scrape --json-out > f; inverba verify f` path must
    work: scrape wraps the record under {job_id, markdown, provenance:{...}} while
    verify expects a flat record. verify must accept both shapes."""
    import json
    from click.testing import CliRunner
    from inverba import cli
    from inverba.models import FetchResult, FetchMethod
    from inverba.provenance import ProvenanceSigner

    signer = ProvenanceSigner.generate()
    fr = FetchResult(url="https://example.com/", final_url="https://example.com/",
                     status_code=200, content=b"<html>hi</html>", content_type="text/html",
                     method=FetchMethod.HTTP, fetched_at=1.0)
    rec = signer.sign(fr)

    # wrapped, exactly as `scrape --json-out` emits it
    wrapped = tmp_path / "wrapped.json"
    wrapped.write_text(json.dumps({"job_id": "abc", "url": "https://example.com/",
                                   "markdown": "hi", "structured": None,
                                   "provenance": rec.to_dict()}))
    r = CliRunner().invoke(cli.main, ["verify", str(wrapped)])
    assert r.exit_code == 0, r.output
    assert "VALID" in r.output and "INVALID" not in r.output

    # flat, as `solo` emits it — must still work
    flat = tmp_path / "flat.json"
    flat.write_text(json.dumps(rec.to_dict()))
    r2 = CliRunner().invoke(cli.main, ["verify", str(flat)])
    assert r2.exit_code == 0 and "VALID" in r2.output
