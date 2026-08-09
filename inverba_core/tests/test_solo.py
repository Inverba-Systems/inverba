import tempfile
import time
from pathlib import Path

from inverba.provenance import ProvenanceSigner, verify_record
from inverba.models import FetchResult, FetchMethod
from inverba.solo import (
    SoloConfig, SoloSession, ensure_notary_preference, SoloResult,
)


def fetch_result(content=b"<html>solo page</html>", url="https://x.com"):
    return FetchResult(url=url, final_url=url, status_code=200, content=content,
                       content_type="text/html", method=FetchMethod.HTTP,
                       fetched_at=time.time())


class FakeNotaryClient:
    """Stands in for NotaryClient; reports a controllable corroboration."""
    def __init__(self, corroborated=True, detail="notary agreed"):
        self._corroborated = corroborated
        self._detail = detail
        self.called = False

    def notarize(self, record, content):
        self.called = True
        from inverba.notary import NotaryResult
        # simulate folding a corroboration in on match
        if self._corroborated:
            corr_signer = ProvenanceSigner.generate()
            record.corroborations.append(corr_signer.sign(
                FetchResult(url=record.url, final_url=record.url, status_code=200,
                            content=content, content_type="text/html",
                            method=FetchMethod.HTTP, fetched_at=record.fetched_at)))
        return NotaryResult(corroborated=self._corroborated, notary_record=None,
                            agreement="match" if self._corroborated else "mismatch",
                            detail=self._detail)


# ---- solo works fully at N=1 ----

def test_solo_scrape_produces_valid_signed_record_without_notary():
    signer = ProvenanceSigner.generate()
    cfg = SoloConfig(notary_enabled=False, asked_notary=True)
    session = SoloSession(signer, config=cfg)
    result = session.sign_result(fetch_result())
    assert verify_record(result.record) is True
    assert result.notary_used is False
    assert result.corroborated is False


def test_solo_stays_fully_local_when_notary_declined():
    signer = ProvenanceSigner.generate()
    cfg = SoloConfig(notary_enabled=False, asked_notary=True)
    notary = FakeNotaryClient()
    session = SoloSession(signer, config=cfg, notary_client=notary)
    session.sign_result(fetch_result())
    # notary must NOT be contacted when the user declined
    assert notary.called is False


# ---- notary opt-in ----

def test_solo_uses_notary_when_opted_in():
    signer = ProvenanceSigner.generate()
    cfg = SoloConfig(notary_enabled=True, asked_notary=True)
    notary = FakeNotaryClient(corroborated=True)
    session = SoloSession(signer, config=cfg, notary_client=notary)
    result = session.sign_result(fetch_result())
    assert notary.called is True
    assert result.notary_used is True
    assert result.corroborated is True
    assert len(result.record.corroborations) == 1


# ---- first-run prompt ----

def test_first_run_prompt_asked_once_and_persisted():
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "solo_config.json"
        cfg = SoloConfig.load(path)
        assert cfg.asked_notary is False   # never asked yet

        calls = {"n": 0}
        def prompt():
            calls["n"] += 1
            return True

        cfg = ensure_notary_preference(cfg, prompt)
        cfg.save(path)
        assert cfg.asked_notary is True
        assert cfg.notary_enabled is True
        assert calls["n"] == 1

        # reload -> should NOT ask again
        cfg2 = SoloConfig.load(path)
        cfg2 = ensure_notary_preference(cfg2, prompt)
        assert calls["n"] == 1   # prompt not called a second time


def test_declining_prompt_persists_as_false():
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "solo_config.json"
        cfg = SoloConfig.load(path)
        cfg = ensure_notary_preference(cfg, lambda: False)
        cfg.save(path)
        reloaded = SoloConfig.load(path)
        assert reloaded.asked_notary is True
        assert reloaded.notary_enabled is False


def test_config_distinguishes_never_asked_from_declined():
    # None = never asked; False = asked and said no. Important distinction.
    fresh = SoloConfig()
    assert fresh.notary_enabled is None
    assert fresh.asked_notary is False

    declined = SoloConfig(notary_enabled=False, asked_notary=True)
    assert declined.notary_enabled is False
    assert declined.asked_notary is True


def test_solo_cli_failed_fetch_is_not_reported_as_success(monkeypatch, tmp_path):
    """`inverba solo` against an unreachable URL must NOT print green 'Signed.'
    A network failure (status 0 + error) is surfaced as a failure with a
    non-zero exit -- reporting success on failed data is the cardinal sin."""
    from click.testing import CliRunner
    from inverba import cli
    from inverba.models import FetchResult, FetchMethod

    async def failing_fetch(self, url):
        return FetchResult(url=url, final_url=url, status_code=0, content=b"",
                           content_type="", method=FetchMethod.HTTP,
                           fetched_at=1.0, error="simulated network failure")

    monkeypatch.setattr("inverba.fetch.FetchEngine.fetch", failing_fetch)
    out = tmp_path / "rec.json"
    key = tmp_path / "worker.key"
    result = CliRunner().invoke(cli.main, ["solo", "http://x.invalid/", "--out", str(out), "--key", str(key)])

    assert result.exit_code != 0, "failed fetch must exit non-zero"
    assert "Signed." not in result.output, "failed fetch must not print the success banner"
    assert "FETCH FAILED" in result.output
