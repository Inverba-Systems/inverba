import tempfile
import time
from pathlib import Path

from inverba.models import FetchResult, FetchMethod
from inverba.provenance import ProvenanceSigner
from inverba.changes import ChangeStore, ChangeDetector, verify_change_report, DiffLevel


def fr(url, content, at=None):
    return FetchResult(
        url=url, final_url=url, status_code=200, content=content,
        content_type="text/html", method=FetchMethod.HTTP,
        fetched_at=at or time.time(),
    )


PAGE = (b"<html><body><article><h1>Widget Pro</h1>"
        b"<p>Price: $49.99. In stock. Durable stainless steel widget for "
        b"professionals who need reliable precision tooling every day.</p>"
        b"</article></body></html>")


def make_detector(tmp):
    store = ChangeStore(Path(tmp) / "changes.db")
    signer = ProvenanceSigner.generate()
    return ChangeDetector(store, signer), store


def test_first_observation_sets_baseline():
    with tempfile.TemporaryDirectory() as tmp:
        detector, store = make_detector(tmp)
        report = detector.detect(fr("https://shop.com/w", PAGE))
        assert report.first_observation is True
        assert report.changed is False
        assert report.before_hash is None
        assert report.after_provenance is not None
        # A first observation must be unmistakable, never confusable with "unchanged":
        assert report.level == "first_observation"
        assert report.similarity is None
        store.close()


def test_clock_skew_never_drops_or_misorders_observations():
    # observed_at is a self-asserted, untrusted, non-monotonic clock value.
    # The store must survive equal timestamps (no silent loss) and a clock
    # rewind (latest = most-recently-inserted, not highest observed_at).
    with tempfile.TemporaryDirectory() as tmp:
        detector, store = make_detector(tmp)
        url = "https://shop.com/skew"
        # (1) two distinct observations sharing one observed_at -> both retained
        detector.detect(fr(url, b"<html><body>one two three four</body></html>", at=1000.0))
        detector.detect(fr(url, b"<html><body>five six seven eight</body></html>", at=1000.0))
        assert len(store.history(url)) == 2, "an observation was silently dropped"
        # (2) clock rewind: the newest INSERT is latest, regardless of observed_at
        detector.detect(fr(url, b"<html><body>NEWEST after a clock rewind</body></html>", at=1.0))
        assert "NEWEST" in store.latest(url).text, "latest() misordered under clock rewind"
        store.close()


def test_no_change_between_identical_fetches():
    with tempfile.TemporaryDirectory() as tmp:
        detector, store = make_detector(tmp)
        detector.detect(fr("https://shop.com/w", PAGE, at=1000))
        # same content, later, with volatile noise added
        noisy = PAGE.replace(b"</article>", b"<script nonce='xyz123abc'>x</script></article>")
        report = detector.detect(fr("https://shop.com/w", noisy, at=2000))
        assert report.changed is False
        assert report.level == DiffLevel.IDENTICAL.value
        store.close()


def test_price_change_detected_as_material_with_evidence():
    with tempfile.TemporaryDirectory() as tmp:
        detector, store = make_detector(tmp)
        detector.detect(fr("https://shop.com/w", PAGE, at=1000))
        changed = PAGE.replace(b"49.99", b"59.99")
        report = detector.detect(fr("https://shop.com/w", changed, at=2000))

        assert report.changed is True
        assert report.level == DiffLevel.MATERIAL.value
        assert report.before_at == 1000
        assert report.after_at == 2000
        # both states are signed -> the change is evidenced
        assert report.before_provenance is not None
        assert report.after_provenance is not None

        verification = verify_change_report(report)
        assert verification["before_valid"] is True
        assert verification["after_valid"] is True
        store.close()


def test_history_accumulates():
    with tempfile.TemporaryDirectory() as tmp:
        detector, store = make_detector(tmp)
        detector.detect(fr("https://shop.com/w", PAGE, at=1000))
        detector.detect(fr("https://shop.com/w", PAGE.replace(b"49.99", b"59.99"), at=2000))
        detector.detect(fr("https://shop.com/w", PAGE.replace(b"49.99", b"69.99"), at=3000))
        hist = store.history("https://shop.com/w")
        assert len(hist) == 3
        # newest first
        assert hist[0].observed_at == 3000
        store.close()


def test_tracking_params_dont_create_separate_baselines():
    with tempfile.TemporaryDirectory() as tmp:
        detector, store = make_detector(tmp)
        detector.detect(fr("https://shop.com/w?utm_source=google", PAGE, at=1000))
        report = detector.detect(fr("https://shop.com/w?utm_source=facebook", PAGE, at=2000))
        # same canonical URL -> second is compared against first, not treated as new
        assert report.first_observation is False
        assert report.changed is False
        store.close()
