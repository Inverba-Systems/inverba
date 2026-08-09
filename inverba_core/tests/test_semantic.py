"""
Tests for the semantic normalization + spectrum diff engine.

These lock in the fix for the adversarial-review flaw: honest workers
fetching the same page with volatile per-request noise must NOT be flagged
as disagreeing, while real content changes must be classified by
significance rather than raw text similarity.
"""

from inverba.semantic import (
    SemanticNormalizer, SpectrumDiffer, canonicalize_url, DiffLevel,
)

norm = SemanticNormalizer()
differ = SpectrumDiffer()

BASE = (b"<html><body><article><h1>Widget Pro</h1>"
        b"<p>Price: $49.99. In stock. High quality stainless steel widget for "
        b"professionals who demand reliability and precision in daily work.</p>"
        b"</article></body></html>")


def n(html, url="https://shop.com/w"):
    return norm.normalize(url, html)


# ---------- URL canonicalization ----------

def test_canonicalize_drops_tracking_params():
    a = canonicalize_url("https://x.com/p?utm_source=g&id=5&fbclid=abc")
    assert "utm_source" not in a
    assert "fbclid" not in a
    assert "id=5" in a


def test_canonicalize_drops_fragment_and_lowercases_host():
    a = canonicalize_url("https://EXAMPLE.com/Path#section")
    assert a == "https://example.com/Path"


# ---------- the core fix: volatile noise normalizes to identical ----------

def test_volatile_noise_is_identical():
    a = (b"<html><head><script nonce='abc123'>x</script>"
         b"<meta name='csrf-token' content='tok_9f8e7d6c5b4a'></head>"
         b"<body><article><h1>Hi</h1><p>Stable body text here for content.</p>"
         b"</article><span>2026-07-12T06:31:00</span></body></html>")
    b = (b"<html><head><script nonce='zzz999'>x</script>"
         b"<meta name='csrf-token' content='tok_1122334455'></head>"
         b"<body><article><h1>Hi</h1><p>Stable body text here for content.</p>"
         b"</article><span>2026-07-12T09:15:42</span></body></html>")
    result = differ.diff(n(a), n(b))
    assert result.level == DiffLevel.IDENTICAL
    assert result.changed is False


def test_tracking_param_urls_canonicalize_equal():
    a = n(BASE, "https://shop.com/w?utm_source=google&sid=xyz")
    b = n(BASE, "https://shop.com/w?utm_source=fb&sid=abc")
    assert a.url_canonical == b.url_canonical


# ---------- significance-aware classification ----------

def test_price_change_is_material_despite_high_similarity():
    changed = BASE.replace(b"49.99", b"59.99")
    result = differ.diff(n(BASE), n(changed))
    assert result.level == DiffLevel.MATERIAL
    assert result.similarity > 0.98  # tiny textual change...
    assert result.changed is True     # ...but flagged material


def test_stock_status_change_is_material():
    changed = BASE.replace(b"In stock", b"Out of stock")
    result = differ.diff(n(BASE), n(changed))
    assert result.level == DiffLevel.MATERIAL


def test_cloaking_is_divergent_even_with_money_words():
    cloaked = (b"<html><body><article><h1>Casino Bonus</h1>"
               b"<p>Click here to win big money now! Free spins available "
               b"today only for lucky visitors from your region.</p>"
               b"</article></body></html>")
    result = differ.diff(n(BASE), n(cloaked))
    # "free" is a money-word but the pages are wholly different -> DIVERGENT wins
    assert result.level == DiffLevel.DIVERGENT
    assert result.similarity < 0.6


def test_excerpts_populated_on_change():
    changed = BASE.replace(b"49.99", b"59.99")
    result = differ.diff(n(BASE), n(changed))
    assert result.added_excerpt is not None or result.removed_excerpt is not None


def test_identical_has_no_excerpts():
    result = differ.diff(n(BASE), n(BASE))
    assert result.added_excerpt is None
    assert result.removed_excerpt is None


def test_content_hash_stable_across_normalizer_instances():
    h1 = SemanticNormalizer().normalize("https://x.com", BASE).content_hash
    h2 = SemanticNormalizer().normalize("https://x.com", BASE).content_hash
    assert h1 == h2
