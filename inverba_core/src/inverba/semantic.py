"""
Semantic content normalization and spectrum diffing.

WHY THIS EXISTS:
Two honest workers fetching the same URL rarely get identical bytes --
personalization, A/B tests, timestamps, ad tokens, CSRF nonces, rotating
build hashes, and analytics all mutate the raw response. A naive
byte-hash corroboration would flag honest workers as liars on the majority
of real pages and destroy the trust layer.

The fix has two parts:

  1. NORMALIZATION -- reduce a page to its stable semantic content, stripping
     the volatile scaffolding (scripts, nonces, timestamps, tracking params)
     before hashing. Two honest observations of "the same page" should
     normalize to the same content hash even when raw bytes differ.

  2. SPECTRUM DIFF -- "different" is not binary. Two normalized observations
     fall on a spectrum:
         IDENTICAL   -> same normalized content hash
         COSMETIC    -> trivial differences (whitespace, attribute order)
         MATERIAL    -> real content changed (prices, text, links)
         DIVERGENT   -> so different it suggests cloaking or a wrong page

This module is the shared foundation for change-detection (same URL over
time) AND cloaking-detection (different workers, same time). Both are
"compare two normalized observations and classify the difference."
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from difflib import SequenceMatcher
from enum import Enum
from typing import Optional
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

import trafilatura


class DiffLevel(str, Enum):
    FIRST_OBSERVATION = "first_observation"  # no prior snapshot existed; nothing to compare
    IDENTICAL = "identical"     # normalized content hashes match exactly
    COSMETIC = "cosmetic"        # >= COSMETIC_THRESHOLD similar; no material change
    MATERIAL = "material"        # real content changed but recognizably same page
    DIVERGENT = "divergent"      # so different it suggests cloaking / wrong page


# Similarity thresholds on normalized text (0..1). Tuned conservatively;
# callers can override via SemanticNormalizer/SpectrumDiffer construction.
COSMETIC_THRESHOLD = 0.98   # >= this and not identical -> COSMETIC
MATERIAL_THRESHOLD = 0.60   # >= this (and < cosmetic) -> MATERIAL; below -> DIVERGENT


# Query params that are almost always volatile tracking/session noise.
_VOLATILE_QUERY_PARAMS = {
    "utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content",
    "gclid", "fbclid", "msclkid", "mc_cid", "mc_eid", "_ga", "ref", "referrer",
    "session", "sessionid", "sid", "csrf", "csrftoken", "token", "nonce",
    "timestamp", "ts", "_", "cache", "cb", "v", "version",
}

# Patterns for volatile inline content stripped before hashing.
_SCRIPT_STYLE = re.compile(r"<(script|style|noscript)\b[^>]*>.*?</\1>", re.IGNORECASE | re.DOTALL)
_HTML_COMMENT = re.compile(r"<!--.*?-->", re.DOTALL)
_NONCE_ATTR = re.compile(r'\s(nonce|integrity|csrf[-_]?token)=["\'][^"\']*["\']', re.IGNORECASE)
_LONG_HEX = re.compile(r"\b[0-9a-f]{16,}\b", re.IGNORECASE)   # build/cache hashes
_ISO_TIMESTAMP = re.compile(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(:\d{2})?")
_MULTISPACE = re.compile(r"\s+")

# High-signal tokens whose change is material even when overall text similarity
# is high. A one-character price edit is trivially similar by character ratio
# but is the most important change possible for monitoring use cases -- so we
# detect changed numbers/prices/currency directly rather than relying on
# whole-text similarity alone (the review's MATERIAL-vs-COSMETIC gap).
_PRICE = re.compile(r"[$£€¥]\s?\d[\d,]*(?:\.\d+)?|\b\d[\d,]*\.\d{2}\b")
_NUMBER = re.compile(r"\b\d[\d,]*(?:\.\d+)?\b")
_MONEY_WORDS = re.compile(r"\b(?:free|sold out|out of stock|in stock|unavailable|discontinued)\b", re.IGNORECASE)


def canonicalize_url(url: str) -> str:
    """Drop volatile tracking params and fragments so the same logical URL
    hashes consistently across workers and over time."""
    parsed = urlparse(url)
    if parsed.query:
        params = parse_qs(parsed.query, keep_blank_values=True)
        kept = {k: v for k, v in params.items() if k.lower() not in _VOLATILE_QUERY_PARAMS}
        query = urlencode(kept, doseq=True)
    else:
        query = ""
    # strip fragment; lowercase host; keep path/params as-is
    return urlunparse((
        parsed.scheme.lower(),
        parsed.netloc.lower(),
        parsed.path,
        parsed.params,
        query,
        "",  # no fragment
    ))


@dataclass
class NormalizedContent:
    """The stable semantic representation of a fetched page."""
    url_canonical: str
    text: str                       # extracted main content, normalized
    content_hash: str                # sha256 of the normalized text
    raw_hash: str                    # sha256 of raw bytes (kept for reference)
    text_length: int = 0

    def __post_init__(self):
        self.text_length = len(self.text)


class SemanticNormalizer:
    """Turn raw fetched bytes into stable NormalizedContent."""

    def normalize(self, url: str, raw: bytes) -> NormalizedContent:
        raw_hash = hashlib.sha256(raw).hexdigest()
        html = raw.decode("utf-8", errors="ignore")

        # Prefer trafilatura's main-content extraction (drops nav/ads/boilerplate,
        # which are among the most volatile parts of a page). Fall back to a
        # scrubbed version of the whole document if extraction yields nothing.
        extracted = trafilatura.extract(html, output_format="txt", favor_recall=True)
        basis = extracted if extracted else self._scrub_html(html)

        text = self._normalize_text(basis)
        content_hash = hashlib.sha256(text.encode("utf-8")).hexdigest()

        return NormalizedContent(
            url_canonical=canonicalize_url(url),
            text=text,
            content_hash=content_hash,
            raw_hash=raw_hash,
        )

    @staticmethod
    def _scrub_html(html: str) -> str:
        html = _SCRIPT_STYLE.sub(" ", html)
        html = _HTML_COMMENT.sub(" ", html)
        html = _NONCE_ATTR.sub("", html)
        # strip tags crudely -- we only need stable text for hashing/diffing
        html = re.sub(r"<[^>]+>", " ", html)
        return html

    @staticmethod
    def _normalize_text(text: str) -> str:
        # Neutralize volatile tokens that change per-request but aren't content.
        text = _LONG_HEX.sub("<HEX>", text)
        text = _ISO_TIMESTAMP.sub("<TIMESTAMP>", text)
        text = _MULTISPACE.sub(" ", text)
        return text.strip()


@dataclass
class DiffResult:
    level: DiffLevel
    similarity: float                       # 0..1 on normalized text
    changed: bool                            # True unless IDENTICAL
    a_hash: str = ""
    b_hash: str = ""
    summary: str = ""
    added_excerpt: Optional[str] = None      # sample of text present in B not A
    removed_excerpt: Optional[str] = None    # sample of text present in A not B


class SpectrumDiffer:
    """Classify the difference between two NormalizedContent observations."""

    def __init__(
        self,
        cosmetic_threshold: float = COSMETIC_THRESHOLD,
        material_threshold: float = MATERIAL_THRESHOLD,
    ):
        self.cosmetic_threshold = cosmetic_threshold
        self.material_threshold = material_threshold

    def diff(self, a: NormalizedContent, b: NormalizedContent) -> DiffResult:
        if a.content_hash == b.content_hash:
            return DiffResult(
                level=DiffLevel.IDENTICAL, similarity=1.0, changed=False,
                a_hash=a.content_hash, b_hash=b.content_hash,
                summary="Normalized content is identical.",
            )

        similarity = SequenceMatcher(None, a.text, b.text).ratio()

        # Significance check: did any high-signal tokens (prices, numbers,
        # stock words) actually change? A tiny edit that flips a price is
        # MATERIAL even at 0.99 text similarity. This closes the gap where
        # whole-text ratio underweights small-but-critical changes.
        significant = self._significant_token_change(a.text, b.text)

        if similarity < self.material_threshold:
            # Genuine divergence wins regardless of token signals -- a wholly
            # different page (cloaking / wrong response) is DIVERGENT even if
            # both happen to contain a price or the word "free".
            level = DiffLevel.DIVERGENT
            summary = ("Content diverges sharply -- possible cloaking, wrong "
                       "page, or a fundamentally different response.")
        elif similarity >= self.cosmetic_threshold and not significant:
            level = DiffLevel.COSMETIC
            summary = "Trivial differences only; no material content change."
        else:
            # Either mid-range similarity, or high similarity with a changed
            # high-signal token -- both are MATERIAL.
            level = DiffLevel.MATERIAL
            if significant and similarity >= self.cosmetic_threshold:
                summary = ("Small edit but a high-signal value (price/number/"
                           "stock status) changed -- treated as material.")
            else:
                summary = "Material content changed; recognizably the same page."

        added, removed = self._excerpts(a.text, b.text)

        return DiffResult(
            level=level, similarity=round(similarity, 4), changed=True,
            a_hash=a.content_hash, b_hash=b.content_hash, summary=summary,
            added_excerpt=added, removed_excerpt=removed,
        )

    @staticmethod
    def _significant_token_change(a_text: str, b_text: str) -> bool:
        """True if prices, numbers, or stock-status words differ between the two."""
        if set(_PRICE.findall(a_text)) != set(_PRICE.findall(b_text)):
            return True
        if set(m.lower() for m in _MONEY_WORDS.findall(a_text)) != \
           set(m.lower() for m in _MONEY_WORDS.findall(b_text)):
            return True
        # Number-set change is a weaker signal; only count it when the overall
        # texts are otherwise very similar (i.e. a targeted numeric edit).
        if SequenceMatcher(None, a_text, b_text).ratio() >= 0.95:
            if set(_NUMBER.findall(a_text)) != set(_NUMBER.findall(b_text)):
                return True
        return False

    @staticmethod
    def _excerpts(a_text: str, b_text: str, max_len: int = 240) -> tuple[Optional[str], Optional[str]]:
        """Small human-readable samples of what changed, for reports."""
        sm = SequenceMatcher(None, a_text, b_text)
        added_parts, removed_parts = [], []
        for tag, i1, i2, j1, j2 in sm.get_opcodes():
            if tag in ("replace", "delete"):
                removed_parts.append(a_text[i1:i2])
            if tag in ("replace", "insert"):
                added_parts.append(b_text[j1:j2])
        added = " ".join(added_parts).strip()[:max_len] or None
        removed = " ".join(removed_parts).strip()[:max_len] or None
        return added, removed
