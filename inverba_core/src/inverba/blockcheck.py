"""
Bot-wall / soft-block detection.

The failure this addresses: a CAPTCHA or "please wait while we verify your
browser" page returns HTTP 200 with junk content. A naive fetch treats it as a
successful scrape, signs it, and now there is a cryptographically perfect record
attesting to a CAPTCHA. Verification passes over garbage -- the single worst
failure mode for a provenance product, because the math is right and the content
is a lie.

Two layers of defence, because who needs the signal differs:

  1. SIGNED FETCH METADATA (in the record itself) -- status_code, final_url,
     content_type are now part of the signed payload. A redirect to a challenge
     URL (final_url != url) is the classic tell, and it's tamper-evident. This
     protects the DOWNSTREAM VERIFIER, who sees the record months later.

  2. CONTENT HEURISTICS (this module) -- pattern-match the body for the
     signatures of known challenge pages. This protects the PERSON FETCHING, who
     gets an immediate warning instead of a false green "Signed."

Heuristics are inherently imperfect: they miss novel walls (false negatives) and
could flag a page that merely discusses CAPTCHAs (false positives). So this
NEVER blocks silently and never claims certainty -- it returns a confidence and
the signals it matched, and the caller decides. The signed-metadata layer is the
tamper-proof half; this is the helpful-warning half.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class BlockVerdict(str, Enum):
    CLEAN = "clean"                    # no block signals
    SUSPECTED_BLOCK = "suspected_block"  # matched challenge signals
    HARD_BLOCK = "hard_block"          # non-2xx status: the site said no outright


# Substrings that strongly indicate an interstitial challenge rather than content.
# Kept specific to reduce false positives -- generic words like "captcha" alone
# aren't enough; these are phrases challenge pages actually render.
_CHALLENGE_MARKERS = (
    "checking your browser before accessing",
    "please wait while we verify",
    "verifying you are human",
    "enable javascript and cookies to continue",
    "ddos protection by",
    "cf-browser-verification",
    "cf_chl_",                          # cloudflare challenge tokens
    "just a moment...",                  # cloudflare interstitial title
    "attention required! | cloudflare",
    "please verify you are a human",
    "px-captcha",                        # perimeterx
    "/recaptcha/api",                    # google recaptcha widget
    "hcaptcha.com/captcha",
    "access to this page has been denied",  # perimeterx block
    "unusual traffic from your computer network",  # google sorry page
    "to continue, please type the characters",
    "request unsuccessful. incapsula",   # imperva/incapsula
    "_incapsula_resource",
    # Amazon's anti-bot / CAPTCHA page (one of the most common e-commerce walls).
    # High-precision phrases -- these do not appear on ordinary product content.
    "to discuss automated access to amazon",
    "api-services-support@amazon",
    "enter the characters you see below",
    "type the characters you see in this image",
    "characters you see in this image",
)

# Redirect path fragments that indicate a challenge endpoint.
_CHALLENGE_PATHS = ("/cdn-cgi/challenge", "/sorry/", "/challenge", "/px/", "/_incapsula")


@dataclass
class BlockCheck:
    verdict: str
    is_suspicious: bool
    confidence: str                    # "high" | "medium" | "low" | "none"
    signals: list[str] = field(default_factory=list)
    status_code: Optional[int] = None

    def to_dict(self) -> dict:
        return {"verdict": self.verdict, "is_suspicious": self.is_suspicious,
                "confidence": self.confidence, "signals": self.signals,
                "status_code": self.status_code}


def detect_block(
    content: bytes,
    *,
    status_code: int = 200,
    url: str = "",
    final_url: str = "",
    content_type: str = "",
) -> BlockCheck:
    """
    Inspect a fetch result for bot-wall / soft-block signals.

    Combines the tamper-evident signals (status, redirect) with content
    heuristics. Returns a verdict + confidence + the specific signals matched,
    never a silent block.
    """
    signals: list[str] = []

    # Failed fetch: status_code 0 means the fetch never produced an HTTP response
    # (network error, DNS failure, TLS error, timeout -- FetchEngine returns
    # status 0 + error rather than raising). This is NOT "clean"; it must never
    # fall through to a clean verdict, or a failed fetch reads as a success.
    if status_code == 0:
        return BlockCheck(
            verdict=BlockVerdict.HARD_BLOCK.value, is_suspicious=True,
            confidence="high", status_code=status_code,
            signals=["fetch produced no HTTP response (status 0 -- network/DNS/TLS failure or timeout)"],
        )

    # Hard block: the site refused outright. Unambiguous.
    if status_code and not (200 <= status_code < 300):
        return BlockCheck(
            verdict=BlockVerdict.HARD_BLOCK.value, is_suspicious=True,
            confidence="high", status_code=status_code,
            signals=[f"non-2xx status {status_code}"],
        )

    # Redirect to a challenge endpoint (tamper-evident signal).
    if final_url and url and final_url != url:
        lowered_final = final_url.lower()
        if any(p in lowered_final for p in _CHALLENGE_PATHS):
            signals.append(f"redirected to challenge endpoint: {final_url}")

    # Content heuristics.
    try:
        text = content[:20000].decode("utf-8", errors="ignore").lower()
    except Exception:
        text = ""
    for marker in _CHALLENGE_MARKERS:
        if marker in text:
            signals.append(f"challenge marker: {marker!r}")

    # Suspiciously tiny body for an HTML 200 is a weak corroborating signal
    # (challenge pages are often small), only counted alongside another signal.
    if signals and len(content) < 2000:
        signals.append(f"unusually small body ({len(content)} bytes)")

    if not signals:
        return BlockCheck(verdict=BlockVerdict.CLEAN.value, is_suspicious=False,
                          confidence="none", status_code=status_code)

    # Confidence scales with how many independent signals fired.
    strong = [s for s in signals if s.startswith(("challenge marker", "redirected"))]
    confidence = "high" if len(strong) >= 2 else "medium" if strong else "low"
    return BlockCheck(
        verdict=BlockVerdict.SUSPECTED_BLOCK.value, is_suspicious=True,
        confidence=confidence, signals=signals, status_code=status_code,
    )


def check_record_for_block(record, content: Optional[bytes] = None) -> BlockCheck:
    """
    Assess a provenance record for bot-wall signals using its SIGNED metadata
    (status_code, final_url) plus content if available.

    This is what a downstream verifier calls: even without the original bytes,
    the signed status and redirect are enough to flag many walls.
    """
    return detect_block(
        content or b"",
        status_code=getattr(record, "status_code", 200),
        url=record.url,
        final_url=getattr(record, "final_url", "") or "",
        content_type=getattr(record, "content_type", "") or "",
    )
