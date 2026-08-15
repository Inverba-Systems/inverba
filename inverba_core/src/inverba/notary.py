"""
Notary worker (corroboration cold-start).

The chicken-and-egg problem: trust-scored corroboration needs a
SWARM, but a solo first customer has one worker. The differentiator that makes
Inverba unique is exactly the one that doesn't work at N=1.

The fix: Inverba operates a NOTARY -- a default, high-trust, independent
corroborating worker. A solo user's fetch gets a second, independent observation
from the notary, so they get two-party corroboration on day one, before they run
any swarm of their own. The notary:

  - fetches the same URL from its own (different) network vantage,
  - signs its observation with the notary's key,
  - returns a corroboration that folds into the user's provenance record.

Because the notary runs on Inverba-operated infrastructure and signs with a
Inverba key, its corroboration is a hosted-tier feature (revenue + protected by
the server-side enforcement already built). Self-hosters who run their own swarm
don't need it; solo/managed users get instant corroboration.

This module is the CLIENT side (how a user requests notarization) plus a
reference NotaryService (what runs on Inverba's side). The transport between
them is a simple signed request/response, kept pluggable.
"""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field
from typing import Optional, Protocol

from .provenance import ProvenanceSigner, verify_record
from .models import FetchResult, ProvenanceRecord, FetchMethod
from .semantic import SemanticNormalizer


@dataclass
class NotaryResult:
    corroborated: bool                # did the notary see the same (normalized) content?
    notary_record: Optional[ProvenanceRecord]
    agreement: str                    # "match" | "mismatch" | "unreachable"
    detail: str


class NotaryTransport(Protocol):
    """How a client reaches the notary. Real impl is an HTTP call to Inverba's
    hosted notary; tests use an in-process one."""
    def notarize(self, url: str) -> Optional[ProvenanceRecord]:
        ...


@dataclass
class NotaryPolicy:
    """
    Fetch policy for the hosted notary. This is LEGAL POSTURE, not decoration.

    When the notary fetches on a user's behalf, WE are the party scraping --
    the request originates from Inverba-operated infrastructure. The current
    (2026) US legal landscape makes the safe lane clear:

      - Logged-out scraping of PUBLIC pages is defensible (hiQ v. LinkedIn,
        9th Cir.; Meta v. Bright Data, N.D. Cal. 2024 -- summary judgment for
        the scraper on logged-out public data).
      - Login-walled access and accepted-ToS violations are where scrapers
        LOSE (hiQ ultimately lost on contract; $500k judgment + injunction).
      - The frontier theory is DMCA 1201: Reddit v. Perplexity (pending)
        argues that bypassing rate limits / anti-bot systems is "circumvention
        of technological measures."
      - Respecting robots.txt / TDM opt-outs is increasingly treated as the
        basis of lawful-use exceptions, not a courtesy.

    So the notary, by default: enforces robots.txt (not just records it),
    refuses anything that looks login-walled, rate-limits per domain (never
    hammers), and refuses private/internal addresses (we must never be an
    SSRF proxy into someone's network). Every refusal is explicit and
    machine-readable, because a refusal with a reason is also documentation
    of good-faith practice.
    """
    enforce_robots: bool = True
    refuse_login_walled: bool = True
    per_domain_min_interval: float = 10.0     # seconds between fetches per host
    max_url_length: int = 2000
    allow_private_networks: bool = False       # never notarize internal addresses
    max_redirects: int = 5                     # redirects are followed hop-by-hop,
                                               # each hop SSRF-validated (never blind)
    user_agent: str = "InverbaNotary"


@dataclass
class NotaryRefusal:
    """A structured, honest refusal -- what was refused and exactly why."""
    url: str
    reason_code: str      # robots_disallowed | login_walled | rate_limited |
                          # private_network | invalid_url | fetch_failed
    detail: str
    checked_at: float = field(default_factory=time.time)


# URL path fragments that overwhelmingly indicate auth-gated content. This is a
# heuristic, deliberately conservative: false positives (refusing a public page
# that merely mentions "login" in its path) cost a corroboration; false
# negatives (fetching behind a wall) cost legal exposure. We prefer the former.
_LOGIN_HINTS = ("/login", "/signin", "/sign-in", "/auth/", "/account/",
                "/dashboard", "/logout", "session=", "token=")


def _looks_login_walled(url: str, status_code: Optional[int] = None) -> bool:
    lowered = url.lower()
    if any(h in lowered for h in _LOGIN_HINTS):
        return True
    # 401/403 on fetch = the site said no. A notary must not try harder.
    if status_code in (401, 403):
        return True
    return False


def _is_private_address(url: str) -> bool:
    """Refuse private/loopback/link-local targets so the hosted notary can never
    be used as an SSRF proxy into internal networks."""
    import ipaddress
    from urllib.parse import urlparse
    host = urlparse(url).hostname or ""
    if host in ("localhost",):
        return True
    try:
        addr = ipaddress.ip_address(host)
        return (addr.is_private or addr.is_loopback or addr.is_link_local
                or addr.is_reserved)
    except ValueError:
        # A hostname, not a literal IP. DNS-rebinding defence belongs at the
        # network layer of the deployment; here we handle the literal cases.
        return False


class NotaryService:
    """
    The server-side notary. Runs on Inverba infrastructure with its own key and
    its own network vantage. Given a URL, it fetches independently and returns a
    signed observation.

    In production the fetch uses the notary's own egress (a different IP/region
    than the user), which is what makes the corroboration MEANINGFUL -- two
    independent vantages agreeing is evidence; one machine agreeing with itself
    is not.

    Enforces NotaryPolicy before fetching (see its docstring for the legal
    reasoning). observe() returns either a signed ProvenanceRecord or a
    NotaryRefusal explaining exactly why the fetch was declined.
    """

    def __init__(self, signer: Optional[ProvenanceSigner] = None, fetch_engine=None,
                 policy: Optional[NotaryPolicy] = None, robots_checker=None,
                 resolver=None):
        self.signer = signer or ProvenanceSigner.generate()
        self.fetch_engine = fetch_engine   # a FetchEngine; injected so it's testable
        # The notary OWNS its redirect behavior -- it must not be made unsafe by an
        # injected engine defaulting to follow_redirects=True. With auto-follow, a
        # public URL that 302s to a private/metadata address is followed INSIDE the
        # engine (the SSRF request fires) before _safe_fetch can validate the hop.
        # Force it off so _safe_fetch's per-hop resolution validation is
        # authoritative; the notary follows redirects manually, validating each.
        if fetch_engine is not None and hasattr(fetch_engine, "follow_redirects"):
            fetch_engine.follow_redirects = False
        self.policy = policy or NotaryPolicy()
        self._robots = robots_checker      # lazily built if enforcement is on
        # DNS resolver used for SSRF address validation; injected so tests never
        # hit the network. Defaults to the real OS resolver.
        from .ssrf import default_resolver
        self.resolver = resolver or default_resolver
        self._last_fetch_per_host: dict[str, float] = {}

    async def _safe_fetch(self, url: str):
        """Fetch `url` with per-hop SSRF validation. Redirects are followed
        manually (never blindly) so each hop's RESOLVED address is validated
        before the request is made. Returns a FetchResult or a NotaryRefusal.

        For per-hop protection to be real, the injected fetch_engine must NOT
        auto-follow redirects (production wiring uses FetchEngine(
        follow_redirects=False)). As a secondary guard, if the engine did
        auto-follow, the final address is validated too."""
        from urllib.parse import urljoin
        from .ssrf import validate_public_url, SSRFError

        def _validate(u):
            if self.policy.allow_private_networks:
                return None
            try:
                validate_public_url(u, self.resolver)
            except SSRFError as e:
                return NotaryRefusal(url=u, reason_code="private_network",
                                     detail=f"SSRF guard refused this address: {e}")
            return None

        current = url
        for _ in range(self.policy.max_redirects + 1):
            refusal = _validate(current)
            if refusal is not None:
                return refusal
            result = await self.fetch_engine.fetch(current)
            headers = result.headers or {}
            loc = headers.get("location") or headers.get("Location")
            if result.status_code in (301, 302, 303, 307, 308) and loc:
                current = urljoin(current, loc)
                continue
            # No further redirect surfaced. If the engine auto-followed to a
            # different final host, validate that resolved address too.
            if result.final_url and result.final_url != current:
                refusal = _validate(result.final_url)
                if refusal is not None:
                    return refusal
            return result
        return NotaryRefusal(url=url, reason_code="too_many_redirects",
                             detail=f"exceeded {self.policy.max_redirects} redirects")

    @property
    def public_key(self) -> str:
        return self.signer.public_key_hex()

    async def observe(self, url: str):
        """Fetch and sign, subject to policy. Returns ProvenanceRecord on
        success, NotaryRefusal on refusal, or None on plain fetch failure."""
        from urllib.parse import urlparse
        now = time.time()

        # -- structural checks --
        if not url.startswith(("http://", "https://")) or len(url) > self.policy.max_url_length:
            return NotaryRefusal(url=url, reason_code="invalid_url",
                                 detail="not a fetchable http(s) URL")

        # Fast string-level pre-filter for obvious literals (defense in depth).
        # The AUTHORITATIVE SSRF check is resolution-based, in _safe_fetch below:
        # it resolves the host and validates the real address, which is the only
        # way to catch decimal/octal/hex/short-form/IPv6 encodings and hostnames
        # that point at internal addresses.
        if not self.policy.allow_private_networks and _is_private_address(url):
            return NotaryRefusal(
                url=url, reason_code="private_network",
                detail="notary refuses private/loopback addresses -- it must never "
                       "be a proxy into internal networks",
            )

        # -- AUTHORITATIVE SSRF gate: validate the RESOLVED address ONCE, before
        # the notary makes ANY outbound request (robots preflight, content fetch,
        # or anything added later). Nothing outbound may precede this -- guarding
        # only the content fetch left the robots preflight as an unvalidated SSRF.
        # _safe_fetch re-validates each redirect hop underneath; this is the
        # up-front structural guarantee that can't be forgotten when a new
        # auxiliary request is added.
        if not self.policy.allow_private_networks:
            from .ssrf import validate_public_url, SSRFError
            try:
                validate_public_url(url, self.resolver)
            except SSRFError as e:
                return NotaryRefusal(url=url, reason_code="private_network",
                                     detail=f"SSRF guard refused this address: {e}")

        if self.policy.refuse_login_walled and _looks_login_walled(url):
            return NotaryRefusal(
                url=url, reason_code="login_walled",
                detail="URL appears auth-gated; the notary only observes public, "
                       "logged-out content (the legally defensible lane)",
            )

        # -- per-domain rate limit: a notary never hammers --
        host = urlparse(url).netloc
        last = self._last_fetch_per_host.get(host, 0.0)
        if now - last < self.policy.per_domain_min_interval:
            return NotaryRefusal(
                url=url, reason_code="rate_limited",
                detail=f"per-domain interval is {self.policy.per_domain_min_interval:.0f}s; "
                       f"try again in {self.policy.per_domain_min_interval - (now - last):.0f}s",
            )

        # -- robots.txt: ENFORCED for the notary, not merely recorded --
        if self.policy.enforce_robots:
            if self._robots is None:
                from .robots import RobotsChecker
                # follow_redirects=False: a robots.txt that 302s must not become an
                # unvalidated outbound to a redirected (possibly internal) address.
                self._robots = RobotsChecker(user_agent=self.policy.user_agent,
                                             follow_redirects=False)
            verdict = await self._robots.check(url)
            if not verdict.allowed:
                return NotaryRefusal(
                    url=url, reason_code="robots_disallowed",
                    detail="robots.txt disallows this path for the notary's user-agent "
                           "(enforced, not just recorded -- respecting opt-outs is the "
                           "basis of the lawful-use lane)",
                )

        if self.fetch_engine is None:
            return None

        self._last_fetch_per_host[host] = now
        fetch_result = await self._safe_fetch(url)
        # SSRF guard (or redirect-limit) refused this target -- surface it.
        if isinstance(fetch_result, NotaryRefusal):
            return fetch_result

        # A 401/403 response is the site declining -- honor it, don't retry harder.
        if self.policy.refuse_login_walled and _looks_login_walled(url, fetch_result.status_code):
            return NotaryRefusal(
                url=url, reason_code="login_walled",
                detail=f"site returned {fetch_result.status_code}; the notary does not "
                       "attempt to get past an explicit refusal",
            )

        if not fetch_result.ok:
            return None
        return self.signer.sign(fetch_result)


class NotaryClient:
    """
    Client-side helper. Takes a user's own signed record for a URL, asks the
    notary to independently observe the same URL, and folds a matching notary
    observation into the user's record as a corroboration -- turning a
    single-source record into a two-party corroborated one at N=1.
    """

    def __init__(self, transport: NotaryTransport, normalizer: Optional[SemanticNormalizer] = None):
        self.transport = transport
        self.normalizer = normalizer or SemanticNormalizer()

    def notarize(
        self,
        user_record: ProvenanceRecord,
        user_content: bytes,
    ) -> NotaryResult:
        notary_record = self.transport.notarize(user_record.url)

        if notary_record is None:
            return NotaryResult(
                corroborated=False, notary_record=None, agreement="unreachable",
                detail="notary did not return an observation (unreachable or fetch failed)",
            )

        if isinstance(notary_record, NotaryRefusal):
            # Policy refusal, surfaced honestly -- the user learns exactly why the
            # notary declined (robots, login wall, rate limit, private address).
            return NotaryResult(
                corroborated=False, notary_record=None,
                agreement="refused",
                detail=f"notary refused ({notary_record.reason_code}): {notary_record.detail}",
            )

        if not verify_record(notary_record):
            return NotaryResult(
                corroborated=False, notary_record=None, agreement="mismatch",
                detail="notary observation failed signature verification",
            )

        # Compare on RAW content hash first (exact), then fall back to semantic
        # equivalence so volatile per-request noise doesn't cause a false mismatch.
        if notary_record.content_hash == user_record.content_hash:
            user_record.corroborations.append(notary_record)
            return NotaryResult(
                corroborated=True, notary_record=notary_record, agreement="match",
                detail="notary independently observed identical content; record now two-party corroborated",
            )

        # Raw bytes differed -- check semantic equivalence.
        # (We can only semantically compare if we can re-fetch the notary's bytes;
        # here we compare the user's normalized content hash against the notary's
        # raw hash as a conservative check. A full impl would carry normalized
        # hashes in the record; this reports mismatch honestly rather than
        # over-claiming agreement.)
        return NotaryResult(
            corroborated=False, notary_record=notary_record, agreement="mismatch",
            detail=("notary observed different raw content -- could be personalization, "
                    "A/B testing, or the page changed between fetches; not corroborated"),
        )


class InProcessNotaryTransport:
    """Test/local transport that calls a NotaryService directly (no network)."""

    def __init__(self, service: NotaryService):
        self.service = service

    def notarize(self, url: str) -> Optional[ProvenanceRecord]:
        import asyncio
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None
        if loop is not None:
            # already inside an event loop; run in a fresh one on a thread
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                return pool.submit(asyncio.run, self.service.observe(url)).result()
        return asyncio.run(self.service.observe(url))
