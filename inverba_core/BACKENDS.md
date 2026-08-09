# Fetch Backends — renting coverage instead of rebuilding it

## The problem

Firecrawl ships anti-bot bypass, residential proxy rotation, stealth mode, and
real-Chromium rendering with ~96% web coverage and 99% success rates, backed by
a funded team and two years of production. Inverba has httpx and a Playwright
fallback. On Cloudflare, DataDome, Amazon, or LinkedIn, Inverba fails.

That gap is unwinnable by a solo maintainer, and it blocks the best use cases —
most pages worth monitoring for price or compliance are protected.

## The move

**Verification is fetch-agnostic.** A signed record over content someone else
retrieved is just as cryptographically valid as one over content we retrieved.
So Inverba does not need to win the extraction arms race — it can sit on top of
whoever already won it.

> Use whatever scraper you like. Inverba proves what it got.

Competitors become fetch infrastructure. Their coverage is inherited, not
rebuilt. Their users become distribution.

## Backends

| Backend | Attribution | Notes |
|---|---|---|
| `NativeBackend` | `native` | Our own fetch. The only one that supports a genuine "I observed this" claim. |
| `FirecrawlBackend` | `firecrawl` | Rents their anti-bot/proxy coverage. Needs an API key. Live HTTP; not exercised offline. |
| `CallableBackend` | caller-supplied | Escape hatch for Crawl4AI, ScrapingBee, Bright Data, a corporate proxy, or your own stack. |

## The honest part (this is load-bearing)

**Who fetched the bytes changes what a signature MEANS.**

- `fetched_by="native"` — we retrieved the page ourselves. The record attests
  *"I observed this at this URL."*
- `fetched_by="firecrawl"` — a third party retrieved it and handed us bytes. We
  can only attest *"this is what Firecrawl gave me."* We did **not** observe the
  origin. If that backend is compromised, lies, or is itself served cloaked
  content, our signature faithfully attests to a falsehood.

Inverba's entire pitch is independent verification, so pretending a relay is an
observation would be the one lie that invalidates the product. Therefore:

- **`fetched_by` is covered by the signature.** It is not mutable metadata.
  Editing it breaks verification (tested). A relayed record cannot be upgraded
  into a claimed first-hand observation.
- **A third-party backend may not claim `native`.** Enforced at construction.
- **`verify_handoff` surfaces it** — every verdict carries `fetched_by` and
  `independent_observation`, so a consuming agent knows whether it holds an
  observation or a relay.
- **`require_independent_observation=True`** rejects relayed records outright,
  for callers where independence is the point.
- **Absence of a claim is not a claim of independence** — a missing attribution
  is treated as non-independent.

A relayed record is a *weaker* claim, not an invalid one, so it stays usable by
default with the caveat attached. **Corroboration is what recovers strength:**
two backends with different vantages agreeing is real evidence even when neither
is us.

## The strategic risk, named

This makes Inverba a layer over someone else's product. If Firecrawl ships
signed records, the thin version of this is gone.

The defense is the part they structurally will not build: independent
corroboration across vantages, self-hostable, no-cloud-required, and a verifier
that is not the fetcher. Their business is *being* the trusted operator. Inverba's
is not needing one. A signed record from Firecrawl is still "trust Firecrawl" —
which is exactly the assumption Inverba exists to remove.

## Usage

```python
from inverba.backends import NativeBackend, FirecrawlBackend, CallableBackend

# Default: we observe the origin ourselves
backend = NativeBackend()

# Rent coverage for protected sites
backend = FirecrawlBackend(api_key="fc-...")

# Bring your own
async def my_fetch(url):
    return content_bytes, 200, "text/html"
backend = CallableBackend("crawl4ai", my_fetch)

result = await backend.fetch(url)      # result.fetched_by is set
record = signer.sign(result)            # attribution is signed in
```
