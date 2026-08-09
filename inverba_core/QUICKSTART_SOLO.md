# Inverba Quickstart (solo)

No swarm. No account. No API key. No cloud. One machine, 60 seconds.

## 0. See it work first (30 seconds, no network)

```
pip install -e ./inverba_core   # from a repo clone; PyPI package comes with the first release
inverba demo
```

Signs a page, verifies it, then tampers with one character and watches the
verification fail. No setup, no key, no network. This is the whole product in
30 seconds.

## 1. Do it for real — one command

```
inverba solo https://example.com
```

That's it. Your signing key is created automatically on first run and never
leaves your machine. You get `record.json` — cryptographic proof of what was at
that URL, when — plus the content it describes.

## 2. Verify it — anywhere, by anyone

```
inverba verify record.json
```

```
  ✓ VALID
  url        https://example.com
  fetched    2026-05-14 12:00:00Z
  signature  valid
  content    matches the signed hash
```

Now flip one character in the `record.content` file (it sits next to
`record.json`) and run it again:

```
  ✗ INVALID
  signature  valid
  content    DOES NOT MATCH — this record does not describe this data
```

Verification needs ~30 lines of any language and a public key. No Inverba
install, no account, no call to us. Hand the record to anyone; they can confirm
it themselves.

## 3. Optional: an independent second observer

Off by default. Nothing leaves your machine unless you turn it on.

```
inverba notary enable    # or: inverba notary status / disable
```

When enabled, the Inverba notary independently fetches the same URL from its own
network vantage, giving you two-party corroboration as a solo user. Only the URL
is sent — your content and keys stay local.

> **Not available yet.** There is no hosted notary endpoint at this time (the
> default URL is a placeholder), and the hosted notary is gated on closing a
> DNS-rebinding window before exposure — see `SECURITY.md`. Everything else in
> this guide is fully local and works today; the notary is opt-in and off by
> default.

## What works with a single worker (i.e. almost everything)

| Capability | Solo (N=1)? |
|---|---|
| Signed provenance records | Yes |
| Offline verification | Yes |
| Change detection with signed before/after evidence | Yes |
| C2PA compliance export | Yes |
| Agent-to-agent `verify_handoff` | Yes |
| Two-party corroboration (via notary) | Yes (opt-in) |
| N-vantage corroboration | Needs swarm |
| Full cloaking detection | Needs swarm (2-vantage basic works via notary) |

The only things that *inherently* need multiple machines are N-way
corroboration and full multi-vantage cloaking detection -- because they mean
"several independent observers agreed," which you can't fake with one machine.
Everything else is fully yours at N=1.

## When you're ready to scale: the swarm

The swarm is a power-up, not a prerequisite. When you want stronger evidence --
many independent workers corroborating, full cloaking detection across regions
-- you add workers (your own machines, or federate with others) and Inverba
uses them automatically. Same product, more vantages.

The swarm ships as a **separate package** (`inverba-swarm`) that plugs into these
same signed records — it is not part of this open-core CLI, and there's nothing
to change in your solo setup to be ready for it.

Nothing about your solo records changes when you scale -- they were always
valid. The swarm just adds corroboration depth on top.

## Change detection (solo)

Inverba's change detector compares two signed records of the same URL and flags
*material* changes with signed before/after evidence — a diff that isn't a claim,
it's two pieces of cryptographic proof (a flipped price is caught even if 99% of
the page is unchanged). It's available today as a library call (`inverba.changes`);
a `watch` CLI wrapper is on the roadmap.

## The one-line pitch

Buy once, run on your own hardware, prove what you scraped -- to yourself, to an
auditor, or to another agent. Solo is the front door; the swarm is the scale
story. Both are the same product.
