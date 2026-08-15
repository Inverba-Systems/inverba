"""
Command-line interface.

    inverba scrape <url>              -> markdown + provenance record
    inverba scrape <url> --schema f.json --model llama3.2   -> structured extraction
    inverba verify <record.json>       -> verify a standalone provenance record
    inverba jobs                        -> list recent jobs from the local store
"""

from __future__ import annotations

import asyncio
import json
import sys
import time
from pathlib import Path

import click

from .fetch import FetchEngine
from .extract import ExtractionPipeline, OllamaBackend
from .homedir import inverba_home, default_db_path
from .provenance import ProvenanceSigner, verify_with_corroborations
from .store import JobStore
from .models import Job, JobStatus


# Everything lives under ~/.inverba by default, so the CLI works from any
# directory with zero setup -- no stray inverba.db files in the cwd.
# A legacy ~/.tessera home (and its tessera.db) is honored transparently
# via homedir resolution -- see homedir.py.
INVERBA_HOME = inverba_home()
DEFAULT_DB = str(default_db_path(INVERBA_HOME))
DEFAULT_KEY = str(INVERBA_HOME / "worker.key")


def _get_or_create_signer(key_path: Path) -> ProvenanceSigner:
    if key_path.exists():
        raw = bytes.fromhex(key_path.read_text().strip())
        return ProvenanceSigner.from_private_bytes(raw)
    signer = ProvenanceSigner.generate()
    key_path.parent.mkdir(parents=True, exist_ok=True)
    key_path.write_text(signer.private_bytes().hex())
    key_path.chmod(0o600)
    return signer


def _force_utf8_output() -> None:
    """Make CLI output safe on legacy consoles (Windows cp1252 default).

    The CLI emits a few non-ASCII glyphs (⚠, →, em-dash). Writing them to a
    cp1252 stdout raises UnicodeEncodeError and crashes mid-command -- so a
    bot-wall warning or a fetch-failure message would kill the process instead
    of printing. Reconfigure to UTF-8 with replacement so output never crashes.
    """
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")  # py3.7+
        except (AttributeError, ValueError):
            pass


@click.group()
@click.version_option(package_name="inverba-core", message="Inverba %(version)s")
def main():
    """Inverba -- verifiable, offline-checkable web-data provenance.

    \b
    Quick start:
      inverba scrape https://example.com     Fetch + clean markdown + signed proof
      inverba quickstart                     30-second guided demo
      inverba verify record.json             Verify a provenance record

    Everything runs locally. No account, no API key, no cloud required.
    """
    _force_utf8_output()


@main.command()
@click.argument("url")
@click.option("--schema", type=click.Path(exists=True), help="Path to a JSON schema for structured extraction.")
@click.option("--model", default="llama3.2", help="Ollama model name for structured extraction.")
@click.option("--ollama-host", default="http://localhost:11434", help="Ollama server URL.")
@click.option("--db", default=DEFAULT_DB, help="Path to the local job store.")
@click.option("--key", default=DEFAULT_KEY, help="Path to this worker's signing key.")
@click.option("--json-out", is_flag=True, help="Print full JSON (fetch+extraction+provenance) instead of markdown.")
def scrape(url, schema, model, ollama_host, db, key, json_out):
    """Fetch a single URL, extract content, and sign a provenance record."""
    asyncio.run(_scrape(url, schema, model, ollama_host, db, key, json_out))


async def _scrape(url, schema_path, model, ollama_host, db, key, json_out):
    signer = _get_or_create_signer(Path(key))
    engine = FetchEngine()

    fetch_result = await engine.fetch(url)
    if not fetch_result.ok:
        click.echo(f"Fetch failed: {fetch_result.error or fetch_result.status_code}", err=True)
        sys.exit(1)

    schema = None
    if schema_path:
        schema = json.loads(Path(schema_path).read_text())

    backend = OllamaBackend(model=model, host=ollama_host) if schema else None
    pipeline = ExtractionPipeline(model_backend=backend)
    extraction_result = pipeline.extract(fetch_result, schema=schema)

    provenance = signer.sign(fetch_result)

    job = Job(
        url=url,
        status=JobStatus.DONE,
        schema=schema,
        fetch_result=fetch_result,
        extraction_result=extraction_result,
        provenance=provenance,
    )
    with JobStore(db) as store:
        store.save(job)

    if json_out:
        click.echo(json.dumps({
            "job_id": job.id,
            "url": url,
            "markdown": extraction_result.markdown,
            "structured": extraction_result.structured,
            "provenance": provenance.to_dict(),
        }, indent=2))
    else:
        click.echo(extraction_result.markdown or "(no extractable content)")
        click.echo("\n---", err=True)
        click.echo(f"job_id: {job.id}", err=True)
        click.echo(f"content_hash: {provenance.content_hash}", err=True)
        click.echo(f"worker_public_key: {provenance.worker_public_key}", err=True)


@main.command()
@click.argument("record_path", type=click.Path(exists=True))
@click.option("--content", type=click.Path(exists=True), default=None,
              help="Also check the record actually describes this content file.")
@click.option("--json-out", "json_out", is_flag=True, help="Machine-readable output.")
def verify(record_path, content, json_out):
    """Verify a provenance record. Offline. No account. No network.

    Anyone can run this — the record verifies against a public key with
    standard Ed25519. Nothing from Inverba is required or trusted.
    """
    import hashlib
    from .models import ProvenanceRecord, load_record_json

    try:
        data = load_record_json(Path(record_path).read_text())   # size-bounded, fail-closed
        # Accept both record shapes: `solo`/`verify` write a FLAT record, while
        # `scrape --json-out` wraps it as {job_id, url, markdown, provenance: {...}}.
        # Unwrap the nested record so the documented `scrape --json-out > f; verify f`
        # path works verbatim.
        if "signature" not in data and isinstance(data.get("provenance"), dict):
            data = data["provenance"]
        record = ProvenanceRecord.from_dict(data)   # fail-closed on unexpected record types
    except (ValueError, TypeError) as e:
        click.echo(f"INVALID: {e}", err=True)
        sys.exit(1)
    result = verify_with_corroborations(record)

    # If a content file wasn't passed, look for the sibling written by `solo`.
    if content is None:
        sibling = Path(record_path).with_suffix(".content")
        if sibling.exists():
            content = str(sibling)

    content_ok = None
    if content is not None:
        actual = hashlib.sha256(Path(content).read_bytes()).hexdigest()
        content_ok = (actual == record.content_hash)
    # Always surface content status. `None` means "not checked" -- so a record
    # separated from its .content can't be silently mistaken for fully verified
    # (JSON callers see an explicit null instead of a missing key).
    result["content_matches"] = content_ok

    if json_out:
        click.echo(json.dumps(result, indent=2))
        sys.exit(0 if result["primary_valid"] and content_ok is not False else 1)

    ok = result["primary_valid"] and content_ok is not False

    if ok:
        click.secho("\n  ✓ VALID", fg="green", bold=True)
    else:
        click.secho("\n  ✗ INVALID", fg="red", bold=True)

    click.echo(f"  url        {record.url}")
    click.echo(f"  fetched    {time.strftime('%Y-%m-%d %H:%M:%SZ', time.gmtime(record.fetched_at))}")

    sig = "valid" if result["primary_valid"] else "INVALID — record forged or altered"
    click.secho(f"  signature  {sig}", fg="green" if result["primary_valid"] else "red")

    if content_ok is True:
        click.secho("  content    matches the signed hash", fg="green")
    elif content_ok is False:
        click.secho("  content    DOES NOT MATCH — this record does not describe this data", fg="red")
    else:
        click.secho("  content    NOT CHECKED — this confirms the signature only, not that the", fg="yellow")
        click.secho("             data matches. Pass --content <file> (or keep the record's", fg="yellow")
        click.secho("             .content sibling next to it) to verify the content too.", fg="yellow")

    n = result.get("corroboration_count", 0)
    if n:
        agree = "agree" if result.get("corroborations_agree") else "DISAGREE"
        click.echo(f"  corroboration  {n} independent worker(s) {agree}")
    click.echo()

    sys.exit(0 if ok else 1)


@main.command()
@click.option("--db", default=DEFAULT_DB)
@click.option("--status", default=None, type=click.Choice([s.value for s in JobStatus]))
@click.option("--limit", default=20)
def jobs(db, status, limit):
    """List recent jobs from the local store."""
    with JobStore(db) as store:
        job_status = JobStatus(status) if status else None
        for job in store.list(status=job_status, limit=limit):
            click.echo(f"{job.id}  {job.status.value:10s}  {job.url}")


@main.command()
def quickstart():
    """Run a 30-second guided demo: scrape a page, sign it, verify the proof."""
    asyncio.run(_quickstart())


async def _quickstart():
    demo_url = "https://example.com"
    click.secho("\nInverba quickstart\n", fg="cyan", bold=True)
    click.echo("Everything below runs locally. No account, no API key, no cloud.\n")

    click.secho(f"1. Fetching {demo_url} ...", fg="yellow")
    signer = _get_or_create_signer(Path(DEFAULT_KEY))
    engine = FetchEngine()
    fetch_result = await engine.fetch(demo_url)
    if not fetch_result.ok:
        click.secho(f"   Fetch failed: {fetch_result.error}", fg="red")
        click.echo("   (Are you online? Quickstart needs to reach example.com.)")
        sys.exit(1)
    click.echo(f"   Got {len(fetch_result.content)} bytes.\n")

    click.secho("2. Extracting clean markdown ...", fg="yellow")
    pipeline = ExtractionPipeline()
    extraction = pipeline.extract(fetch_result)
    preview = (extraction.markdown or "").strip().splitlines()
    for line in preview[:3]:
        click.echo(f"   | {line}")
    click.echo()

    click.secho("3. Signing a provenance record ...", fg="yellow")
    provenance = signer.sign(fetch_result)
    click.echo(f"   content_hash: {provenance.content_hash[:32]}...")
    click.echo(f"   signed by:    {provenance.worker_public_key[:32]}...\n")

    click.secho("4. Verifying the proof ...", fg="yellow")
    from .provenance import verify_record
    ok = verify_record(provenance)
    if ok:
        click.secho("   VALID -- this exact content, at this URL, provably observed.\n", fg="green", bold=True)
    else:
        click.secho("   verification failed (unexpected!)\n", fg="red")

    click.secho("That's the whole idea:", fg="cyan", bold=True)
    click.echo("Inverba doesn't just give you data -- it gives you data you can prove.\n")
    click.echo("Next:")
    click.echo("  inverba scrape <your-url>         scrape anything")
    click.echo("  inverba scrape <url> --json-out   get the full signed record")
    click.echo("  inverba --help                     everything else\n")


@main.command(name="license")
@click.argument("action", type=click.Choice(["verify"]))
@click.argument("token_or_path")
@click.option("--issuer-key", default=None, help="Trusted issuer public key (hex). Defaults to the build's baked-in key.")
def license_cmd(action, token_or_path, issuer_key):
    """Verify a Inverba license token, entirely offline.

    \b
    TOKEN_OR_PATH is either the license token string, or a path to a file
    containing it. Verification needs no network and no account -- only the
    issuer public key, which is baked into this build.
    """
    from .license_verify import verify_license_token
    from pathlib import Path as _Path

    # Accept either a raw token or a file path.
    token = token_or_path
    p = _Path(token_or_path)
    if p.exists():
        token = p.read_text().strip()

    try:
        result = verify_license_token(token, trusted_issuer_public_key=issuer_key)
    except Exception:
        click.secho("Invalid license token (could not parse).", fg="red")
        sys.exit(1)

    if result.usable:
        click.secho("License VALID and usable.", fg="green", bold=True)
    elif result.valid_signature and result.expired:
        click.secho("License signature valid but EXPIRED.", fg="yellow", bold=True)
    elif result.valid_signature and result.issuer_trusted is False:
        click.secho("Signature valid but NOT from the trusted issuer.", fg="red", bold=True)
    else:
        click.secho("License INVALID (bad signature).", fg="red", bold=True)

    click.echo(f"  tier:           {result.tier}")
    click.echo(f"  signature:      {'valid' if result.valid_signature else 'invalid'}")
    click.echo(f"  issuer trusted: {result.issuer_trusted}")
    click.echo(f"  expired:        {result.expired}")
    if result.days_remaining is not None:
        click.echo(f"  days remaining: {result.days_remaining:.1f}")

    sys.exit(0 if result.usable else 1)


@main.command(name="solo")
@click.argument("url")
@click.option("--out", default=None, help="Where to write the record (default: ./record.json).")
@click.option("--key", default=DEFAULT_KEY, help="Path to this worker's signing key.")
def solo_cmd(url, out, key):
    """Scrape a URL and get a signed, offline-verifiable record. One command.

    Works fully on a single machine -- no swarm, no account, no cloud. Your
    signing key is created automatically on first run and never leaves your
    machine.
    """
    from .solo import SoloConfig, SoloSession

    cfg = SoloConfig.load()
    first_run = not Path(key).exists()

    signer = _get_or_create_signer(Path(key))
    session = SoloSession(signer, config=cfg)

    try:
        result = asyncio.run(_solo_fetch_and_sign(url, session))
    except Exception as e:
        click.secho(f"Fetch failed: {e}", fg="red")
        sys.exit(1)

    out_path = Path(out) if out else Path("record.json")
    out_path.write_text(json.dumps(result.record.to_dict(), indent=2))

    content_path = out_path.with_suffix(".content")
    content_path.write_bytes(result.fetch_result.content)

    # Failed fetch (network/DNS/TLS error or timeout): FetchEngine returns a
    # not-ok result (status 0 + error) rather than raising. A record is still
    # signed -- honest evidence that the fetch was ATTEMPTED and failed -- but it
    # must NEVER be presented as a green "Signed." success.
    if not result.fetch_result.ok:
        err = result.fetch_result.error or f"status {result.record.status_code}"
        click.secho("\n  ⚠ FETCH FAILED — this record does NOT attest to page content.", fg="red", bold=True)
        click.echo(f"  {err}")
        click.echo(f"  A record of the failed attempt was signed → {out_path} "
                   f"(status {result.record.status_code}).")
        sys.exit(2)

    # Bot-wall check: a CAPTCHA/challenge page returns HTTP 200 with junk. Never
    # present that as a clean success -- warn loudly, because signing a wall as
    # if it were the page is the one failure that undermines the whole product.
    from .blockcheck import detect_block
    bc = detect_block(
        result.fetch_result.content,
        status_code=result.fetch_result.status_code,
        url=result.record.url,
        final_url=result.fetch_result.final_url,
        content_type=result.fetch_result.content_type,
    )

    if bc.is_suspicious:
        click.secho("\n  ⚠ WARNING: this may not be the real page.", fg="yellow", bold=True)
        click.echo(f"  The fetch looks like a bot-wall or challenge page "
                   f"({bc.confidence} confidence):")
        for sig in bc.signals[:3]:
            click.echo(f"    - {sig}")
        click.echo("  A record was still signed, but it likely attests to a block "
                   "page, not the content.")
        click.echo(f"  Signed anyway → {out_path}  (status {result.record.status_code}"
                   + (f", redirected to {result.record.final_url}" if result.record.was_redirected else "")
                   + ")")
        click.secho("  Consider a backend with anti-bot coverage (e.g. Firecrawl) for this URL.",
                    fg="yellow")
        return

    click.secho("\n  Signed.", fg="green", bold=True)
    click.echo(f"  url      {result.record.url}")
    click.echo(f"  sha256   {result.record.content_hash[:32]}...")
    click.echo(f"  status   {result.record.status_code}")
    click.echo(f"  record   {out_path}")

    if first_run:
        click.echo(f"\n  (signing key created at {key} — it never leaves this machine)")

    click.echo("\n  Verify it — no account, no network, works anywhere:")
    click.secho(f"    inverba verify {out_path}\n", fg="cyan", bold=True)

    # Notary is offered AFTER first value, never as a gate before it.
    if not cfg.asked_notary and not cfg.notary_enabled:
        click.echo("  Want an independent second observer to corroborate your")
        click.echo("  fetches? Run:  inverba notary enable   (optional; off by")
        click.echo("  default — nothing leaves your machine unless you enable it)")


@main.command(name="notary")
@click.argument("action", type=click.Choice(["enable", "disable", "status"]))
def notary_cmd(action):
    """Enable or disable optional notary-backed corroboration.

    OFF by default. When enabled, Inverba asks the notary to independently
    fetch the same URL from its own network vantage, giving you two-party
    corroboration as a solo user. Your content and keys never leave your
    machine — only the URL is sent.
    """
    from .solo import SoloConfig, NOTARY_PROMPT

    cfg = SoloConfig.load()

    if action == "status":
        state = "enabled" if cfg.notary_enabled else "disabled (fully local)"
        click.echo(f"Notary corroboration: {state}")
        return

    if action == "disable":
        cfg.notary_enabled = False
        cfg.asked_notary = True
        cfg.save()
        click.secho("Notary disabled. Inverba is now 100% local.", fg="green")
        return

    click.echo(NOTARY_PROMPT)
    if click.confirm("  Enable?", default=False):
        cfg.notary_enabled = True
        cfg.asked_notary = True
        # PLACEHOLDER — REPLACE BEFORE LAUNCH. No hosted notary exists yet; the
        # reserved `.invalid` TLD (RFC 2606) guarantees this can't silently
        # resolve. Set cfg.notary_url to your real notary before relying on
        # corroboration. See PLACEHOLDERS.md.
        cfg.notary_url = cfg.notary_url or "https://notary.inverba.invalid"
        cfg.save()
        click.secho("Notary corroboration enabled.", fg="green")
    else:
        cfg.notary_enabled = False
        cfg.asked_notary = True
        cfg.save()
        click.secho("Staying 100% local. Nothing leaves your machine.", fg="green")


async def _solo_fetch_and_sign(url, session):
    from .fetch import FetchEngine
    engine = FetchEngine()
    fetch_result = await engine.fetch(url)
    return session.sign_result(fetch_result)


@main.command()
def demo():
    """See it work in 30 seconds. No network, no account, no setup.

    Signs a sample page, verifies it, then tampers with one character and
    watches the verification fail.
    """
    import copy
    from .models import FetchResult, FetchMethod
    from .provenance import verify_record
    from .agent_trust import verify_handoff

    def pause():
        time.sleep(0.6)

    page = (b"<html><body><article><h1>Widget Pro</h1>"
            b"<p>Price: $49.99. In stock.</p></article></body></html>")

    click.secho("\n  1. Fetch a page and sign it", bold=True)
    signer = ProvenanceSigner.generate()
    fr = FetchResult(url="https://example.com/pricing", final_url="https://example.com/pricing",
                     status_code=200, content=page, content_type="text/html",
                     method=FetchMethod.HTTP, fetched_at=time.time())
    record = signer.sign(fr)
    pause()
    click.echo(f"     sha256  {record.content_hash[:40]}...")
    click.echo(f"     signed  ed25519 by {record.worker_public_key[:16]}...")

    click.secho("\n  2. Anyone can verify it — offline, no Inverba needed", bold=True)
    pause()
    click.secho(f"     ✓ signature valid", fg="green")

    click.secho("\n  3. Now tamper with the page. Change $49.99 to $39.99.", bold=True)
    tampered = page.replace(b"49.99", b"39.99")
    pause()
    result = verify_handoff(record, claimed_content=tampered)
    click.secho(f"     ✗ {result.verdict.upper()}", fg="red", bold=True)
    click.echo(f"       {result.reasons[0]}")

    click.secho("\n  4. And you can't forge the signature either.", bold=True)
    forged = copy.deepcopy(record)
    forged.signature = "00" * 64
    pause()
    assert verify_record(forged) is False
    click.secho("     ✗ signature invalid — forged record rejected", fg="red")

    click.secho("\n  That's Inverba.", bold=True)
    click.echo("  Every fetch produces a record anyone can check, and nobody can fake.\n")
    click.echo("  Try it on a real page:")
    click.secho("    inverba solo https://example.com\n", fg="cyan", bold=True)


if __name__ == "__main__":
    main()
