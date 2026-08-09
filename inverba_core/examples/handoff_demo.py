"""Agent A -> Agent B handoff demo (offline, no network, no account).

Agent A fetches a page and signs a provenance record. Agent B receives
(data + record) and calls verify_handoff to decide whether to trust it -- on
cryptographic grounds, not faith. Demonstrates the three outcomes that matter:

    1. a good handoff        -> TRUSTED
    2. the same record again -> REPLAYED   (Agent B keeps a SeenStore)
    3. a tampered record     -> UNVERIFIED

Run:  python examples/handoff_demo.py
"""
import time

from inverba.provenance import ProvenanceSigner
from inverba.models import FetchResult, FetchMethod
from inverba.agent_trust import verify_handoff
from inverba.seen import InMemorySeenStore


def agent_a_fetches(page: bytes, url: str):
    """Agent A: fetch + sign. Returns (record, data) to hand to Agent B."""
    signer = ProvenanceSigner.generate()
    fr = FetchResult(url=url, final_url=url, status_code=200, content=page,
                     content_type="text/html", method=FetchMethod.HTTP,
                     fetched_at=time.time())
    return signer.sign(fr), page


def main() -> None:
    record, data = agent_a_fetches(
        b"<html><body><h1>Widget Pro</h1><p>Price: $49.99</p></body></html>",
        "https://example.com/pricing",
    )

    # Agent B keeps a SeenStore, so a record can't be replayed to it.
    seen = InMemorySeenStore()

    v = verify_handoff(record, claimed_content=data, seen=seen)
    print(f"1. fresh handoff     -> {v.verdict.upper():12} trusted={v.trusted}")

    v = verify_handoff(record, claimed_content=data, seen=seen)
    print(f"2. same record again -> {v.verdict.upper():12} trusted={v.trusted}  ({v.reasons[-1]})")

    record.content_hash = "00" * 32  # tamper with the signed content hash
    v = verify_handoff(record, claimed_content=data, seen=seen)
    print(f"3. tampered record   -> {v.verdict.upper():12} trusted={v.trusted}")


if __name__ == "__main__":
    main()
