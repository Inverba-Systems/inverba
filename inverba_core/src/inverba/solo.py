"""
Solo mode: the single-worker front door.

Most of Inverba works perfectly at N=1 -- signed provenance, offline
verification, change detection with signed before/after evidence, C2PA export,
and agent-to-agent verify_handoff none of these need a swarm. Solo mode is the
clean path that gives a single-worker user the full value without ever having to
think about swarms.

The ONE feature that inherently needs multiple observers -- corroboration -- is
provided via the optional Inverba notary (a second independent vantage). Because
Inverba is sovereignty-first, we do NOT silently phone the notary: on first run
we ASK the user whether to enable notary-backed corroboration, and remember
their choice. A fully-local user can decline and stay 100% offline; a user who
wants stronger evidence can opt in.

This module is the solo workflow API; the CLI wraps it.
"""

from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Optional

from .homedir import inverba_home
from .models import FetchResult, ProvenanceRecord
from .provenance import ProvenanceSigner
from .semantic import SemanticNormalizer


# Honors INVERBA_HOME (or legacy TESSERA_HOME) and falls back to an existing
# pre-rename ~/.tessera -- see homedir.py.
DEFAULT_CONFIG_DIR = inverba_home()
CONFIG_PATH = DEFAULT_CONFIG_DIR / "solo_config.json"


@dataclass
class SoloConfig:
    """Persisted solo-mode preferences. `notary_enabled` is None until the user
    is asked on first run (so we can distinguish 'never asked' from 'said no')."""
    notary_enabled: Optional[bool] = None
    notary_url: Optional[str] = None
    asked_notary: bool = False

    @classmethod
    def load(cls, path: Path = CONFIG_PATH) -> "SoloConfig":
        if path.exists():
            try:
                return cls(**json.loads(path.read_text()))
            except (json.JSONDecodeError, TypeError):
                return cls()
        return cls()

    def save(self, path: Path = CONFIG_PATH) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(asdict(self), indent=2))


# The first-run prompt text, kept here so CLI and any GUI share one wording.
NOTARY_PROMPT = (
    "Inverba can strengthen your evidence with an independent second observation "
    "from the Inverba notary (a different network vantage). This gives you "
    "two-party corroboration even as a solo user.\n\n"
    "  - Enabling it sends the URL you scrape to the notary so it can fetch "
    "independently. Your content and keys never leave your machine.\n"
    "  - Declining keeps Inverba 100% local: nothing leaves your machine.\n\n"
    "You can change this anytime. Enable notary corroboration?"
)


@dataclass
class SoloResult:
    """What a solo scrape produces."""
    fetch_result: FetchResult
    record: ProvenanceRecord
    corroborated: bool
    notary_used: bool
    notary_detail: Optional[str] = None


class SoloSession:
    """
    Drives the solo single-worker workflow: fetch -> sign -> (optional notary
    corroboration). Corroboration is only attempted if the user has opted in;
    the caller is responsible for having resolved the first-run prompt via
    ensure_notary_preference().
    """

    def __init__(
        self,
        signer: ProvenanceSigner,
        config: Optional[SoloConfig] = None,
        notary_client=None,        # optional NotaryClient; only used if opted in
        normalizer: Optional[SemanticNormalizer] = None,
    ):
        self.signer = signer
        self.config = config or SoloConfig.load()
        self.notary_client = notary_client
        self.normalizer = normalizer or SemanticNormalizer()

    def sign_result(self, fetch_result: FetchResult) -> SoloResult:
        """Sign a fetched result and optionally corroborate via the notary."""
        record = self.signer.sign(fetch_result)

        # Corroborate only if the user opted in AND a notary client is wired.
        if self.config.notary_enabled and self.notary_client is not None:
            nr = self.notary_client.notarize(record, fetch_result.content)
            return SoloResult(
                fetch_result=fetch_result, record=record,
                corroborated=nr.corroborated, notary_used=True,
                notary_detail=nr.detail,
            )

        return SoloResult(
            fetch_result=fetch_result, record=record,
            corroborated=False, notary_used=False,
            notary_detail=None,
        )


def ensure_notary_preference(
    config: SoloConfig,
    prompt_fn,
    notary_url_default: Optional[str] = None,
) -> SoloConfig:
    """
    Resolve the first-run notary question. `prompt_fn()` should return a bool
    (True=enable). Only asks once; the choice is persisted. Returns the updated
    config.

    prompt_fn is injected so the CLI can use click.confirm, a GUI can use a
    dialog, and tests can pass a stub -- no I/O assumptions in the core.
    """
    if config.asked_notary:
        return config
    enabled = bool(prompt_fn())
    config.notary_enabled = enabled
    config.asked_notary = True
    if enabled and notary_url_default:
        config.notary_url = notary_url_default
    config.save()
    return config
