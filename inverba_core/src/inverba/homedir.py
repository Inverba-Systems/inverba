"""
Resolution of the Inverba home directory (config/keys/db), with a graceful
one-time fallback for installs created under the project's former name
(Tessera, renamed 2026-07-25 due to a PyPI name collision).

Resolution order for the home directory:

1. ``INVERBA_HOME`` environment variable (explicit wins).
2. ``TESSERA_HOME`` environment variable (legacy, still honored).
3. ``~/.inverba`` if it already exists.
4. ``~/.tessera`` if it exists and ``~/.inverba`` does not — an existing
   legacy install keeps working unchanged, nothing is moved or rewritten.
5. Otherwise ``~/.inverba`` (fresh default; created on first write).

The DB filename inside the home follows the same principle: prefer
``inverba.db``, but if it is absent and a legacy ``tessera.db`` exists in the
resolved home, keep using the legacy file. ``worker.key`` and
``solo_config.json`` kept their names across the rename, so the directory
fallback alone covers them.
"""

from __future__ import annotations

import os
from pathlib import Path

_NEW_DIRNAME = ".inverba"
_LEGACY_DIRNAME = ".tessera"
_NEW_DBNAME = "inverba.db"
_LEGACY_DBNAME = "tessera.db"


def inverba_home() -> Path:
    """Resolve the Inverba home directory (see module docstring for order)."""
    env = os.environ.get("INVERBA_HOME") or os.environ.get("TESSERA_HOME")
    if env:
        return Path(env)
    new = Path.home() / _NEW_DIRNAME
    legacy = Path.home() / _LEGACY_DIRNAME
    if not new.exists() and legacy.exists():
        return legacy
    return new


def default_db_path(home: Path | None = None) -> Path:
    """Default job-store DB inside the home; falls back to a legacy
    ``tessera.db`` if that is what exists there."""
    home = home or inverba_home()
    new = home / _NEW_DBNAME
    legacy = home / _LEGACY_DBNAME
    if not new.exists() and legacy.exists():
        return legacy
    return new
