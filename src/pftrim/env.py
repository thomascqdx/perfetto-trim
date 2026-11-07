"""Environment variable lookup (stdlib only).

Public name is PERFETTO_TRIM_<name>; the pre-rename PFTRIM_<name> is
still honored as a fallback.
"""

from __future__ import annotations

import os


def getenv(name: str) -> str | None:
    """PERFETTO_TRIM_<name>, falling back to the legacy PFTRIM_<name>."""
    return os.environ.get("PERFETTO_TRIM_" + name) or \
        os.environ.get("PFTRIM_" + name) or None
