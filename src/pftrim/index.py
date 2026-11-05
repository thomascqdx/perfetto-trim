"""Sidecar cache for ScanResult.

Location: %LOCALAPPDATA%\\pftrim\\cache (env PFTRIM_CACHE_DIR overrides).
Key = sha1(abs path | file size | mtime_ns | SCAN_FORMAT_VERSION).
Value = gzip-compressed ScanResult.to_dict() JSON. Corrupt/unreadable
cache entries are ignored silently and the file is rescanned.
"""

from __future__ import annotations

import gzip
import hashlib
import json
import os
import pathlib

from .scan import SCAN_FORMAT_VERSION, ScanResult, scan


def cache_dir() -> pathlib.Path:
    override = os.environ.get("PFTRIM_CACHE_DIR")
    if override:
        return pathlib.Path(override)
    base = os.environ.get("LOCALAPPDATA") or str(
        pathlib.Path.home() / "AppData" / "Local")
    return pathlib.Path(base) / "pftrim" / "cache"


def _key(path: str, size: int, mtime_ns: int) -> str:
    h = hashlib.sha1()
    h.update(os.path.abspath(path).encode("utf-8", "surrogateescape"))
    h.update(b"|")
    h.update(str(size).encode())
    h.update(b"|")
    h.update(str(mtime_ns).encode())
    h.update(b"|")
    h.update(str(SCAN_FORMAT_VERSION).encode())
    return h.hexdigest()


def _cache_path(path: str, size: int, mtime_ns: int) -> pathlib.Path:
    return cache_dir() / (_key(path, size, mtime_ns) + ".json.gz")


def load_or_scan(path, *, progress=None, use_cache: bool = True) -> ScanResult:
    """Return a ScanResult for `path`, using the sidecar cache when valid."""
    path = os.fspath(path)
    size = os.path.getsize(path)
    mtime_ns = os.stat(path).st_mtime_ns

    if use_cache:
        cp = _cache_path(path, size, mtime_ns)
        try:
            with gzip.open(cp, "rt", encoding="utf-8") as f:
                d = json.load(f)
            if d.get("version") == SCAN_FORMAT_VERSION:
                res = ScanResult.from_dict(d)
                res.cache_hit = True
                return res
        except Exception:
            pass  # missing/corrupt cache -> rescan silently

    res = scan(path, progress=progress)
    res.cache_hit = False
    if use_cache:
        try:
            cp = _cache_path(path, size, mtime_ns)
            cp.parent.mkdir(parents=True, exist_ok=True)
            tmp = cp.with_suffix(".json.gz.part")
            with gzip.open(tmp, "wt", encoding="utf-8") as f:
                json.dump(res.to_dict(), f)
            os.replace(tmp, cp)
        except Exception:
            pass  # cache write failure is non-fatal
    return res
