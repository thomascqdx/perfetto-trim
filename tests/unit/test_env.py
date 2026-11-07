"""pftrim.env: PERFETTO_TRIM_* preferred, PFTRIM_* legacy fallback."""

import pytest

from pftrim import ftpar, index
from pftrim.env import getenv


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for suffix in ("FOO", "CACHE_DIR", "PAR_MIN_BYTES"):
        monkeypatch.delenv("PERFETTO_TRIM_" + suffix, raising=False)
        monkeypatch.delenv("PFTRIM_" + suffix, raising=False)


def test_getenv_new_only(monkeypatch):
    monkeypatch.setenv("PERFETTO_TRIM_FOO", "new")
    assert getenv("FOO") == "new"


def test_getenv_legacy_only(monkeypatch):
    monkeypatch.setenv("PFTRIM_FOO", "legacy")
    assert getenv("FOO") == "legacy"


def test_getenv_new_wins_over_legacy(monkeypatch):
    monkeypatch.setenv("PERFETTO_TRIM_FOO", "new")
    monkeypatch.setenv("PFTRIM_FOO", "legacy")
    assert getenv("FOO") == "new"


def test_getenv_unset_is_none():
    assert getenv("FOO") is None


def test_cache_dir_honors_legacy(monkeypatch, tmp_path):
    monkeypatch.setenv("PFTRIM_CACHE_DIR", str(tmp_path / "legacy"))
    assert index.cache_dir() == tmp_path / "legacy"


def test_cache_dir_default(monkeypatch, tmp_path):
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    assert index.cache_dir() == tmp_path / "perfetto-trim" / "cache"


def test_min_parallel_bytes_honors_legacy(monkeypatch):
    monkeypatch.setenv("PFTRIM_PAR_MIN_BYTES", "123")
    assert ftpar.min_parallel_bytes() == 123
