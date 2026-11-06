from __future__ import annotations

import json
import pathlib
import sys

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
TESTS_DIR = pathlib.Path(__file__).resolve().parent

# Make tests/tp.py and tests/synthetic/ importable.
for p in (str(TESTS_DIR), str(TESTS_DIR / "synthetic")):
    if p not in sys.path:
        sys.path.insert(0, p)

TESTDATA_DIR = REPO_ROOT / "testdata"


def load_manifest() -> dict:
    manifest_path = TESTDATA_DIR / "MANIFEST.json"
    if not manifest_path.exists():
        return {}
    return json.loads(manifest_path.read_text(encoding="utf-8"))


@pytest.fixture(scope="session")
def sample_trace() -> pathlib.Path:
    manifest = load_manifest()
    if "files" in manifest:
        manifest = manifest["files"][0]  # primary sample = first entry
    filename = manifest.get("filename", "")
    path = TESTDATA_DIR / filename
    if not filename or not path.exists():
        pytest.skip("sample trace not present (see testdata/MANIFEST.json)")
    if manifest.get("size") is not None and path.stat().st_size != manifest["size"]:
        pytest.skip("sample trace size mismatch vs MANIFEST.json")
    return path


@pytest.fixture(scope="session")
def big_trace() -> pathlib.Path:
    """The real ~1.5 GB trace (2nd MANIFEST entry) for perf/TP tests."""
    files = load_manifest().get("files", [])
    if len(files) < 2:
        pytest.skip("big trace not listed in testdata/MANIFEST.json")
    entry = files[1]
    path = TESTDATA_DIR / entry["filename"]
    if not path.exists() or path.stat().st_size != entry.get("size"):
        pytest.skip("big trace not present (see testdata/MANIFEST.json)")
    return path


@pytest.fixture(scope="session")
def kn8_interned_trace() -> pathlib.Path:
    """New-build KN8 trace (~230MB): ftrace packets carrying
    interned_data AFTER ftrace_events + track_event packets on a
    sequence-scoped incremental clock (seq 8). Found by filename so it
    stays put if earlier MANIFEST entries change."""
    name = "trace_TECNO_KN8_20261106_114131.perfetto-trace"
    entry = next((f for f in load_manifest().get("files", [])
                  if f.get("filename") == name), None)
    path = TESTDATA_DIR / name
    if entry is None or not path.exists() or \
            path.stat().st_size != entry.get("size"):
        pytest.skip("kn8 interned sample not present "
                    "(see testdata/MANIFEST.json)")
    return path


@pytest.fixture(scope="session")
def sample_tp(sample_trace):
    from tp import open_tp

    tp = open_tp(sample_trace)
    yield tp
    tp.close()
