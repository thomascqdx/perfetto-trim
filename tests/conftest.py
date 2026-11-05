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
    filename = manifest.get("filename", "")
    path = TESTDATA_DIR / filename
    if not filename or not path.exists():
        pytest.skip("sample trace not present (see testdata/MANIFEST.json)")
    if manifest.get("size") is not None and path.stat().st_size != manifest["size"]:
        pytest.skip("sample trace size mismatch vs MANIFEST.json")
    return path


@pytest.fixture(scope="session")
def sample_tp(sample_trace):
    from tp import open_tp

    tp = open_tp(sample_trace)
    yield tp
    tp.close()
