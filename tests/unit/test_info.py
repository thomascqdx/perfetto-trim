import pytest

from pftrim import cli


@pytest.fixture
def cache_env(tmp_path, monkeypatch):
    monkeypatch.setenv("PFTRIM_CACHE_DIR", str(tmp_path / "cache"))


@pytest.mark.sample
def test_info_cli_sample(sample_trace, cache_env, capsys):
    rc = cli.main(["info", str(sample_trace)])
    assert rc == 0
    out = capsys.readouterr().out
    assert "5537349512888059" in out
    assert "5537360124690214" in out
    assert "ftrace" in out


@pytest.mark.sample
def test_info_cli_json(sample_trace, cache_env, capsys):
    import json
    rc = cli.main(["info", "--json", str(sample_trace)])
    assert rc == 0
    d = json.loads(capsys.readouterr().out)
    assert d["start_ns"] == 5537349512888059
    assert d["end_ns"] == 5537360124690214


def test_info_missing_file(tmp_path, cache_env, capsys):
    rc = cli.main(["info", str(tmp_path / "nope.perfetto-trace")])
    assert rc != 0
    err = capsys.readouterr().err
    assert "不存在" in err
