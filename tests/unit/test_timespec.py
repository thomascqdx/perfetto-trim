import pytest

from pftrim import timespec


def test_parse_duration():
    assert timespec.parse_duration("3.5s") == 3_500_000_000
    assert timespec.parse_duration("1200ms") == 1_200_000_000
    assert timespec.parse_duration("800us") == 800_000
    assert timespec.parse_duration("250ns") == 250
    assert timespec.parse_duration("1s") == 1_000_000_000
    assert timespec.parse_duration("42") == 42


def test_parse_time():
    start = 5_000_000_000_000
    assert timespec.parse_time("3.5s", start) == start + 3_500_000_000
    assert timespec.parse_time("0ms", start) == start
    assert timespec.parse_time("800us", start) == start + 800_000
    assert timespec.parse_time("123456789", start) == 123456789  # absolute
    assert timespec.parse_time(123456789, start) == 123456789


def test_parse_time_errors():
    with pytest.raises(ValueError, match="无法识别"):
        timespec.parse_time("abc", 0)
    with pytest.raises(ValueError, match="整数"):
        timespec.parse_time("1.5", 0)  # bare float not allowed


def test_parse_duration_errors():
    with pytest.raises(ValueError):
        timespec.parse_duration("10min")
    with pytest.raises(ValueError):
        timespec.parse_duration("")


def test_parse_size():
    assert timespec.parse_size("500MB") == 500 * 1024 * 1024
    assert timespec.parse_size("1.5GB") == int(1.5 * 1024 ** 3)
    assert timespec.parse_size("200k") == 200 * 1024
    assert timespec.parse_size("1024") == 1024
    assert timespec.parse_size("64b") == 64
    with pytest.raises(ValueError):
        timespec.parse_size("lots")


def test_format_ns():
    assert timespec.format_ns(500) == "500 ns"
    assert timespec.format_ns(1500) == "1.500 us"
    assert timespec.format_ns(2_500_000) == "2.500 ms"
    assert timespec.format_ns(3_512_000_000) == "3.512 s"
    assert timespec.format_ns(None) == "-"
