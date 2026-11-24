import pytest
from scanner.logs import format_duration

@pytest.mark.parametrize("seconds, expected", [
    (0, "0.0s"),
    (59.9, "59.9s"),
    (60, "1m 00s"),
    (61, "1m 01s"),
    (120, "2m 00s"),
    (3600, "60m 00s")
])
def test_format_duration(seconds, expected):
    assert format_duration(seconds) == expected