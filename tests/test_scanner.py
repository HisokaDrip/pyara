import os

import pytest

from pyara.rules import parse_rules
from pyara.scanner import Scanner, shannon_entropy


def matches(src, data):
    return [m.rule for m in Scanner(parse_rules(src)).scan_bytes(data)]


def hit(cond, data, strings='$a = "foo" $b = "bar" $c = "baz"'):
    return matches(f"rule T {{ strings: {strings} condition: {cond} }}", data) == ["T"]


@pytest.mark.parametrize("cond,data,expected", [
    ("$a", b"xx foo", True),
    ("$a and $b", b"foo", False),
    ("$a or $b", b"bar", True),
    ("not $c", b"foo", True),
    ("#a == 3", b"foofoofoo", True),
    ("#a > 3", b"foofoofoo", False),
    ("any of them", b"baz", True),
    ("all of them", b"foo bar", False),
    ("all of them", b"foo bar baz", True),
    ("2 of them", b"foo baz", True),
    ("2 of ($a, $b)", b"foo baz", False),
    ("filesize == 6", b"123456", True),
    ("filesize < 1KB", b"x" * 2000, False),
    ("true", b"", True),
    ("not ($a or $b) and filesize > 0", b"zzz", True),
])
def test_conditions(cond, data, expected):
    assert hit(cond, data) is expected


def test_wildcard_sets():
    strings = '$s1 = "one" $s2 = "two" $other = "three"'
    assert hit("all of ($s*)", b"one two", strings)
    assert not hit("all of ($s*, $other)", b"one two", strings)


def test_int_readers():
    data = b"MZ\x90\x00" + b"\x00" * 60
    assert hit("uint16(0) == 0x5A4D", data)
    assert hit("uint16be(0) == 0x4D5A", data)
    assert hit("uint8(2) == 0x90", data)
    # reading past the end is undefined, so the comparison is just false
    assert not hit("uint32(1000) == 0", data)
    assert not hit("uint32(1000) != 0", data)


def test_nocase_and_wide():
    assert hit("$a", b"FoO", '$a = "foo" nocase')
    assert not hit("$a", b"FoO", '$a = "foo"')
    assert hit("$a", "secret".encode("utf-16-le"), '$a = "secret" wide')
    assert not hit("$a", b"secret", '$a = "secret" wide')
    assert hit("$a", b"secret", '$a = "secret" wide ascii')


def test_hits_record_offsets():
    (m,) = Scanner(parse_rules('rule T { strings: $a = "ab" $r = /c+d/ condition: any of them }')).scan_bytes(b"abxabccd")
    assert m.hits == {"$a": [0, 3], "$r": [5]}


def test_entropy():
    assert shannon_entropy(b"") == 0
    assert shannon_entropy(b"aaaa") == 0
    assert shannon_entropy(bytes(range(256))) == pytest.approx(8.0)
    assert hit("entropy > 7.5", os.urandom(1 << 16))
    assert not hit("entropy > 7.5", b"hello world " * 1000)


def test_many_rules_share_one_pass():
    src = "\n".join(f'rule R{i} {{ strings: $a = "token{i:03d}" condition: $a }}' for i in range(300))
    data = b"... token042 ... token299 ..."
    assert matches(src, data) == ["R42", "R299"]
