import pytest

from pyara.lexer import RuleSyntaxError
from pyara.rules import hex_to_regex, parse_rules, resolve_set

SAMPLE = r'''
// a comment
rule Sample : demo test
{
    meta:
        author = "mazy"
        score = 70
        enabled = true
    strings:
        $txt = "hello\tworld\x21" nocase
        $hex = { 4D 5A ?? 00 }
        $re  = /ab+c/i
    condition:
        any of them and filesize < 2KB
}

/* second rule,
   multi-line comment */
rule Other { condition: true }
'''


def test_parses_full_rule():
    rules = parse_rules(SAMPLE)
    assert [r.name for r in rules] == ["Sample", "Other"]
    r = rules[0]
    assert r.tags == ["demo", "test"]
    assert r.meta == {"author": "mazy", "score": 70, "enabled": True}
    assert r.strings[0].raw == b"hello\tworld!"
    assert r.strings[0].modifiers == {"nocase"}
    assert [s.kind for s in r.strings] == ["text", "hex", "regex"]
    assert r.condition == ("and", ("of", "any", ("them",)), ("cmp", "<", ("filesize",), ("num", 2048)))


def test_precedence_and_binds_tighter_than_or():
    (r,) = parse_rules('rule X { strings: $a="a" $b="b" $c="c" condition: $a or $b and $c }')
    assert r.condition == ("or", ("str", "$a"), ("and", ("str", "$b"), ("str", "$c")))


def test_wide_variants():
    (r,) = parse_rules('rule X { strings: $a = "ab" wide ascii condition: $a }')
    assert r.strings[0].variants() == [b"ab", b"a\x00b\x00"]


@pytest.mark.parametrize("hexstr,data,expected", [
    ("4D 5A", b"xxMZ", True),
    ("4D ?? 5A", b"M\xffZ", True),
    ("4D [2-3] 5A", b"M12Z", True),
    ("4D [2-3] 5A", b"M1Z", False),
    ("4D [2] 5A", b"M12Z", True),
    ("(41|42) 43", b"BC", True),
    ("(41|42) 43", b"DC", False),
    ("4? 43", b"\x4fC", True),
    ("?1 43", b"\xa1C", True),
    ("?1 43", b"\xa2C", False),
])
def test_hex_strings(hexstr, data, expected):
    assert bool(hex_to_regex(hexstr).search(data)) is expected


def test_hex_bytes_are_escaped():
    # 0x2E is '.', which must not turn into a regex wildcard
    assert not hex_to_regex("41 2E 42").search(b"AxB")


def test_resolve_set_wildcards():
    names = ["$a1", "$a2", "$b"]
    assert resolve_set(("$a*",), names) == ["$a1", "$a2"]
    assert resolve_set(("them",), names) == names


@pytest.mark.parametrize("src,msg", [
    ('rule X { strings: $a = "oops condition: $a }', "unterminated string"),
    ('rule X { strings: $a = "a" condition: $b }', "undefined string"),
    ('rule X { strings: $a = "a" }', "no condition"),
    ('rule X { strings: $a = "a" $a = "b" condition: $a }', "duplicate"),
    ('rule X { strings: $a = "a" condition: 3 of them }', "more strings"),
    ('rule X { strings: $a = { 4D ZZ } condition: $a }', "bad hex"),
    ('rule X { strings: $a = /(unclosed/ condition: $a }', "bad regex"),
    ('rule X { condition: $a* }', "wildcards"),
])
def test_syntax_errors(src, msg):
    with pytest.raises(RuleSyntaxError, match=msg):
        parse_rules(src)


def test_error_reports_line_number():
    with pytest.raises(RuleSyntaxError, match="line 3"):
        parse_rules('rule X {\n  strings:\n    $a = "nope\n  condition: $a }')
