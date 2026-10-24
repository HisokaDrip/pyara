import re
from dataclasses import dataclass


class RuleSyntaxError(Exception):
    def __init__(self, msg, line=None):
        super().__init__(f"line {line}: {msg}" if line else msg)
        self.line = line


@dataclass
class Token:
    kind: str
    value: object
    line: int


KEYWORDS = {
    "rule", "meta", "strings", "condition", "and", "or", "not", "any", "all",
    "of", "them", "filesize", "entropy", "true", "false", "nocase", "wide",
    "ascii",
}

_NUMBER = re.compile(r"0x[0-9a-fA-F]+|\d+\.\d+|\d+(?:KB|MB)?")
_IDENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_STRID = re.compile(r"\$[A-Za-z0-9_]*\*?")
_COUNT = re.compile(r"#[A-Za-z0-9_]+")

_ESCAPES = {"n": b"\n", "t": b"\t", "r": b"\r", "\\": b"\\", '"': b'"', "0": b"\0"}


def _read_text(src, i, line):
    out = bytearray()
    j = i + 1
    while j < len(src):
        c = src[j]
        if c == '"':
            return bytes(out), j + 1
        if c == "\n":
            break
        if c == "\\":
            nxt = src[j + 1:j + 2]
            if nxt == "x":
                try:
                    out.append(int(src[j + 2:j + 4], 16))
                except ValueError:
                    raise RuleSyntaxError("bad \\x escape", line) from None
                j += 4
                continue
            if nxt not in _ESCAPES:
                raise RuleSyntaxError(f"unknown escape \\{nxt}", line)
            out += _ESCAPES[nxt]
            j += 2
            continue
        out += c.encode("utf-8")
        j += 1
    raise RuleSyntaxError("unterminated string", line)


def _read_number(text):
    if text.startswith("0x"):
        return int(text, 16)
    if "." in text:
        return float(text)
    if text.endswith("KB"):
        return int(text[:-2]) * 1024
    if text.endswith("MB"):
        return int(text[:-2]) * 1024 * 1024
    return int(text)


def tokenize(src: str):
    tokens = []
    i, line, n = 0, 1, len(src)

    def prev():
        return tokens[-1].kind if tokens else None

    while i < n:
        c = src[i]
        if c == "\n":
            line += 1
            i += 1
            continue
        if c.isspace():
            i += 1
            continue
        if src.startswith("//", i):
            j = src.find("\n", i)
            i = n if j == -1 else j
            continue
        if src.startswith("/*", i):
            j = src.find("*/", i + 2)
            if j == -1:
                raise RuleSyntaxError("unterminated comment", line)
            line += src.count("\n", i, j)
            i = j + 2
            continue

        if c == '"':
            value, i = _read_text(src, i, line)
            tokens.append(Token("TEXT", value, line))
            continue

        # `{` and `/` are ambiguous; right after `=` they start a hex string
        # or a regex, anywhere else they're just punctuation
        if c == "{" and prev() == "=":
            j = src.find("}", i)
            if j == -1:
                raise RuleSyntaxError("unterminated hex string", line)
            tokens.append(Token("HEX", src[i + 1:j], line))
            line += src.count("\n", i, j)
            i = j + 1
            continue
        if c == "/" and prev() == "=":
            j = i + 1
            while j < n and src[j] != "/":
                if src[j] == "\n":
                    raise RuleSyntaxError("unterminated regex", line)
                j += 2 if src[j] == "\\" else 1
            if j >= n:
                raise RuleSyntaxError("unterminated regex", line)
            body = src[i + 1:j]
            j += 1
            flags = ""
            while j < n and src[j] in "is":
                flags += src[j]
                j += 1
            tokens.append(Token("REGEX", (body, flags), line))
            i = j
            continue

        m = _NUMBER.match(src, i)
        if m:
            tokens.append(Token("NUMBER", _read_number(m.group()), line))
            i = m.end()
            continue
        m = _IDENT.match(src, i)
        if m:
            word = m.group()
            tokens.append(Token("KW" if word in KEYWORDS else "IDENT", word, line))
            i = m.end()
            continue
        m = _STRID.match(src, i)
        if m:
            tokens.append(Token("STRID", m.group(), line))
            i = m.end()
            continue
        m = _COUNT.match(src, i)
        if m:
            tokens.append(Token("COUNT", "$" + m.group()[1:], line))
            i = m.end()
            continue

        two = src[i:i + 2]
        if two in ("==", "!=", "<=", ">="):
            tokens.append(Token(two, two, line))
            i += 2
            continue
        if c in "<>(){}:=,":
            tokens.append(Token(c, c, line))
            i += 1
            continue
        raise RuleSyntaxError(f"unexpected character {c!r}", line)
    return tokens
