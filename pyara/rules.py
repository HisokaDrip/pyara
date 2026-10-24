import re
from dataclasses import dataclass, field
from pathlib import Path

from .lexer import RuleSyntaxError, tokenize

CMP_OPS = {"==", "!=", "<", ">", "<=", ">="}
INT_FUNCS = {
    # name -> (width, byteorder)
    "uint8": (1, "little"),
    "uint16": (2, "little"),
    "uint32": (4, "little"),
    "uint16be": (2, "big"),
    "uint32be": (4, "big"),
}


@dataclass
class StringDef:
    name: str
    kind: str  # text | hex | regex
    raw: object
    modifiers: set = field(default_factory=set)
    regex: re.Pattern = None

    def variants(self):
        """The literal byte sequences a text string should match."""
        plain = self.raw
        wide = b"".join(bytes([b, 0]) for b in plain)
        if "wide" in self.modifiers:
            return [plain, wide] if "ascii" in self.modifiers else [wide]
        return [plain]


@dataclass
class Rule:
    name: str
    tags: list
    meta: dict
    strings: list
    condition: tuple

    @property
    def string_names(self):
        return [s.name for s in self.strings]


def hex_to_regex(body: str, line=None) -> re.Pattern:
    """Turn a YARA hex string like `4D 5A ?? [2-4] (AA|BB) C?` into a bytes regex."""
    s = re.sub(r"\s+", "", body)
    out = []
    i = 0
    while i < len(s):
        c = s[i]
        if c == "[":
            j = s.find("]", i)
            if j == -1:
                raise RuleSyntaxError("unterminated jump in hex string", line)
            jump = s[i + 1:j]
            m = re.fullmatch(r"(\d*)(-?)(\d*)", jump)
            if not m or (not m.group(2) and not m.group(1)):
                raise RuleSyntaxError(f"bad jump [{jump}]", line)
            lo = m.group(1) or "0"
            if m.group(2):
                out.append(b".{%s,%s}" % (lo.encode(), m.group(3).encode()))
            else:
                out.append(b".{%s}" % lo.encode())
            i = j + 1
            continue
        if c in "(|)":
            out.append({"(": b"(?:", "|": b"|", ")": b")"}[c])
            i += 1
            continue
        pair = s[i:i + 2]
        if len(pair) < 2 or not re.fullmatch(r"[0-9A-Fa-f?]{2}", pair):
            raise RuleSyntaxError(f"bad hex byte {pair!r}", line)
        hi, lo = pair
        if pair == "??":
            out.append(b".")
        elif lo == "?":
            base = int(hi, 16) << 4
            out.append(b"[" + re.escape(bytes([base])) + b"-" + re.escape(bytes([base | 0xF])) + b"]")
        elif hi == "?":
            options = b"".join(re.escape(bytes([(h << 4) | int(lo, 16)])) for h in range(16))
            out.append(b"[" + options + b"]")
        else:
            out.append(re.escape(bytes([int(pair, 16)])))
        i += 2
    if not out:
        raise RuleSyntaxError("empty hex string", line)
    try:
        return re.compile(b"".join(out), re.DOTALL)
    except re.error as e:
        raise RuleSyntaxError(f"hex string doesn't compile: {e}", line) from None


class Parser:
    def __init__(self, tokens):
        self.toks = tokens
        self.pos = 0

    def peek(self, offset=0):
        i = self.pos + offset
        return self.toks[i] if i < len(self.toks) else None

    def at(self, kind, value=None, offset=0):
        t = self.peek(offset)
        return t is not None and t.kind == kind and (value is None or t.value == value)

    def next(self):
        t = self.peek()
        if t is None:
            last = self.toks[-1].line if self.toks else None
            raise RuleSyntaxError("unexpected end of input", last)
        self.pos += 1
        return t

    def expect(self, kind, value=None):
        t = self.next()
        if t.kind != kind or (value is not None and t.value != value):
            want = value or kind
            raise RuleSyntaxError(f"expected {want}, got {t.value!r}", t.line)
        return t

    # -- top level ---------------------------------------------------------

    def parse(self):
        rules = []
        while self.peek() is not None:
            rules.append(self.parse_rule())
        return rules

    def parse_rule(self):
        self.expect("KW", "rule")
        name_tok = self.expect("IDENT")
        tags = []
        if self.at(":"):
            self.next()
            while self.at("IDENT"):
                tags.append(self.next().value)
        self.expect("{")

        meta, strings, condition = {}, [], None
        while not self.at("}"):
            section = self.expect("KW")
            self.expect(":")
            if section.value == "meta":
                while self.at("IDENT"):
                    key = self.next().value
                    self.expect("=")
                    meta[key] = self._meta_value()
            elif section.value == "strings":
                while self.at("STRID"):
                    strings.append(self._string_def())
            elif section.value == "condition":
                condition = self.parse_or()
            else:
                raise RuleSyntaxError(f"unknown section {section.value!r}", section.line)
        self.expect("}")

        if condition is None:
            raise RuleSyntaxError(f"rule {name_tok.value} has no condition", name_tok.line)
        rule = Rule(name_tok.value, tags, meta, strings, condition)
        _check_refs(rule, name_tok.line)
        return rule

    def _meta_value(self):
        t = self.next()
        if t.kind == "TEXT":
            return t.value.decode("utf-8", "replace")
        if t.kind == "NUMBER":
            return t.value
        if t.kind == "KW" and t.value in ("true", "false"):
            return t.value == "true"
        raise RuleSyntaxError(f"bad meta value {t.value!r}", t.line)

    def _string_def(self):
        name_tok = self.next()
        name = name_tok.value
        if name.endswith("*") or name == "$":
            raise RuleSyntaxError(f"bad string name {name!r}", name_tok.line)
        self.expect("=")
        t = self.next()
        mods = set()
        while self.at("KW") and self.peek().value in ("nocase", "wide", "ascii"):
            mods.add(self.next().value)

        if t.kind == "TEXT":
            if not t.value:
                raise RuleSyntaxError(f"{name} is empty", t.line)
            return StringDef(name, "text", t.value, mods)
        if mods:
            raise RuleSyntaxError(f"modifiers only work on text strings ({name})", t.line)
        if t.kind == "HEX":
            return StringDef(name, "hex", t.value, mods, hex_to_regex(t.value, t.line))
        if t.kind == "REGEX":
            body, flags = t.value
            re_flags = (re.IGNORECASE if "i" in flags else 0) | (re.DOTALL if "s" in flags else 0)
            try:
                rx = re.compile(body.replace("\\/", "/").encode("utf-8"), re_flags)
            except re.error as e:
                raise RuleSyntaxError(f"bad regex for {name}: {e}", t.line) from None
            return StringDef(name, "regex", body, mods, rx)
        raise RuleSyntaxError(f"expected a string value for {name}", t.line)

    # -- conditions ---------------------------------------------------------
    # precedence, loosest first: or, and, not, comparison, term

    def parse_or(self):
        node = self.parse_and()
        while self.at("KW", "or"):
            self.next()
            node = ("or", node, self.parse_and())
        return node

    def parse_and(self):
        node = self.parse_not()
        while self.at("KW", "and"):
            self.next()
            node = ("and", node, self.parse_not())
        return node

    def parse_not(self):
        if self.at("KW", "not"):
            self.next()
            return ("not", self.parse_not())
        return self.parse_cmp()

    def parse_cmp(self):
        left = self.parse_term()
        t = self.peek()
        if t is not None and t.kind in CMP_OPS:
            self.next()
            return ("cmp", t.kind, left, self.parse_term())
        return left

    def parse_term(self):
        t = self.next()
        if t.kind == "(":
            node = self.parse_or()
            self.expect(")")
            return node
        if t.kind == "STRID":
            if t.value.endswith("*"):
                raise RuleSyntaxError("wildcards only make sense inside 'of (...)'", t.line)
            return ("str", t.value)
        if t.kind == "COUNT":
            return ("count", t.value)
        if t.kind == "NUMBER":
            if self.at("KW", "of"):
                return self._of(t.value)
            return ("num", t.value)
        if t.kind == "KW":
            if t.value in ("any", "all"):
                return self._of(t.value)
            if t.value in ("filesize", "entropy"):
                return (t.value,)
            if t.value in ("true", "false"):
                return ("bool", t.value == "true")
        if t.kind == "IDENT" and t.value in INT_FUNCS:
            self.expect("(")
            offset = self.expect("NUMBER").value
            self.expect(")")
            return ("func", t.value, offset)
        raise RuleSyntaxError(f"unexpected {t.value!r} in condition", t.line)

    def _of(self, quant):
        self.expect("KW", "of")
        if self.at("KW", "them"):
            self.next()
            return ("of", quant, ("them",))
        self.expect("(")
        names = [self.expect("STRID").value]
        while self.at(","):
            self.next()
            names.append(self.expect("STRID").value)
        self.expect(")")
        return ("of", quant, tuple(names))


def _walk(node):
    yield node
    for child in node[1:]:
        if isinstance(child, tuple) and child and isinstance(child[0], str):
            yield from _walk(child)


def resolve_set(names, string_names):
    if names == ("them",):
        return list(string_names)
    picked = []
    for n in names:
        if n.endswith("*"):
            picked += [s for s in string_names if s.startswith(n[:-1]) and s not in picked]
        elif n not in picked:
            picked.append(n)
    return picked


def _check_refs(rule, line):
    known = set(rule.string_names)
    if len(known) != len(rule.strings):
        raise RuleSyntaxError(f"duplicate string name in rule {rule.name}", line)
    for node in _walk(rule.condition):
        if node[0] in ("str", "count") and node[1] not in known:
            raise RuleSyntaxError(f"rule {rule.name} references undefined string {node[1]}", line)
        if node[0] == "of":
            names = node[2]
            for n in names:
                if n != "them" and not resolve_set((n,), rule.string_names):
                    raise RuleSyntaxError(f"rule {rule.name}: {n} matches no strings", line)
            if isinstance(node[1], int) and node[1] > len(resolve_set(names, rule.string_names)):
                raise RuleSyntaxError(f"rule {rule.name}: '{node[1]} of' asks for more strings than exist", line)


def parse_rules(src: str):
    return Parser(tokenize(src)).parse()


def load_rules(path):
    path = Path(path)
    files = sorted(path.rglob("*.yar")) + sorted(path.rglob("*.yara")) if path.is_dir() else [path]
    rules, seen = [], {}
    for f in files:
        try:
            parsed = parse_rules(f.read_text(encoding="utf-8"))
        except RuleSyntaxError as e:
            raise RuleSyntaxError(f"{f}: {e}") from None
        for r in parsed:
            if r.name in seen:
                raise RuleSyntaxError(f"rule {r.name} defined in both {seen[r.name]} and {f}")
            seen[r.name] = f
        rules += parsed
    return rules
