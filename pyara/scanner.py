import math
import operator
import time
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from functools import cached_property
from pathlib import Path

from .ahocorasick import Automaton
from .rules import INT_FUNCS, resolve_set

_CMP = {
    "==": operator.eq, "!=": operator.ne, "<": operator.lt,
    ">": operator.gt, "<=": operator.le, ">=": operator.ge,
}


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    n = len(data)
    return -sum(c / n * math.log2(c / n) for c in Counter(data).values())


class FileInfo:
    def __init__(self, data: bytes):
        self.data = data
        self.filesize = len(data)

    @cached_property
    def entropy(self):
        # only computed if some rule actually asks for it
        return shannon_entropy(self.data)

    def read_int(self, name, offset):
        width, order = INT_FUNCS[name]
        if offset < 0 or offset + width > self.filesize:
            return None  # undefined, like YARA: comparisons with it are false
        return int.from_bytes(self.data[offset:offset + width], order)


def evaluate(node, info, hits, string_names):
    kind = node[0]
    if kind == "or":
        return evaluate(node[1], info, hits, string_names) or evaluate(node[2], info, hits, string_names)
    if kind == "and":
        return evaluate(node[1], info, hits, string_names) and evaluate(node[2], info, hits, string_names)
    if kind == "not":
        return not evaluate(node[1], info, hits, string_names)
    if kind == "cmp":
        left = evaluate(node[2], info, hits, string_names)
        right = evaluate(node[3], info, hits, string_names)
        if left is None or right is None:
            return False
        return _CMP[node[1]](left, right)
    if kind == "str":
        return bool(hits.get(node[1]))
    if kind == "count":
        return len(hits.get(node[1], ()))
    if kind == "num":
        return node[1]
    if kind == "bool":
        return node[1]
    if kind == "filesize":
        return info.filesize
    if kind == "entropy":
        return info.entropy
    if kind == "func":
        return info.read_int(node[1], node[2])
    if kind == "of":
        names = resolve_set(node[2], string_names)
        matched = sum(1 for n in names if hits.get(n))
        quant = node[1]
        if quant == "any":
            return matched >= 1
        if quant == "all":
            return bool(names) and matched == len(names)
        return matched >= quant
    raise ValueError(f"unknown node {kind!r}")


@dataclass
class Match:
    rule: str
    tags: list
    meta: dict
    hits: dict = field(default_factory=dict)  # string name -> sorted offsets


class Scanner:
    def __init__(self, rules):
        self.rules = rules
        self._exact = Automaton()
        self._nocase = Automaton()
        self._regexes = []
        for ri, rule in enumerate(rules):
            for s in rule.strings:
                if s.kind == "text":
                    nocase = "nocase" in s.modifiers
                    for variant in s.variants():
                        if nocase:
                            self._nocase.add(variant.lower(), (ri, s.name))
                        else:
                            self._exact.add(variant, (ri, s.name))
                else:
                    self._regexes.append((ri, s.name, s.regex))
        self._exact.build()
        self._nocase.build()

    def _collect_hits(self, data):
        hits = [defaultdict(list) for _ in self.rules]
        if len(self._exact):
            for off, (ri, name) in self._exact.iter(data):
                hits[ri][name].append(off)
        if len(self._nocase):
            for off, (ri, name) in self._nocase.iter(data.lower()):
                hits[ri][name].append(off)
        for ri, name, rx in self._regexes:
            hits[ri][name].extend(m.start() for m in rx.finditer(data))
        return hits

    def scan_bytes(self, data: bytes):
        info = FileInfo(data)
        all_hits = self._collect_hits(data)
        matches = []
        for rule, hits in zip(self.rules, all_hits):
            if evaluate(rule.condition, info, hits, rule.string_names):
                matches.append(Match(rule.name, rule.tags, rule.meta,
                                     {n: sorted(hits[n]) for n in rule.string_names if hits.get(n)}))
        return matches

    def scan_file(self, path):
        with open(path, "rb") as fh:
            return self.scan_bytes(fh.read())


def iter_files(targets, recursive=False, max_size=None):
    """Yield files under targets, skipping things too big or not regular files."""
    for target in targets:
        target = Path(target)
        if target.is_file():
            candidates = [target]
        elif target.is_dir():
            candidates = target.rglob("*") if recursive else target.iterdir()
        else:
            continue
        for p in sorted(candidates):
            try:
                if not p.is_file() or p.is_symlink():
                    continue
                if max_size is not None and p.stat().st_size > max_size:
                    continue
            except OSError:
                continue
            yield p


def scan_paths(scanner, targets, recursive=False, max_size=None):
    """Returns (results, stats). results is a list of (path, [Match])."""
    results, scanned, errors = [], 0, 0
    t0 = time.perf_counter()
    for path in iter_files(targets, recursive, max_size):
        try:
            found = scanner.scan_file(path)
        except (OSError, PermissionError):
            errors += 1
            continue
        scanned += 1
        if found:
            results.append((path, found))
    stats = {"files": scanned, "errors": errors, "seconds": time.perf_counter() - t0,
             "matches": sum(len(m) for _, m in results)}
    return results, stats
