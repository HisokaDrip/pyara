import argparse
import json
import sys

from . import __version__
from .lexer import RuleSyntaxError
from .rules import load_rules
from .scanner import Scanner, scan_paths


def _snippet(data, offset, width=24):
    chunk = data[offset:offset + width]
    text = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
    return text + ("..." if len(data) > offset + width else "")


def build_parser():
    p = argparse.ArgumentParser(prog="pyara", description="Scan files with YARA-style rules.")
    p.add_argument("rules", help="a .yar file or a directory of them")
    p.add_argument("targets", nargs="+", help="files or directories to scan")
    p.add_argument("-r", "--recursive", action="store_true", help="walk directories recursively")
    p.add_argument("-s", "--show-strings", action="store_true", help="print the matching strings and offsets")
    p.add_argument("--json", action="store_true", help="one JSON object per matching file")
    p.add_argument("--max-size", type=float, default=32, metavar="MB", help="skip files bigger than this (default 32)")
    p.add_argument("--fail-on-match", action="store_true", help="exit 1 if anything matched (handy in CI / pre-commit)")
    p.add_argument("-V", "--version", action="version", version=f"pyara {__version__}")
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    try:
        rules = load_rules(args.rules)
    except (RuleSyntaxError, OSError) as e:
        print(f"pyara: {e}", file=sys.stderr)
        return 2

    scanner = Scanner(rules)
    results, stats = scan_paths(scanner, args.targets, args.recursive, int(args.max_size * 1024 * 1024))

    for path, found in results:
        if args.json:
            print(json.dumps({
                "path": str(path),
                "matches": [{"rule": m.rule, "tags": m.tags, "meta": m.meta, "strings": m.hits} for m in found],
            }))
            continue
        data = path.read_bytes() if args.show_strings else None
        for m in found:
            tags = f" [{','.join(m.tags)}]" if m.tags else ""
            print(f"{m.rule}{tags} {path}")
            if args.show_strings:
                for name, offsets in m.hits.items():
                    for off in offsets[:5]:
                        print(f"  0x{off:x}:{name}: {_snippet(data, off)}")
                    if len(offsets) > 5:
                        print(f"  ... {len(offsets) - 5} more {name} hits")

    print(f"{len(rules)} rules, {stats['files']} file{'s' if stats['files'] != 1 else ''} scanned in {stats['seconds']:.2f}s, "
          f"{stats['matches']} matches", file=sys.stderr)
    return 1 if args.fail_on_match and results else 0
