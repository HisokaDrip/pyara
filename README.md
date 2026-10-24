# pyara

A small YARA-style rule engine written in plain Python, no dependencies.

I use YARA-ish rules a lot when poking at files, and at some point I wanted to
know how it actually works under the hood: how do you check hundreds of string
signatures against a file without scanning it hundreds of times? So I wrote my
own. It has a real lexer and parser for a subset of the YARA rule language,
an Aho-Corasick automaton so every literal string in every rule gets matched in
**one pass** over the file, hex strings with wildcards/jumps/alternations
compiled down to regexes, and a little condition evaluator.

It's meant for defensive stuff on your own machine: catching leaked secrets
before they get committed, sorting out file types, testing detection rules.

## What the rule language supports

```yara
rule Private_Key_Block : secret crypto
{
    meta:
        description = "PEM private key"
    strings:
        $begin = /-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/
        $end = "PRIVATE KEY-----"
    condition:
        $begin and #end >= 2
}
```

- text strings with escapes (`\n`, `\x41`, ...) and the `nocase`, `wide`, `ascii` modifiers
- hex strings: `{ 4D 5A ?? [2-4] (AA | BB) C? ?F }`
- regexes: `/AKIA[0-9A-Z]{16}/i`
- conditions: `and` / `or` / `not`, comparisons, `$a`, `#a` (match count),
  `any of them`, `all of ($s*)`, `2 of ($a, $b, $c)`, `filesize`, `1MB` / `4KB`,
  `uint8/16/32(offset)` (and `uint16be/uint32be`), plus an `entropy` keyword
  that real YARA puts behind the math module
- tags and meta

Not supported (yet): `at`/`in` offsets, `for` loops, modules like `pe`,
arithmetic in conditions.

## Running it

```
git clone https://github.com/HisokaDrip/pyara && cd pyara
python examples/make_samples.py          # writes harmless test files to samples/
python -m pyara -r examples/rules samples
```

Output from my machine:

```
8 rules, 9 files scanned in 0.01s, 7 matches
EICAR_Test_File [testfile] samples/eicar.com
PE_Executable [filetype] samples/fake_app.exe
ELF_Binary [filetype] samples/fake_lib.so
PowerShell_Download_Cradle [script,suspicious] samples/project/deploy.ps1
Private_Key_Block [secret,crypto] samples/project/id_rsa_backup
AWS_Access_Key_ID [secret,cloud] samples/project/settings.env
High_Entropy_Blob [heuristic] samples/vault.bin
```

`-s` shows which strings hit and where:

```
$ python -m pyara -r -s examples/rules samples/project
PowerShell_Download_Cradle [script,suspicious] samples/project/deploy.ps1
  0x1e:$ps: powershell -nop -w hidde...
  0x41:$dl1: New-Object Net.WebClient...
  0x5b:$dl3: DownloadString('http://e...
  0x3c:$exec1: IEX (New-Object Net.WebC...
Private_Key_Block [secret,crypto] samples/project/id_rsa_backup
  0x0:$begin: -----BEGIN RSA PRIVATE K...
  0xf:$end: PRIVATE KEY-----.UvImZaY...
  0x358:$end: PRIVATE KEY-----.
AWS_Access_Key_ID [secret,cloud] samples/project/settings.env
  0x33:$key: AKIAIOSFODNN7EXAMPLE.
```

Other flags: `--json` for one JSON line per file, `--max-size MB` to skip big
files, and `--fail-on-match` which exits 1 when anything matches, so you can drop
it into a pre-commit hook:

```
python -m pyara --fail-on-match -r examples/rules/secrets.yar .
```

Bad rules give you a line number instead of a stack trace:

```
pyara: broken.yar: line 1: rule Broken references undefined string $nope
```

(Everything in `samples/` is fake: the AWS key is Amazon's documented example
key, the private key is random bytes and the EICAR file is the standard
antivirus test string. The generator assembles them at runtime so the repo
itself doesn't set off secret scanners.)

## How it works

1. `lexer.py` turns rule text into tokens. The one annoying bit is that `{` and
   `/` mean different things depending on context, so right after an `=` they're
   read as a hex string / regex.
2. `rules.py` is a recursive descent parser. Conditions become small tuple ASTs
   like `("and", ("str", "$a"), ("cmp", ">", ("count", "$b"), ("num", 2)))`.
   It also checks that every `$x` you reference actually exists.
3. `scanner.py` throws every literal string from every rule into one
   Aho-Corasick automaton (`ahocorasick.py`), plus a second one for `nocase`
   strings that runs over a lowercased copy. Hex strings and regexes go through
   `re`. Then each rule's condition gets evaluated against the hits.

The Aho-Corasick implementation is tested against a brute-force `bytes.find`
loop on random inputs with a tiny alphabet, which is where all the nasty
overlapping cases show up.

Speed: it's pure Python, so it's not going to compete with real YARA. Scanning
my whole `/usr/lib/python3.13` (1258 files) with the example rules takes about
4 seconds.

## Tests

```
pip install -r requirements-dev.txt
pytest
```

76 tests, covering the matcher, parser errors, hex string edge cases, condition
semantics and the CLI end to end.

## What I'd do next

- `at` / `in` so strings can be pinned to offsets (`$mz at 0`)
- use the Aho-Corasick pass as a prefilter for hex strings too (pull out the
  longest fixed run of bytes, only run the regex near those hits)
- a `pe` module, at least for section names and imports
- run the scanning loop in multiple processes for big directories

MIT licensed.
