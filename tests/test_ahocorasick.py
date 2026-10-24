import random

import pytest

from pyara.ahocorasick import Automaton


def brute_force(patterns, data):
    found = set()
    for key, p in enumerate(patterns):
        start = data.find(p)
        while start != -1:
            found.add((start, key))
            start = data.find(p, start + 1)
    return found


def test_textbook_example():
    ac = Automaton()
    for word in [b"he", b"she", b"his", b"hers"]:
        ac.add(word, word)
    hits = sorted(ac.iter(b"ushers"))
    assert hits == [(1, b"she"), (2, b"he"), (2, b"hers")]


def test_overlapping_matches():
    ac = Automaton()
    ac.add(b"aa", "aa")
    assert [off for off, _ in ac.iter(b"aaaa")] == [0, 1, 2]


def test_empty_pattern_rejected():
    with pytest.raises(ValueError):
        Automaton().add(b"", "x")


@pytest.mark.parametrize("seed", range(20))
def test_matches_brute_force(seed):
    rng = random.Random(seed)
    alphabet = b"abcd"  # small alphabet = lots of overlap, which is the fun part
    patterns = []
    for _ in range(rng.randint(1, 15)):
        n = rng.randint(1, 5)
        patterns.append(bytes(rng.choice(alphabet) for _ in range(n)))
    data = bytes(rng.choice(alphabet) for _ in range(500))

    ac = Automaton()
    for key, p in enumerate(patterns):
        ac.add(p, key)
    assert set(ac.iter(data)) == brute_force(patterns, data)
