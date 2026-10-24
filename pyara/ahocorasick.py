"""Aho-Corasick multi-pattern search over bytes.

The point of this is that a rule set with hundreds of literal strings still
only needs one pass over each file, instead of one bytes.find() per string.
"""
from collections import deque


class Automaton:
    def __init__(self):
        # node 0 is the root. each node: transitions, failure link, outputs
        self._goto = [{}]
        self._fail = [0]
        self._out = [[]]
        self._built = False
        self.size = 0  # number of patterns added

    def add(self, pattern: bytes, key) -> None:
        if not pattern:
            raise ValueError("can't add an empty pattern")
        node = 0
        for b in pattern:
            nxt = self._goto[node].get(b)
            if nxt is None:
                nxt = len(self._goto)
                self._goto[node][b] = nxt
                self._goto.append({})
                self._fail.append(0)
                self._out.append([])
            node = nxt
        self._out[node].append((key, len(pattern)))
        self.size += 1
        self._built = False

    def build(self) -> None:
        goto, fail, out = self._goto, self._fail, self._out
        queue = deque(goto[0].values())
        for child in queue:
            fail[child] = 0

        # BFS so a node's failure target (always shallower) is finished first
        while queue:
            node = queue.popleft()
            for b, child in goto[node].items():
                queue.append(child)
                f = fail[node]
                while f and b not in goto[f]:
                    f = fail[f]
                fail[child] = goto[f].get(b, 0)
                if out[fail[child]]:
                    out[child] = out[child] + out[fail[child]]
        self._built = True

    def iter(self, data: bytes):
        """Yield (start_offset, key) for every match, overlaps included."""
        if not self._built:
            self.build()
        goto, fail, out = self._goto, self._fail, self._out
        node = 0
        for i, b in enumerate(data):
            while node and b not in goto[node]:
                node = fail[node]
            node = goto[node].get(b, 0)
            if out[node]:
                for key, length in out[node]:
                    yield i - length + 1, key

    def __len__(self):
        return self.size
