"""
ac.py - Aho-Corasick Multi-Pattern Matching Engine & Baseline
Educational user-space simulation. Not a real antivirus, not a kernel driver.

Variables:
n = input bytes, k = number of signatures, m = signature length,
M = total signature length, z = matches found.
"""
from collections import deque
import random

EICAR = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"


class Automaton:
    """Trie with BFS failure links and merged output sets."""
    __slots__ = ('trans', 'fail', 'out', 'node_count', 'k', 'M')

    def __init__(self):
        self.trans: list[dict[int, int]] = [{}]
        self.fail: list[int] = [0]
        self.out: list[list[tuple[int, int]]] = [[]]
        self.node_count: int = 1
        self.k: int = 0
        self.M: int = 0


def build(signatures: list[bytes]) -> Automaton:
    """Constructs Aho-Corasick automaton: Trie + BFS failure links + merged outputs."""
    auto = Automaton()
    auto.k = len(signatures)
    auto.M = sum(len(s) for s in signatures)

    # 1. Build Trie
    for sid, sig in enumerate(signatures):
        curr = 0
        for b in sig:
            nxt = auto.trans[curr].get(b)
            if nxt is None:
                nxt = len(auto.trans)
                auto.trans[curr][b] = nxt
                auto.trans.append({})
                auto.fail.append(0)
                auto.out.append([])
            curr = nxt
        auto.out[curr].append((sid, len(sig)))
    auto.node_count = len(auto.trans)

    # 2. Build BFS failure links and merge output sets
    q = deque()
    for b, nxt in auto.trans[0].items():
        auto.fail[nxt] = 0
        q.append(nxt)

    while q:
        u = q.popleft()
        for b, v in auto.trans[u].items():
            q.append(v)
            f = auto.fail[u]
            while f and b not in auto.trans[f]:
                f = auto.fail[f]
            tgt = auto.trans[f].get(b, 0)
            auto.fail[v] = tgt
            if auto.out[tgt]:
                auto.out[v].extend(auto.out[tgt])
    return auto


def scan(auto: Automaton, data: bytes) -> list[tuple[int, int]]:
    """Scans full buffer; returns sorted list of (start_position, signature_id)."""
    matches = []
    curr = 0
    trans, fail, out = auto.trans, auto.fail, auto.out
    for i, b in enumerate(data):
        while curr and b not in trans[curr]:
            curr = fail[curr]
        curr = trans[curr].get(b, 0)
        if out[curr]:
            for sid, m in out[curr]:
                matches.append((i - m + 1, sid))
    return sorted(matches)


def scan_stream(auto: Automaton, chunks) -> list[tuple[int, int]]:
    """Carries automaton state across chunks without re-reading or overlap."""
    curr = 0
    pos = 0
    trans, fail, out = auto.trans, auto.fail, auto.out
    matches = []
    for chunk in chunks:
        for b in chunk:
            while curr and b not in trans[curr]:
                curr = fail[curr]
            curr = trans[curr].get(b, 0)
            if out[curr]:
                for sid, m in out[curr]:
                    matches.append((pos - m + 1, sid))
            pos += 1
    return sorted(matches)


def naive(signatures: list[bytes], data: bytes) -> list[tuple[int, int]]:
    """
    Per-signature bytes.find loop (k passes).
    Note: bytes.find is implemented in C, so compare scaling trends (O(k*n) vs O(n+z)),
    not raw interpreted Python vs native C speed.
    """
    matches = []
    for sid, sig in enumerate(signatures):
        if not sig:
            continue
        pos = 0
        while True:
            idx = data.find(sig, pos)
            if idx == -1:
                break
            matches.append((idx, sid))
            pos = idx + 1
    return sorted(matches)


def make_signatures(k: int, seed: int = 42, min_m: int = 8, max_m: int = 32) -> list[bytes]:
    """Generates k random signatures over full byte alphabet (0-255)."""
    rng = random.Random(seed)
    return [rng.randbytes(rng.randint(min_m, max_m)) for _ in range(k)]


def make_data(n: int, signatures: list[bytes] = None, plant: int = 10, seed: int = 42) -> tuple[bytes, list[tuple[int, int]]]:
    """Generates n random bytes with planted signatures at known offsets."""
    rng = random.Random(seed)
    buf = bytearray(rng.randbytes(n))
    planted = []
    if signatures and plant > 0 and n > 0:
        for _ in range(plant):
            sid = rng.randint(0, len(signatures) - 1)
            sig = signatures[sid]
            m = len(sig)
            if m <= n:
                off = rng.randint(0, n - m)
                buf[off:off + m] = sig
                planted.append((off, sid))
    return bytes(buf), sorted(planted)
