"""
ac.py - Exact pattern matching algorithms for educational simulation.
Educational user-space simulation. Not a real antivirus, not a kernel driver.
"""
from collections import deque
import random

EICAR = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

# Automaton representation for Aho-Corasick
class Automaton:
    __slots__ = ('trans', 'fail', 'out', 'node_count', 'k', 'M')

    def __init__(self):
        self.trans = [{}]
        self.fail = [0]
        self.out = [[]]
        self.node_count = 1
        self.k = 0
        self.M = 0

# Construction of Aho-Corasick automaton
def build(signatures: list[bytes]) -> Automaton:
    auto = Automaton()
    auto.k = len(signatures)
    auto.M = sum(len(s) for s in signatures)
    # Insert patterns into Trie
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
    # Build failure links via BFS queue
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

# Full buffer scan with Aho-Corasick
def scan(auto: Automaton, data: bytes) -> list[tuple[int, int]]:
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

# Streaming scan with Aho-Corasick across block boundaries
def scan_stream(auto: Automaton, chunks) -> list[tuple[int, int]]:
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

# Naive pattern matching (pure Python byte-by-byte comparison)
def naive(signatures: list[bytes], data: bytes) -> list[tuple[int, int]]:
    matches = []
    n = len(data)
    for sid, sig in enumerate(signatures):
        m = len(sig)
        if m == 0 or m > n:
            continue
        for i in range(n - m + 1):
            matched = True
            for j in range(m):
                if data[i + j] != sig[j]:
                    matched = False
                    break
            if matched:
                matches.append((i, sid))
    return sorted(matches)

# Helper for KMP failure table
def _kmp_table(sig: bytes) -> list[int]:
    m = len(sig)
    pi = [0] * m
    j = 0
    for i in range(1, m):
        while j > 0 and sig[i] != sig[j]:
            j = pi[j - 1]
        if sig[i] == sig[j]:
            j += 1
            pi[i] = j
    return pi

# Knuth-Morris-Pratt multi-pass algorithm
def kmp(signatures: list[bytes], data: bytes) -> list[tuple[int, int]]:
    matches = []
    n = len(data)
    for sid, sig in enumerate(signatures):
        m = len(sig)
        if m == 0 or m > n:
            continue
        pi = _kmp_table(sig)
        j = 0
        for i in range(n):
            b = data[i]
            while j > 0 and b != sig[j]:
                j = pi[j - 1]
            if b == sig[j]:
                j += 1
            if j == m:
                matches.append((i - m + 1, sid))
                j = pi[j - 1]
    return sorted(matches)

# Preprocessing tables for Boyer-Moore
def _bm_tables(sig: bytes) -> tuple[dict[int, int], list[int]]:
    m = len(sig)
    bad_char = {sig[i]: i for i in range(m)}
    suff = [0] * m
    suff[m - 1] = m
    g = f = m - 1
    for i in range(m - 2, -1, -1):
        if i > g and suff[i + m - 1 - f] < i - g:
            suff[i] = suff[i + m - 1 - f]
        else:
            if i < g:
                g = i
            f = i
            while g >= 0 and sig[g] == sig[g + m - 1 - f]:
                g -= 1
            suff[i] = f - g
    good_suffix = [m] * m
    j = 0
    for i in range(m - 1, -1, -1):
        if suff[i] == i + 1:
            while j < m - 1 - i:
                if good_suffix[j] == m:
                    good_suffix[j] = m - 1 - i
                j += 1
    for i in range(m - 1):
        good_suffix[m - 1 - suff[i]] = m - 1 - i
    return bad_char, good_suffix

# Boyer-Moore multi-pass algorithm
def boyer_moore(signatures: list[bytes], data: bytes) -> list[tuple[int, int]]:
    matches = []
    n = len(data)
    for sid, sig in enumerate(signatures):
        m = len(sig)
        if m == 0 or m > n:
            continue
        bad_char, good_suffix = _bm_tables(sig)
        shift = 0
        while shift <= n - m:
            j = m - 1
            while j >= 0 and sig[j] == data[shift + j]:
                j -= 1
            if j < 0:
                matches.append((shift, sid))
                shift += good_suffix[0]
            else:
                c = data[shift + j]
                bc_shift = j - bad_char.get(c, -1)
                gs_shift = good_suffix[j]
                shift += max(bc_shift, gs_shift)
    return sorted(matches)

# Synthetic signature generation
def make_signatures(k: int, seed: int = 42, min_m: int = 8, max_m: int = 32) -> list[bytes]:
    rng = random.Random(seed)
    return [rng.randbytes(rng.randint(min_m, max_m)) for _ in range(k)]

# Synthetic data generation with planted signatures
def make_data(n: int, signatures: list[bytes] = None, plant: int = 10, seed: int = 1042) -> tuple[bytes, list[tuple[int, int]]]:
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
