"""
test_ac.py - Correctness tests for pattern matching algorithms.
Educational user-space simulation. Not a real antivirus, not a kernel driver.
"""
import os
import sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from ac import (
    build, scan, scan_stream, naive, kmp, boyer_moore,
    make_signatures, make_data, EICAR
)


# Helper to assert all four algorithms return identical results
def _check_all(sigs: list[bytes], data: bytes, expected=None):
    res_ac = scan(build(sigs), data)
    res_nv = naive(sigs, data)
    res_kmp = kmp(sigs, data)
    res_bm = boyer_moore(sigs, data)
    assert res_ac == res_nv == res_kmp == res_bm
    if expected is not None:
        assert res_ac == expected
    return res_ac


# Classic Aho-Corasick test case on "ushers"
def test_classic_corasick():
    sigs = [b"he", b"she", b"his", b"hers"]
    expected = [(1, 1), (2, 0), (2, 3)]
    _check_all(sigs, b"ushers", sorted(expected))


# Edge cases: empty data, single byte, start/end matches
def test_edge_cases():
    sigs = [b"a", b"b"]
    _check_all(sigs, b"", [])
    _check_all(sigs, b"a", [(0, 0)])
    _check_all(sigs, b"z", [])
    _check_all([], b"data", [])
    _check_all([b"start", b"end"], b"start_middle_end", [(0, 0), (13, 1)])


# Overlapping and suffix matches
def test_overlapping_and_suffix():
    sigs = [b"ab", b"bc", b"abc", b"c", b"b"]
    _check_all(sigs, b"abcabc")


# Detection of EICAR test signature
def test_eicar_found():
    sigs = [EICAR, b"safe"]
    data = b"pre_" + EICAR + b"_post"
    res = _check_all(sigs, data)
    assert any(sid == 0 for _, sid in res)


# Chunk streaming across various block sizes and splits
def test_stream_chunks_and_boundary_split():
    sigs = [b"DANGEROUS", b"ANTIVIRUS", b"stream"]
    data = b"12345DANGEROUS6789ANTIVIRUS_stream_buffer"
    auto = build(sigs)
    expected = scan(auto, data)
    split_chunks = [b"12345DANG", b"EROUS6789ANTIVIRUS_stream_buffer"]
    assert scan_stream(auto, split_chunks) == expected
    for cz in [1, 2, 7, 4096]:
        chunks = [data[i:i + cz] for i in range(0, len(data), cz)]
        assert scan_stream(auto, chunks) == expected


# Verify clean data with independent seeds produces 0 matches
def test_clean_data_zero_matches():
    sigs = make_signatures(k=50, seed=42)
    clean_data, _ = make_data(n=10000, signatures=None, plant=0, seed=1042)
    _check_all(sigs, clean_data, [])


# Cross-check all four algorithms over 200 random workloads
def test_all_algorithms_200_random_cases():
    for seed in range(200):
        k = (seed % 10) + 1
        sigs = make_signatures(k=k, seed=seed, min_m=3, max_m=8)
        data, _ = make_data(n=250, signatures=sigs, plant=4, seed=seed + 1000)
        _check_all(sigs, data)
