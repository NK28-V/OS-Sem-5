"""
test_ac.py - Correctness Tests for Aho-Corasick Multi-Pattern Scanner
Educational user-space simulation. Not a real antivirus, not a kernel driver.
"""
import os
import sys
import pytest
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from ac import build, scan, scan_stream, naive, make_signatures, make_data, EICAR


def test_classic_corasick():
    sigs = [b"he", b"she", b"his", b"hers"]
    res = scan(build(sigs), b"ushers")
    assert res == sorted([(1, 1), (2, 0), (2, 3)])  # she, he, hers


def test_edge_cases():
    auto = build([b"a", b"b"])
    assert scan(auto, b"") == []
    assert scan(auto, b"a") == [(0, 0)]
    assert scan(auto, b"z") == []
    assert scan(build([]), b"data") == []


def test_overlapping_and_suffix():
    sigs = [b"ab", b"bc", b"abc", b"c", b"b"]
    data = b"abcabc"
    assert scan(build(sigs), data) == naive(sigs, data)


def test_eicar_found():
    sigs = [EICAR, b"safe"]
    data = b"pre_" + EICAR + b"_post"
    assert scan(build(sigs), data) == naive(sigs, data)
    assert any(sid == 0 for _, sid in scan(build(sigs), data))


def test_stream_chunks_and_boundary_split():
    sigs = [b"DANGEROUS", b"ANTIVIRUS", b"stream"]
    data = b"12345DANGEROUS6789ANTIVIRUS_stream_buffer"
    auto = build(sigs)
    expected = scan(auto, data)

    # Chunk boundary splits "DANG" and "EROUS"
    split_chunks = [b"12345DANG", b"EROUS6789ANTIVIRUS_stream_buffer"]
    assert scan_stream(auto, split_chunks) == expected

    for cz in [1, 2, 7, 4096]:
        chunks = [data[i:i + cz] for i in range(0, len(data), cz)]
        assert scan_stream(auto, chunks) == expected


def test_ac_equals_naive_200_cases():
    for seed in range(200):
        k = (seed % 10) + 1
        sigs = make_signatures(k=k, seed=seed, min_m=3, max_m=8)
        data, _ = make_data(n=250, signatures=sigs, plant=4, seed=seed + 1000)
        assert scan(build(sigs), data) == naive(sigs, data)
