"""
run.py - Main runner and analysis suite for pattern matching simulation.
Educational user-space simulation. Not a real antivirus, not a kernel driver.
"""
import os
import sys
import time
import json
import math
import platform
import argparse
import statistics
import threading
import multiprocessing as mp
from ac import (
    build, scan, scan_stream, naive, kmp, boyer_moore,
    make_signatures, make_data, EICAR
)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
RESULTS_DIR = os.path.join(BASE_DIR, "results")

# Standard 95th percentile helper using nearest-rank method
def p95(vals: list[float]) -> float:
    if not vals:
        return 0.0
    s = sorted(vals)
    idx = max(0, math.ceil(0.95 * len(s)) - 1)
    return s[idx]

# Helper to write CSV files with rounding to 4 decimal places
def write_csv(path: str, headers: list[str], rows: list[dict], comments: list[str] = None):
    with open(path, "w", encoding="utf-8") as f:
        for c in (comments or []):
            f.write(f"# {c}\n")
        f.write(",".join(headers) + "\n")
        for r in rows:
            line = [f"{r.get(h, ''):.4f}" if isinstance(r.get(h, ""), float) else str(r.get(h, "")) for h in headers]
            f.write(",".join(line) + "\n")

# Helper to save matplotlib plots safely
def save_plot(out_path: str, plot_fn):
    try:
        import matplotlib.pyplot as plt
        plt.figure(figsize=(7, 4))
        plot_fn(plt)
        plt.tight_layout()
        plt.savefig(out_path, dpi=150)
        plt.close()
    except Exception as e:
        print(f"[-] matplotlib not available: {e}")

# Write environment metadata to file
def write_env(exp: str, params: dict, seed: int, out_dir: str, extra: dict = None):
    os.makedirs(out_dir, exist_ok=True)
    ram, cpu, psutil_ok, mpl_ok = "N/A", str(os.cpu_count()), "no", "no"
    try:
        import psutil
        ram, cpu, psutil_ok = f"{psutil.virtual_memory().total / (1024**3):.1f} GB", f"{psutil.cpu_count(False)} phys, {psutil.cpu_count(True)} log", "yes"
    except ImportError:
        pass
    try:
        import matplotlib
        mpl_ok = "yes"
    except ImportError:
        pass
    lines = [
        f"Experiment: {exp}", f"Date/Time: {time.strftime('%Y-%m-%d %H:%M:%S')}",
        f"OS: {platform.system()} {platform.release()} ({platform.platform()})",
        f"Python: {sys.version.split()[0]} ({platform.python_compiler()})",
        f"CPU Cores: {cpu}", f"RAM: {ram}", f"Random Seed: {seed}",
        f"psutil available: {psutil_ok}", f"matplotlib available: {mpl_ok}",
        f"Parameters: {json.dumps(params)}",
        "Notice: Educational user-space simulation. Not a real antivirus, not a kernel driver.",
        "Caution: Do not compare absolute numbers across machines. Relative trends illustrate OS trade-offs."
    ]
    if extra:
        lines.extend(f"{k}: {v}" for k, v in extra.items())
    with open(os.path.join(out_dir, f"env_{exp}.txt"), "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")

# Pre-flight sanity assertions
def sanity_check():
    assert scan(build([b"he", b"she", b"his", b"hers"]), b"ushers") == sorted([(1, 1), (2, 0), (2, 3)])
    assert scan_stream(build([b"DANG", b"EROUS"]), [b"12345DANG", b"EROUS6789"]) == [(5, 0), (9, 1)]
    print("[+] Pre-flight sanity check passed.")

# Teaching demo: trace step-by-step state transitions on "ushers"
def cmd_demo(quick: bool = False, out_dir: str = RESULTS_DIR, seed: int = 42):
    write_env("demo", {}, seed, out_dir)
    sigs, text = [b"he", b"she", b"his", b"hers"], b"ushers"
    names, auto = [s.decode() for s in sigs], build(sigs)
    trie_edges = [{"state": u, "edges": [{"byte": b, "char": chr(b), "target": v} for b, v in sorted(auto.trans[u].items())]} for u in range(auto.node_count)]
    failure_links = [{"state": u, "fail": auto.fail[u]} for u in range(auto.node_count)]
    output_sets = [{"state": u, "outputs": [{"sig_id": sid, "name": names[sid], "len": m} for sid, m in auto.out[u]]} for u in range(auto.node_count)]
    trace, curr = [], 0
    for i, b in enumerate(text):
        old_state, jumps, path = curr, 0, []
        while curr and b not in auto.trans[curr]:
            path.append(f"{curr}->{auto.fail[curr]}")
            curr = auto.fail[curr]
            jumps += 1
        curr = auto.trans[curr].get(b, 0)
        m_list = [{"sig_id": sid, "name": names[sid], "start": i - m + 1, "end": i} for sid, m in auto.out[curr]]
        trace.append({"pos": i, "byte": b, "char": chr(b), "old_state": old_state, "fail_jumps": jumps, "fail_path": " -> ".join(path) or "none", "new_state": curr, "matches": m_list})
    data = {"signatures": names, "text": text.decode(), "trie_edges": trie_edges, "failure_links": failure_links, "output_sets": output_sets, "trace": trace}
    with open(os.path.join(out_dir, "demo.json"), "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    print(f"[+] Saved demo trace to {os.path.join(out_dir, 'demo.json')}")

# Experiment E1a: Algorithm Comparison (Naive, KMP, Boyer-Moore, Aho-Corasick)
def cmd_e1a(quick: bool = False, out_dir: str = RESULTS_DIR, seed: int = 42):
    n_bytes = 1024 * 1024
    k_list = [10, 100] if quick else [10, 100, 1000]
    repeats, warmup, threshold = (1, 0, 15.0) if quick else (3, 1, 120.0)
    write_env("e1a", {"k_list": k_list, "n_bytes": n_bytes, "repeats": repeats}, seed, out_dir)
    print(f"\n--- EXPERIMENT E1a: Algorithm Comparison (n=1MB, k={k_list}) ---")
    test_data, _ = make_data(n_bytes, seed=seed + 1000)
    algs = [("Naive", naive), ("KMP", kmp), ("Boyer-Moore", boyer_moore), ("Aho-Corasick", None)]
    rows, prev_time = [], {}
    for k in k_list:
        sigs = make_signatures(k, seed=seed)
        M = sum(len(s) for s in sigs)
        auto = build(sigs)
        ref_matches = scan(auto, test_data)
        ref_z = len(ref_matches)
        for name, fn in algs:
            if name != "Aho-Corasick" and name in prev_time:
                prev_k, p_time = prev_time[name]
                if p_time * (k / prev_k) > threshold:
                    rows.append({"algorithm": name, "k": k, "M": M, "scan_med_s": "skipped", "scan_min_s": "skipped", "scan_max_s": "skipped", "tp_mbs": "skipped", "z": "skipped"})
                    print(f"  k={k:4d} | {name:12s} | skipped (exceeds {threshold}s)")
                    continue
            fn_scan = (lambda: scan(auto, test_data)) if name == "Aho-Corasick" else (lambda: fn(sigs, test_data))
            if warmup > 0:
                fn_scan()
            durations = []
            for _ in range(repeats):
                t0 = time.perf_counter()
                m = fn_scan()
                durations.append(time.perf_counter() - t0)
            assert len(m) == ref_z, f"Match mismatch for {name}: {len(m)} != {ref_z}"
            med_s = statistics.median(durations)
            prev_time[name] = (k, med_s)
            tp = (n_bytes / (1024 * 1024)) / med_s
            rows.append({"algorithm": name, "k": k, "M": M, "scan_med_s": med_s, "scan_min_s": min(durations), "scan_max_s": max(durations), "tp_mbs": tp, "z": ref_z})
            print(f"  k={k:4d} | {name:12s} | Scan: {med_s:.4f}s | TP: {tp:.2f} MB/s | z: {ref_z}")
    write_csv(os.path.join(out_dir, "e1a.csv"), ["algorithm", "k", "M", "scan_med_s", "scan_min_s", "scan_max_s", "tp_mbs", "z"], rows)
    def plot_e1a(plt):
        for name, _ in algs:
            pts = [r for r in rows if r["algorithm"] == name and r["scan_med_s"] != "skipped"]
            if pts:
                plt.plot([int(r["k"]) for r in pts], [float(r["scan_med_s"]) for r in pts], "o-", label=name)
        plt.xscale("log")
        plt.yscale("log")
        plt.title("Scan Time vs k (1 MiB)")
        plt.legend()
    save_plot(os.path.join(out_dir, "e1a_scan_vs_k.png"), plot_e1a)

# Experiment E1b: Aho-Corasick Scaling
def cmd_e1b(quick: bool = False, out_dir: str = RESULTS_DIR, seed: int = 42):
    import tracemalloc
    k_list = [100, 1000, 10000] if quick else [100, 1000, 10000, 100000]
    n_bytes, repeats = (2 * 1024 * 1024, 2) if quick else (10 * 1024 * 1024, 5)
    write_env("e1b", {"k_list": k_list, "n_bytes": n_bytes, "repeats": repeats}, seed, out_dir)
    print(f"\n--- EXPERIMENT E1b: Aho-Corasick Scaling (n={n_bytes/(1024*1024):.1f}MB, k={k_list}) ---")
    test_data, _ = make_data(n_bytes, seed=seed + 1000)
    rows = []
    for k in k_list:
        sigs = make_signatures(k, seed=seed)
        M = sum(len(s) for s in sigs)
        tracemalloc.start()
        mem_auto = build(sigs)
        _, peak_mem = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        mem_mb, node_cnt = peak_mem / (1024 * 1024), mem_auto.node_count
        auto = build(sigs)
        b_times, s_times = [], []
        for _ in range(repeats):
            t0 = time.perf_counter()
            _ = build(sigs)
            b_times.append(time.perf_counter() - t0)
            t1 = time.perf_counter()
            m = scan(auto, test_data)
            s_times.append(time.perf_counter() - t1)
        b_med, s_med = statistics.median(b_times), statistics.median(s_times)
        tp = (n_bytes / (1024 * 1024)) / s_med
        rows.append({"k": k, "M": M, "build_med_s": b_med, "scan_med_s": s_med, "scan_min_s": min(s_times), "scan_max_s": max(s_times), "tp_mbs": tp, "node_count": node_cnt, "mem_mb": mem_mb, "z": len(m)})
        print(f"  k={k:6d} | Build: {b_med:.4f}s | Scan: {s_med:.4f}s ({tp:.2f} MB/s) | Mem: {mem_mb:.2f}MB")
    headers = ["k", "M", "build_med_s", "scan_med_s", "scan_min_s", "scan_max_s", "tp_mbs", "node_count", "mem_mb", "z"]
    write_csv(os.path.join(out_dir, "e1b.csv"), headers, rows)
    def plot_e1b(plt):
        plt.plot([r["M"] / 1024 for r in rows], [float(r["mem_mb"]) for r in rows], "o-", color="orange")
        plt.xlabel("Total Sig Length M (KB)")
        plt.ylabel("Trie Peak Mem (MB)")
        plt.title("Trie Memory vs M")
    save_plot(os.path.join(out_dir, "e1b_mem_vs_M.png"), plot_e1b)

# Experiment E2: Chunk Streaming and I/O Buffering
def cmd_e2(quick: bool = False, out_dir: str = RESULTS_DIR, seed: int = 42):
    k = 1000
    n_bytes, repeats = (4 * 1024 * 1024, 2) if quick else (20 * 1024 * 1024, 5)
    blocks = [("4 KB", 4096), ("64 KB", 65536), ("1 MB", 1048576), ("16 MB", 16777216), ("Whole file", -1)]
    write_env("e2", {"k": k, "n_bytes": n_bytes, "repeats": repeats}, seed, out_dir)
    print(f"\n--- EXPERIMENT E2: Chunk Streaming (File={n_bytes/(1024*1024):.1f}MB, k={k}) ---")
    sigs = make_signatures(k, seed=seed)
    auto = build(sigs)
    t_path = os.path.join(out_dir, "e2_test.bin")
    data, _ = make_data(n_bytes, signatures=sigs, plant=20, seed=seed + 1000)
    with open(t_path, "wb") as f:
        f.write(data)
    ref_matches = scan(auto, data)
    rows = []
    for name, b_sz in blocks:
        t_list, r_calls, all_equal = [], 0, True
        for _ in range(repeats):
            calls = [0]
            def chunk_gen():
                with open(t_path, "rb") as f:
                    while chunk := f.read(b_sz if b_sz > 0 else -1):
                        calls[0] += 1
                        yield chunk
            t0 = time.perf_counter()
            m_res = scan_stream(auto, chunk_gen())
            t_list.append(time.perf_counter() - t0)
            r_calls = calls[0]
            all_equal = all_equal and (m_res == ref_matches)
        med_s = statistics.median(t_list)
        tp = (n_bytes / (1024 * 1024)) / med_s
        rows.append({"block": name, "bytes": b_sz if b_sz > 0 else n_bytes, "read_calls": r_calls, "med_time_s": med_s, "tp_mbs": tp, "matches_equal": all_equal})
        print(f"  Block: {name:10s} | Reads: {r_calls:5d} | Time: {med_s:.4f}s | TP: {tp:.2f} MB/s | Equal: {all_equal}")
    if os.path.exists(t_path):
        os.remove(t_path)
    write_csv(os.path.join(out_dir, "e2.csv"), ["block", "bytes", "read_calls", "med_time_s", "tp_mbs", "matches_equal"], rows)
    save_plot(os.path.join(out_dir, "e2_tp_vs_block.png"), lambda plt: (plt.bar([r["block"] for r in rows], [float(r["tp_mbs"]) for r in rows], color="#0284c7"), plt.ylabel("Throughput (MB/s)"), plt.title("Throughput vs Block Size")))

# Dedicated worker process for on-access scanning
def scanner_worker(sigs: list[bytes], pipe):
    auto = build(sigs)
    pipe.send("READY")
    while True:
        try:
            req = pipe.recv()
        except EOFError:
            break
        if req is None:
            break
        req_id, path = req
        try:
            with open(path, "rb") as f:
                def gen():
                    while chunk := f.read(65536):
                        yield chunk
                m = scan_stream(auto, gen())
            pipe.send((req_id, "DENY" if m else "ALLOW", len(m)))
        except Exception:
            pipe.send((req_id, "ERROR", 0))

# Experiment E3: On-Access Interception Pipeline
def cmd_e3(quick: bool = False, out_dir: str = RESULTS_DIR, seed: int = 42):
    try:
        import psutil
    except ImportError:
        psutil = None
    ops_count, repeats = (60, 2) if quick else (300, 5)
    work_dir = os.path.join(out_dir, "workload")
    os.makedirs(work_dir, exist_ok=True)
    print(f"\n--- EXPERIMENT E3: On-Access Pipeline (Ops={ops_count}, Repeats={repeats}) ---")
    sigs = make_signatures(k=100, seed=seed)
    sigs[0] = EICAR
    specs = [("cfg.json", 16384, False), ("auth.log", 32768, False), ("manifest.xml", 20480, False), ("dropper.bin", 24576, True), ("user.dat", 10240, False), ("hosts.txt", 12288, False), ("eicar_test.bin", len(EICAR), True), ("lib_a.dll", 256000, False), ("lib_b.dll", 307200, False), ("trojan.dll", 286720, True), ("font.ttf", 409600, False), ("locale.db", 460800, False), ("sys.bin", 1048576, False), ("db.dat", 1228800, False), ("malware.bin", 1126400, True), ("app_1.bin", 1536000, False), ("app_2.bin", 1843200, False), ("app_3.bin", 2048000, False)]
    files = []
    for idx, (name, sz, is_inf) in enumerate(specs):
        p = os.path.join(work_dir, name)
        d = EICAR if (is_inf and name == "eicar_test.bin") else make_data(sz, signatures=sigs if is_inf else None, plant=5 if is_inf else 0, seed=seed + 1000 + idx)[0]
        with open(p, "wb") as f:
            f.write(d)
        files.append((p, is_inf))
    host_av = "no"
    try:
        _ = open(os.path.join(work_dir, "eicar_test.bin"), "rb").read()
    except OSError:
        host_av = "yes"
    write_env("e3", {"ops_count": ops_count, "repeats": repeats, "work_dir": work_dir}, seed, out_dir, {"host_av_blocked_eicar": host_av})
    def safe_read(p):
        try:
            return open(p, "rb").read(128)
        except OSError:
            return b""
    for p, _ in files:
        safe_read(p)
    import random
    rng = random.Random(seed)
    ops_seq = []
    for i in range(ops_count):
        if i in (15, 35, 55):
            ops_seq.append(("MODIFY", rng.choice(files)[0]))
        ops_seq.append(("OPEN", rng.choice(files)))
    modes_all, raw_runs = ["no_scan", "sync_every", "sync_cached", "async_scan"], []
    for r in range(repeats):
        for mode in modes_all[r % 4:] + modes_all[:r % 4]:
            p_conn, c_conn = mp.Pipe()
            proc = mp.Process(target=scanner_worker, args=(sigs, c_conn))
            proc.start()
            assert p_conn.recv() == "READY"
            proc_ps = psutil.Process(proc.pid) if psutil else None
            cpu0 = proc_ps.cpu_times() if proc_ps else None
            open_lats, cache, open_records, async_verdicts = [], {}, {}, {}
            cache_hits = cache_invalids = denied_cnt = scan_errors = 0
            inf_unscanned = inf_allowed = total_opens = 0
            stop_coll = threading.Event()
            def collector():
                while not stop_coll.is_set():
                    if p_conn.poll(0.01):
                        try:
                            msg = p_conn.recv()
                            if msg:
                                async_verdicts[msg[0]] = (msg[1], time.perf_counter())
                        except EOFError:
                            break
            coll_t = threading.Thread(target=collector) if mode == "async_scan" else None
            if coll_t:
                coll_t.start()
            t_run_start = time.perf_counter()
            for op, arg in ops_seq:
                if op == "MODIFY":
                    try:
                        with open(arg, "ab") as f:
                            f.write(b"mod")
                        os.utime(arg, None)
                    except OSError:
                        pass
                    cache_invalids += 1
                    continue
                f_path, is_inf = arg
                total_opens += 1
                t0 = time.perf_counter()
                open_records[total_opens] = (t0, is_inf)
                v = "ALLOW"
                if mode == "sync_every":
                    p_conn.send((total_opens, f_path))
                    _, v, _ = p_conn.recv()
                elif mode == "sync_cached":
                    try:
                        st = os.stat(f_path)
                        ck = (f_path, st.st_mtime, st.st_size)
                    except OSError:
                        ck = (f_path, 0, 0)
                    if ck in cache:
                        v, cache_hits = cache[ck], cache_hits + 1
                    else:
                        p_conn.send((total_opens, f_path))
                        _, v, _ = p_conn.recv()
                        cache[ck] = v
                elif mode == "async_scan":
                    p_conn.send((total_opens, f_path))
                if v in ("DENY", "ERROR"):
                    denied_cnt += 1
                    scan_errors += (v == "ERROR")
                else:
                    safe_read(f_path)
                    inf_unscanned += (is_inf and mode == "no_scan")
                    inf_allowed += (is_inf and mode != "no_scan")
                open_lats.append((time.perf_counter() - t0) * 1000.0)
            mean_exp, p95_exp, inf_before = 0.0, 0.0, 0
            if mode == "async_scan":
                t_w0 = time.perf_counter()
                while len(async_verdicts) < total_opens and time.perf_counter() - t_w0 < 120.0:
                    time.sleep(0.01)
                stop_coll.set()
                coll_t.join(timeout=2.0)
                exposures = []
                for qid, (op_t, inf_flag) in open_records.items():
                    if qid in async_verdicts:
                        v_str, arr_t = async_verdicts[qid]
                        denied_cnt += (v_str in ("DENY", "ERROR"))
                        scan_errors += (v_str == "ERROR")
                        inf_before += (inf_flag and arr_t > op_t)
                        exposures.append((arr_t - op_t) * 1000.0)
                mean_exp = statistics.mean(exposures) if exposures else 0.0
                p95_exp = p95(exposures)
            t_run_total, cpu_s = time.perf_counter() - t_run_start, 0.0
            if proc_ps:
                try:
                    cpu1 = proc_ps.cpu_times()
                    cpu_s = (cpu1.user - cpu0.user) + (cpu1.system - cpu0.system)
                except Exception:
                    pass
            p_conn.send(None)
            proc.join(timeout=2.0)
            if proc.is_alive():
                proc.terminate()
            raw_runs.append({
                "repeat": r + 1, "mode": mode, "total_opens": total_opens, "mean_lat_ms": statistics.mean(open_lats),
                "p95_lat_ms": p95(open_lats), "total_time_s": t_run_total, "tp_ops_s": total_opens / t_run_total, "scanner_cpu_s": cpu_s,
                "cache_hits": cache_hits, "cache_invalids": cache_invalids, "denied_count": denied_cnt, "scan_errors": scan_errors,
                "infected_opened_unscanned": inf_unscanned, "infected_allowed": inf_allowed, "mean_exposure_ms": mean_exp,
                "p95_exposure_ms": p95_exp, "infected_opened_before_verdict": inf_before
            })
    p_conn, c_conn = mp.Pipe()
    p_dead = mp.Process(target=scanner_worker, args=(sigs, c_conn))
    p_dead.start()
    p_conn.recv()
    p_dead.terminate()
    p_dead.join()
    fail_rows = []
    cases = [("clean_file", files[0][0], False), ("infected_file", [f[0] for f in files if f[1]][0], True)]
    for f_lbl, f_p, is_inf in cases:
        for pol in ["fail_open", "fail_closed"]:
            t0 = time.perf_counter()
            try:
                p_conn.send((999, f_p))
                p_conn.poll(0.2)
            except Exception:
                pass
            dt = (time.perf_counter() - t0) * 1000.0
            outc = "ALLOWED" if pol == "fail_open" else "DENIED"
            eff = ("SECURITY BREACH" if is_inf else "Clean file available") if pol == "fail_open" else ("Threat blocked" if is_inf else "DENIAL OF SERVICE")
            fail_rows.append({"file_type": f_lbl, "policy": pol, "decision_time_ms": dt, "outcome": outc, "security_effect": eff})
    write_csv(os.path.join(out_dir, "e3_failure.csv"), ["file_type", "policy", "decision_time_ms", "outcome", "security_effect"], fail_rows)
    med_rows = []
    flt_cols = ["mean_lat_ms", "p95_lat_ms", "total_time_s", "tp_ops_s", "scanner_cpu_s", "mean_exposure_ms", "p95_exposure_ms"]
    int_cols = ["cache_hits", "cache_invalids", "denied_count", "infected_opened_unscanned", "infected_allowed", "scan_errors", "infected_opened_before_verdict"]
    for m in modes_all:
        mr = [r for r in raw_runs if r["mode"] == m]
        row = {"repeat": "median", "mode": m, "total_opens": mr[0]["total_opens"]}
        row.update({h: statistics.median(r[h] for r in mr) for h in flt_cols})
        row.update({h: int(statistics.median(r[h] for r in mr)) for h in int_cols})
        med_rows.append(row)
        print(f"  Mode: {m:12s} | Mean Lat: {row['mean_lat_ms']:.2f}ms | P95: {row['p95_lat_ms']:.2f}ms | Denied: {row['denied_count']}")
    headers = ["repeat", "mode", "total_opens", "mean_lat_ms", "p95_lat_ms", "total_time_s", "tp_ops_s", "scanner_cpu_s", "cache_hits", "cache_invalids", "denied_count", "infected_opened_unscanned", "infected_allowed", "scan_errors", "mean_exposure_ms", "p95_exposure_ms", "infected_opened_before_verdict"]
    comments = ["infected_opened_unscanned: count of unscanned infected opens", "infected_allowed: count of false negatives"]
    write_csv(os.path.join(out_dir, "e3.csv"), headers, raw_runs + med_rows, comments)
    def plot_e3(plt):
        x = range(len(med_rows))
        plt.bar([p - 0.2 for p in x], [r["mean_lat_ms"] for r in med_rows], width=0.4, label="Mean (ms)", color="#0284c7")
        plt.bar([p + 0.2 for p in x], [r["p95_lat_ms"] for r in med_rows], width=0.4, label="P95 (ms)", color="#ef4444")
        plt.xticks(x, [r["mode"] for r in med_rows])
        plt.yscale("log")
        plt.title("Open Latency by Interception Mode")
        plt.legend()
    save_plot(os.path.join(out_dir, "e3_latency.png"), plot_e3)

# Generate offline interactive HTML dashboard
def cmd_html(quick: bool = False, out_dir: str = RESULTS_DIR, seed: int = 42):
    def read_csv(fn):
        p = os.path.join(out_dir, fn)
        if not os.path.exists(p):
            return []
        lines = [l.strip() for l in open(p, encoding="utf-8") if l.strip() and not l.startswith("#")]
        return [dict(zip([h.strip() for h in lines[0].split(",")], [v.strip() for v in l.split(",")])) for l in lines[1:]] if lines else []
    def read_json(fn):
        p = os.path.join(out_dir, fn)
        return json.load(open(p, encoding="utf-8")) if os.path.exists(p) else None
    payload = {
        "demo": read_json("demo.json"), "e1a": read_csv("e1a.csv"),
        "e1b": read_csv("e1b.csv"), "e2": read_csv("e2.csv"),
        "e3": read_csv("e3.csv"), "e3_fail": read_csv("e3_failure.csv")
    }
    date_str = time.strftime("%Y-%m-%d %H:%M:%S")
    css = "body{font-family:-apple-system,BlinkMacSystemFont,Segoe UI,Roboto,sans-serif;background:#fff;color:#1e293b;margin:0;padding:24px 16px}.container{max-width:1000px;margin:0 auto}header{border-bottom:2px solid #e2e8f0;padding-bottom:14px;margin-bottom:18px}h1{font-size:22px;color:#0f172a;margin:0 0 6px}.notice{display:inline-block;background:#fef3c7;color:#92400e;padding:3px 8px;border-radius:4px;font-size:12px;font-weight:600}.tabs{display:flex;gap:6px;border-bottom:1px solid #cbd5e1;margin-bottom:18px}.tab-btn{background:none;border:none;padding:8px 14px;font-size:13px;font-weight:600;color:#64748b;cursor:pointer;border-bottom:2px solid transparent}.tab-btn.active{color:#0284c7;border-bottom:2px solid #0284c7}.tab-pane{display:none}.tab-pane.active{display:block}.c-box{background:#f8fafc;border-left:4px solid #0284c7;padding:8px 12px;font-size:12px;line-height:1.5;margin-bottom:14px}table{width:100%;border-collapse:collapse;font-size:12px;margin:12px 0}th,td{border:1px solid #e2e8f0;padding:5px 8px;text-align:left}th{background:#f1f5f9;font-weight:600}tr.active-step{background:#e0f2fe;font-weight:600}.btn{background:#0284c7;color:#fff;border:none;padding:5px 10px;border-radius:4px;cursor:pointer;font-size:11px}svg{background:#fff;border:1px solid #e2e8f0;border-radius:4px;margin:10px 0;display:block}footer{margin-top:36px;border-top:1px solid #e2e8f0;padding-top:14px;font-size:11px;color:#64748b;line-height:1.5}"
    html = f"""<!DOCTYPE html><html><head><meta charset="UTF-8"><title>Aho-Corasick OS Simulation Dashboard</title><style>{css}</style></head><body><div class="container"><header><h1>Aho-Corasick Multi-Pattern Antivirus Simulation</h1><div class="notice">Educational user-space simulation. Not a real antivirus, not a kernel driver.</div><div style="font-size:12px;color:#64748b;margin-top:4px;">Run Date: {date_str}</div></header><nav class="tabs"><button class="tab-btn active" onclick="showTab('demo')">Demo</button><button class="tab-btn" onclick="showTab('e1a')">Algorithms (E1a)</button><button class="tab-btn" onclick="showTab('e1b')">Scaling (E1b)</button><button class="tab-btn" onclick="showTab('e2')">Block size (E2)</button><button class="tab-btn" onclick="showTab('e3')">Pipeline (E3)</button></nav><div id="tab-demo" class="tab-pane active"><div class="c-box"><b>What this shows:</b> Step-by-step state machine transitions and failure link traversals on sample text "ushers".<br><b>OS Concept:</b> Deterministic finite automaton state representation and amortized O(1) matching.</div><div id="d-c"><em>Not run yet: python run.py demo</em></div></div><div id="tab-e1a" class="tab-pane"><div class="c-box"><b>What this shows:</b> Scan time scaling of Naive, KMP, Boyer-Moore, and Aho-Corasick across signature counts.<br><b>OS Concept:</b> Multi-pass per-pattern traversal vs. single-pass multi-pattern automaton.</div><div id="e1a-c"><em>Not run yet: python run.py e1a</em></div></div><div id="tab-e1b" class="tab-pane"><div class="c-box"><b>What this shows:</b> Aho-Corasick throughput decreases gently at large k due to Trie memory footprint and CPU cache misses.<br><b>OS Concept:</b> Memory hierarchy trade-offs and spatial locality during state graph traversal.</div><div id="e1b-c"><em>Not run yet: python run.py e1b</em></div></div><div id="tab-e2" class="tab-pane"><div class="c-box"><b>What this shows:</b> Automaton maintains correct cross-chunk matching state across block sizes from 4 KB to full buffer.<br><b>OS Concept:</b> I/O buffering trade-offs: system call invocation overhead vs kernel read buffer allocation.</div><div id="e2-c"><em>Not run yet: python run.py e2</em></div></div><div id="tab-e3" class="tab-pane"><div class="c-box"><b>What this shows:</b> Open latency across synchronous, metadata-cached, and asynchronous interception modes.<br><b>OS Concept:</b> Blocking IPC latency, file stat caching, exposure window race conditions, and fail-closed security.</div><div id="e3-c"><em>Not run yet: python run.py e3</em></div></div><footer><b>Simulation Limitations:</b> User-space execution in pure Python; no kernel minifilter hook (FLTMGR.SYS / fanotify); synthetic random signatures rather than malware opcode distributions; host filesystem page cache benefits; single-machine local test.</footer></div><script id="exp-d" type="application/json">{json.dumps(payload)}</script><script>
const D=JSON.parse(document.getElementById('exp-d').textContent);
function showTab(id){{document.querySelectorAll('.tab-btn').forEach(b=>b.classList.remove('active'));document.querySelectorAll('.tab-pane').forEach(p=>p.classList.remove('active'));document.getElementById('tab-'+id).classList.add('active');event.target.classList.add('active');}}
if(D.demo){{let s=0;const t=D.demo.trace;const edges=D.demo.trie_edges.filter(e=>e.edges.length>0).map(e=>`State ${{e.state}}: `+e.edges.map(x=>`'${{x.char}}'&rarr;${{x.target}}`).join(', ')).slice(0,6).join('<br>');document.getElementById('d-c').innerHTML=`<div style="margin-bottom:8px;"><button class="btn" onclick="pS()">Prev</button> <button class="btn" onclick="nS()">Next</button> <span style="margin-left:8px;font-size:12px;">Step <b id="s-l">1</b> of ${{t.length}}</span></div><div style="font-size:12px;color:#475569;margin-bottom:8px;"><b>Trie transitions:</b><br>${{edges}}</div><table><thead><tr><th>Pos</th><th>Char</th><th>State Transition</th><th>Fail Path</th><th>Matches</th></tr></thead><tbody>${{t.map((r,i)=>`<tr id="r-${{i}}" class="${{i===0?'active-step':''}}"><td>${{r.pos}}</td><td>'${{r.char}}'</td><td>S${{r.old_state}}&rarr;S${{r.new_state}}</td><td>${{r.fail_path}}</td><td>${{r.matches.map(m=>m.name).join(', ')||'-'}}</td></tr>`).join('')}}</tbody></table>`;window.nS=()=>{{if(s<t.length-1){{s++;uS();}}}};window.pS=()=>{{if(s>0){{s--;uS();}}}};function uS(){{t.forEach((_,i)=>document.getElementById('r-'+i).className=(i===s?'active-step':''));document.getElementById('s-l').textContent=s+1;}}}}
if(D.e1a&&D.e1a.length){{const pts=D.e1a.filter(r=>r.algorithm==='Aho-Corasick').map((r,i)=>`${{80+i*130}},${{120-(Math.log10(parseFloat(r.scan_med_s)||0.001)+3)*25}}`).join(' ');document.getElementById('e1a-c').innerHTML=`<svg width="600" height="150"><text x="15" y="20" font-size="11" fill="#64748b">Aho-Corasick Scan Time (s) [log scale]</text><polyline fill="none" stroke="#0284c7" stroke-width="2" points="${{pts}}" />${{D.e1a.filter(r=>r.algorithm==='Aho-Corasick').map((r,i)=>`<circle cx="${{80+i*130}}" cy="${{120-(Math.log10(parseFloat(r.scan_med_s)||0.001)+3)*25}}" r="4" fill="#0284c7" /><text x="${{80+i*130}}" y="142" font-size="11" text-anchor="middle">k=${{r.k}}</text><text x="${{80+i*130}}" y="${{110-(Math.log10(parseFloat(r.scan_med_s)||0.001)+3)*25}}" font-size="11" text-anchor="middle">${{parseFloat(r.scan_med_s).toFixed(3)}}s</text>`).join('')}}</svg><table><thead><tr><th>Algorithm</th><th>Signatures (k)</th><th>Total M</th><th>Scan Time (s)</th><th>Throughput (MB/s)</th><th>Matches (z)</th></tr></thead><tbody>${{D.e1a.map(r=>`<tr><td><b>${{r.algorithm}}</b></td><td>${{r.k}}</td><td>${{r.M}}</td><td>${{r.scan_med_s}}</td><td>${{r.tp_mbs}}</td><td>${{r.z}}</td></tr>`).join('')}}</tbody></table>`;}}
if(D.e1b&&D.e1b.length){{const maxM=Math.max(...D.e1b.map(r=>parseFloat(r.mem_mb)||1));const pts=D.e1b.map((r,i)=>`${{80+i*130}},${{130-((parseFloat(r.mem_mb)||0)/maxM)*90}}`).join(' ');document.getElementById('e1b-c').innerHTML=`<svg width="600" height="160"><text x="15" y="20" font-size="11" fill="#64748b">Trie Memory (MB) vs k</text><polyline fill="none" stroke="#0284c7" stroke-width="2" points="${{pts}}" />${{D.e1b.map((r,i)=>`<circle cx="${{80+i*130}}" cy="${{130-((parseFloat(r.mem_mb)||0)/maxM)*90}}" r="4" fill="#0284c7" /><text x="${{80+i*130}}" y="150" font-size="11" text-anchor="middle">k=${{r.k}}</text><text x="${{80+i*130}}" y="${{118-((parseFloat(r.mem_mb)||0)/maxM)*90}}" font-size="11" text-anchor="middle">${{parseFloat(r.mem_mb).toFixed(1)}}MB</text>`).join('')}}</svg><table><thead><tr><th>Signatures (k)</th><th>Total M</th><th>Build Time (s)</th><th>Scan Time (s)</th><th>Throughput (MB/s)</th><th>Trie Mem (MB)</th></tr></thead><tbody>${{D.e1b.map(r=>`<tr><td>${{r.k}}</td><td>${{r.M}}</td><td>${{r.build_med_s}}</td><td>${{r.scan_med_s}}</td><td>${{r.tp_mbs}}</td><td>${{r.mem_mb}}</td></tr>`).join('')}}</tbody></table>`;}}
if(D.e2&&D.e2.length){{const maxTp=Math.max(...D.e2.map(r=>parseFloat(r.tp_mbs)||1));document.getElementById('e2-c').innerHTML=`<svg width="600" height="150"><text x="15" y="20" font-size="11" fill="#64748b">Throughput vs Block Size (MB/s)</text>${{D.e2.map((r,i)=>{{const h=((parseFloat(r.tp_mbs)||0)/maxTp)*80;return `<rect x="${{60+i*100}}" y="${{120-h}}" width="50" height="${{h}}" fill="#0284c7" /><text x="${{85+i*100}}" y="140" font-size="11" text-anchor="middle">${{r.block}}</text><text x="${{85+i*100}}" y="${{112-h}}" font-size="11" text-anchor="middle">${{parseFloat(r.tp_mbs).toFixed(1)}}</text>`;}}).join('')}}</svg><table><thead><tr><th>Block Size</th><th>Read Syscalls</th><th>Time (s)</th><th>Throughput (MB/s)</th><th>Matches Equal</th></tr></thead><tbody>${{D.e2.map(r=>`<tr><td><b>${{r.block}}</b></td><td>${{r.read_calls}}</td><td>${{r.med_time_s}}</td><td>${{r.tp_mbs}}</td><td>${{r.matches_equal}}</td></tr>`).join('')}}</tbody></table>`;}}
if(D.e3&&D.e3.length){{const med=D.e3.filter(r=>r.repeat==='median');const maxL=Math.max(...med.map(r=>parseFloat(r.mean_lat_ms)||1));document.getElementById('e3-c').innerHTML=`<svg width="600" height="150"><text x="15" y="20" font-size="11" fill="#64748b">Open Latency by Mode (ms)</text>${{med.map((r,i)=>{{const h=((parseFloat(r.mean_lat_ms)||0.1)/maxL)*80;return `<rect x="${{60+i*120}}" y="${{120-h}}" width="45" height="${{h}}" fill="#0284c7" /><text x="${{82+i*120}}" y="140" font-size="11" text-anchor="middle">${{r.mode.replace('_scan','')}}</text><text x="${{82+i*120}}" y="${{112-h}}" font-size="11" text-anchor="middle">${{parseFloat(r.mean_lat_ms).toFixed(1)}}</text>`;}}).join('')}}</svg><table><thead><tr><th>Mode</th><th>Mean Lat (ms)</th><th>P95 Lat (ms)</th><th>Denied</th><th>Cache Hits</th><th>Mean Exposure (ms)</th></tr></thead><tbody>${{med.map(r=>`<tr><td><b>${{r.mode}}</b></td><td>${{r.mean_lat_ms}}</td><td>${{r.p95_lat_ms}}</td><td>${{r.denied_count}}</td><td>${{r.cache_hits}}</td><td>${{r.mean_exposure_ms}}</td></tr>`).join('')}}</tbody></table>${{D.e3_fail&&D.e3_fail.length?`<div style="font-size:13px;font-weight:600;margin:14px 0 6px 0;">Scanner Daemon Failure Test</div><table><thead><tr><th>File Type</th><th>Policy</th><th>Decision (ms)</th><th>Outcome</th><th>Security Effect</th></tr></thead><tbody>${{D.e3_fail.map(r=>`<tr><td>${{r.file_type}}</td><td><b>${{r.policy}}</b></td><td>${{r.decision_time_ms}}</td><td><b>${{r.outcome}}</b></td><td>${{r.security_effect}}</td></tr>`).join('')}}</tbody></table>`:''}}`;}}
</script></body></html>"""
    with open(os.path.join(out_dir, "dashboard.html"), "w", encoding="utf-8") as f:
        f.write(html)
    print(f"[+] Saved dashboard to {os.path.join(out_dir, 'dashboard.html')}")

# Run all tasks sequentially
def cmd_all(quick: bool = False, out_dir: str = RESULTS_DIR, seed: int = 42):
    sanity_check()
    for fn in [cmd_demo, cmd_e1a, cmd_e1b, cmd_e2, cmd_e3, cmd_html]:
        fn(quick, out_dir, seed)
    print(f"\n[+] All tasks finished. Dashboard: {os.path.join(out_dir, 'dashboard.html')}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Aho-Corasick OS Simulation")
    parser.add_argument("cmd", choices=["demo", "e1a", "e1b", "e1", "e2", "e3", "all", "html"])
    parser.add_argument("--quick", action="store_true")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--out-dir", type=str, default=RESULTS_DIR)
    a = parser.parse_args()
    fn_map = {
        "demo": [cmd_demo], "e1a": [cmd_e1a], "e1b": [cmd_e1b],
        "e1": [cmd_e1a, cmd_e1b], "e2": [cmd_e2], "e3": [cmd_e3],
        "html": [cmd_html], "all": [cmd_all]
    }
    for task in fn_map[a.cmd]:
        task(a.quick, a.out_dir, a.seed)
