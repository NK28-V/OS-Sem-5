"""
run.py - Main Runner & Analysis Suite for Aho-Corasick OS Simulation
Educational user-space simulation. Not a real antivirus, not a kernel driver.
Variables: n=bytes, k=signatures, m=sig len, M=total sig len, z=matches.
Usage: python run.py demo | e1 | e2 | e3 | all | html [--quick] [--seed SEED]
"""
import os, sys, time, json, platform, argparse, statistics, threading, tempfile
import multiprocessing as mp
from ac import build, scan, scan_stream, naive, make_signatures, make_data, EICAR

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
RESULTS_DIR = os.path.join(BASE_DIR, "results")


def write_env(exp: str, params: dict, seed: int, out_dir: str):
    os.makedirs(out_dir, exist_ok=True)
    try:
        import psutil; ram, cpu, has_psutil = f"{psutil.virtual_memory().total / (1024**3):.1f} GB", f"{psutil.cpu_count(False)} phys, {psutil.cpu_count(True)} log", "yes"
    except ImportError: ram, cpu, has_psutil = "N/A", str(os.cpu_count()), "no"
    try: import matplotlib; has_mpl = "yes"
    except ImportError: has_mpl = "no"
    lines = [
        f"Experiment: {exp}", f"Date/Time: {time.strftime('%Y-%m-%d %H:%M:%S')}",
        f"OS: {platform.system()} {platform.release()} ({platform.platform()})",
        f"Python: {sys.version.split()[0]} ({platform.python_compiler()})",
        f"CPU Cores: {cpu}", f"RAM: {ram}", f"Random Seed: {seed}",
        f"psutil available: {has_psutil}", f"matplotlib available: {has_mpl}",
        "Parameters: " + json.dumps(params),
        "Notice: Educational user-space simulation. Not a real antivirus, not a kernel driver.",
        "Caution: Do not compare absolute numbers across machines. Relative trends illustrate OS trade-offs."
    ]
    if exp == "e3": lines.append("Note: The host antivirus (e.g., Windows Defender) may scan generated files; this is a confounding factor.")
    with open(os.path.join(out_dir, f"env_{exp}.txt"), "w", encoding="utf-8") as f: f.write("\n".join(lines) + "\n")


def sanity_check():
    sigs = [b"he", b"she", b"his", b"hers"]
    assert scan(build(sigs), b"ushers") == sorted([(1, 1), (2, 0), (2, 3)]), "Sanity fail: demo"
    assert scan_stream(build([b"DANG", b"EROUS"]), [b"12345DANG", b"EROUS6789"]) == [(5, 0), (9, 1)], "Sanity fail: stream"
    print("[+] Pre-flight sanity check passed.")


def cmd_demo(out_dir: str = RESULTS_DIR, seed: int = 42):
    write_env("demo", {}, seed, out_dir)
    sigs, text = [b"he", b"she", b"his", b"hers"], b"ushers"
    names, auto = [s.decode() for s in sigs], build(sigs)
    trie_edges, failure_links, output_sets, trace = [], [], [], []
    for u in range(auto.node_count):
        trie_edges.append({"state": u, "edges": [{"byte": b, "char": chr(b), "target": v} for b, v in sorted(auto.trans[u].items())]})
        failure_links.append({"state": u, "fail": auto.fail[u]})
        output_sets.append({"state": u, "outputs": [{"sig_id": sid, "name": names[sid], "len": m} for sid, m in auto.out[u]]})
    curr = 0
    for i, b in enumerate(text):
        old_state, jumps, path = curr, 0, []
        while curr and b not in auto.trans[curr]:
            path.append(f"{curr}->{auto.fail[curr]}"); curr = auto.fail[curr]; jumps += 1
        curr = auto.trans[curr].get(b, 0)
        m_list = [{"sig_id": sid, "name": names[sid], "start": i - m + 1, "end": i} for sid, m in auto.out[curr]]
        trace.append({"pos": i, "byte": b, "char": chr(b), "old_state": old_state, "fail_jumps": jumps,
                      "fail_path": " -> ".join(path) or "none", "new_state": curr, "matches": m_list})
    with open(os.path.join(out_dir, "demo.json"), "w", encoding="utf-8") as f:
        json.dump({"signatures": names, "text": text.decode(), "trie_edges": trie_edges,
                   "failure_links": failure_links, "output_sets": output_sets, "trace": trace}, f, indent=2)
    print("\n--- AHO-CORASICK TEACHING DEMO (ushers) ---")
    for f in failure_links:
        print(f" State {f['state']:2d} | Fail: {f['fail']:2d} | Out: {[o['name'] for o in output_sets[f['state']]['outputs']] or '-'}")
    for t in trace:
        m_str = ", ".join(f"{m['name']}@[{m['start']}..{m['end']}]" for m in t["matches"]) or "-"
        print(f" Pos {t['pos']} '{t['char']}' | S{t['old_state']} -> S{t['new_state']} | Jumps: {t['fail_jumps']} | Matches: {m_str}")
    print(f"[+] Saved {os.path.join(out_dir, 'demo.json')}")


def cmd_e1(quick: bool = False, out_dir: str = RESULTS_DIR, seed: int = 42):
    import tracemalloc
    k_list = [100, 1000, 10000] if quick else [100, 1000, 10000, 100000]
    n_bytes, repeats = (2 * 1024 * 1024, 2) if quick else (10 * 1024 * 1024, 5)
    write_env("e1", {"k_list": k_list, "n_bytes": n_bytes, "repeats": repeats}, seed, out_dir)
    print(f"\n--- EXPERIMENT E1: Signature Scaling (n={n_bytes/(1024*1024):.1f}MB, k={k_list}) ---")
    test_data, _ = make_data(n_bytes, seed=seed)
    has_pyac = False
    try:
        import ahocorasick
        has_pyac = True
    except ImportError: pass
    rows = []
    for k in k_list:
        sigs = make_signatures(k, seed=seed)
        M = sum(len(s) for s in sigs)
        tracemalloc.start(); mem_auto = build(sigs); _, peak_mem = tracemalloc.get_traced_memory(); tracemalloc.stop()
        mem_mb, node_cnt = peak_mem / (1024 * 1024), mem_auto.node_count
        auto = build(sigs); _ = scan(auto, test_data[:65536])
        b_times, s_times = [], []
        for _ in range(repeats):
            t0 = time.perf_counter(); _ = build(sigs); b_times.append(time.perf_counter() - t0)
            t1 = time.perf_counter(); m_ac = scan(auto, test_data); s_times.append(time.perf_counter() - t1)
        z_ac, s_med = len(m_ac), statistics.median(s_times)
        tp_ac = (n_bytes / (1024 * 1024)) / s_med
        rows.append({"method": "Aho-Corasick", "k": k, "M": M, "build_med_s": statistics.median(b_times),
                     "scan_med_s": s_med, "scan_min_s": min(s_times), "scan_max_s": max(s_times),
                     "tp_mbs": tp_ac, "node_count": node_cnt, "mem_mb": mem_mb, "z": z_ac})
        if k <= 1000:
            nv_times = []
            for _ in range(repeats):
                t0 = time.perf_counter(); m_nv = naive(sigs, test_data); nv_times.append(time.perf_counter() - t0)
            nv_med = statistics.median(nv_times); assert z_ac == len(m_nv)
            rows.append({"method": "Naive", "k": k, "M": M, "build_med_s": 0.0, "scan_med_s": nv_med,
                         "scan_min_s": min(nv_times), "scan_max_s": max(nv_times), "tp_mbs": (n_bytes / (1024 * 1024)) / nv_med,
                         "node_count": 0, "mem_mb": 0.0, "z": len(m_nv)})
        else:
            rows.append({"method": "Naive", "k": k, "M": M, "build_med_s": "skipped", "scan_med_s": "skipped",
                         "scan_min_s": "skipped", "scan_max_s": "skipped", "tp_mbs": "skipped", "node_count": 0, "mem_mb": "skipped", "z": "skipped"})
        if has_pyac:
            A, test_str = ahocorasick.Automaton(), test_data.decode("latin-1")
            for idx, s in enumerate(sigs): A.add_word(s.decode("latin-1"), (idx, s))
            A.make_automaton()
            p_times = []
            for _ in range(repeats):
                t0 = time.perf_counter(); m_py = list(A.iter(test_str)); p_times.append(time.perf_counter() - t0)
            p_med = statistics.median(p_times)
            rows.append({"method": "pyahocorasick (C ref)", "k": k, "M": M, "build_med_s": 0.0, "scan_med_s": p_med,
                         "scan_min_s": min(p_times), "scan_max_s": max(p_times), "tp_mbs": (n_bytes / (1024 * 1024)) / p_med,
                         "node_count": -1, "mem_mb": -1, "z": len(m_py)})
        print(f"  k={k:6d} | AC Scan: {s_med:.3f}s ({tp_ac:.2f} MB/s) | Nodes: {node_cnt} | Mem: {mem_mb:.2f}MB")
    csv_path = os.path.join(out_dir, "e1.csv")
    headers = ["method", "k", "M", "build_med_s", "scan_med_s", "scan_min_s", "scan_max_s", "tp_mbs", "node_count", "mem_mb", "z"]
    with open(csv_path, "w", encoding="utf-8") as f:
        f.write(",".join(headers) + "\n" + "\n".join(",".join(str(r[h]) for h in headers) for r in rows) + "\n")
    print(f"[+] Saved {csv_path}")
    try:
        import matplotlib.pyplot as plt
        ac_pts = [r for r in rows if r["method"] == "Aho-Corasick"]
        plt.figure(figsize=(7, 4)); plt.plot([r["k"] for r in ac_pts], [r["scan_med_s"] for r in ac_pts], "o-", label="AC Scan (s)")
        nv_pts = [r for r in rows if r["method"] == "Naive" and r["scan_med_s"] != "skipped"]
        if nv_pts: plt.plot([r["k"] for r in nv_pts], [r["scan_med_s"] for r in nv_pts], "s-", label="Naive Scan (s)")
        plt.xscale("log"); plt.xlabel("Signatures (k)"); plt.ylabel("Time (s)"); plt.legend(); plt.tight_layout()
        plt.savefig(os.path.join(out_dir, "e1_scan_vs_k.png"), dpi=150); plt.close()
        plt.figure(figsize=(7, 4)); plt.plot([r["M"] / 1024 for r in ac_pts], [r["mem_mb"] for r in ac_pts], "o-", color="orange")
        plt.xlabel("Total Sig Length M (KB)"); plt.ylabel("Trie Peak Mem (MB)"); plt.tight_layout()
        plt.savefig(os.path.join(out_dir, "e1_mem_vs_M.png"), dpi=150); plt.close()
    except Exception as e: print(f"[-] matplotlib note: {e}")


def cmd_e2(quick: bool = False, out_dir: str = RESULTS_DIR, seed: int = 42):
    k, n_bytes, repeats = 1000, (4 * 1024 * 1024 if quick else 20 * 1024 * 1024), (2 if quick else 5)
    blocks = [("4 KB", 4096), ("64 KB", 65536), ("1 MB", 1048576), ("16 MB", 16777216), ("Whole file", -1)]
    write_env("e2", {"k": k, "n_bytes": n_bytes, "repeats": repeats, "blocks": [b[0] for b in blocks]}, seed, out_dir)
    print(f"\n--- EXPERIMENT E2: Chunk Streaming (File={n_bytes/(1024*1024):.1f}MB, k={k}) ---")
    sigs = make_signatures(k, seed=seed); auto = build(sigs)
    t_path = os.path.join(out_dir, "e2_test.bin")
    data, _ = make_data(n_bytes, signatures=sigs, plant=20, seed=seed)
    with open(t_path, "wb") as f: f.write(data)
    ref_matches = scan(auto, data)
    rows = []
    for name, b_sz in blocks:
        t_list, r_calls, all_equal = [], 0, True
        for _ in range(repeats):
            calls = 0
            def chunk_gen():
                nonlocal calls
                with open(t_path, "rb") as f:
                    while True:
                        c = f.read(b_sz if b_sz > 0 else -1)
                        if not c: break
                        calls += 1; yield c
            t0 = time.perf_counter(); m_res = scan_stream(auto, chunk_gen()); t_list.append(time.perf_counter() - t0)
            r_calls = calls
            if m_res != ref_matches: all_equal = False
        med_s = statistics.median(t_list); tp = (n_bytes / (1024 * 1024)) / med_s
        rows.append({"block": name, "bytes": b_sz if b_sz > 0 else n_bytes, "read_calls": r_calls,
                     "med_time_s": med_s, "tp_mbs": tp, "matches_equal": all_equal})
        print(f"  Block: {name:10s} | Reads: {r_calls:5d} | Time: {med_s:.3f}s | TP: {tp:.2f} MB/s | Equal: {all_equal}")
    if os.path.exists(t_path): os.remove(t_path)
    csv_path = os.path.join(out_dir, "e2.csv")
    headers = ["block", "bytes", "read_calls", "med_time_s", "tp_mbs", "matches_equal"]
    with open(csv_path, "w", encoding="utf-8") as f:
        f.write(",".join(headers) + "\n" + "\n".join(",".join(str(r[h]) for h in headers) for r in rows) + "\n")
    print(f"[+] Saved {csv_path}")
    try:
        import matplotlib.pyplot as plt
        plt.figure(figsize=(7, 4)); plt.bar([r["block"] for r in rows], [r["tp_mbs"] for r in rows], color="#0284c7")
        plt.ylabel("Throughput (MB/s)"); plt.title("Throughput vs Block Size"); plt.tight_layout()
        plt.savefig(os.path.join(out_dir, "e2_tp_vs_block.png"), dpi=150); plt.close()
    except Exception as e: print(f"[-] matplotlib note: {e}")


def scanner_worker(sigs: list[bytes], pipe):
    auto = build(sigs); pipe.send("READY")
    while True:
        try: req = pipe.recv()
        except EOFError: break
        if req is None: break
        req_id, path = req
        try:
            with open(path, "rb") as f:
                def gen():
                    while True:
                        c = f.read(65536)
                        if not c: break
                        yield c
                m = scan_stream(auto, gen())
            pipe.send((req_id, "DENY" if m else "ALLOW", len(m)))
        except Exception: pipe.send((req_id, "ERROR", 0))


def cmd_e3(quick: bool = False, out_dir: str = RESULTS_DIR, seed: int = 42):
    try: import psutil
    except ImportError: psutil = None
    ops_count, repeats = (60, 2) if quick else (300, 5)
    work_dir = os.path.join(out_dir, "workload"); os.makedirs(work_dir, exist_ok=True)
    write_env("e3", {"ops_count": ops_count, "repeats": repeats, "work_dir": work_dir}, seed, out_dir)
    print(f"\n--- EXPERIMENT E3: On-Access Pipeline (Ops={ops_count}, Repeats={repeats}) ---")
    sigs = make_signatures(k=100, seed=seed); sigs[0] = EICAR
    specs = [("cfg.json", 16384, False), ("auth.log", 32768, False), ("manifest.xml", 20480, False),
             ("dropper.bin", 24576, True), ("user.dat", 10240, False), ("hosts.txt", 12288, False),
             ("eicar.bin", len(EICAR), True), ("lib_a.dll", 256000, False), ("lib_b.dll", 307200, False),
             ("trojan.dll", 286720, True), ("font.ttf", 409600, False), ("locale.db", 460800, False),
             ("sys.bin", 1048576, False), ("db.dat", 1228800, False), ("malware.bin", 1126400, True),
             ("app_1.bin", 1536000, False), ("app_2.bin", 1843200, False), ("app_3.bin", 2048000, False)]
    files = []
    for name, sz, is_inf in specs:
        p = os.path.join(work_dir, name)
        d, _ = make_data(sz, signatures=sigs if is_inf else None, plant=5 if is_inf else 0, seed=seed + len(files))
        if is_inf and name == "eicar.bin": d = EICAR
        with open(p, "wb") as f: f.write(d)
        files.append((p, is_inf))
    for p, _ in files:
        try:
            with open(p, "rb") as f: _ = f.read()
        except OSError: pass

    import random
    rng = random.Random(seed); ops_seq = []
    for i in range(ops_count):
        if i in [15, 35, 55]: ops_seq.append(("MODIFY", rng.choice(files)[0]))
        ops_seq.append(("OPEN", rng.choice(files)))

    def safe_read(p):
        try:
            with open(p, "rb") as f: return f.read(128)
        except OSError: return b""

    modes_all, raw_runs = ["no_scan", "sync_every", "sync_cached", "async_scan"], []
    for r in range(repeats):
        for mode in modes_all[r % 4:] + modes_all[:r % 4]:
            p_conn, c_conn = mp.Pipe()
            proc = mp.Process(target=scanner_worker, args=(sigs, c_conn)); proc.start()
            assert p_conn.recv() == "READY"
            proc_ps = psutil.Process(proc.pid) if psutil else None
            cpu0 = proc_ps.cpu_times() if proc_ps else None

            open_lats, cache = [], {}
            cache_hits, cache_invalids, denied_cnt, inf_unscanned, inf_allowed, total_opens = 0, 0, 0, 0, 0, 0
            async_verdicts, stop_coll = {}, threading.Event()

            def collector():
                while not stop_coll.is_set():
                    if p_conn.poll(0.01):
                        try:
                            msg = p_conn.recv()
                            if msg: async_verdicts[msg[0]] = (msg[1], time.perf_counter())
                        except EOFError: break
            coll_t = threading.Thread(target=collector) if mode == "async_scan" else None
            if coll_t: coll_t.start()

            t_run_start = time.perf_counter()
            for op, arg in ops_seq:
                if op == "MODIFY":
                    try:
                        with open(arg, "ab") as f: f.write(b"mod")
                        os.utime(arg, None)
                    except OSError: pass
                    cache_invalids += 1; continue
                f_path, is_inf = arg; total_opens += 1; t0 = time.perf_counter()
                if mode == "no_scan":
                    safe_read(f_path)
                    open_lats.append((time.perf_counter() - t0) * 1000.0)
                    if is_inf: inf_unscanned += 1
                elif mode == "sync_every":
                    p_conn.send((total_opens, f_path)); _, v, _ = p_conn.recv()
                    if v == "DENY": denied_cnt += 1
                    else:
                        safe_read(f_path)
                        if is_inf: inf_allowed += 1
                    open_lats.append((time.perf_counter() - t0) * 1000.0)
                elif mode == "sync_cached":
                    try: st = os.stat(f_path); ck = (f_path, st.st_mtime, st.st_size)
                    except OSError: ck = (f_path, 0, 0)
                    if ck in cache: v = cache[ck]; cache_hits += 1
                    else:
                        p_conn.send((total_opens, f_path)); _, v, _ = p_conn.recv(); cache[ck] = v
                    if v == "DENY": denied_cnt += 1
                    else:
                        safe_read(f_path)
                        if is_inf: inf_allowed += 1
                    open_lats.append((time.perf_counter() - t0) * 1000.0)
                elif mode == "async_scan":
                    safe_read(f_path)
                    open_lats.append((time.perf_counter() - t0) * 1000.0); p_conn.send((total_opens, f_path))

            if mode == "async_scan":
                t_w0 = time.perf_counter()
                while len(async_verdicts) < total_opens and time.perf_counter() - t_w0 < 5.0: time.sleep(0.01)
                stop_coll.set(); coll_t.join(timeout=1.0)
                denied_cnt = sum(1 for v in async_verdicts.values() if v[0] == "DENY")

            t_run_total, cpu_s = time.perf_counter() - t_run_start, 0.0
            if proc_ps:
                try: cpu1 = proc_ps.cpu_times(); cpu_s = (cpu1.user - cpu0.user) + (cpu1.system - cpu0.system)
                except Exception: pass
            p_conn.send(None); proc.join(timeout=2.0)
            if proc.is_alive(): proc.terminate()
            raw_runs.append({"repeat": r + 1, "mode": mode, "total_opens": total_opens,
                             "mean_lat_ms": statistics.mean(open_lats),
                             "p95_lat_ms": sorted(open_lats)[int(len(open_lats) * 0.95)],
                             "total_time_s": t_run_total, "tp_ops_s": total_opens / t_run_total,
                             "scanner_cpu_s": cpu_s, "cache_hits": cache_hits, "cache_invalids": cache_invalids,
                             "denied_count": denied_cnt, "infected_opened_unscanned": inf_unscanned, "infected_allowed": inf_allowed})

    p_conn, c_conn = mp.Pipe()
    p_dead = mp.Process(target=scanner_worker, args=(sigs, c_conn)); p_dead.start(); _ = p_conn.recv(); p_dead.terminate(); p_dead.join()
    fail_rows = []
    for f_lbl, f_p, is_inf in [("clean_file", files[0][0], False), ("infected_file", [f[0] for f in files if f[1]][0], True)]:
        for pol in ["fail_open", "fail_closed"]:
            t0 = time.perf_counter()
            try: p_conn.send((999, f_p)); _ = p_conn.poll(0.2)
            except Exception: pass
            dt = (time.perf_counter() - t0) * 1000.0
            outc = "ALLOWED" if pol == "fail_open" else "DENIED"
            eff = ("SECURITY BREACH (Infected executed)" if is_inf else "Clean file available") if pol == "fail_open" else ("Threat blocked" if is_inf else "DENIAL OF SERVICE (Clean file blocked)")
            fail_rows.append({"file_type": f_lbl, "policy": pol, "decision_time_ms": f"{dt:.2f}", "outcome": outc, "security_effect": eff})

    with open(os.path.join(out_dir, "e3_failure.csv"), "w", encoding="utf-8") as f:
        f.write("file_type,policy,decision_time_ms,outcome,security_effect\n" + "\n".join(",".join(fr.values()) for fr in fail_rows) + "\n")

    med_rows = []
    for m in modes_all:
        mr = [r for r in raw_runs if r["mode"] == m]
        med_rows.append({"repeat": "median", "mode": m, "total_opens": mr[0]["total_opens"],
                         "mean_lat_ms": statistics.median(r["mean_lat_ms"] for r in mr),
                         "p95_lat_ms": statistics.median(r["p95_lat_ms"] for r in mr),
                         "total_time_s": statistics.median(r["total_time_s"] for r in mr),
                         "tp_ops_s": statistics.median(r["tp_ops_s"] for r in mr),
                         "scanner_cpu_s": statistics.median(r["scanner_cpu_s"] for r in mr),
                         "cache_hits": int(statistics.median(r["cache_hits"] for r in mr)),
                         "cache_invalids": int(statistics.median(r["cache_invalids"] for r in mr)),
                         "denied_count": int(statistics.median(r["denied_count"] for r in mr)),
                         "infected_opened_unscanned": int(statistics.median(r["infected_opened_unscanned"] for r in mr)),
                         "infected_allowed": int(statistics.median(r["infected_allowed"] for r in mr))})
        print(f"  Mode: {m:12s} | Mean Lat: {med_rows[-1]['mean_lat_ms']:.2f}ms | P95: {med_rows[-1]['p95_lat_ms']:.2f}ms | Denied: {med_rows[-1]['denied_count']}")

    csv_path = os.path.join(out_dir, "e3.csv")
    headers = ["repeat", "mode", "total_opens", "mean_lat_ms", "p95_lat_ms", "total_time_s", "tp_ops_s",
               "scanner_cpu_s", "cache_hits", "cache_invalids", "denied_count", "infected_opened_unscanned", "infected_allowed"]
    with open(csv_path, "w", encoding="utf-8") as f:
        f.write("# infected_opened_unscanned: count of infected files opened without inspection (no_scan mode)\n")
        f.write("# infected_allowed: count of infected files permitted by inspection (false negatives, 0 for AC)\n")
        f.write(",".join(headers) + "\n" + "\n".join(",".join(str(r[h]) if not isinstance(r[h], float) else f"{r[h]:.3f}" for h in headers) for r in raw_runs + med_rows) + "\n")
    print(f"[+] Saved {csv_path}")

    try:
        import matplotlib.pyplot as plt
        plt.figure(figsize=(7, 4)); m_names = [r["mode"] for r in med_rows]; x = range(len(m_names))
        plt.bar([p - 0.2 for p in x], [r["mean_lat_ms"] for r in med_rows], width=0.4, label="Mean (ms)", color="#0284c7")
        plt.bar([p + 0.2 for p in x], [r["p95_lat_ms"] for r in med_rows], width=0.4, label="P95 (ms)", color="#ef4444")
        plt.xticks(x, m_names); plt.yscale("log"); plt.ylabel("Latency (ms) [log]"); plt.legend(); plt.tight_layout()
        plt.savefig(os.path.join(out_dir, "e3_latency.png"), dpi=150); plt.close()
    except Exception as e: print(f"[-] matplotlib note: {e}")


def cmd_html(out_dir: str = RESULTS_DIR):
    def read_csv(fn):
        p = os.path.join(out_dir, fn)
        if not os.path.exists(p): return []
        lines = [l.strip() for l in open(p, encoding="utf-8") if l.strip() and not l.startswith("#")]
        return [dict(zip([h.strip() for h in lines[0].split(",")], [v.strip() for v in l.split(",")])) for l in lines[1:]] if lines else []

    def read_json(fn):
        p = os.path.join(out_dir, fn); return json.load(open(p, encoding="utf-8")) if os.path.exists(p) else None

    payload = {"demo": read_json("demo.json"), "e1": read_csv("e1.csv"),
               "e2": read_csv("e2.csv"), "e3": read_csv("e3.csv"), "e3_fail": read_csv("e3_failure.csv")}

    html = """<!DOCTYPE html><html><head><meta charset="UTF-8"><title>Aho-Corasick OS Simulation Dashboard</title>
<style>
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,monospace;background:#f8fafc;color:#0f172a;margin:0;padding:20px;}
.card{background:#fff;border:1px solid #e2e8f0;border-radius:8px;padding:16px;margin-bottom:18px;}
h1{font-size:20px;color:#0284c7;margin:0 0 6px 0;}h2{font-size:15px;border-bottom:1px solid #e2e8f0;padding-bottom:5px;margin:0 0 8px 0;}
.badge{display:inline-block;padding:2px 7px;border-radius:4px;font-size:11px;font-weight:600;}
.b-warn{background:#fef3c7;color:#92400e;}.b-ok{background:#dcfce7;color:#166534;}.b-fail{background:#fee2e2;color:#991b1b;}
.c-box{background:#f0f9ff;border-left:3px solid #0284c7;padding:8px 12px;font-size:12px;line-height:1.4;margin-bottom:10px;}
table{width:100%;border-collapse:collapse;font-size:12px;margin:8px 0;}th,td{border:1px solid #e2e8f0;padding:5px 7px;text-align:left;}
th{background:#f1f5f9;}tr.active-step{background:#e0f2fe;font-weight:600;}
.btn{background:#0284c7;color:#fff;border:none;padding:4px 10px;border-radius:4px;cursor:pointer;font-size:11px;}
svg{background:#fff;border:1px solid #e2e8f0;border-radius:4px;margin:6px 0;}
</style></head><body><div style="max-width:980px;margin:0 auto;">
<div class="card"><h1>Aho-Corasick Multi-Pattern Antivirus Simulation</h1><span class="badge b-warn">Educational user-space simulation. Not a real antivirus, not a kernel driver.</span></div>
<div class="card"><h2>1. Teaching Demonstration: "ushers" Trace</h2><div class="c-box"><b>What this shows:</b> Trie, failure links, output inheritance on ["he","she","his","hers"].<br><b>OS Concept:</b> Automaton state representation, failure jump paths, amortized O(1) state transitions.</div><div id="d-c"><em>Not run yet - run <code>python run.py demo</code></em></div></div>
<div class="card"><h2>2. Experiment E1: Signature Scaling</h2><div class="c-box"><b>What this shows:</b> Invariance of AC throughput as k scales vs Naive O(k*n) decay.<br><b>OS Concept:</b> Complexity decoupling from memory; Trie memory scaling.</div><div id="e1-c"><em>Not run yet - run <code>python run.py e1</code></em></div></div>
<div class="card"><h2>3. Experiment E2: Chunk Streaming & I/O Buffering</h2><div class="c-box"><b>What this shows:</b> Streaming scan across block sizes without backtracking or boundary misses.<br><b>OS Concept:</b> I/O buffering trade-offs: system call count vs buffer allocation.</div><div id="e2-c"><em>Not run yet - run <code>python run.py e2</code></em></div></div>
<div class="card"><h2>4. Experiment E3: On-Access Interception Pipeline</h2><div class="c-box"><b>What this shows:</b> Open latency across Sync, Cached, and Async interception modes.<br><b>OS Concept:</b> Blocking IPC, caching (path, mtime, size), race conditions, and Fail-Open vs Fail-Closed reliability.</div><div id="e3-c"><em>Not run yet - run <code>python run.py e3</code></em></div></div>
<div class="card"><h2>Simulation Limitations</h2><ul style="font-size:12px;color:#64748b;line-height:1.5;padding-left:18px;"><li><b>Python Overhead:</b> Pure Python loop limits speed; C/Rust engines run at gigabytes/sec.</li><li><b>User-Space Interception:</b> Real OS antivirus uses kernel minifilters / fanotify in ring 0.</li><li><b>Synthetic Data & Cache:</b> Random bytes and repeated reads reflect OS page cache benefits.</li></ul></div>
</div><script id="exp-d" type="application/json">""" + json.dumps(payload) + """</script>
<script>
const D=JSON.parse(document.getElementById('exp-d').textContent);
if(D.demo){
  let s=0;const t=D.demo.trace;
  document.getElementById('d-c').innerHTML=`<div style="margin-bottom:6px;"><button class="btn" onclick="pS()">Prev</button> <button class="btn" onclick="nS()">Next</button> <span style="margin-left:6px;font-size:11px;">Step <b id="s-l">1</b>/${t.length}</span></div><table><thead><tr><th>Pos</th><th>Char</th><th>State Transition</th><th>Fail Jumps</th><th>Matches</th></tr></thead><tbody>${t.map((r,i)=>`<tr id="r-${i}" class="${i===0?'active-step':''}"><td>${r.pos}</td><td>'${r.char}'</td><td>S${r.old_state}&rarr;S${r.new_state}</td><td>${r.fail_path}</td><td>${r.matches.map(m=>m.name).join(', ')||'-'}</td></tr>`).join('')}</tbody></table>`;
  window.nS=()=>{if(s<t.length-1){s++;uS();}};window.pS=()=>{if(s>0){s--;uS();}};
  function uS(){t.forEach((_,i)=>document.getElementById('r-'+i).className=(i===s?'active-step':''));document.getElementById('s-l').textContent=s+1;}
}
if(D.e1&&D.e1.length){
  const ac=D.e1.filter(r=>r.method==='Aho-Corasick'),maxTp=Math.max(...ac.map(r=>parseFloat(r.tp_mbs)||1));
  const pts=ac.map((r,i)=>`${70+i*140},${120-((parseFloat(r.tp_mbs)||0)/maxTp)*80}`).join(' ');
  document.getElementById('e1-c').innerHTML=`<table><thead><tr><th>Method</th><th>k</th><th>Total M</th><th>Scan (s)</th><th>Throughput (MB/s)</th><th>Trie Mem (MB)</th><th>Matches (z)</th></tr></thead><tbody>${D.e1.map(r=>`<tr><td>${r.method}</td><td>${r.k}</td><td>${r.M}</td><td>${r.scan_med_s}</td><td>${r.tp_mbs}</td><td>${r.mem_mb}</td><td>${r.z}</td></tr>`).join('')}</tbody></table>
  <svg width="500" height="150"><text x="10" y="18" font-size="11" fill="#64748b">AC Throughput (MB/s) vs k</text><polyline fill="none" stroke="#0284c7" stroke-width="2" points="${pts}" />${ac.map((r,i)=>`<circle cx="${70+i*140}" cy="${120-((parseFloat(r.tp_mbs)||0)/maxTp)*80}" r="3" fill="#0284c7" /><text x="${70+i*140}" y="140" font-size="10" text-anchor="middle">k=${r.k}</text><text x="${70+i*140}" y="${110-((parseFloat(r.tp_mbs)||0)/maxTp)*80}" font-size="10" text-anchor="middle">${parseFloat(r.tp_mbs).toFixed(1)}M/s</text>`).join('')}</svg>`;
}
if(D.e2&&D.e2.length){
  const eq=D.e2.every(r=>r.matches_equal==='True');
  document.getElementById('e2-c').innerHTML=`<span class="badge ${eq?'b-ok':'b-fail'}">Match sets identical across all block sizes: ${eq?'YES':'NO'}</span><table><thead><tr><th>Block Size</th><th>Read Calls</th><th>Median Time (s)</th><th>Throughput (MB/s)</th><th>Matches Equal</th></tr></thead><tbody>${D.e2.map(r=>`<tr><td>${r.block}</td><td>${r.read_calls}</td><td>${r.med_time_s}</td><td>${r.tp_mbs}</td><td>${r.matches_equal}</td></tr>`).join('')}</tbody></table>`;
}
if(D.e3&&D.e3.length){
  const med=D.e3.filter(r=>r.repeat==='median');
  document.getElementById('e3-c').innerHTML=`<table><thead><tr><th>Mode</th><th>Mean Latency (ms)</th><th>P95 Latency (ms)</th><th>Total Time (s)</th><th>Cache Hits</th><th>Denied</th><th>Infected Unscanned</th></tr></thead><tbody>${med.map(r=>`<tr><td><b>${r.mode}</b></td><td>${r.mean_lat_ms}</td><td>${r.p95_lat_ms}</td><td>${r.total_time_s}</td><td>${r.cache_hits}</td><td>${r.denied_count}</td><td>${r.infected_opened_unscanned}</td></tr>`).join('')}</tbody></table>
  ${D.e3_fail&&D.e3_fail.length?`<h3 style="font-size:13px;margin:10px 0 4px 0;">Scanner Daemon Failure Test</h3><table><thead><tr><th>File Type</th><th>Policy</th><th>Decision (ms)</th><th>Outcome</th><th>Result</th></tr></thead><tbody>${D.e3_fail.map(r=>`<tr><td>${r.file_type}</td><td><b>${r.policy}</b></td><td>${r.decision_time_ms}</td><td><span class="badge ${r.outcome==='ALLOWED'?'b-warn':'b-fail'}">${r.outcome}</span></td><td>${r.security_effect}</td></tr>`).join('')}</tbody></table>`:''}`;
}
</script></body></html>"""
    with open(os.path.join(out_dir, "dashboard.html"), "w", encoding="utf-8") as f: f.write(html)
    print(f"[+] Saved dashboard to {os.path.join(out_dir, 'dashboard.html')}")


def cmd_all(quick: bool = False, out_dir: str = RESULTS_DIR, seed: int = 42):
    sanity_check(); cmd_demo(out_dir, seed); cmd_e1(quick, out_dir, seed); cmd_e2(quick, out_dir, seed); cmd_e3(quick, out_dir, seed); cmd_html(out_dir)
    print(f"\n[+] All tasks finished. Dashboard: {os.path.join(out_dir, 'dashboard.html')}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Aho-Corasick OS Simulation")
    parser.add_argument("cmd", choices=["demo", "e1", "e2", "e3", "all", "html"])
    parser.add_argument("--quick", action="store_true")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--out-dir", type=str, default=RESULTS_DIR)
    args = parser.parse_args()

    if args.cmd == "demo": cmd_demo(args.out_dir, args.seed)
    elif args.cmd == "e1": cmd_e1(args.quick, args.out_dir, args.seed)
    elif args.cmd == "e2": cmd_e2(args.quick, args.out_dir, args.seed)
    elif args.cmd == "e3": cmd_e3(args.quick, args.out_dir, args.seed)
    elif args.cmd == "html": cmd_html(args.out_dir)
    elif args.cmd == "all": cmd_all(args.quick, args.out_dir, args.seed)
