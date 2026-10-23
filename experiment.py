"""
Aho-Corasick in Antivirus Scanning - the one experiment of the OS case study.

Question: how does scan time grow as the number of virus signatures (k) grows,
for four matching algorithms?

    Naive, KMP, Boyer-Moore : one pass over the file PER signature  -> k passes
    Aho-Corasick            : one automaton for all signatures       -> 1 pass

Run:   python experiment.py            (full run, a few minutes)
       python experiment.py --quick    (smoke test, well under a minute)

Output: results.html next to this file (opens in your browser automatically).
Python 3.9+, standard library only. Educational user-space simulation:
not a real antivirus and not a kernel driver.
"""

import argparse
import datetime
import html
import math
import os
import platform
import random
import statistics
import sys
import time
import tracemalloc
import webbrowser
from collections import deque

# ---------------------------------------------------------------- settings
SEED = 42                 # signatures use SEED, data uses SEED + 1000
SIG_MIN, SIG_MAX = 8, 32  # signature length in bytes
PLANTED = 10              # signatures copied into the data at known places
FULL = dict(n=1 << 19, ks=[10, 100, 1000, 10000, 100000], repeats=3, budget=120.0)
QUICK = dict(n=1 << 16, ks=[10, 100, 1000], repeats=1, budget=5.0)
ALGORITHMS = ["Aho-Corasick", "Naive", "KMP", "Boyer-Moore"]


# ---------------------------------------------------------------- test data
def make_signatures(k, seed=SEED):
    """k random byte strings of 8-32 bytes (the 'virus signatures')."""
    rng = random.Random(seed)
    return [bytes(rng.getrandbits(8) for _ in range(rng.randint(SIG_MIN, SIG_MAX)))
            for _ in range(k)]


def make_data(n, signatures, seed=SEED + 1000):
    """n random bytes with PLANTED signatures copied in at random offsets."""
    rng = random.Random(seed)
    data = bytearray(rng.getrandbits(8) for _ in range(n))
    for _ in range(min(PLANTED, len(signatures))):
        sig = signatures[rng.randrange(len(signatures))]
        pos = rng.randrange(n - len(sig))
        data[pos:pos + len(sig)] = sig
    return bytes(data)


# ---------------------------------------------------------------- 1. naive
def naive(signatures, data):
    """Try every start position, compare byte by byte. k passes."""
    found = []
    n = len(data)
    for sid, p in enumerate(signatures):
        m = len(p)
        first = p[0]
        for i in range(n - m + 1):
            if data[i] != first:
                continue
            j = 1
            while j < m and data[i + j] == p[j]:
                j += 1
            if j == m:
                found.append((i, sid))
    return sorted(found)


# ---------------------------------------------------------------- 2. KMP
def kmp_table(p):
    """fail[i] = length of the longest proper prefix of p[:i+1] that is also a suffix."""
    fail = [0] * len(p)
    q = 0
    for i in range(1, len(p)):
        while q and p[i] != p[q]:
            q = fail[q - 1]
        if p[i] == p[q]:
            q += 1
        fail[i] = q
    return fail


def kmp(signatures, data):
    """Knuth-Morris-Pratt: never moves backwards in the input. k passes."""
    found = []
    for sid, p in enumerate(signatures):
        fail = kmp_table(p)
        m = len(p)
        q = 0
        for i, c in enumerate(data):
            while q and c != p[q]:
                q = fail[q - 1]
            if c == p[q]:
                q += 1
                if q == m:
                    found.append((i - m + 1, sid))
                    q = fail[q - 1]
    return sorted(found)


# ---------------------------------------------------------------- 3. Boyer-Moore
def bm_tables(p):
    """Bad-character table and (strong) good-suffix shift table."""
    m = len(p)
    bad = [-1] * 256
    for i, c in enumerate(p):
        bad[c] = i
    shift = [0] * (m + 1)
    border = [0] * (m + 1)
    i, j = m, m + 1
    border[i] = j
    while i > 0:
        while j <= m and p[i - 1] != p[j - 1]:
            if shift[j] == 0:
                shift[j] = j - i
            j = border[j]
        i -= 1
        j -= 1
        border[i] = j
    j = border[0]
    for i in range(m + 1):
        if shift[i] == 0:
            shift[i] = j
        if i == j:
            j = border[j]
    return bad, shift


def boyer_moore(signatures, data):
    """Compare from the right end; skip ahead with bad-character / good-suffix rules. k passes."""
    found = []
    n = len(data)
    for sid, p in enumerate(signatures):
        m = len(p)
        bad, shift = bm_tables(p)
        s = 0
        while s <= n - m:
            j = m - 1
            while j >= 0 and p[j] == data[s + j]:
                j -= 1
            if j < 0:
                found.append((s, sid))
                s += shift[0]
            else:
                s += max(shift[j + 1], j - bad[data[s + j]])
    return sorted(found)


# ---------------------------------------------------------------- 4. Aho-Corasick
def ac_build(signatures):
    """Goto (trie), failure links (BFS) and outputs (merged along failure links)."""
    goto = [{}]
    out = [[]]
    for sid, p in enumerate(signatures):
        s = 0
        for c in p:
            nxt = goto[s].get(c)
            if nxt is None:
                nxt = len(goto)
                goto[s][c] = nxt
                goto.append({})
                out.append([])
            s = nxt
        out[s].append(sid)
    fail = [0] * len(goto)
    queue = deque(goto[0].values())
    while queue:
        r = queue.popleft()
        for c, s in goto[r].items():
            queue.append(s)
            f = fail[r]
            while f and c not in goto[f]:
                f = fail[f]
            fail[s] = goto[f].get(c, 0) if goto[f].get(c, 0) != s else 0
            out[s] = out[s] + out[fail[s]]
    lengths = [len(p) for p in signatures]
    return goto, fail, out, lengths


def ac_scan(automaton, data):
    """One pass over the data for all signatures: O(n + z)."""
    goto, fail, out, lengths = automaton
    found = []
    s = 0
    for i, c in enumerate(data):
        while s and c not in goto[s]:
            s = fail[s]
        s = goto[s].get(c, 0)
        if out[s]:
            for sid in out[s]:
                found.append((i - lengths[sid] + 1, sid))
    return sorted(found)


# ---------------------------------------------------------------- measuring
def median_time(fn, repeats):
    times, result = [], None
    for _ in range(repeats):
        t0 = time.perf_counter()
        result = fn()
        times.append(time.perf_counter() - t0)
    return statistics.median(times), result


def run(cfg):
    n, repeats, budget = cfg["n"], cfg["repeats"], cfg["budget"]
    sigs_all = make_signatures(max(cfg["ks"]))
    single = {"Naive": naive, "KMP": kmp, "Boyer-Moore": boyer_moore}
    rows = []
    last = {}  # algorithm -> (k, seconds) of its last completed run, for the skip estimate
    for k in cfg["ks"]:
        sigs = sigs_all[:k]
        data = make_data(n, sigs)
        M = sum(len(s) for s in sigs)
        row = {"k": k, "M": M, "time": {}, "z": {}}

        # Aho-Corasick: build time, memory (separate build-only pass), scan time
        t0 = time.perf_counter()
        auto = ac_build(sigs)
        row["build"] = time.perf_counter() - t0
        row["states"] = len(auto[0])
        del auto
        tracemalloc.start()
        auto = ac_build(sigs)
        row["mem_mb"] = tracemalloc.get_traced_memory()[1] / 1e6
        tracemalloc.stop()
        ac_scan(auto, data[: min(n, 1 << 14)])  # warm-up
        row["time"]["Aho-Corasick"], res = median_time(lambda: ac_scan(auto, data), repeats)
        row["z"]["Aho-Corasick"] = len(res)
        reference = res
        del auto
        print(f"k={k:>6}  Aho-Corasick  {row['time']['Aho-Corasick']:8.3f} s  "
              f"states={row['states']:,}  mem={row['mem_mb']:.1f} MB")

        # the three single-pattern algorithms (skip if the estimate is over budget)
        row["agree"] = True
        for name, fn in single.items():
            if name in last:
                k0, t_prev = last[name]
                estimate = t_prev * k / k0 * repeats
                if estimate > budget:
                    row["time"][name] = None
                    print(f"k={k:>6}  {name:<12}  skipped (estimated {estimate:,.0f} s)")
                    continue
            secs, res = median_time(lambda: fn(sigs, data), repeats)
            row["time"][name] = secs
            row["z"][name] = len(res)
            row["agree"] = row["agree"] and res == reference
            last[name] = (k, secs)
            print(f"k={k:>6}  {name:<12}  {secs:8.3f} s")
        rows.append(row)
    return rows


def environment(cfg):
    return {
        "Date": datetime.datetime.now().strftime("%Y-%m-%d %H:%M"),
        "OS": f"{platform.system()} {platform.release()} ({platform.version()})",
        "Python": f"{platform.python_version()} ({platform.architecture()[0]})",
        "CPU": platform.processor() or platform.machine(),
        "Logical cores": str(os.cpu_count()),
        "Input size n": f"{cfg['n']:,} bytes",
        "Repeats": f"{cfg['repeats']} (median reported)",
        "Seed": f"{SEED} (signatures), {SEED + 1000} (data)",
    }


# ---------------------------------------------------------------- HTML report
COLORS = {"Aho-Corasick": "#2a78d6", "Naive": "#eb6834", "KMP": "#1baf7a", "Boyer-Moore": "#eda100"}


def fmt_s(x):
    if x is None:
        return "skipped"
    return f"{x:.3f}" if x < 10 else f"{x:.1f}"


def line_chart(series, xlabel, ylabel, title):
    """Log-log SVG line chart. series: {name: [(x, y), ...]}."""
    W, H, L, R, T, B = 640, 360, 72, 120, 30, 50
    pts = [p for s in series.values() for p in s]
    xs = [p[0] for p in pts]
    ys = [p[1] for p in pts]
    x0, x1 = math.floor(math.log10(min(xs))), math.ceil(math.log10(max(xs)))
    y0, y1 = math.floor(math.log10(min(ys))), math.ceil(math.log10(max(ys)))
    x1 = max(x1, x0 + 1)
    y1 = max(y1, y0 + 1)
    px = lambda x: L + (math.log10(x) - x0) / (x1 - x0) * (W - L - R)
    py = lambda y: H - B - (math.log10(y) - y0) / (y1 - y0) * (H - T - B)
    g = [f'<svg viewBox="0 0 {W} {H}" role="img" aria-label="{html.escape(title)}">']
    for e in range(y0, y1 + 1):
        y = py(10 ** e)
        g.append(f'<line x1="{L}" x2="{W-R}" y1="{y:.1f}" y2="{y:.1f}" class="grid"/>')
        g.append(f'<text x="{L-8}" y="{y+4:.1f}" class="tick" text-anchor="end">{10**e:g}</text>')
    for e in range(x0, x1 + 1):
        x = px(10 ** e)
        g.append(f'<text x="{x:.1f}" y="{H-B+18}" class="tick" text-anchor="middle">{10**e:,.0f}</text>')
    g.append(f'<line x1="{L}" x2="{W-R}" y1="{H-B}" y2="{H-B}" class="axis"/>')
    g.append(f'<text x="{(L+W-R)/2:.0f}" y="{H-8}" class="lab" text-anchor="middle">{xlabel}</text>')
    g.append(f'<text transform="translate(16,{(T+H-B)/2:.0f}) rotate(-90)" class="lab" '
             f'text-anchor="middle">{ylabel}</text>')
    labels = []
    for name, s in series.items():
        if not s:
            continue
        c = COLORS.get(name, "#2a78d6")
        d = " ".join(f"{'M' if i == 0 else 'L'}{px(x):.1f},{py(y):.1f}" for i, (x, y) in enumerate(s))
        g.append(f'<path d="{d}" fill="none" stroke="{c}" stroke-width="2"/>')
        for x, y in s:
            g.append(f'<circle cx="{px(x):.1f}" cy="{py(y):.1f}" r="4.5" fill="{c}" '
                     f'stroke="var(--surface)" stroke-width="2"><title>{name}: '
                     f'{y:.4g} at {x:,}</title></circle>')
        lx, ly = s[-1]
        labels.append([py(ly) + 4, px(lx) + 10, name])
    # end-of-line labels: push apart vertically so they never overlap
    labels.sort()
    for i in range(1, len(labels)):
        if labels[i][1] == labels[i - 1][1] or abs(labels[i][1] - labels[i - 1][1]) < 80:
            labels[i][0] = max(labels[i][0], labels[i - 1][0] + 15)
    for y, x, name in labels:
        g.append(f'<text x="{x:.1f}" y="{y:.1f}" class="dl">{name}</text>')
    g.append("</svg>")
    return "".join(g)


def growth(row_a, row_b, name):
    a, b = row_a["time"].get(name), row_b["time"].get(name)
    return b / a if a and b else None


def build_html(rows, env, quick):
    timed = {a: [(r["k"], r["time"][a]) for r in rows if r["time"].get(a)] for a in ALGORITHMS}
    chart1 = line_chart(timed, "Number of signatures k (log)", "Median scan time, s (log)",
                        "Scan time versus number of signatures")
    chart2 = line_chart({"Aho-Corasick": [(r["M"], r["mem_mb"]) for r in rows]},
                        "Total signature length M, bytes (log)", "Automaton memory, MB (log)",
                        "Automaton memory versus M")

    # facts computed from the data (no hard-coded results)
    first, last = rows[0], rows[-1]
    facts = []
    ac_g = growth(first, last, "Aho-Corasick")
    if ac_g:
        facts.append(f"Aho-Corasick scan time grew <b>{ac_g:.1f}×</b> while k grew "
                     f"<b>{last['k'] // first['k']:,}×</b> ({first['k']:,} → {last['k']:,}).")
    for name in ["Naive", "KMP", "Boyer-Moore"]:
        done = [r for r in rows if r["time"].get(name)]
        if len(done) >= 2:
            g = growth(done[0], done[-1], name)
            facts.append(f"{name} grew <b>{g:.1f}×</b> for a {done[-1]['k'] // done[0]['k']:,}× "
                         f"increase in k (k = {done[0]['k']:,} → {done[-1]['k']:,}).")
    facts.append(f"Automaton memory reached <b>{last['mem_mb']:.1f} MB</b> at k = {last['k']:,} "
                 f"({last['states']:,} states).")
    all_agree = all(r["agree"] for r in rows)
    facts.append("All algorithms that ran found exactly the same matches." if all_agree
                 else "<b>Warning:</b> the algorithms did not all find the same matches.")

    head = "".join(f"<th>{h}</th>" for h in
                   ["k", "M (bytes)"] + [f"{a} (s)" for a in ALGORITHMS] +
                   ["AC states", "AC memory (MB)", "AC build (s)", "Matches z"])
    body = ""
    for r in rows:
        cells = [f"{r['k']:,}", f"{r['M']:,}"] + [fmt_s(r["time"].get(a)) for a in ALGORITHMS]
        cells += [f"{r['states']:,}", f"{r['mem_mb']:.1f}", f"{r['build']:.3f}",
                  f"{r['z']['Aho-Corasick']}"]
        body += "<tr>" + "".join(f"<td>{c}</td>" for c in cells) + "</tr>"
    env_rows = "".join(f"<tr><th>{html.escape(k)}</th><td>{html.escape(v)}</td></tr>"
                       for k, v in env.items())
    legend = "".join(f'<span class="key"><i style="background:{COLORS[a]}"></i>{a}</span>'
                     for a in ALGORITHMS)
    mode = " (quick run: smaller input, fewer repeats)" if quick else ""

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Signature Scaling Results</title>
<style>
:root {{ --surface:#fcfcfb; --ink:#1d1d1b; --ink2:#5d5c55; --line:#e4e3dd; --accent:#2952a1; }}
@media (prefers-color-scheme: dark) {{
  :root {{ --surface:#1a1a19; --ink:#f0efec; --ink2:#c3c2b7; --line:#3a3a37; --accent:#86b6ef; }}
}}
* {{ box-sizing:border-box; }}
body {{ margin:0; background:var(--surface); color:var(--ink);
  font:16px/1.55 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif; }}
main {{ max-width:1000px; margin:0 auto; padding:32px 16px 48px; }}
h1 {{ font-size:28px; margin:0 0 4px; color:var(--accent); }}
h2 {{ font-size:19px; margin:36px 0 10px; }}
.sub {{ color:var(--ink2); margin:0 0 20px; }}
.label {{ display:inline-block; border:1px solid var(--line); border-radius:6px;
  padding:2px 10px; font-size:13px; color:var(--ink2); }}
.box {{ border-left:4px solid var(--accent); background:color-mix(in srgb,var(--accent) 7%,transparent);
  padding:12px 16px; border-radius:4px; }}
.box ul {{ margin:6px 0 0; padding-left:20px; }}
.charts {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(300px,1fr)); gap:24px; }}
figure {{ margin:0; }} figcaption {{ font-size:14px; color:var(--ink2); margin-top:4px; }}
svg {{ width:100%; height:auto; overflow:visible; }}
.grid {{ stroke:var(--line); stroke-width:1; }} .axis {{ stroke:var(--ink2); stroke-width:1; }}
.tick {{ fill:var(--ink2); font-size:12px; }} .lab {{ fill:var(--ink2); font-size:13px; }}
.dl {{ fill:var(--ink); font-size:12px; }}
.legend {{ display:flex; flex-wrap:wrap; gap:16px; font-size:14px; margin:4px 0 8px; }}
.key i {{ display:inline-block; width:12px; height:12px; border-radius:3px; margin-right:6px;
  vertical-align:-1px; }}
.table-wrap {{ overflow-x:auto; }}
table {{ border-collapse:collapse; width:100%; font-size:14px; font-variant-numeric:tabular-nums; }}
th, td {{ padding:7px 10px; border-bottom:1px solid var(--line); text-align:right; white-space:nowrap; }}
th:first-child, td:first-child {{ text-align:left; }}
thead th {{ color:var(--ink2); font-weight:600; }}
.env th {{ text-align:left; color:var(--ink2); font-weight:500; width:160px; }}
.env td {{ text-align:left; white-space:normal; }}
footer {{ margin-top:36px; font-size:13px; color:var(--ink2); }}
</style></head>
<body><main>
<h1>Aho-Corasick in Antivirus Scanning</h1>
<p class="sub">How scan time grows with the number of virus signatures, for four algorithms{mode}.</p>
<span class="label">Educational user-space simulation. Not a real antivirus, not a kernel driver.</span>

<h2>What was measured</h2>
<div class="box">An antivirus checks every scanned file against k signatures. <b>Naive, KMP and
Boyer-Moore</b> search for one signature at a time, so they read the file k times.
<b>Aho-Corasick</b> puts all signatures into one automaton and reads the file once.
We scanned the same {env['Input size n']} of data for k = {', '.join(f'{r["k"]:,}' for r in rows)}.
A single-pattern algorithm is skipped when its estimated time would exceed the time budget.</div>

<h2>Result</h2>
<div class="box"><ul>{''.join(f'<li>{f}</li>' for f in facts)}</ul></div>

<h2>Charts</h2>
<div class="legend">{legend}</div>
<div class="charts">
<figure>{chart1}<figcaption>Scan time versus number of signatures (log-log). Steeper line = cost grows faster with k.</figcaption></figure>
<figure>{chart2}<figcaption>Aho-Corasick automaton memory versus total signature length M (log-log).</figcaption></figure>
</div>

<h2>Results table</h2>
<div class="table-wrap"><table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table></div>

<h2>Environment</h2>
<div class="table-wrap"><table class="env">{env_rows}</table></div>

<footer>All four algorithms are pure Python, so absolute times are slow; compare how the
times grow, not the absolute numbers. Single machine, synthetic random data,
{PLANTED} planted signatures. Results are written fresh on every run.</footer>
</main></body></html>"""


# ---------------------------------------------------------------- main
def self_check():
    """Quick correctness check on the classic example before measuring."""
    sigs = [b"he", b"she", b"his", b"hers"]
    expected = [(1, 1), (2, 0), (2, 3)]  # she at 1, he at 2, hers at 2 in "ushers"
    for name, res in [("Naive", naive(sigs, b"ushers")), ("KMP", kmp(sigs, b"ushers")),
                      ("Boyer-Moore", boyer_moore(sigs, b"ushers")),
                      ("Aho-Corasick", ac_scan(ac_build(sigs), b"ushers"))]:
        if res != expected:
            sys.exit(f"Self-check failed for {name}: {res}")
    print("Self-check passed: all four algorithms find she, he, hers in 'ushers'.")


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    ap.add_argument("--quick", action="store_true", help="small, fast smoke run")
    ap.add_argument("--no-open", action="store_true", help="do not open the browser")
    args = ap.parse_args()
    cfg = QUICK if args.quick else FULL
    self_check()
    rows = run(cfg)
    out = os.path.join(os.path.dirname(os.path.abspath(__file__)), "results.html")
    with open(out, "w", encoding="utf-8") as f:
        f.write(build_html(rows, environment(cfg), args.quick))
    print(f"\nResults written to {out}")
    if not args.no_open:
        webbrowser.open("file://" + out)


if __name__ == "__main__":
    main()
