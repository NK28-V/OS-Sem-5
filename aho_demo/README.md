# Aho-Corasick Multi-Pattern Antivirus Scanning Simulation

> **DISCLAIMER:**  
> **Educational user-space simulation. Not a real antivirus, not a kernel driver.**  
> This project is designed strictly for Operating Systems coursework to demonstrate multi-pattern string matching algorithms, asynchronous IPC, file caching, and I/O buffer management.

---

## 1. Quick Setup & Execution

### Prerequisites
- Python 3.10+ (Standard library only for core simulation)
- Optional dependencies: `psutil` (CPU tracking), `matplotlib` (PNG plotting), `pytest` (test runner)

```bash
# 1. Create virtual environment & activate
python -m venv .venv
# On Windows:
.venv\Scripts\activate
# On Linux/macOS:
source .venv/bin/activate

# 2. Install optional packages (pytest, psutil, matplotlib)
pip install pytest psutil matplotlib

# 3. Run unit tests
python -m pytest test_ac.py

# 4. Fast smoke run (validates all benchmarks in ~3 seconds)
python run.py all --quick

# 5. Full experiment execution
python run.py all

# 6. View interactive offline dashboard
# Double-click or open results/dashboard.html in any browser
```

---

## 2. File & Output Architecture

### Source Files (`aho_demo/`)
| File | Lines | Purpose |
| :--- | :--- | :--- |
| `ac.py` | ~142 | Aho-Corasick automaton, `bytes.find` naive baseline, full-alphabet seeded generator |
| `test_ac.py` | ~59 | Pytest test suite (200 random cases, suffix links, streaming boundary splits, EICAR) |
| `run.py` | ~449 | Unified CLI runner: demo, E1, E2, E3, environment capture, and HTML dashboard compiler |
| `README.md` | ~80 | Project specification, setup instructions, OS mapping, and limitations |

### Generated Artifacts (`results/`)
| Artifact | Type | Description |
| :--- | :--- | :--- |
| `demo.json` | JSON | Trie structure, BFS failure transitions, output sets, and "ushers" trace |
| `e1.csv` & PNGs | Data/Plot | Scaling metrics: build/scan time, memory, throughput vs signature count $k$ |
| `e2.csv` & PNG | Data/Plot | Throughput and system call count across block sizes (4 KB to 16 MB) |
| `e3.csv` & PNG | Data/Plot | Latency across 4 interception modes: No Scan, Sync, Cached, Async |
| `e3_failure.csv` | Data | Measured outcomes under scanner process failure (Fail-Open vs Fail-Closed) |
| `env_*.txt` | Text | Per-experiment OS, CPU, RAM, Python version, and execution environment |
| `dashboard.html` | Web | 100% self-contained offline dashboard with interactive SVG charts and demo trace |

---

## 3. Operating Systems Concepts Mapping

| Experiment | OS Concept Illustrated | Key Mechanism Analyzed |
| :--- | :--- | :--- |
| **Demo** | Finite Automata in Kernels | Amortized $O(1)$ state traversal per byte via failure links |
| **E1 (Signatures)** | Working Set & Memory Decoupling | Decoupling scan time from dictionary size $k$; Trie memory expansion ($M$) |
| **E2 (Streaming)** | I/O Buffering & System Calls | Context switch overhead in small blocks vs memory bandwidth in large chunks |
| **E3 (Pipeline)** | Real-Time Interception & IPC | Synchronous blocking vs Asynchronous vulnerability window; `(path, mtime, size)` caching |
| **E3 (Failure)** | Fault Tolerance & Security Policy | Fail-Open (availability over security) vs Fail-Closed (security over availability) |

---

## 4. Key Variables
- `n`: Total input length in bytes
- `k`: Number of loaded signatures
- `m`: Length of an individual signature
- `M`: Aggregate length of all signatures ($\sum m_i$)
- `z`: Total count of reported match occurrences

---

## 5. Measured Limitations & Confounding Factors
1. **Interpreted Python Overhead:** Scan throughput (~1–7 MB/s) is constrained by Python bytecode dispatch. Native C/Rust implementations achieve gigabytes/sec.
2. **User-Space Emulation:** Real-time AV intercepts I/O in kernel ring 0 via filesystem minifilter drivers (e.g. `FLTMGR.SYS` on Windows) or `fanotify` on Linux.
3. **Synthetic Signatures:** Random bytes uniformly distribute transitions; real malware opcodes exhibit distinct clustering.
4. **OS Page Cache & Host Antivirus:** Repeated file opens hit memory caches. Host AV (e.g., Windows Defender) may intercept or lock test files during execution.
...