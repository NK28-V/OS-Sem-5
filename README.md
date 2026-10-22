# OS-Sem-5 Simulation Repository

> **Educational user-space simulation. Not a real antivirus, not a kernel driver.**

## Overview
This project demonstrates multi‑pattern string‑matching algorithms (Naive, KMP, Boyer‑Moore, Aho‑Corasick) and their impact on OS‑level concepts such as I/O buffering, caching, and real‑time interception.

## Quick Setup & Execution
1. **Prerequisites**
   - Python 3.10+ (standard library only for core simulation)
   - Optional: `psutil`, `matplotlib`, `pytest`
2. **Create and activate a virtual environment**
   ```bash
   python -m venv .venv
   .venv\\Scripts\\activate  # Windows
   # source .venv/bin/activate  # Unix
   ```
3. **Install optional packages** (if you want testing or plots)
   ```bash
   pip install pytest psutil matplotlib
   ```
4. **Run unit tests**
   ```bash
   python -m pytest aho_demo/test_ac.py
   ```
5. **Run the full benchmark suite** (quick version ~3 s)
   ```bash
   cd aho_demo
   python run.py all --quick
   ```
6. **Run the full experiments (no `--quick` flag)**
   ```bash
   python run.py all
   ```
7. **View results**
   - All generated artifacts are placed in `aho_demo/results/`.
   - Open `aho_demo/results/dashboard.html` in any browser for an interactive offline dashboard.
   - CSV files (`e1a.csv`, `e2.csv`, `e3.csv`, …) contain raw data for further analysis.

## Repository Hygiene
- `.gitignore` excludes caches, compiled byte‑code, virtual environments, and large workload files.
- All `__pycache__/` files and the `aho_demo/results/workload/` directory are untracked.

## License & Attribution
This is a teaching project; feel free to fork and modify for educational purposes.
