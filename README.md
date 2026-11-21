# ATDOMS: Automated Threat Detection and Optimal Resource Mitigation System

<p align="left">
  <img src="https://img.shields.io/badge/Language-C%2B%2B17-00599C?style=flat-square&logo=c%2B%2B" alt="C++17" />
  <img src="https://img.shields.io/badge/Domain-Cybersecurity%20%2F%20IDPS-red?style=flat-square" alt="Cybersecurity / IDPS" />
  <img src="https://img.shields.io/badge/Course-Design%20%26%20Analysis%20of%20Algorithms-blue?style=flat-square" alt="DAA" />
  <img src="https://img.shields.io/badge/Build-Passing-brightgreen?style=flat-square" alt="Build Passing" />
  <img src="https://img.shields.io/badge/License-MIT-lightgrey?style=flat-square" alt="License" />
</p>

**ATDOMS** is a high-performance, dual-phase Intrusion Detection and Prevention System (IDPS) prototype built in C++17. Developed as a Complex Computing Project for the *Design and Analysis of Algorithms (DAA)* course, it bridges linear-time string matching with dynamic programming optimization to detect malicious network payloads in real time and mathematically prioritize threat mitigation under strict server CPU constraints.

> **Quick Access:** [Read Final Report (PDF)](docs/ATDOMS_CCP_Report.pdf) • [Editable Report (DOCX)](docs/ATDOMS_CCP_Report.docx) • [Jump to File Navigator](#file-navigator) • [Build & Run](#4-installation--build-instructions)

---

## Table of Contents

1. [Problem Statement](#1-problem-statement)
2. [Algorithmic Pipeline & Complexity Analysis](#2-algorithmic-pipeline--complexity-analysis)
3. [Project Directory Structure & File Navigator](#3-project-directory-structure--file-navigator)
4. [Installation & Build Instructions](#4-installation--build-instructions)
5. [Empirical Benchmark Results](#5-empirical-benchmark-results)
6. [Future Scope & Scalability](#6-future-scope--scalability)
7. [License](#7-license)

---

## 1. Problem Statement

Modern network defense systems face two critical bottlenecks during high-volume cyberattacks:

1. **Detection Complexity Attacks:** Naive pattern-matching engines suffer from quadratic worst-case time complexity ($\mathcal{O}(n \cdot m)$), allowing attackers to craft malicious packet streams that cause Denial of Service (DoS) via excessive backtracking.
2. **Resource Exhaustion During Triage:** Deep-packet sandboxing, connection resetting, and cryptographic verification consume significant CPU cycles. During a coordinated multi-vector attack, attempting to mitigate every flagged alert simultaneously can crash the defense server itself.

**ATDOMS** resolves both challenges by pipelining the **Knuth-Morris-Pratt (KMP)** string-matching algorithm into a **0/1 Knapsack Dynamic Programming** triage engine.

---

## 2. Algorithmic Pipeline & Complexity Analysis

### Phase A: Real-Time Signature Detection (KMP Algorithm)

The ingestion engine captures raw network streams and scans them against a database of known exploit signatures (SQL Injection, Local File Inclusion, Remote Code Execution, XSS, and Buffer Overflow NOP sleds).

* **Mechanism:** Pre-computes a Longest Proper Prefix which is also a Suffix ($\text{LPS}$) array for each threat signature of length $m$. When scanning a network buffer of length $n$, the engine uses previous match states via $j = \text{LPS}[j - 1]$ to avoid backtracking the buffer index $i$.
* **Overlapping Payload Detection:** Modified to transition state immediately upon a complete match rather than resetting $j = 0$, accurately isolating overlapping exploit sequences (e.g., nested patterns like `ABAABAABA`).
* **Time Complexity:**
  $$\mathcal{O}(n + m) \text{ per signature} \implies \mathcal{O}\left(k \cdot (n + m)\right) \text{ for } k \text{ signatures}$$
* **Space Complexity:**
  $$\mathcal{O}(m) \text{ auxiliary space for the LPS array}$$

### Phase B: Resource-Constrained Triage (0/1 Knapsack via Dynamic Programming)

When multiple threats are flagged within a single network window, each alert $i \in \{1, \dots, N\}$ carries a **Severity Score** ($v_i$, Profit) and a **Mitigation Cost** ($w_i$, Weight in CPU cycles). Given a strict server resource ceiling $W$, the system maximizes total mitigated severity.

* **Recurrence Relation:**
  $$DP[i][w] = \begin{cases} DP[i-1][w] & \text{if } w_i > w \\ \max\left(DP[i-1][w], \; v_i + DP[i-1][w - w_i]\right) & \text{if } w_i \le w \end{cases}$$
* **Why DP over Greedy?** A greedy heuristic sorting by highest severity or best severity-to-cost ratio fails on discrete boundaries (e.g., selecting a single `800`-cycle Buffer Overflow alert can starve the CPU budget from mitigating three high-severity SQLi/LFI/RCE alerts). Bottom-up tabulation guarantees the global mathematical optimum, followed by an $\mathcal{O}(N)$ backtracking pass to partition alerts into `[BLOCK]` and `[PASS]` action lists.
* **Time Complexity:**
  $$\mathcal{O}(N \cdot W)$$
* **Space Complexity:**
  $$\mathcal{O}(N \cdot W) \text{ for the 2D tabulation matrix}$$

---

## 3. Project Directory Structure & File Navigator

### Directory Tree

```text
ATDOMS/
├── docs/
│   ├── ATDOMS_CCP_Report.docx   # Editable Complex Computing Project final report
│   └── ATDOMS_CCP_Report.pdf    # Final formatted PDF report with benchmarks & diagrams
├── include/
│   ├── atdoms.hpp               # Core structs (ThreatSignature, DetectedAlert) & DB loader
│   ├── kmp_engine.hpp           # Phase 2 header: LPS computation & stream scanner API
│   └── knapsack_engine.hpp      # Phase 3 header: TriageResult struct & DP solver API
├── src/
│   ├── kmp_engine.cpp           # KMP implementation with overlapping pattern support
│   ├── knapsack_engine.cpp      # Bottom-up 0/1 Knapsack DP tabulation & backtracking
│   └── main.cpp                 # Phase 4 full pipeline integration & cycle simulator
├── tests/
│   ├── phase1_test.cpp          # Unit test: Threat DB & 100KB synthetic buffer generator
│   ├── phase2_test.cpp          # Unit test: KMP accuracy, byte offsets & overlaps
│   └── phase3_test.cpp          # Unit test: DP optimality & CPU ceiling verification
├── .gitattributes               # Git line-ending & diff attributes
├── .gitignore                   # Build artifacts, binaries & IDE ignore rules
├── LICENSE                      # Project license
└── README.md                    # Project documentation
```

### File Navigator

Use the table below to jump directly to any source file, test suite, or project document:

| Category | File | Description |
| :--- | :--- | :--- |
| **Documentation** | [`docs/ATDOMS_CCP_Report.pdf`](docs/ATDOMS_CCP_Report.pdf) | Final formatted CCP report (architecture, proofs, screenshots, annexure) |
| **Documentation** | [`docs/ATDOMS_CCP_Report.docx`](docs/ATDOMS_CCP_Report.docx) | Editable Word version of the final CCP report |
| **Headers** | [`include/atdoms.hpp`](include/atdoms.hpp) | `ThreatSignature`, `DetectedAlert`, and `loadThreatDatabase()` |
| **Headers** | [`include/kmp_engine.hpp`](include/kmp_engine.hpp) | Declarations for `computeLPSArray()` and `kmpSearch()` |
| **Headers** | [`include/knapsack_engine.hpp`](include/knapsack_engine.hpp) | `TriageResult` struct and `solveKnapsackTriage()` declaration |
| **Core Source** | [`src/kmp_engine.cpp`](src/kmp_engine.cpp) | Linear-time KMP matcher with overlapping signature detection |
| **Core Source** | [`src/knapsack_engine.cpp`](src/knapsack_engine.cpp) | Bottom-up 0/1 Knapsack DP solver and $\mathcal{O}(N)$ state backtracking |
| **Core Source** | [`src/main.cpp`](src/main.cpp) | Integrated 3-cycle real-time stream simulator and benchmarker |
| **Verification** | [`tests/phase1_test.cpp`](tests/phase1_test.cpp) | Phase 1 test: Threat dictionary & $\ge 100,000$-byte stream generation |
| **Verification** | [`tests/phase2_test.cpp`](tests/phase2_test.cpp) | Phase 2 test: Exact offset matching & `ABAABA` overlap verification |
| **Verification** | [`tests/phase3_test.cpp`](tests/phase3_test.cpp) | Phase 3 test: Mathematical optimality (`315`) & ceiling check (`1500`) |
| **Config & Meta** | [`.gitignore`](.gitignore) • [`.gitattributes`](.gitattributes) • [`LICENSE`](LICENSE) | Repository configuration and licensing |

---

## 4. Installation & Build Instructions

### Prerequisites

* A C++17 compliant compiler (`g++` via MinGW-w64 / MSYS2 UCRT64 on Windows, or standard `gcc` / `clang` on Linux/macOS).

### 1. Run Individual Phase Verification Tests

From the root `ATDOMS/` directory, compile and execute any phase test to verify modular integrity:

```bash
# Phase 1: Data Structures & Synthetic Traffic Generator (>= 100,000 bytes)
g++ -std=c++17 -O2 tests/phase1_test.cpp -o phase1_test
./phase1_test

# Phase 2: KMP Detection Engine & Overlapping Match Verification
g++ -std=c++17 -O2 tests/phase2_test.cpp src/kmp_engine.cpp -o phase2_test
./phase2_test

# Phase 3: 0/1 Knapsack Triage Engine Mathematical Optimality Test
g++ -std=c++17 -O2 tests/phase3_test.cpp src/knapsack_engine.cpp -o phase3_test
./phase3_test
```

### 2. Build and Run the Full ATDOMS Pipeline

Compile the complete integrated system with `-O2` optimization enabled:

```bash
g++ -std=c++17 -O2 src/main.cpp src/kmp_engine.cpp src/knapsack_engine.cpp -o atdoms_app
./atdoms_app
```

---

## 5. Empirical Benchmark Results

All benchmarks were recorded using `std::chrono::high_resolution_clock` on a 64-bit Windows environment (MSYS2 UCRT64 GCC 16.2.0, `-std=c++17 -O2`) with a stream buffer constraint of $\ge 100,000$ bytes and a server resource ceiling of $W = 1,500$ CPU cycles.

### Modular Phase Benchmarks

| Phase | Module Tested | Workload Parameters | Execution Time | Verification Outcome |
| :--- | :--- | :--- | :--- | :--- |
| **Phase 1** | Buffer Ingestion & DB Loader | $100,010\text{ bytes}$, $7\text{ signatures}$ | `0.1407 ms` | **PASSED** (Deterministic injection verified) |
| **Phase 2** | KMP Detection Engine | $100,010\text{ bytes} \times 7\text{ passes}$ | `2.3478 ms` | **PASSED** ($6\text{ alerts}$ found; overlaps at `75000` & `75003`) |
| **Phase 3** | 0/1 Knapsack DP Triage | $N = 6\text{ alerts}$, $W = 1,500\text{ cycles}$ | `0.1113 ms` | **PASSED** (Optimal Severity: `315`, Cost: `1400 / 1500` cycles) |

### Full Pipeline Real-Time Simulation (`atdoms_app`)

Across 3 continuous inspection cycles ($100,050\text{ bytes}$ per cycle, $5$ active exploits injected requiring $2,700$ total cycles), ATDOMS averaged **`2.8695 ms`** for KMP scanning and **`0.0907 ms`** for DP triage (**`2.9602 ms`** total latency—well below the $1,000\text{ ms}$ real-time limit):

| Cycle | Buffer Size | Threats Found | KMP Time | DP Triage Time | Total Latency | Severity Mitigated | Resources Used |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Cycle 1** | $100,050\text{ B}$ | $5$ | `1.8603 ms` | `0.1094 ms` | `1.9697 ms` | `283` | `1450 / 1500` |
| **Cycle 2** | $100,050\text{ B}$ | $5$ | `3.4601 ms` | `0.1367 ms` | `3.5968 ms` | `283` | `1450 / 1500` |
| **Cycle 3** | $100,050\text{ B}$ | $5$ | `3.2880 ms` | `0.0261 ms` | `3.3141 ms` | `283` | `1450 / 1500` |
| **Average** | $100,050\text{ B}$ | $5$ | **`2.8695 ms`** | **`0.0907 ms`** | **`2.9602 ms`** | **`283`** | **`1450 / 1500`** |

```text
--- [ CYCLE 1 ] ---
[KMP ENGINE] Scanned 100050 bytes. Found 5 threats in 1.8603 ms.
[DP ENGINE]  Mitigation plan formulated in 0.1094 ms.
             Severity Mitigated: 283
             Resources Used:     1450 / 1500

  -> Actioning Mitigations:
     [BLOCK] SQLi: DROP TABLE (Offset: 90000)
     [BLOCK] LFI: Directory Traversal (Offset: 45000)
     [BLOCK] RCE: Command Shell (Offset: 5000)
  -> Dropped due to Resource Limits:
     [PASS]  SQLi: UNION SELECT (Requires 450 cycles)
     [PASS]  Buffer Overflow: NOP Sled (Requires 800 cycles)
```

---

## 6. Future Scope & Scalability 🔬

* **Multi-Pattern Automaton (Aho-Corasick):** Upgrade the KMP loop into a finite state machine using the Aho-Corasick algorithm to scan all $k$ signatures in a single pass over the buffer in $\mathcal{O}(n + m_{\text{total}} + z)$ time.
* **Space-Optimized Knapsack:** Compress the 2D DP table into a 1D rolling array with bitset tracking to reduce space complexity from $\mathcal{O}(N \cdot W)$ to $\mathcal{O}(W)$.
* **Topological Attack Graph Analysis:** Integrate Topological Sorting to model multi-stage dependency chains between alerts (e.g., prioritizing an initial privilege escalation exploit that unlocks downstream RCE payloads).
* **Live PCAP Ingestion:** Hook the ingestion buffer directly into `libpcap` / `WinPcap` to inspect live Ethernet frames on a local network interface.

---

## 7. License

This project is licensed under the terms of the [LICENSE](LICENSE) file in this repository.
