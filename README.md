# ATDOMS: Automated Threat Detection and Optimal Resource Mitigation System

![C++](https://img.shields.io/badge/Language-C%2B%2B17-00599C?style=flat-square&logo=c%2B%2B)
![Domain](https://img.shields.io/badge/Domain-Cybersecurity%20%2F%20IDPS-red?style=flat-square)
![Course](https://img.shields.io/badge/Course-Design%20%26%20Analysis%20of%20Algorithms-blue?style=flat-square)
![Status](https://img.shields.io/badge/Build-Passing-brightgreen?style=flat-square)

**ATDOMS** is a high-performance, dual-phase Intrusion Detection and Prevention System (IDPS) prototype built in C++. Developed as a complex computing project for the *Design and Analysis of Algorithms (DAA)* course, it bridges linear-time string matching with dynamic programming optimization to detect malicious network payloads in real time and mathematically prioritize threat mitigation under strict server CPU constraints.

---

## Table of Contents
1. [Problem Statement](#1-problem-statement)
2. [Algorithmic Pipeline & Complexity Analysis](#2-algorithmic-pipeline--complexity-analysis)
3. [Project Directory Structure](#3-project-directory-structure)
4. [Installation & Build Instructions](#4-installation--build-instructions)
5. [Empirical Benchmark Results](#5-empirical-benchmark-results)
6. [Future Scope & Scalability](#6-future-scope--scalability)

---

## 1. Problem Statement

Modern network defense systems face two critical bottlenecks during high-volume cyber attacks:
1. **Detection Complexity Attacks:** Naive pattern-matching engines suffer from quadratic worst-case time complexity, allowing attackers to craft malicious packet streams that cause Denial of Service (DoS) via excessive backtracking.
2. **Resource Exhaustion During Triage:** Deep-packet sandboxing, connection resetting, and cryptographic verification consume significant CPU cycles. During a coordinated multi-vector attack, attempting to mitigate every flagged alert simultaneously can crash the defense server itself.

**ATDOMS** resolves both challenges by pipelining the **Knuth-Morris-Pratt (KMP)** string matching algorithm into a **0/1 Knapsack Dynamic Programming** triage engine.

---

## 2. Algorithmic Pipeline & Complexity Analysis

### Phase A: Real-Time Signature Detection (KMP Algorithm)
The ingestion engine captures raw network streams and scans them against a database of known exploit signatures (SQL Injection, Local File Inclusion, Remote Code Execution, XSS, and Buffer Overflow NOP sleds).

* **Mechanism:** Pre-computes a Longest Proper Prefix which is also a Suffix ($\text{LPS}$) array for each threat signature of length $m$. When scanning a network buffer of length $n$, the engine utilizes previous match states via $\text{j} = \text{LPS}[\text{j} - 1]$ to avoid backtracking the buffer index $i$.
* **Overlapping Payload Detection:** Modified to transition state immediately upon a complete match rather than resetting, accurately isolating overlapping exploit sequences (e.g., repeated buffer overflow sleds or nested patterns like `ABAABAABA`).
* **Time Complexity:** 
  $$\mathcal{O}(n + m) \text{ per signature} \implies \mathcal{O}\left(k \cdot (n + m)\right) \text{ for } k \text{ signatures}$$
* **Space Complexity:** 
  $$\mathcal{O}(m) \text{ auxiliary space for the LPS array}$$

### Phase B: Resource-Constrained Triage (0/1 Knapsack via Dynamic Programming)
When multiple threats are flagged within a single network window, each alert $i \in \{1, \dots, N\}$ carries a **Severity Score** ($v_i$, Profit) and a **Mitigation Cost** ($w_i$, Weight in CPU cycles). Given a strict server resource ceiling $W$, the system maximizes total mitigated severity.

* **Recurrence Relation:**
  $$DP[i][w] = \begin{cases} 
  DP[i-1][w] & \text{if } w_i > w \\
  \max\left(DP[i-1][w], \; v_i + DP[i-1][w - w_i]\right) & \text{if } w_i \le w 
  \end{cases}$$
* **Why DP over Greedy?** A greedy heuristic sorting by highest severity or best severity-to-cost ratio fails on discrete boundaries (e.g., selecting a single `800`-cycle Buffer Overflow alert can starve the CPU budget from mitigating three high-severity RCE/LFI alerts). Bottom-up tabulation guarantees the global mathematical optimum, followed by an $\mathcal{O}(N)$ backtracking pass to partition alerts into `[BLOCK]` and `[PASS]` action lists.
* **Time Complexity:** 
  $$\mathcal{O}(N \cdot W)$$
* **Space Complexity:** 
  $$\mathcal{O}(N \cdot W) \text{ for the 2D tabulation matrix}$$

---

## 3. Project Directory Structure

```text
ATDOMS/
├── include/
│   ├── atdoms.hpp          # Core data structures (ThreatSignature, DetectedAlert) & DB loader
│   ├── kmp_engine.hpp      # Phase 2 header: LPS computation & stream scanner declarations
│   └── knapsack_engine.hpp # Phase 3 header: TriageResult struct & DP solver declarations
├── src/
│   ├── kmp_engine.cpp      # KMP implementation with overlapping pattern support
│   ├── knapsack_engine.cpp # Bottom-up 0/1 Knapsack DP tabulation & backtracking logic
│   └── main.cpp            # Phase 4 full pipeline integration & real-time cycle simulator
├── tests/
│   ├── phase1_test.cpp     # Unit test: Threat DB initialization & 100KB payload generation
│   ├── phase2_test.cpp     # Unit test: KMP accuracy, byte-offset verification & overlaps
│   └── phase3_test.cpp     # Unit test: DP optimality verification under CPU ceiling
└── README.md               # Project documentation
```

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

All benchmarks were recorded using `std::chrono::high_resolution_clock` on a 64-bit Windows environment (MSYS2 UCRT64 GCC 16.2.0) with a stream buffer constraint of $\ge 100,000$ bytes and a server resource ceiling of $W = 1,500$ CPU cycles.

### Modular Phase Benchmarks
| Phase | Module Tested | Workload Parameters | Execution Time | Verification Outcome |
| :--- | :--- | :--- | :--- | :--- |
| **Phase 1** | Buffer Ingestion & DB Loader | $100,010\text{ bytes}$, $7\text{ signatures}$ | `0.2850 ms` | **PASSED** (Deterministic injection verified) |
| **Phase 2** | KMP Detection Engine | $100,010\text{ bytes} \times 7\text{ passes}$ | `38.7642 ms` | **PASSED** ($6\text{ alerts}$ found, including overlaps at offsets `75000` & `75003`) |
| **Phase 3** | 0/1 Knapsack DP Triage | $N = 6\text{ alerts}$, $W = 1,500\text{ cycles}$ | `0.5210 ms` | **PASSED** (Optimal Severity: `315`, Cost: `1400 / 1500` cycles) |

### Full Pipeline Real-Time Simulation (`atdoms_app.exe`)
During continuous stream inspection ($100,050\text{ bytes}$ per cycle, $5$ active exploits injected requiring $2,700$ total cycles), ATDOMS consistently achieved sub-40ms total processing latency—well below the $1,000\text{ ms}$ ($1\text{ second}$) real-time specification:

```text
--- [ CYCLE 1 ] ---
[KMP ENGINE] Scanned 100050 bytes. Found 5 threats in 37.6675 ms.
[DP ENGINE]  Mitigation plan formulated in 0.5418 ms.
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

## 6. Future Scope & Scalability

* **Multi-Pattern Automaton (Aho-Corasick):** Upgrade the KMP loop into a finite state machine using the Aho-Corasick algorithm to scan all $k$ signatures in a single pass over the buffer in $\mathcal{O}(n + m_{\text{total}} + z)$ time.
* **Space-Optimized Knapsack:** Compress the 2D DP table into a 1D rolling array with bitset tracking to reduce space complexity from $\mathcal{O}(N \cdot W)$ to $\mathcal{O}(W)$.
* **Topological Attack Graph Analysis:** Integrate Topological Sorting to model multi-stage dependency chains between alerts (e.g., prioritizing an initial privilege escalation exploit that unlocks downstream RCE payloads).
* **Live PCAP Ingestion:** Hook the ingestion buffer directly into `libpcap` / `WinPcap` to inspect live Ethernet frames on a local network interface.
