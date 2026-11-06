#include "../include/atdoms.hpp"
#include "../include/knapsack_engine.hpp"
#include <chrono>

int main() {
    std::cout << "=== ATDOMS: PHASE 3 VERIFICATION (0/1 KNAPSACK ENGINE) ===" << std::endl;

    // The exact 6 alerts flagged by KMP in Phase 2 (Total Cost = 2500)
    std::vector<DetectedAlert> simulated_alerts = {
        {1, "SQLi: UNION SELECT", 1050, 85, 450},
        {3, "LFI: Directory Traversal", 25000, 95, 300},
        {5, "RCE: Command Shell", 50000, 98, 650},
        {6, "Buffer Overflow: NOP Sled", 95000, 100, 800},
        {7, "Overlap Test Pattern", 75000, 60, 150},
        {7, "Overlap Test Pattern", 75003, 60, 150}
    };

    const int RESOURCE_CEILING = 1500; // Strict CPU resource limit
    int total_demand = 0;
    for (const auto& a : simulated_alerts) total_demand += a.mitigation_cost;

    std::cout << "[*] Active Alerts Queued: " << simulated_alerts.size() << std::endl;
    std::cout << "[*] Total Mitigation Demand: " << total_demand << " cycles" << std::endl;
    std::cout << "[*] System Resource Ceiling: " << RESOURCE_CEILING << " cycles\n" << std::endl;

    auto start_time = std::chrono::high_resolution_clock::now();
    TriageResult triage = solveKnapsackTriage(simulated_alerts, RESOURCE_CEILING);
    auto end_time = std::chrono::high_resolution_clock::now();

    std::chrono::duration<double, std::milli> dp_time = end_time - start_time;

    std::cout << "--- OPTIMAL MITIGATION ACTION PLAN (SELECTED) ---" << std::endl;
    std::cout << std::left << std::setw(28) << "Threat Name" 
              << std::setw(12) << "Offset" 
              << std::setw(12) << "Severity" 
              << std::setw(10) << "Cost" << std::endl;
    std::cout << std::string(62, '-') << std::endl;

    for (const auto& alert : triage.mitigated_alerts) {
        std::cout << std::left << std::setw(28) << alert.threat_name
                  << std::setw(12) << alert.buffer_offset
                  << std::setw(12) << alert.severity_score
                  << std::setw(10) << alert.mitigation_cost << std::endl;
    }

    std::cout << "\n--- DROPPED / DEFERRED ALERTS (RESOURCE EXCEEDED) ---" << std::endl;
    for (const auto& alert : triage.dropped_alerts) {
        std::cout << " [x] " << std::left << std::setw(25) << alert.threat_name
                  << " (Severity: " << alert.severity_score 
                  << ", Cost: " << alert.mitigation_cost << ")" << std::endl;
    }

    std::cout << "\n[+] Total Severity Mitigated: " << triage.max_severity_mitigated << " (Optimal)" << std::endl;
    std::cout << "[+] Resource Capacity Utilized: " << triage.total_cost_used << " / " << RESOURCE_CEILING << " cycles" << std::endl;
    std::cout << "[+] Knapsack DP Execution Time: " << dp_time.count() << " ms\n" << std::endl;

    // Mathematical verification: Optimal subset for W=1500 is LFI(300) + RCE(650) + Overlap1(150) + Overlap2(150) = 1250 cost (313 val)
    // OR SQLi(450) + LFI(300) + RCE(650) = 1400 cost (278 val)
    // Wait: LFI(95, 300) + RCE(98, 650) + SQLi(85, 450) = 278 val, 1400 cost
    // LFI(95, 300) + RCE(98, 650) + Overlap(60, 150) + Overlap(60, 150) = 313 val, 1250 cost
    if (triage.max_severity_mitigated == 313 && triage.total_cost_used <= RESOURCE_CEILING) {
        std::cout << "[+] Mathematical Optimality & Ceiling Check: PASSED" << std::endl;
        std::cout << ">>> PHASE 3 READY. Move to Phase 4 (Full Pipeline & Benchmarking). <<<" << std::endl;
    } else {
        std::cout << "[-] Optimality check FAILED." << std::endl;
    }

    return 0;
}