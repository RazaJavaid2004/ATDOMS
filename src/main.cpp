#include "../include/atdoms.hpp"
#include "../include/kmp_engine.hpp"
#include "../include/knapsack_engine.hpp"
#include <chrono>
#include <thread>

// Simulates continuous network traffic ingestion
std::string captureNetworkBuffer(size_t chunk_size) {
    std::string benign_chunk = "GET /api/status HTTP/1.1\r\nHost: 10.0.0.5\r\nUser-Agent: curl/7.68.0\r\n\r\n";
    std::string buffer;
    buffer.reserve(chunk_size + 1024);
    
    while (buffer.size() < chunk_size) {
        buffer += benign_chunk;
    }

    // Inject scattered threats
    buffer.replace(5000, 10, "cmd.exe /c");
    buffer.replace(15000, 12, "UNION SELECT");
    buffer.replace(45000, 16, "../../etc/passwd");
    buffer.replace(80000, 8, "\x90\x90\x90\x90\x90\x90\x90\x90");
    buffer.replace(90000, 10, "DROP TABLE");
    
    return buffer;
}

int main() {
    std::cout << "==========================================================" << std::endl;
    std::cout << "  ATDOMS: Automated Threat Detection & Optimal Mitigation " << std::endl;
    std::cout << "==========================================================\n" << std::endl;

    std::vector<ThreatSignature> db = loadThreatDatabase();
    const int RESOURCE_CEILING = 1500;
    const size_t BUFFER_CHUNK_SIZE = 100000; // 100KB per scan cycle

    std::cout << "[*] Threat Database Loaded (" << db.size() << " signatures)." << std::endl;
    std::cout << "[*] System Resource Ceiling set to " << RESOURCE_CEILING << " cycles." << std::endl;
    std::cout << "[*] Beginning Real-Time Stream Inspection...\n" << std::endl;

    // Simulate 3 network cycles
    for (int cycle = 1; cycle <= 3; cycle++) {
        std::cout << "\n--- [ CYCLE " << cycle << " ] ---" << std::endl;
        
        // 1. Ingestion
        std::string buffer = captureNetworkBuffer(BUFFER_CHUNK_SIZE);
        std::vector<DetectedAlert> active_alerts;

        // 2. Detection (KMP)
        auto start_kmp = std::chrono::high_resolution_clock::now();
        for (const auto& threat : db) {
            std::vector<DetectedAlert> matches = kmpSearch(buffer, threat);
            active_alerts.insert(active_alerts.end(), matches.begin(), matches.end());
        }
        auto end_kmp = std::chrono::high_resolution_clock::now();
        std::chrono::duration<double, std::milli> kmp_time = end_kmp - start_kmp;

        std::cout << "[KMP ENGINE] Scanned " << buffer.size() << " bytes. Found " 
                  << active_alerts.size() << " threats in " << kmp_time.count() << " ms." << std::endl;

        // 3. Triage (Knapsack)
        if (!active_alerts.empty()) {
            auto start_dp = std::chrono::high_resolution_clock::now();
            TriageResult triage = solveKnapsackTriage(active_alerts, RESOURCE_CEILING);
            auto end_dp = std::chrono::high_resolution_clock::now();
            std::chrono::duration<double, std::milli> dp_time = end_dp - start_dp;

            std::cout << "[DP ENGINE]  Mitigation plan formulated in " << dp_time.count() << " ms." << std::endl;
            std::cout << "             Severity Mitigated: " << triage.max_severity_mitigated << std::endl;
            std::cout << "             Resources Used:     " << triage.total_cost_used << " / " << RESOURCE_CEILING << std::endl;
            
            std::cout << "\n  -> Actioning Mitigations:" << std::endl;
            for (const auto& alert : triage.mitigated_alerts) {
                std::cout << "     [BLOCK] " << alert.threat_name << " (Offset: " << alert.buffer_offset << ")" << std::endl;
            }

            if (!triage.dropped_alerts.empty()) {
                std::cout << "  -> Dropped due to Resource Limits:" << std::endl;
                for (const auto& alert : triage.dropped_alerts) {
                    std::cout << "     [PASS]  " << alert.threat_name << " (Requires " << alert.mitigation_cost << " cycles)" << std::endl;
                }
            }
        }
        
        // Brief pause to simulate network wait time before next packet chunk
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }

    std::cout << "\n==========================================================" << std::endl;
    std::cout << " System Shutdown. All network buffers processed." << std::endl;
    std::cout << "==========================================================" << std::endl;

    return 0;
}