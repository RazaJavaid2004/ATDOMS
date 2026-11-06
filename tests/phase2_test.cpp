#include "../include/atdoms.hpp"
#include "../include/kmp_engine.hpp"
#include <chrono>

// Reusing the generator from Phase 1 for consistent testing
std::string generateSyntheticTraffic(size_t target_size) {
    std::string benign_chunk = "GET /index.html HTTP/1.1\r\nHost: 192.168.1.10\r\nUser-Agent: Mozilla/5.0\r\n\r\n";
    std::string buffer;
    buffer.reserve(target_size + 1024);
    while (buffer.size() < target_size) buffer += benign_chunk;

    buffer.replace(1050, 12, "UNION SELECT");
    buffer.replace(25000, 16, "../../etc/passwd");
    buffer.replace(50000, 10, "cmd.exe /c");
    buffer.replace(75000, 9, "ABAABAABA"); 
    buffer.replace(95000, 8, "\x90\x90\x90\x90\x90\x90\x90\x90");
    return buffer;
}

int main() {
    std::cout << "=== ATDOMS: PHASE 2 VERIFICATION (KMP ENGINE) ===" << std::endl;

    std::vector<ThreatSignature> db = loadThreatDatabase();
    std::string packet_stream = generateSyntheticTraffic(100000);
    std::vector<DetectedAlert> all_alerts;

    std::cout << "[*] Scanning " << packet_stream.size() << " bytes of network traffic...\n" << std::endl;

    auto start_time = std::chrono::high_resolution_clock::now();

    // Run KMP for every signature in the database
    for (const auto& threat : db) {
        std::vector<DetectedAlert> matches = kmpSearch(packet_stream, threat);
        all_alerts.insert(all_alerts.end(), matches.begin(), matches.end());
    }

    auto end_time = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double, std::milli> scan_time = end_time - start_time;

    std::cout << std::left << std::setw(30) << "Threat Detected" 
              << std::setw(15) << "Byte Offset" 
              << std::setw(10) << "Severity" << std::endl;
    std::cout << std::string(55, '-') << std::endl;

    for (const auto& alert : all_alerts) {
        std::cout << std::left << std::setw(30) << alert.threat_name
                  << std::setw(15) << alert.buffer_offset
                  << std::setw(10) << alert.severity_score << std::endl;
    }

    std::cout << "\n[+] Total Threats Found: " << all_alerts.size() << std::endl;
    std::cout << "[+] KMP Scan Execution Time: " << scan_time.count() << " ms\n" << std::endl;

    if (all_alerts.size() == 6) { 
        // 4 standard payloads + 2 overlapping instances of ABAABA
        std::cout << "[+] Overlapping detection and integrity check: PASSED" << std::endl;
        std::cout << ">>> PHASE 2 READY. Move to Phase 3 (Knapsack). <<<" << std::endl;
    } else {
        std::cout << "[-] Integrity check FAILED. Expected 6 alerts." << std::endl;
    }

    return 0;
}