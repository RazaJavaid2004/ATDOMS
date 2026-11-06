#include "../include/atdoms.hpp"
#include <chrono>

// Generates a large synthetic packet stream >= 100,000 characters
std::string generateSyntheticTraffic(size_t target_size) {
    std::string benign_chunk = "GET /index.html HTTP/1.1\r\nHost: 192.168.1.10\r\nUser-Agent: Mozilla/5.0\r\n\r\n";
    std::string buffer;
    buffer.reserve(target_size + 1024);

    while (buffer.size() < target_size) {
        buffer += benign_chunk;
    }

    // Deterministically inject malicious signatures at known offsets for verification
    buffer.replace(1050, 12, "UNION SELECT");
    buffer.replace(25000, 16, "../../etc/passwd");
    buffer.replace(50000, 10, "cmd.exe /c");
    buffer.replace(75000, 9, "ABAABAABA"); // Contains two overlapping "ABAABA" patterns (at 75000 and 75003)
    buffer.replace(95000, 8, "\x90\x90\x90\x90\x90\x90\x90\x90");

    return buffer;
}

int main() {
    std::cout << "=== ATDOMS: PHASE 1 VERIFICATION ===" << std::endl;

    // 1. Test Threat Database Loading
    std::vector<ThreatSignature> db = loadThreatDatabase();
    std::cout << "[+] Loaded Threat Signatures: " << db.size() << "\n\n";

    std::cout << std::left << std::setw(5) << "ID" 
              << std::setw(28) << "Threat Name" 
              << std::setw(12) << "Severity" 
              << std::setw(10) << "Cost" << std::endl;
    std::cout << std::string(55, '-') << std::endl;

    for (const auto& sig : db) {
        std::cout << std::left << std::setw(5) << sig.id
                  << std::setw(28) << sig.name
                  << std::setw(12) << sig.severity_score
                  << std::setw(10) << sig.mitigation_cost << std::endl;
    }

    // 2. Test Synthetic Traffic Generation Constraint (>= 100,000 chars)
    const size_t REQUIRED_BUFFER_SIZE = 100000;
    auto start_time = std::chrono::high_resolution_clock::now();
    std::string packet_stream = generateSyntheticTraffic(REQUIRED_BUFFER_SIZE);
    auto end_time = std::chrono::high_resolution_clock::now();

    std::chrono::duration<double, std::milli> gen_time = end_time - start_time;

    std::cout << "\n[+] Traffic Buffer Generated Successfully." << std::endl;
    std::cout << "    -> Buffer Size: " << packet_stream.size() << " bytes (Constraint: >= 100,000 bytes)" << std::endl;
    std::cout << "    -> Generation Time: " << gen_time.count() << " ms" << std::endl;

    // 3. Verify Injection Integrity
    if (packet_stream.substr(1050, 12) == "UNION SELECT" && 
        packet_stream.substr(75000, 9) == "ABAABAABA") {
        std::cout << "[+] Payload Injection Verification: PASSED" << std::endl;
        std::cout << "\n>>> PHASE 1 READY. Compile and run to verify. <<<" << std::endl;
    } else {
        std::cout << "[-] Payload Injection Verification: FAILED" << std::endl;
    }

    return 0;
}