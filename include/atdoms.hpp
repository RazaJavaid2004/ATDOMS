#ifndef ATDOMS_HPP
#define ATDOMS_HPP

#include <string>
#include <vector>
#include <iostream>
#include <iomanip>

// Represents a known malicious signature in our database
struct ThreatSignature {
    int id;
    std::string name;
    std::string pattern;
    int severity_score;   // Knapsack Value (Profit)
    int mitigation_cost;  // Knapsack Weight (CPU cycles/Resource cost)
};

// Represents an active threat flagged inside the network buffer
struct DetectedAlert {
    int signature_id;
    std::string threat_name;
    size_t buffer_offset; // Exact byte index where KMP found the threat
    int severity_score;
    int mitigation_cost;
};

// Initializes the static threat dictionary
inline std::vector<ThreatSignature> loadThreatDatabase() {
    return {
        {1, "SQLi: UNION SELECT", "UNION SELECT", 85, 450},
        {2, "SQLi: DROP TABLE", "DROP TABLE", 90, 500},
        {3, "LFI: Directory Traversal", "../../etc/passwd", 95, 300},
        {4, "XSS: Script Injection", "<script>alert", 70, 200},
        {5, "RCE: Command Shell", "cmd.exe /c", 98, 650},
        {6, "Buffer Overflow: NOP Sled", "\x90\x90\x90\x90\x90\x90\x90\x90", 100, 800},
        {7, "Overlap Test Pattern", "ABAABA", 60, 150} // Specifically for testing overlapping KMP matches
    };
}

#endif // ATDOMS_HPP