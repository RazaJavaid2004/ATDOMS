#include "../include/kmp_engine.hpp"

std::vector<int> computeLPSArray(const std::string& pattern) {
    int m = pattern.length();
    std::vector<int> lps(m, 0);
    int len = 0;
    int i = 1;

    while (i < m) {
        if (pattern[i] == pattern[len]) {
            len++;
            lps[i] = len;
            i++;
        } else {
            if (len != 0) {
                len = lps[len - 1];
            } else {
                lps[i] = 0;
                i++;
            }
        }
    }
    return lps;
}

std::vector<DetectedAlert> kmpSearch(const std::string& text, const ThreatSignature& threat) {
    std::vector<DetectedAlert> alerts;
    int n = text.length();
    int m = threat.pattern.length();
    
    if (m == 0 || n == 0) return alerts;

    std::vector<int> lps = computeLPSArray(threat.pattern);
    int i = 0; // index for text
    int j = 0; // index for pattern

    while (i < n) {
        if (threat.pattern[j] == text[i]) {
            j++;
            i++;
        }
        
        if (j == m) {
            // Match found! Record the alert.
            alerts.push_back({
                threat.id, 
                threat.name, 
                static_cast<size_t>(i - j), 
                threat.severity_score, 
                threat.mitigation_cost
            });
            // To find overlapping occurrences, fallback to previous LPS state
            j = lps[j - 1]; 
        } else if (i < n && threat.pattern[j] != text[i]) {
            if (j != 0) {
                j = lps[j - 1];
            } else {
                i++;
            }
        }
    }
    return alerts;
}