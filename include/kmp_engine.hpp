#ifndef KMP_ENGINE_HPP
#define KMP_ENGINE_HPP

#include "atdoms.hpp"
#include <vector>
#include <string>

// Computes the Longest Prefix Suffix (LPS) array for the KMP algorithm
std::vector<int> computeLPSArray(const std::string& pattern);

// Searches the network buffer for a specific threat signature
std::vector<DetectedAlert> kmpSearch(const std::string& text, const ThreatSignature& threat);

#endif // KMP_ENGINE_HPP