#ifndef KNAPSACK_ENGINE_HPP
#define KNAPSACK_ENGINE_HPP

#include "atdoms.hpp"
#include <vector>

// Holds the complete mathematical result of the Knapsack DP triage
struct TriageResult {
    int max_severity_mitigated;
    int total_cost_used;
    int resource_capacity;
    std::vector<DetectedAlert> mitigated_alerts;
    std::vector<DetectedAlert> dropped_alerts;
};

// Solves the 0/1 Knapsack problem using bottom-up Dynamic Programming tabulation
TriageResult solveKnapsackTriage(const std::vector<DetectedAlert>& alerts, int capacity);

#endif // KNAPSACK_ENGINE_HPP