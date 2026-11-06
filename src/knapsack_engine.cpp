#include "../include/knapsack_engine.hpp"
#include <algorithm>

TriageResult solveKnapsackTriage(const std::vector<DetectedAlert>& alerts, int capacity) {
    int n = alerts.size();
    
    // 2D DP Tabulation Matrix: (n + 1) x (capacity + 1) initialized to 0
    std::vector<std::vector<int>> dp(n + 1, std::vector<int>(capacity + 1, 0));

    // Build table bottom-up in O(N * W)
    for (int i = 1; i <= n; i++) {
        int val = alerts[i - 1].severity_score;
        int wt = alerts[i - 1].mitigation_cost;

        for (int w = 0; w <= capacity; w++) {
            if (wt <= w) {
                dp[i][w] = std::max(val + dp[i - 1][w - wt], dp[i - 1][w]);
            } else {
                dp[i][w] = dp[i - 1][w];
            }
        }
    }

    TriageResult result;
    result.max_severity_mitigated = dp[n][capacity];
    result.total_cost_used = 0;
    result.resource_capacity = capacity;

    // Backtrack through the DP table in O(N) to identify selected vs dropped alerts
    int w = capacity;
    for (int i = n; i > 0; i--) {
        if (dp[i][w] != dp[i - 1][w]) {
            // Item i-1 was included in the optimal subset
            result.mitigated_alerts.push_back(alerts[i - 1]);
            result.total_cost_used += alerts[i - 1].mitigation_cost;
            w -= alerts[i - 1].mitigation_cost;
        } else {
            // Item i-1 was dropped due to resource ceiling constraints
            result.dropped_alerts.push_back(alerts[i - 1]);
        }
    }

    // Reverse to maintain chronological detection order
    std::reverse(result.mitigated_alerts.begin(), result.mitigated_alerts.end());
    std::reverse(result.dropped_alerts.begin(), result.dropped_alerts.end());

    return result;
}