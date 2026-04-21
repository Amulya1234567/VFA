package com.vfa.service;

import com.vfa.model.response.VulnerabilityRecommendation;
import org.springframework.stereotype.Service;
import java.util.List;

@Service
public class SecurityScoreService {

    public int calculateScore(List<VulnerabilityRecommendation> recs) {
        int score = 100;
        for (VulnerabilityRecommendation r : recs) {
            int deduction = switch (r.getSeverity() != null ? r.getSeverity().toUpperCase() : "UNKNOWN") {
                case "CRITICAL" -> 20; case "HIGH" -> 10; case "MEDIUM" -> 5; case "LOW" -> 2; default -> 1;
            };
            if ("CONFLICT".equals(r.getStatus())) deduction += 5;
            if ("ALREADY_FIXED".equals(r.getStatus())) deduction = -2;
            score -= deduction;
        }
        return Math.max(0, Math.min(100, score));
    }

    public String calculateGrade(int score) {
        if (score >= 90) return "A";
        if (score >= 75) return "B";
        if (score >= 60) return "C";
        if (score >= 40) return "D";
        return "F";
    }

    public String buildHealthSummary(int score, String grade, List<VulnerabilityRecommendation> recs) {
        long critical = recs.stream().filter(r -> "CRITICAL".equals(r.getSeverity())).count();
        long high = recs.stream().filter(r -> "HIGH".equals(r.getSeverity())).count();
        long safe = recs.stream().filter(r -> "SAFE".equals(r.getStatus())).count();
        return String.format("Security Grade %s (%d/100) — %d critical, %d high severity issues. %d can be fixed safely today.",
            grade, score, critical, high, safe);
    }

    public List<String> buildTopPriorities(List<VulnerabilityRecommendation> recs) {
        return recs.stream()
            .filter(r -> !"ALREADY_FIXED".equals(r.getStatus()))
            .sorted((a, b) -> severityScore(b) - severityScore(a))
            .limit(3)
            .map(r -> String.format("Fix %s (%s) — %s", r.getLibrary(), r.getSeverity(), r.getAction()))
            .toList();
    }

    private int severityScore(VulnerabilityRecommendation r) {
        return switch (r.getSeverity() != null ? r.getSeverity().toUpperCase() : "UNKNOWN") {
            case "CRITICAL" -> 40; case "HIGH" -> 20; case "MEDIUM" -> 10; case "LOW" -> 5; default -> 1;
        };
    }
}
