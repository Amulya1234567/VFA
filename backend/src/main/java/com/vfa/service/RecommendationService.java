package com.vfa.service;

import com.vfa.model.response.SbomReport;
import com.vfa.model.response.VfaAnalysisResponse;
import com.vfa.model.response.VulnerabilityRecommendation;
import com.vfa.model.trivy.TrivyReport;
import com.vfa.model.trivy.TrivyVulnerability;
import com.vfa.service.PomAnalyzerService.PomAnalysisResult;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;

@Slf4j @Service @RequiredArgsConstructor
public class RecommendationService {

    private final TrivyParserService trivyParserService;
    private final PomAnalyzerService pomAnalyzerService;
    private final CompatibilityService compatibilityService;
    private final SecurityScoreService scoreService;
    private final PomFixGeneratorService pomFixGeneratorService;
    private final SbomService sbomService;

    public VfaAnalysisResponse analyze(String trivyJson, String pomContent) {
        log.info("VFA Analysis Started");

        TrivyReport report = trivyParserService.parseReport(trivyJson);
        List<TrivyVulnerability> allVulns = trivyParserService.extractVulnerabilities(report);

        PomAnalysisResult pomResult = pomAnalyzerService.analyzePom(pomContent);

        if (allVulns.isEmpty()) {
            return buildCleanResponse(pomResult, pomContent);
        }

        Map<String, List<TrivyVulnerability>> grouped = trivyParserService.groupByLibrary(allVulns);

        List<VulnerabilityRecommendation> recommendations = new ArrayList<>();
        for (Map.Entry<String, List<TrivyVulnerability>> entry : grouped.entrySet()) {
            recommendations.add(compatibilityService.analyze(entry.getKey(), entry.getValue(), pomResult));
        }

        // Sort by severity
        recommendations.sort(Comparator.comparingInt(r -> severityOrder(r.getSeverity())));

        long safeCount = recommendations.stream()
            .filter(r -> CompatibilityService.STATUS_SAFE.equals(r.getStatus()) ||
                         CompatibilityService.STATUS_ALREADY_FIXED.equals(r.getStatus())).count();
        long attentionCount = recommendations.size() - safeCount;

        int score = scoreService.calculateScore(recommendations);
        String grade = scoreService.calculateGrade(score);
        String summary = scoreService.buildHealthSummary(score, grade, recommendations);
        List<String> priorities = scoreService.buildTopPriorities(recommendations);
        String fixedPom = pomFixGeneratorService.generateFixedPom(pomContent, recommendations);
        SbomReport sbom = sbomService.generateSbom(pomResult, recommendations);

        log.info("Analysis complete. Score: {}/100 Grade: {} CVEs: {} Safe: {} Attention: {}",
            score, grade, allVulns.size(), safeCount, attentionCount);

        return VfaAnalysisResponse.builder()
            .projectArtifact(pomResult.getGroupId() + ":" + pomResult.getArtifactId())
            .projectVersion(pomResult.getVersion())
            .analyzedAt(LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")))
            .totalVulnerabilities(allVulns.size())
            .safeToFix((int) safeCount)
            .requiresAttention((int) attentionCount)
            .securityHealthScore(score)
            .healthGrade(grade)
            .healthSummary(summary)
            .topPriorities(priorities)
            .recommendations(recommendations)
            .fixedPomContent(fixedPom)
            .sbom(sbom)
            .build();
    }

    private VfaAnalysisResponse buildCleanResponse(PomAnalysisResult pomResult, String pomContent) {
        return VfaAnalysisResponse.builder()
            .projectArtifact(pomResult.getGroupId() + ":" + pomResult.getArtifactId())
            .projectVersion(pomResult.getVersion())
            .analyzedAt(LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")))
            .totalVulnerabilities(0).safeToFix(0).requiresAttention(0)
            .securityHealthScore(100).healthGrade("A")
            .healthSummary("Security Grade A (100/100) — No vulnerabilities found!")
            .topPriorities(Collections.emptyList())
            .recommendations(Collections.emptyList())
            .fixedPomContent(pomContent)
            .build();
    }

    private int severityOrder(String s) {
        return switch (s != null ? s.toUpperCase() : "UNKNOWN") {
            case "CRITICAL" -> 0; case "HIGH" -> 1; case "MEDIUM" -> 2; case "LOW" -> 3; default -> 4;
        };
    }
}
