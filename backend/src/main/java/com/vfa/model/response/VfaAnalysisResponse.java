package com.vfa.model.response;

import lombok.Builder;
import lombok.Data;
import java.util.List;

@Data @Builder
public class VfaAnalysisResponse {
    private String projectArtifact;
    private String projectVersion;
    private String analyzedAt;
    private int totalVulnerabilities;
    private int safeToFix;
    private int requiresAttention;
    private int securityHealthScore;
    private String healthGrade;
    private String healthSummary;
    private List<String> topPriorities;
    private List<VulnerabilityRecommendation> recommendations;
    private String fixedPomContent;
    private SbomReport sbom;
}
