package com.vfa.service;

import com.vfa.model.response.SbomEntry;
import com.vfa.model.response.SbomReport;
import com.vfa.model.response.VulnerabilityRecommendation;
import com.vfa.service.PomAnalyzerService.PomAnalysisResult;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;

@Slf4j @Service @RequiredArgsConstructor
public class SbomService {

    private final MavenCentralService mavenCentralService;

    public SbomReport generateSbom(PomAnalysisResult pomResult,
            List<VulnerabilityRecommendation> recommendations) {

        List<SbomEntry> entries = new ArrayList<>();
        Set<String> vulnerableLibraries = new HashSet<>();

        // Mark all vulnerable libraries
        for (VulnerabilityRecommendation rec : recommendations)
            vulnerableLibraries.add(rec.getLibrary());

        // Add direct dependencies
        for (Map.Entry<String, String> entry : pomResult.getDirectDependencies().entrySet()) {
            String lib = entry.getKey();
            String version = entry.getValue().equals("MANAGED") ?
                pomResult.getManagedVersions().getOrDefault(lib, "MANAGED") : entry.getValue();
            boolean vulnerable = vulnerableLibraries.contains(lib);
            List<String> cves = recommendations.stream()
                .filter(r -> r.getLibrary().equals(lib))
                .map(r -> r.getCveIds()).findFirst().orElse(Collections.emptyList());

            String license = fetchLicenseQuietly(lib, version);
            String licenseRisk = assessLicenseRisk(license);

            entries.add(SbomEntry.builder()
                .library(lib).version(version).license(license)
                .licenseRisk(licenseRisk).vulnerable(vulnerable)
                .cveIds(cves).source("direct").build());
        }

        // Add BOM-managed libraries that are not direct deps
        for (Map.Entry<String, String> entry : pomResult.getManagedVersions().entrySet()) {
            String lib = entry.getKey();
            if (pomResult.getDirectDependencies().containsKey(lib)) continue;
            boolean vulnerable = vulnerableLibraries.contains(lib);
            if (!vulnerable) continue; // Only add managed if vulnerable
            List<String> cves = recommendations.stream()
                .filter(r -> r.getLibrary().equals(lib))
                .map(r -> r.getCveIds()).findFirst().orElse(Collections.emptyList());

            entries.add(SbomEntry.builder()
                .library(lib).version(entry.getValue()).license("Unknown")
                .licenseRisk("UNKNOWN").vulnerable(true)
                .cveIds(cves).source("transitive").build());
        }

        long vulnerableCount = entries.stream().filter(SbomEntry::isVulnerable).count();

        return SbomReport.builder()
            .generatedAt(LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")))
            .projectArtifact(pomResult.getGroupId() + ":" + pomResult.getArtifactId())
            .totalDependencies(entries.size())
            .vulnerableDependencies((int) vulnerableCount)
            .entries(entries)
            .build();
    }

    private String fetchLicenseQuietly(String library, String version) {
        try {
            String[] parts = library.split(":");
            if (parts.length != 2) return "Unknown";
            return mavenCentralService.fetchLicenseInfo(parts[0], parts[1], version);
        } catch (Exception e) {
            return "Unknown";
        }
    }

    private String assessLicenseRisk(String license) {
        if (license == null || license.equalsIgnoreCase("Unknown")) return "UNKNOWN";
        String upper = license.toUpperCase();
        if (upper.contains("GPL") && !upper.contains("LGPL")) return "HIGH_RISK";
        if (upper.contains("LGPL") || upper.contains("AGPL")) return "REVIEW_NEEDED";
        if (upper.contains("APACHE") || upper.contains("MIT") ||
            upper.contains("BSD") || upper.contains("ISC")) return "SAFE";
        return "REVIEW_NEEDED";
    }
}
