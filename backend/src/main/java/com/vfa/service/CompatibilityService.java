package com.vfa.service;

import com.vfa.model.response.VulnerabilityRecommendation;
import com.vfa.model.trivy.TrivyVulnerability;
import com.vfa.service.PomAnalyzerService.PomAnalysisResult;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import java.util.*;

@Slf4j @Service @RequiredArgsConstructor
public class CompatibilityService {

    private final MavenCentralService mavenCentralService;
    private final TrivyParserService trivyParserService;
    private final PomAnalyzerService pomAnalyzerService;

    public static final String STATUS_SAFE = "SAFE";
    public static final String STATUS_BREAKING_CHANGE = "BREAKING_CHANGE";
    public static final String STATUS_CONFLICT = "CONFLICT";
    public static final String STATUS_NO_FIX_AVAILABLE = "NO_FIX_AVAILABLE";
    public static final String STATUS_ALREADY_FIXED = "ALREADY_FIXED";

    public VulnerabilityRecommendation analyze(String library, List<TrivyVulnerability> vulns, PomAnalysisResult pomResult) {
        log.info("Analyzing: {}", library);
        String[] parts = library.split(":");
        if (parts.length != 2) return buildError(library, vulns, "Invalid library format");

        String groupId = parts[0], artifactId = parts[1];
        String installedVersion = vulns.get(0).getInstalledVersion();
        List<String> cveIds = vulns.stream().map(TrivyVulnerability::getVulnerabilityId).toList();
        String severity = trivyParserService.getHighestSeverity(vulns);

        Set<String> allFixes = new LinkedHashSet<>();
        for (TrivyVulnerability v : vulns) allFixes.addAll(trivyParserService.extractFixVersions(v));

        if (allFixes.isEmpty()) {
            return VulnerabilityRecommendation.builder()
                .library(library).installedVersion(installedVersion).cveIds(cveIds).severity(severity)
                .status(STATUS_NO_FIX_AVAILABLE).reason("No fix published yet.")
                .action("Monitor CVE advisories.").breakingChange(false)
                .conflictDetails(Collections.emptyList()).estimatedEffort("N/A")
                .impactedFiles(Collections.emptyList()).build();
        }

        String managedVersion = pomAnalyzerService.getEffectiveVersion(pomResult, groupId, artifactId);
        String managedBy = determineManagedBy(library, pomResult);

        // Check ALREADY_FIXED
        if (managedVersion != null && isAlreadyFixed(managedVersion, new ArrayList<>(allFixes), installedVersion)) {
            return VulnerabilityRecommendation.builder()
                .library(library).installedVersion(installedVersion).cveIds(cveIds).severity(severity)
                .status(STATUS_ALREADY_FIXED).recommendedVersion(managedVersion)
                .managedBy(managedBy).managedVersion(managedVersion)
                .reason("BOM already manages this at a safe version.")
                .action("No action needed. BOM handles this automatically.")
                .breakingChange(false).conflictDetails(Collections.emptyList())
                .estimatedEffort("0 minutes").impactedFiles(Collections.emptyList()).build();
        }

        String bestVersion = mavenCentralService.findBestSafeVersion(groupId, artifactId, installedVersion, new ArrayList<>(allFixes));

        if (bestVersion == null) {
            return VulnerabilityRecommendation.builder()
                .library(library).installedVersion(installedVersion).cveIds(cveIds).severity(severity)
                .status(STATUS_NO_FIX_AVAILABLE).managedBy(managedBy).managedVersion(managedVersion)
                .reason("No stable fix found on Maven Central.")
                .action("Check Maven Central manually or wait for a stable release.")
                .breakingChange(false).conflictDetails(Collections.emptyList())
                .estimatedEffort("Unknown").impactedFiles(Collections.emptyList()).build();
        }

        boolean isBreaking = isBreakingChange(installedVersion, bestVersion);
        List<String> conflicts = checkConflicts(groupId, artifactId, bestVersion, pomResult);

        if (managedVersion != null && !managedVersion.equals(bestVersion))
            conflicts.add(String.format("BOM manages %s at %s but safe fix requires %s", library, managedVersion, bestVersion));

        String status = determineStatus(isBreaking, conflicts);
        String effort = estimateEffort(status, severity);
        String licenseInfo = fetchLicenseQuietly(groupId, artifactId, bestVersion);
        int age = estimateDependencyAge(installedVersion);
        String ageRisk = age > 365 ? "OUTDATED" : age > 180 ? "AGING" : "CURRENT";

        return VulnerabilityRecommendation.builder()
            .library(library).installedVersion(installedVersion).cveIds(cveIds).severity(severity)
            .status(status).recommendedVersion(bestVersion).managedBy(managedBy).managedVersion(managedVersion)
            .breakingChange(isBreaking).conflictDetails(conflicts)
            .action(buildAction(status, library, bestVersion, managedBy, conflicts))
            .reason(buildReason(status, installedVersion, bestVersion, isBreaking, conflicts))
            .estimatedEffort(effort).licenseInfo(licenseInfo)
            .dependencyAge(age).ageRisk(ageRisk)
            .impactedFiles(Collections.emptyList()).build();
    }

    private boolean isAlreadyFixed(String managed, List<String> fixes, String installed) {
        for (String fix : fixes) if (!mavenCentralService.isVersionSufficient(managed, fix)) return false;
        return !managed.equals(installed);
    }

    private boolean isBreakingChange(String current, String next) {
        try {
            if (extractMajor(next) > extractMajor(current)) return true;
            if (extractMinor(next) > extractMinor(current)) return true;
            return false;
        } catch (Exception e) { return false; }
    }

    private List<String> checkConflicts(String groupId, String artifactId, String recommended, PomAnalysisResult pom) {
        List<String> conflicts = new ArrayList<>();
        for (Map.Entry<String, String> e : pom.getDirectDependencies().entrySet()) {
            String key = e.getKey(), ver = e.getValue();
            if (!key.startsWith(groupId + ":")) continue;
            if (key.equals(groupId + ":" + artifactId)) continue;
            if ("MANAGED".equals(ver)) continue;
            if (!mavenCentralService.getMajorMinor(recommended).equals(mavenCentralService.getMajorMinor(ver)))
                conflicts.add(String.format("Version mismatch within %s family: %s is at %s but %s would be at %s",
                    groupId, key, ver, artifactId, recommended));
        }
        return conflicts;
    }

    private String determineManagedBy(String library, PomAnalysisResult pom) {
        if (pom.getManagedVersions().get(library) != null) {
            if (pom.getManagedVersions().containsKey("org.springframework.boot:spring-boot-dependencies")) return "spring-boot-dependencies";
            return "dependencyManagement";
        }
        return "NOT_MANAGED";
    }

    private String determineStatus(boolean breaking, List<String> conflicts) {
        if (!conflicts.isEmpty()) return STATUS_CONFLICT;
        if (breaking) return STATUS_BREAKING_CHANGE;
        return STATUS_SAFE;
    }

    private String estimateEffort(String status, String severity) {
        return switch (status) {
            case STATUS_SAFE -> "15-30 minutes";
            case STATUS_BREAKING_CHANGE -> "CRITICAL".equals(severity) || "HIGH".equals(severity) ? "2-4 hours" : "1-2 hours";
            case STATUS_CONFLICT -> "4-8 hours";
            default -> "Unknown";
        };
    }

    private String fetchLicenseQuietly(String groupId, String artifactId, String version) {
        try { return mavenCentralService.fetchLicenseInfo(groupId, artifactId, version); }
        catch (Exception e) { return "Unknown"; }
    }

    private int estimateDependencyAge(String version) {
        // Simplified — real implementation would check release date from Maven Central
        return 90;
    }

    private String buildAction(String status, String library, String bestVersion, String managedBy, List<String> conflicts) {
        return switch (status) {
            case STATUS_SAFE -> String.format("Add explicit version %s for %s in pom.xml <dependencyManagement>", bestVersion, library);
            case STATUS_BREAKING_CHANGE -> String.format("Review changelog before upgrading to %s. Test thoroughly.", bestVersion);
            case STATUS_CONFLICT -> String.format("Resolve conflicts before upgrading: %s", String.join("; ", conflicts));
            default -> "Manual review required.";
        };
    }

    private String buildReason(String status, String current, String recommended, boolean breaking, List<String> conflicts) {
        return switch (status) {
            case STATUS_SAFE -> String.format("Version %s fixes all CVEs and is compatible with your dependency tree.", recommended);
            case STATUS_BREAKING_CHANGE -> String.format("Version %s fixes CVEs but introduces a version jump from %s.", recommended, current);
            case STATUS_CONFLICT -> String.format("Version %s fixes CVEs but conflicts with: %s", recommended, String.join(", ", conflicts));
            default -> "Could not determine a safe upgrade path.";
        };
    }

    private VulnerabilityRecommendation buildError(String library, List<TrivyVulnerability> vulns, String msg) {
        return VulnerabilityRecommendation.builder().library(library)
            .installedVersion(vulns.isEmpty() ? "UNKNOWN" : vulns.get(0).getInstalledVersion())
            .cveIds(vulns.stream().map(TrivyVulnerability::getVulnerabilityId).toList())
            .status(STATUS_NO_FIX_AVAILABLE).reason("Error: " + msg).action("Manual review required.")
            .conflictDetails(Collections.emptyList()).impactedFiles(Collections.emptyList()).build();
    }

    private int extractMajor(String v) {
        String c = v.replaceAll("[^0-9.]", " ").trim();
        return Integer.parseInt(c.split("\\.")[0].trim());
    }

    private int extractMinor(String v) {
        String c = v.replaceAll("[^0-9.]", " ").trim();
        String[] p = c.split("\\.");
        return p.length >= 2 ? Integer.parseInt(p[1].trim()) : 0;
    }
}
