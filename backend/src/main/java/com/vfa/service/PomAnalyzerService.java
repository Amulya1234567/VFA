package com.vfa.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.maven.model.*;
import org.apache.maven.model.io.xpp3.MavenXpp3Reader;
import org.springframework.stereotype.Service;
import java.io.StringReader;
import java.util.*;

@Slf4j @Service @RequiredArgsConstructor
public class PomAnalyzerService {

    private final MavenCentralService mavenCentralService;

    public PomAnalysisResult analyzePom(String pomContent) {
        try {
            MavenXpp3Reader reader = new MavenXpp3Reader();
            Model model = reader.read(new StringReader(pomContent));
            PomAnalysisResult result = new PomAnalysisResult();

            result.setGroupId(model.getGroupId() != null ? model.getGroupId() : model.getParent().getGroupId());
            result.setArtifactId(model.getArtifactId());
            result.setVersion(model.getVersion() != null ? model.getVersion() : model.getParent().getVersion());

            Map<String, String> directDeps = new LinkedHashMap<>();
            if (model.getDependencies() != null) {
                for (Dependency dep : model.getDependencies()) {
                    String key = dep.getGroupId() + ":" + dep.getArtifactId();
                    String v = dep.getVersion();
                    directDeps.put(key, (v != null && !v.startsWith("${")) ? v : "MANAGED");
                }
            }
            result.setDirectDependencies(directDeps);

            Map<String, String> managedVersions = new LinkedHashMap<>();

            // Process BOM imports
            if (model.getDependencyManagement() != null && model.getDependencyManagement().getDependencies() != null) {
                for (Dependency dep : model.getDependencyManagement().getDependencies()) {
                    if ("pom".equals(dep.getType()) && "import".equals(dep.getScope())) {
                        try {
                            Map<String, String> bomVersions = mavenCentralService.fetchBomManagedVersions(
                                dep.getGroupId(), dep.getArtifactId(), dep.getVersion());
                            bomVersions.forEach(managedVersions::putIfAbsent);
                            log.info("BOM {}:{} contributed {} versions", dep.getArtifactId(), dep.getVersion(), bomVersions.size());
                        } catch (Exception e) {
                            log.warn("Could not fetch BOM {}:{} - {}", dep.getArtifactId(), dep.getVersion(), e.getMessage());
                        }
                    }
                }
                // Explicit dependencyManagement entries override BOM
                for (Dependency dep : model.getDependencyManagement().getDependencies()) {
                    if ("pom".equals(dep.getType()) && "import".equals(dep.getScope())) continue;
                    if (dep.getVersion() != null && !dep.getVersion().startsWith("${"))
                        managedVersions.put(dep.getGroupId() + ":" + dep.getArtifactId(), dep.getVersion());
                }
            }

            // Try public parent
            if (model.getParent() != null) {
                Parent parent = model.getParent();
                result.setParentGroupId(parent.getGroupId());
                result.setParentArtifactId(parent.getArtifactId());
                result.setParentVersion(parent.getVersion());
                try {
                    Map<String, String> parentVersions = mavenCentralService.fetchBomManagedVersions(
                        parent.getGroupId(), parent.getArtifactId(), parent.getVersion());
                    parentVersions.forEach(managedVersions::putIfAbsent);
                } catch (Exception e) {
                    log.warn("Private parent - skipping: {}", e.getMessage());
                }
            }

            result.setManagedVersions(managedVersions);
            log.info("POM analysis complete. Managed: {}, Direct: {}", managedVersions.size(), directDeps.size());
            return result;
        } catch (Exception e) {
            throw new RuntimeException("Failed to analyze pom.xml: " + e.getMessage());
        }
    }

    public String getEffectiveVersion(PomAnalysisResult result, String groupId, String artifactId) {
        String key = groupId + ":" + artifactId;
        String direct = result.getDirectDependencies().get(key);
        if (direct != null && !"MANAGED".equals(direct)) return direct;
        return result.getManagedVersions().get(key);
    }

    @lombok.Data
    public static class PomAnalysisResult {
        private String groupId, artifactId, version;
        private String parentGroupId, parentArtifactId, parentVersion;
        private Map<String, String> directDependencies = new LinkedHashMap<>();
        private Map<String, String> managedVersions = new LinkedHashMap<>();
    }
}
