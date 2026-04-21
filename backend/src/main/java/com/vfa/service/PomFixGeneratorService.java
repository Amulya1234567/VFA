package com.vfa.service;

import com.vfa.model.response.VulnerabilityRecommendation;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import java.util.List;

@Slf4j @Service
public class PomFixGeneratorService {

    public String generateFixedPom(String originalPom, List<VulnerabilityRecommendation> recs) {
        String fixed = originalPom;
        for (VulnerabilityRecommendation rec : recs) {
            if (!"SAFE".equals(rec.getStatus())) continue;
            if (rec.getRecommendedVersion() == null) continue;
            String artifactId = rec.getLibrary().split(":")[1];
            String oldVersion = rec.getInstalledVersion();
            String newVersion = rec.getRecommendedVersion();
            fixed = replaceVersion(fixed, artifactId, oldVersion, newVersion);
            log.info("Applied fix: {} → {}", rec.getLibrary(), newVersion);
        }
        return fixed;
    }

    private String replaceVersion(String pom, String artifactId, String oldVersion, String newVersion) {
        String pattern = String.format(
            "(<artifactId>%s</artifactId>\\s*<version>)%s(</version>)",
            artifactId, escapeRegex(oldVersion));
        return pom.replaceAll(pattern, "$1" + newVersion + "$2");
    }

    private String escapeRegex(String v) {
        return v.replace(".", "\\.").replace("-", "\\-");
    }
}
