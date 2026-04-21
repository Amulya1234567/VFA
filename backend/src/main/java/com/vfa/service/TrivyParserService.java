package com.vfa.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.vfa.model.trivy.TrivyReport;
import com.vfa.model.trivy.TrivyResult;
import com.vfa.model.trivy.TrivyVulnerability;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import java.util.*;

@Slf4j @Service @RequiredArgsConstructor
public class TrivyParserService {

    private final ObjectMapper objectMapper;

    public TrivyReport parseReport(String trivyJson) {
        try {
            TrivyReport report = objectMapper.readValue(trivyJson, TrivyReport.class);
            log.info("Parsed Trivy report with {} results", report.getResults() != null ? report.getResults().size() : 0);
            return report;
        } catch (Exception e) {
            throw new RuntimeException("Invalid Trivy report format: " + e.getMessage());
        }
    }

    public List<TrivyVulnerability> extractVulnerabilities(TrivyReport report) {
        List<TrivyVulnerability> all = new ArrayList<>();
        if (report.getResults() == null) return all;
        for (TrivyResult result : report.getResults()) {
            if (result.getVulnerabilities() != null) all.addAll(result.getVulnerabilities());
        }
        log.info("Total vulnerabilities: {}", all.size());
        return all;
    }

    public Map<String, List<TrivyVulnerability>> groupByLibrary(List<TrivyVulnerability> vulns) {
        Map<String, List<TrivyVulnerability>> grouped = new LinkedHashMap<>();
        for (TrivyVulnerability v : vulns)
            grouped.computeIfAbsent(v.getPackageName(), k -> new ArrayList<>()).add(v);
        return grouped;
    }

    public List<String> extractFixVersions(TrivyVulnerability vuln) {
        List<String> list = new ArrayList<>();
        if (vuln.getFixedVersion() == null || vuln.getFixedVersion().isBlank()) return list;
        for (String v : vuln.getFixedVersion().split(",")) {
            String c = v.trim();
            if (!c.isEmpty()) list.add(c);
        }
        return list;
    }

    public String getHighestSeverity(List<TrivyVulnerability> vulns) {
        for (String s : List.of("CRITICAL","HIGH","MEDIUM","LOW","UNKNOWN"))
            for (TrivyVulnerability v : vulns)
                if (s.equalsIgnoreCase(v.getSeverity())) return s;
        return "UNKNOWN";
    }
}
