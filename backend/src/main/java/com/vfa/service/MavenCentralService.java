package com.vfa.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.maven.model.Dependency;
import org.apache.maven.model.Model;
import org.apache.maven.model.io.xpp3.MavenXpp3Reader;
import org.springframework.stereotype.Service;

import java.io.StringReader;
import java.net.URI;
import java.net.http.*;
import java.time.Duration;
import java.util.*;

@Slf4j @Service @RequiredArgsConstructor
public class MavenCentralService {

    private final ObjectMapper objectMapper;
    private final HttpClient httpClient = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(10)).build();

    private static final String SEARCH_URL = "https://search.maven.org/solrsearch/select";
    private static final String REPO_URL = "https://repo1.maven.org/maven2";

    public List<String> getAllVersions(String groupId, String artifactId) {
        try {
            String url = String.format("%s?q=g:%s+AND+a:%s&core=gav&rows=50&wt=json", SEARCH_URL, groupId, artifactId);
            String resp = httpGet(url);
            JsonNode docs = objectMapper.readTree(resp).path("response").path("docs");
            List<String> versions = new ArrayList<>();
            for (JsonNode doc : docs) {
                String v = doc.path("v").asText();
                if (!v.isEmpty()) versions.add(v);
            }
            return versions;
        } catch (Exception e) {
            log.error("Failed to fetch versions for {}:{} - {}", groupId, artifactId, e.getMessage());
            return Collections.emptyList();
        }
    }

    public Map<String, String> fetchBomManagedVersions(String groupId, String artifactId, String version) {
        Map<String, String> managed = new LinkedHashMap<>();
        try {
            String pomUrl = buildPomUrl(groupId, artifactId, version);
            String pomContent = httpGet(pomUrl);
            MavenXpp3Reader reader = new MavenXpp3Reader();
            Model model = reader.read(new StringReader(pomContent));

            if (model.getDependencyManagement() != null && model.getDependencyManagement().getDependencies() != null) {
                for (Dependency dep : model.getDependencyManagement().getDependencies()) {
                    if ("pom".equals(dep.getType()) && "import".equals(dep.getScope())) continue;
                    String key = dep.getGroupId() + ":" + dep.getArtifactId();
                    String v = dep.getVersion();
                    if (v != null && v.startsWith("${")) v = resolveProperty(v, model);
                    if (v != null && !v.startsWith("${")) managed.put(key, v);
                }
            }
            if (model.getParent() != null) {
                try {
                    Map<String, String> parentVersions = fetchBomManagedVersions(
                        model.getParent().getGroupId(), model.getParent().getArtifactId(), model.getParent().getVersion());
                    parentVersions.forEach(managed::putIfAbsent);
                } catch (Exception e) {
                    log.warn("Could not fetch parent BOM: {}", e.getMessage());
                }
            }
        } catch (Exception e) {
            log.error("Failed to fetch BOM {}:{}:{} - {}", groupId, artifactId, version, e.getMessage());
            throw new RuntimeException("Cannot fetch BOM: " + e.getMessage());
        }
        return managed;
    }

    public String findBestSafeVersion(String groupId, String artifactId, String currentVersion, List<String> fixVersions) {
        List<String> allVersions = getAllVersions(groupId, artifactId);
        if (allVersions.isEmpty()) return null;

        String minFix = findMinimumFixVersion(fixVersions, currentVersion);

        // Try same branch first
        List<String> candidates = new ArrayList<>();
        for (String v : allVersions)
            if (isStableVersion(v) && isInSameBranch(v, currentVersion) && isVersionSufficient(v, minFix))
                candidates.add(v);

        // Cross branch fallback
        if (candidates.isEmpty())
            for (String v : allVersions)
                if (isStableVersion(v) && isVersionSufficient(v, minFix))
                    candidates.add(v);

        if (candidates.isEmpty()) return null;
        return candidates.get(candidates.size() - 1);
    }

    public String buildPomUrl(String groupId, String artifactId, String version) {
        String groupPath = groupId.replace(".", "/");
        return String.format("%s/%s/%s/%s/%s-%s.pom", REPO_URL, groupPath, artifactId, version, artifactId, version);
    }

    public String fetchLicenseInfo(String groupId, String artifactId, String version) {
        try {
            String pomUrl = buildPomUrl(groupId, artifactId, version);
            String pomContent = httpGet(pomUrl);
            MavenXpp3Reader reader = new MavenXpp3Reader();
            Model model = reader.read(new StringReader(pomContent));
            if (model.getLicenses() != null && !model.getLicenses().isEmpty())
                return model.getLicenses().get(0).getName();
        } catch (Exception e) {
            log.debug("Could not fetch license for {}:{}", groupId, artifactId);
        }
        return "Unknown";
    }

    public String httpGet(String url) throws Exception {
        HttpRequest req = HttpRequest.newBuilder().uri(URI.create(url))
                .timeout(Duration.ofSeconds(15))
                .header("Accept", "application/json, application/xml, text/xml").GET().build();
        HttpResponse<String> resp = httpClient.send(req, HttpResponse.BodyHandlers.ofString());
        if (resp.statusCode() != 200) throw new RuntimeException("HTTP " + resp.statusCode() + " for " + url);
        return resp.body();
    }

    public boolean isVersionSufficient(String candidate, String minimum) {
        try {
            int[] c = parseVersionParts(candidate), m = parseVersionParts(minimum);
            int len = Math.max(c.length, m.length);
            for (int i = 0; i < len; i++) {
                int cv = i < c.length ? c[i] : 0, mv = i < m.length ? m[i] : 0;
                if (cv > mv) return true;
                if (cv < mv) return false;
            }
            return true;
        } catch (Exception e) { return false; }
    }

    private String resolveProperty(String value, Model model) {
        if (value == null || !value.startsWith("${")) return value;
        String name = value.substring(2, value.length() - 1);
        if (model.getProperties() != null) {
            String resolved = model.getProperties().getProperty(name);
            if (resolved != null) return resolved;
        }
        return value;
    }

    public boolean isStableVersion(String version) {
        String u = version.toUpperCase();
        return !u.contains("SNAPSHOT") && !u.contains("-M") && !u.contains("-RC") && !u.contains("ALPHA") && !u.contains("BETA");
    }

    public boolean isInSameBranch(String candidate, String current) {
        try { return getMajorMinor(candidate).equals(getMajorMinor(current)); }
        catch (Exception e) { return false; }
    }

    public String getMajorMinor(String version) {
        String cleaned = version.replaceAll("[^0-9.]", " ").trim();
        String[] parts = cleaned.split("\\.");
        return parts.length >= 2 ? parts[0].trim() + "." + parts[1].trim() : parts[0].trim();
    }

    private int[] parseVersionParts(String version) {
        String cleaned = version.replaceAll("[^0-9.]", " ").trim();
        return Arrays.stream(cleaned.split("\\.")).filter(p -> !p.isBlank())
                .mapToInt(p -> { try { return Integer.parseInt(p.trim()); } catch (Exception e) { return 0; } }).toArray();
    }

    private String findMinimumFixVersion(List<String> fixVersions, String currentVersion) {
        if (fixVersions == null || fixVersions.isEmpty()) return currentVersion;
        if (fixVersions.size() == 1) return fixVersions.get(0);
        for (String fix : fixVersions) if (isInSameBranch(fix, currentVersion)) return fix;
        return fixVersions.get(0);
    }
}
