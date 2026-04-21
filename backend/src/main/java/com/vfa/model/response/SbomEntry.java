package com.vfa.model.response;

import lombok.Builder;
import lombok.Data;
import java.util.List;

@Data @Builder
public class SbomEntry {
    private String library;
    private String version;
    private String license;
    private String licenseRisk;
    private boolean vulnerable;
    private List<String> cveIds;
    private String source;
}
