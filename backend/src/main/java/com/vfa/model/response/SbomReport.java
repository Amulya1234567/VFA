package com.vfa.model.response;

import lombok.Builder;
import lombok.Data;
import java.util.List;

@Data @Builder
public class SbomReport {
    private String generatedAt;
    private String projectArtifact;
    private int totalDependencies;
    private int vulnerableDependencies;
    private List<SbomEntry> entries;
}
