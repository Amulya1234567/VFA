package com.vfa.model.trivy;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;
import java.util.List;

@Data @JsonIgnoreProperties(ignoreUnknown = true)
public class TrivyResult {
    @JsonProperty("Target") private String target;
    @JsonProperty("Type") private String type;
    @JsonProperty("Vulnerabilities") private List<TrivyVulnerability> vulnerabilities;
}
