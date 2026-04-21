package com.vfa.controller;

import com.vfa.model.response.VfaAnalysisResponse;
import com.vfa.service.RecommendationService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.*;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import java.nio.charset.StandardCharsets;

@Slf4j @RestController @RequestMapping("/api/v1") @RequiredArgsConstructor
public class AnalysisController {

    private final RecommendationService recommendationService;

    @GetMapping("/health")
    public ResponseEntity<String> health() {
        return ResponseEntity.ok("VFA is running!");
    }

    /**
     * Main analysis endpoint
     * POST /api/v1/analyze
     * Body: multipart/form-data
     *   trivyReport: trivy-report.json file
     *   pomFile: pom.xml file
     */
    @PostMapping(value = "/analyze", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<VfaAnalysisResponse> analyze(
            @RequestPart("trivyReport") MultipartFile trivyReport,
            @RequestPart("pomFile") MultipartFile pomFile) {

        log.info("Received analysis request — trivy: {} bytes, pom: {} bytes",
            trivyReport.getSize(), pomFile.getSize());
        try {
            String trivyJson = new String(trivyReport.getBytes(), StandardCharsets.UTF_8);
            String pomContent = new String(pomFile.getBytes(), StandardCharsets.UTF_8);
            if (trivyJson.isBlank() || pomContent.isBlank())
                return ResponseEntity.badRequest().build();
            return ResponseEntity.ok(recommendationService.analyze(trivyJson, pomContent));
        } catch (Exception e) {
            log.error("Analysis failed: {}", e.getMessage(), e);
            return ResponseEntity.internalServerError().build();
        }
    }

    /**
     * Download fixed pom.xml with all SAFE fixes applied
     * POST /api/v1/generate-fix
     */
    @PostMapping(value = "/generate-fix", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<String> generateFix(
            @RequestPart("trivyReport") MultipartFile trivyReport,
            @RequestPart("pomFile") MultipartFile pomFile) {
        try {
            String trivyJson = new String(trivyReport.getBytes(), StandardCharsets.UTF_8);
            String pomContent = new String(pomFile.getBytes(), StandardCharsets.UTF_8);
            VfaAnalysisResponse analysis = recommendationService.analyze(trivyJson, pomContent);
            return ResponseEntity.ok()
                .header("Content-Disposition", "attachment; filename=pom-fixed.xml")
                .contentType(MediaType.APPLICATION_XML)
                .body(analysis.getFixedPomContent());
        } catch (Exception e) {
            log.error("Fix generation failed: {}", e.getMessage(), e);
            return ResponseEntity.internalServerError().build();
        }
    }
}
