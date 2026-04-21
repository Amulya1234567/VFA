# Vulnerability Fix Assistant (VFA)

Safe dependency upgrade recommendations for Java/Maven projects.

---

## Project Structure

```
vfa-complete/
├── backend/     ← Spring Boot 3.3.11 + Java 21
└── frontend/    ← React 18
```

---

## Quick Start

### Step 1 — Start the Backend

```bash
cd backend
mvn spring-boot:run
```

Backend starts at: http://localhost:8080

Verify: http://localhost:8080/api/v1/health → "VFA is running!"

### Step 2 — Start the Frontend

```bash
cd frontend
npm install
npm start
```

Frontend starts at: http://localhost:3000

---

## How to Use VFA

### Step 1 — Generate Trivy Report
Run this in your Java project folder:
```bash
trivy fs . --scanners vuln --format json --output trivy-report.json
```

### Step 2 — Open VFA UI
Go to http://localhost:3000

### Step 3 — Upload Files
- Upload trivy-report.json
- Upload your project's pom.xml

### Step 4 — Click "Analyze Vulnerabilities"

### Step 5 — Review Results
- Overview tab: Security health score, grade, top priorities
- Vulnerabilities tab: Detailed CVE analysis with fix recommendations
- SBOM tab: Complete software bill of materials with license info
- Fixed POM tab: Auto-generated pom.xml with all safe fixes applied

---

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | /api/v1/health | Health check |
| POST | /api/v1/analyze | Full analysis (trivy JSON + pom.xml) |
| POST | /api/v1/generate-fix | Download fixed pom.xml |

---

## Features

1. **Conflict Detection** — Catches version mismatches before production
2. **Smart Version Picker** — Filters RC/Milestone, picks safest stable version
3. **Security Health Score** — Grade A-F with 0-100 score
4. **One-Click Fix** — Downloads pom-fixed.xml with SAFE fixes applied
5. **SBOM Generation** — Complete bill of materials with license compliance
6. **Effort Estimation** — Time estimate per fix for sprint planning
7. **BOM Resolution** — Downloads and reads spring-boot-dependencies from Maven Central
8. **Private Parent Support** — Gracefully handles private Maven repos

---

## Status Meanings

| Status | Meaning |
|--------|---------|
| ✅ SAFE | Apply this fix, no conflicts |
| ⚠️ BREAKING_CHANGE | Fix works but test thoroughly |
| ❌ CONFLICT | Fix clashes with another dependency |
| 🚫 NO_FIX_AVAILABLE | No stable fix exists yet |
| 🔒 ALREADY_FIXED | BOM already manages a safe version |
