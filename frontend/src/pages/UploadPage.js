import React from 'react';

const UploadPage = ({ trivyFile, pomFile, setTrivyFile, setPomFile, onAnalyze, loading, error }) => {
  return (
    <div className="upload-page">
      <div className="hero">
        <h1 className="hero-title">Vulnerability Fix Assistant</h1>
        <p className="hero-subtitle">
          Upload your Trivy scan report and pom.xml to get safe, conflict-aware
          upgrade recommendations for every vulnerability in your project.
        </p>
      </div>

      <div className="upload-grid">
        <UploadCard
          title="Trivy Scan Report"
          description="Run: trivy fs . --scanners vuln --format json --output trivy-report.json"
          accept=".json"
          file={trivyFile}
          onFile={setTrivyFile}
          icon="🔍"
          color="#6366f1"
        />
        <UploadCard
          title="pom.xml"
          description="Your Maven project's pom.xml file"
          accept=".xml"
          file={pomFile}
          onFile={setPomFile}
          icon="📦"
          color="#10b981"
        />
      </div>

      {error && <div className="error-banner">⚠️ {error}</div>}

      <div className="analyze-section">
        <button
          className={`btn btn-primary btn-large ${loading ? 'loading' : ''}`}
          onClick={onAnalyze}
          disabled={loading || !trivyFile || !pomFile}
        >
          {loading ? (
            <><span className="spinner"></span> Analyzing dependencies...</>
          ) : (
            '🚀 Analyze Vulnerabilities'
          )}
        </button>
        {loading && (
          <p className="loading-hint">
            Downloading BOMs from Maven Central and checking compatibility...
          </p>
        )}
      </div>

      <div className="features-grid">
        {[
          { icon: '🛡️', title: 'Conflict Detection', desc: 'Catches version mismatches before they break production' },
          { icon: '🎯', title: 'Smart Version Picker', desc: 'Selects the safest fix from multiple Trivy suggestions' },
          { icon: '📊', title: 'Security Health Score', desc: 'Grade A-F with actionable priorities for leadership' },
          { icon: '⚡', title: 'One-Click Fix', desc: 'Downloads a ready-to-use pom.xml with all safe fixes applied' },
          { icon: '📋', title: 'SBOM Generation', desc: 'Complete Software Bill of Materials with license compliance' },
          { icon: '⏱️', title: 'Effort Estimation', desc: 'Know how long each fix will take before you start' },
        ].map((f, i) => (
          <div key={i} className="feature-card">
            <div className="feature-icon">{f.icon}</div>
            <div className="feature-title">{f.title}</div>
            <div className="feature-desc">{f.desc}</div>
          </div>
        ))}
      </div>
    </div>
  );
};

const UploadCard = ({ title, description, accept, file, onFile, icon, color }) => {
  const handleDrop = (e) => {
    e.preventDefault();
    const f = e.dataTransfer.files[0];
    if (f) onFile(f);
  };

  return (
    <div
      className={`upload-card ${file ? 'uploaded' : ''}`}
      onDrop={handleDrop}
      onDragOver={(e) => e.preventDefault()}
      style={file ? { borderColor: color } : {}}
    >
      <div className="upload-icon" style={{ color }}>{icon}</div>
      <div className="upload-title">{title}</div>
      {file ? (
        <div className="upload-success">
          <span style={{ color: '#10b981' }}>✓</span> {file.name}
          <button className="btn-remove" onClick={() => onFile(null)}>✕</button>
        </div>
      ) : (
        <>
          <div className="upload-desc">{description}</div>
          <label className="upload-btn" style={{ background: color }}>
            Choose File
            <input type="file" accept={accept} onChange={(e) => onFile(e.target.files[0])} hidden />
          </label>
          <div className="upload-drop">or drag and drop here</div>
        </>
      )}
    </div>
  );
};

export default UploadPage;
