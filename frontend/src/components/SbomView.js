import React, { useState } from 'react';

const licenseRiskColor = {
  SAFE: { bg: '#d1fae5', text: '#065f46' },
  REVIEW_NEEDED: { bg: '#fef3c7', text: '#92400e' },
  HIGH_RISK: { bg: '#fee2e2', text: '#991b1b' },
  UNKNOWN: { bg: '#f3f4f6', text: '#374151' },
};

const SbomView = ({ sbom }) => {
  const [search, setSearch] = useState('');
  const filtered = sbom.entries?.filter(e =>
    e.library.toLowerCase().includes(search.toLowerCase())) || [];

  const handleExport = () => {
    const json = JSON.stringify(sbom, null, 2);
    const blob = new Blob([json], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a'); a.href = url;
    a.download = 'sbom.json'; a.click(); a.remove();
  };

  return (
    <div className="sbom-wrapper">
      <div className="sbom-header">
        <div>
          <h3>Software Bill of Materials</h3>
          <p>Generated at {sbom.generatedAt} · {sbom.totalDependencies} dependencies · {sbom.vulnerableDependencies} vulnerable</p>
        </div>
        <button className="btn btn-primary" onClick={handleExport}>⬇ Export SBOM JSON</button>
      </div>

      <div className="sbom-stats">
        {[
          { label: 'Total', value: sbom.totalDependencies, color: '#6366f1' },
          { label: 'Vulnerable', value: sbom.vulnerableDependencies, color: '#ef4444' },
          { label: 'Clean', value: sbom.totalDependencies - sbom.vulnerableDependencies, color: '#10b981' },
        ].map((s, i) => (
          <div key={i} className="sbom-stat" style={{ borderLeft: `4px solid ${s.color}` }}>
            <div className="sbom-stat-value" style={{ color: s.color }}>{s.value}</div>
            <div className="sbom-stat-label">{s.label}</div>
          </div>
        ))}
      </div>

      <input className="search-input" placeholder="Search dependencies..."
        value={search} onChange={e => setSearch(e.target.value)} />

      <div className="sbom-table">
        <div className="sbom-thead">
          <div>Library</div><div>Version</div><div>License</div><div>Risk</div><div>Source</div><div>Status</div>
        </div>
        {filtered.map((entry, i) => {
          const lrc = licenseRiskColor[entry.licenseRisk] || licenseRiskColor.UNKNOWN;
          return (
            <div key={i} className={`sbom-row ${entry.vulnerable ? 'vulnerable' : ''}`}>
              <div className="sbom-lib">{entry.library}</div>
              <div><code>{entry.version}</code></div>
              <div>{entry.license || '—'}</div>
              <div><span className="risk-badge" style={{ background: lrc.bg, color: lrc.text }}>{entry.licenseRisk}</span></div>
              <div><span className="source-badge">{entry.source}</span></div>
              <div>{entry.vulnerable
                ? <span className="vuln-flag">⚠️ Vulnerable</span>
                : <span className="clean-flag">✅ Clean</span>}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};

export default SbomView;
