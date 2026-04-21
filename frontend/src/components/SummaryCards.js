import React from 'react';

export const SummaryCards = ({ data }) => {
  const cards = [
    { label: 'Total CVEs', value: data.totalVulnerabilities, color: '#6366f1', icon: '🔍' },
    { label: 'Safe to Fix', value: data.safeToFix, color: '#10b981', icon: '✅' },
    { label: 'Needs Attention', value: data.requiresAttention, color: '#f97316', icon: '⚠️' },
    { label: 'Health Score', value: `${data.securityHealthScore}/100`, color: '#6366f1', icon: '🏆' },
  ];
  return (
    <div className="summary-cards">
      {cards.map((c, i) => (
        <div key={i} className="summary-card" style={{ borderTop: `4px solid ${c.color}` }}>
          <div className="summary-icon">{c.icon}</div>
          <div className="summary-value" style={{ color: c.color }}>{c.value}</div>
          <div className="summary-label">{c.label}</div>
        </div>
      ))}
    </div>
  );
};

export default SummaryCards;
