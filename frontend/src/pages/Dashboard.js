import React, { useState } from 'react';
import ScoreCard from '../components/ScoreCard';
import VulnerabilityTable from '../components/VulnerabilityTable';
import SbomView from '../components/SbomView';
import PrioritiesPanel from '../components/PrioritiesPanel';
import SummaryCards from '../components/SummaryCards';

const TABS = ['Overview', 'Vulnerabilities', 'SBOM', 'Fixed POM'];

const Dashboard = ({ data, onDownloadFix, onReset }) => {
  const [activeTab, setActiveTab] = useState('Overview');

  return (
    <div className="dashboard">
      <div className="dashboard-header">
        <div>
          <h2 className="project-name">{data.projectArtifact}</h2>
          <p className="analyzed-at">Analyzed at {data.analyzedAt} · v{data.projectVersion}</p>
        </div>
        <div className="header-actions">
          <button className="btn btn-success" onClick={onDownloadFix}>⬇ Download Fixed pom.xml</button>
          <button className="btn btn-outline" onClick={onReset}>← New Analysis</button>
        </div>
      </div>

      <div className="tab-bar">
        {TABS.map(tab => (
          <button
            key={tab}
            className={`tab ${activeTab === tab ? 'active' : ''}`}
            onClick={() => setActiveTab(tab)}
          >{tab}</button>
        ))}
      </div>

      {activeTab === 'Overview' && (
        <div className="tab-content">
          <div className="overview-top">
            <ScoreCard score={data.securityHealthScore} grade={data.healthGrade} summary={data.healthSummary} />
            <PrioritiesPanel priorities={data.topPriorities} />
          </div>
          <SummaryCards data={data} />
        </div>
      )}

      {activeTab === 'Vulnerabilities' && (
        <div className="tab-content">
          <VulnerabilityTable recommendations={data.recommendations} />
        </div>
      )}

      {activeTab === 'SBOM' && (
        <div className="tab-content">
          {data.sbom ? <SbomView sbom={data.sbom} /> : <p className="empty">No SBOM data available.</p>}
        </div>
      )}

      {activeTab === 'Fixed POM' && (
        <div className="tab-content">
          <div className="fixed-pom-panel">
            <div className="fixed-pom-header">
              <div>
                <h3>Auto-Generated Fixed pom.xml</h3>
                <p>All SAFE fixes have been applied automatically. BREAKING_CHANGE and CONFLICT items require manual review.</p>
              </div>
              <button className="btn btn-success" onClick={onDownloadFix}>⬇ Download pom-fixed.xml</button>
            </div>
            <pre className="pom-content">{data.fixedPomContent}</pre>
          </div>
        </div>
      )}
    </div>
  );
};

export default Dashboard;
