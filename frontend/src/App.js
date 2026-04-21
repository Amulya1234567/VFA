import React, { useState } from 'react';
import { analyzeVulnerabilities, downloadFixedPom } from './services/api';
import Dashboard from './pages/Dashboard';
import UploadPage from './pages/UploadPage';
import './styles/App.css';

function App() {
  const [analysisResult, setAnalysisResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [trivyFile, setTrivyFile] = useState(null);
  const [pomFile, setPomFile] = useState(null);

  const handleAnalyze = async () => {
    if (!trivyFile || !pomFile) {
      setError('Please upload both Trivy report and pom.xml files.');
      return;
    }
    setLoading(true);
    setError(null);
    try {
      const result = await analyzeVulnerabilities(trivyFile, pomFile);
      setAnalysisResult(result);
    } catch (err) {
      setError('Analysis failed. Make sure VFA backend is running on port 8080.');
    } finally {
      setLoading(false);
    }
  };

  const handleDownloadFix = async () => {
    if (!trivyFile || !pomFile) return;
    try {
      await downloadFixedPom(trivyFile, pomFile);
    } catch (err) {
      setError('Could not generate fixed pom.xml.');
    }
  };

  const handleReset = () => {
    setAnalysisResult(null);
    setError(null);
    setTrivyFile(null);
    setPomFile(null);
  };

  return (
    <div className="app">
      <nav className="navbar">
        <div className="nav-brand">
          <div className="nav-logo">VFA</div>
          <div>
            <div className="nav-title">Vulnerability Fix Assistant</div>
            <div className="nav-subtitle">Safe dependency upgrade recommendations</div>
          </div>
        </div>
        {analysisResult && (
          <button className="btn btn-outline" onClick={handleReset}>← New Analysis</button>
        )}
      </nav>

      <main className="main-content">
        {!analysisResult ? (
          <UploadPage
            trivyFile={trivyFile} pomFile={pomFile}
            setTrivyFile={setTrivyFile} setPomFile={setPomFile}
            onAnalyze={handleAnalyze} loading={loading} error={error}
          />
        ) : (
          <Dashboard
            data={analysisResult}
            onDownloadFix={handleDownloadFix}
            onReset={handleReset}
          />
        )}
      </main>
    </div>
  );
}

export default App;
