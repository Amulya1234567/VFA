import React from 'react';
import { RadialBarChart, RadialBar, ResponsiveContainer } from 'recharts';

const gradeColor = { A: '#10b981', B: '#6366f1', C: '#f59e0b', D: '#f97316', F: '#ef4444' };

const ScoreCard = ({ score, grade, summary }) => {
  const color = gradeColor[grade] || '#6b7280';
  const data = [{ value: score, fill: color }];

  return (
    <div className="score-card">
      <h3 className="card-title">Security Health Score</h3>
      <div className="score-body">
        <div className="score-chart">
          <ResponsiveContainer width={160} height={160}>
            <RadialBarChart cx="50%" cy="50%" innerRadius="60%" outerRadius="100%"
              startAngle={90} endAngle={90 - (360 * score / 100)} data={data}>
              <RadialBar dataKey="value" cornerRadius={8} />
            </RadialBarChart>
          </ResponsiveContainer>
          <div className="score-overlay">
            <div className="score-number" style={{ color }}>{score}</div>
            <div className="score-grade" style={{ color }}>Grade {grade}</div>
          </div>
        </div>
        <div className="score-info">
          <p className="score-summary">{summary}</p>
          <div className="grade-legend">
            {Object.entries(gradeColor).map(([g, c]) => (
              <div key={g} className={`grade-pill ${grade === g ? 'active' : ''}`}
                style={grade === g ? { background: c, color: '#fff' } : {}}>
                {g}
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};

export default ScoreCard;
