import React from 'react';

const PrioritiesPanel = ({ priorities }) => (
  <div className="priorities-panel">
    <h3 className="card-title">🎯 Top Priorities</h3>
    {priorities && priorities.length > 0 ? (
      <div className="priority-list">
        {priorities.map((p, i) => (
          <div key={i} className="priority-item">
            <div className="priority-number">{i + 1}</div>
            <div className="priority-text">{p}</div>
          </div>
        ))}
      </div>
    ) : (
      <p className="empty">No priorities — your project is clean! 🎉</p>
    )}
  </div>
);

export default PrioritiesPanel;
