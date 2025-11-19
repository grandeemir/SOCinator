import React from 'react'
import './Statistics.css'

function Statistics({ results }) {
  const { total_detections, high_severity, medium_severity, low_severity } = results

  const stats = [
    {
      label: 'Total Detections',
      value: total_detections,
      color: '#3498db',
      icon: '📊'
    },
    {
      label: 'High Severity',
      value: high_severity,
      color: '#e74c3c',
      icon: '🔴'
    },
    {
      label: 'Medium Severity',
      value: medium_severity,
      color: '#f39c12',
      icon: '🟡'
    },
    {
      label: 'Low Severity',
      value: low_severity,
      color: '#27ae60',
      icon: '🟢'
    }
  ]

  return (
    <div className="statistics-container">
      <h2>Scan Statistics</h2>
      <div className="stats-grid">
        {stats.map((stat, index) => (
          <div key={index} className="stat-card" style={{ borderTopColor: stat.color }}>
            <div className="stat-icon">{stat.icon}</div>
            <div className="stat-value" style={{ color: stat.color }}>
              {stat.value}
            </div>
            <div className="stat-label">{stat.label}</div>
          </div>
        ))}
      </div>
    </div>
  )
}

export default Statistics

