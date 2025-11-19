import React, { useState } from 'react'
import axios from 'axios'
import './ResultsTable.css'

function ResultsTable({ results }) {
  const [filterSeverity, setFilterSeverity] = useState('all')
  const [filterType, setFilterType] = useState('all')

  const getSeverityColor = (severity) => {
    const colors = {
      'High': '#e74c3c',
      'Medium': '#f39c12',
      'Low': '#27ae60'
    }
    return colors[severity] || '#95a5a6'
  }

  const getMitreLink = (mitreId) => {
    if (mitreId === 'N/A') return null
    return `https://attack.mitre.org/techniques/${mitreId}/`
  }

  const handleDownloadPDF = async () => {
    try {
      const response = await axios.post('http://localhost:8000/api/generate-pdf', results, {
        responseType: 'blob',
        headers: {
          'Content-Type': 'application/json'
        }
      })
      
      const url = window.URL.createObjectURL(new Blob([response.data], { type: 'application/pdf' }))
      const link = document.createElement('a')
      link.href = url
      link.setAttribute('download', `scan_report_${new Date().toISOString().split('T')[0]}.pdf`)
      document.body.appendChild(link)
      link.click()
      link.remove()
      window.URL.revokeObjectURL(url)
    } catch (error) {
      alert('Error generating PDF: ' + (error.response?.data?.detail || error.message || 'Unknown error'))
    }
  }

  const filteredResults = results.results.filter(result => {
    const severityMatch = filterSeverity === 'all' || result.severity === filterSeverity
    const typeMatch = filterType === 'all' || result.rule_type === filterType
    return severityMatch && typeMatch
  })

  return (
    <div className="results-container">
      <div className="results-header">
        <h2>Detection Results</h2>
        <div className="results-controls">
          <select
            value={filterSeverity}
            onChange={(e) => setFilterSeverity(e.target.value)}
            className="filter-select"
          >
            <option value="all">All Severities</option>
            <option value="High">High</option>
            <option value="Medium">Medium</option>
            <option value="Low">Low</option>
          </select>
          <select
            value={filterType}
            onChange={(e) => setFilterType(e.target.value)}
            className="filter-select"
          >
            <option value="all">All Types</option>
            <option value="Sigma">Sigma</option>
            <option value="YARA">YARA</option>
          </select>
          <button onClick={handleDownloadPDF} className="pdf-button">
            📄 Download PDF Report
          </button>
        </div>
      </div>

      {filteredResults.length === 0 ? (
        <div className="no-results">
          <p>No detections found matching the selected filters.</p>
        </div>
      ) : (
        <div className="table-wrapper">
          <table className="results-table">
            <thead>
              <tr>
                <th>Rule Name</th>
                <th>Type</th>
                <th>Detected Pattern</th>
                <th>MITRE ATT&CK</th>
                <th>Severity</th>
                <th>False Positive</th>
              </tr>
            </thead>
            <tbody>
              {filteredResults.map((result, index) => (
                <tr key={index}>
                  <td className="rule-name">{result.rule_name}</td>
                  <td>
                    <span className={`rule-type-badge ${result.rule_type.toLowerCase()}`}>
                      {result.rule_type}
                    </span>
                  </td>
                  <td className="pattern-cell">
                    <code>{result.detected_pattern.substring(0, 80)}...</code>
                  </td>
                  <td>
                    {getMitreLink(result.mitre_attack_id) ? (
                      <a
                        href={getMitreLink(result.mitre_attack_id)}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="mitre-link"
                      >
                        {result.mitre_attack_id}
                      </a>
                    ) : (
                      <span className="mitre-na">{result.mitre_attack_id}</span>
                    )}
                  </td>
                  <td>
                    <span
                      className="severity-badge"
                      style={{ backgroundColor: getSeverityColor(result.severity) }}
                    >
                      {result.severity}
                    </span>
                  </td>
                  <td>
                    {result.is_false_positive ? (
                      <span className="fp-badge">⚠️ Possible FP</span>
                    ) : (
                      <span className="no-fp">-</span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}

export default ResultsTable

