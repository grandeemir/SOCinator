import React, { useState } from 'react'
import axios from 'axios'
import './FileUpload.css'

function FileUpload({ onScanStart, onScanComplete, onError, loading }) {
  const [selectedFile, setSelectedFile] = useState(null)
  const [scanType, setScanType] = useState('both')

  const handleFileChange = (e) => {
    const file = e.target.files[0]
    setSelectedFile(file)
  }

  const handleScan = async () => {
    if (!selectedFile) {
      onError('Please select a file to scan')
      return
    }

    onScanStart()

    const formData = new FormData()
    formData.append('file', selectedFile)
    formData.append('scan_type', scanType)

    try {
      const response = await axios.post('http://localhost:8000/api/scan', formData, {
        headers: {
          'Content-Type': 'multipart/form-data',
        },
      })

      onScanComplete(response.data)
    } catch (error) {
      onError(error.response?.data?.detail || error.message || 'Scan failed')
    }
  }

  const handleDownloadPDF = async () => {
    // This would require the scan results to be passed or stored
    // For now, we'll show a placeholder
    alert('PDF download feature - requires scan results')
  }

  return (
    <div className="file-upload-container">
      <div className="upload-card">
        <h2>Upload File for Analysis</h2>
        <p className="upload-description">
          Upload log files (Windows Event Log, Linux Syslog, Web logs) or files for security analysis
        </p>

        <div className="file-input-wrapper">
          <input
            type="file"
            id="file-input"
            onChange={handleFileChange}
            className="file-input"
            disabled={loading}
          />
          <label htmlFor="file-input" className="file-label">
            {selectedFile ? selectedFile.name : 'Choose File'}
          </label>
        </div>

        <div className="scan-type-selector">
          <label>Scan Type:</label>
          <select
            value={scanType}
            onChange={(e) => setScanType(e.target.value)}
            disabled={loading}
            className="scan-select"
          >
            <option value="both">Both (Sigma + YARA)</option>
            <option value="sigma">Sigma Rules Only</option>
            <option value="yara">YARA Rules Only</option>
          </select>
        </div>

        <button
          onClick={handleScan}
          disabled={loading || !selectedFile}
          className="scan-button"
        >
          {loading ? 'Scanning...' : '🔍 Scan File'}
        </button>

        {selectedFile && (
          <div className="file-info">
            <p>Selected: <strong>{selectedFile.name}</strong></p>
            <p>Size: {(selectedFile.size / 1024).toFixed(2)} KB</p>
          </div>
        )}
      </div>
    </div>
  )
}

export default FileUpload

