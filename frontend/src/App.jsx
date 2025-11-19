import React, { useState } from 'react'
import FileUpload from './components/FileUpload'
import ResultsTable from './components/ResultsTable'
import Statistics from './components/Statistics'
import './App.css'

function App() {
  const [scanResults, setScanResults] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)

  const handleScanComplete = (results) => {
    setScanResults(results)
    setLoading(false)
    setError(null)
  }

  const handleScanStart = () => {
    setLoading(true)
    setError(null)
    setScanResults(null)
  }

  const handleError = (err) => {
    setError(err)
    setLoading(false)
  }

  return (
    <div className="app">
      <header className="app-header">
        <h1>🛡️ SOCinator</h1>
        <p className="subtitle">Security Analysis Tool - Log & File Scanner</p>
      </header>

      <main className="app-main">
        <FileUpload
          onScanStart={handleScanStart}
          onScanComplete={handleScanComplete}
          onError={handleError}
          loading={loading}
        />

        {error && (
          <div className="error-message">
            <p>❌ Error: {error}</p>
          </div>
        )}

        {scanResults && (
          <>
            <Statistics results={scanResults} />
            <ResultsTable results={scanResults} />
          </>
        )}
      </main>

      <footer className="app-footer">
        <p>Powered by Sigma & YARA Rules | MITRE ATT&CK Framework</p>
      </footer>
    </div>
  )
}

export default App

