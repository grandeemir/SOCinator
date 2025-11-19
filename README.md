# 🛡️ SOCinator - Security Analysis Tool

SOCinator is an interactive security analysis tool that scans logs and files using Sigma and YARA rules to detect suspicious activities and malicious files.

## Features

- **Log Analysis**: Scan Windows Event Logs, Linux Syslog, Web logs, and more using Sigma rules
- **File Scanning**: Detect malicious files using YARA rules
- **MITRE ATT&CK Mapping**: All detections are mapped to MITRE ATT&CK framework
- **Risk Assessment**: Severity levels (Low, Medium, High, Critical)
- **PDF Reports**: Generate and download detailed PDF reports
- **Modern UI**: Dark-themed, responsive web interface

## Architecture

### Backend (FastAPI)
- Python-based REST API
- Sigma rule engine for log analysis
- YARA rule engine for file scanning
- PDF report generation

### Frontend (React)
- Modern React application with Vite
- File upload interface
- Interactive results table
- Statistics dashboard
- PDF download functionality

## Installation

### Prerequisites
- Python 3.8+
- Node.js 16+
- YARA library (system dependency)

### Backend Setup

```bash
cd backend
pip install -r requirements.txt

# Install YARA system library (Ubuntu/Debian)
sudo apt-get install yara

# Install YARA system library (macOS)
brew install yara
```

### Frontend Setup

```bash
cd frontend
npm install
```

## Running the Application

### Start Backend

```bash
cd backend
python main.py
```

The API will be available at `http://localhost:8000`

### Start Frontend

```bash
cd frontend
npm run dev
```

The frontend will be available at `http://localhost:3000`

## Usage

1. Open the web interface at `http://localhost:3000`
2. Upload a log file or any file for analysis
3. Select scan type (Sigma, YARA, or Both)
4. Click "Scan File"
5. Review results in the table
6. Download PDF report if needed

## Rules

### Sigma Rules (10 rules)
- Suspicious PowerShell Execution
- Lateral Movement via WMI
- Credential Dumping Activity
- Ransomware Indicators
- Web Shell Upload Detection
- Brute Force Attack Detection
- Data Exfiltration via Network
- Suspicious Scheduled Task Creation
- Privilege Escalation Attempts
- Malicious Process Injection

### YARA Rules (5 rules)
- Generic Malware Signatures
- Ransomware Detection
- Web Shell Detection
- Obfuscated Code Detection
- Credential Harvester Detection

Each rule includes:
- Detailed description
- MITRE ATT&CK mapping
- Severity level
- False positive considerations

## API Endpoints

- `POST /api/scan` - Scan uploaded file
- `POST /api/generate-pdf` - Generate PDF report
- `GET /api/rules` - Get list of all rules

## Project Structure

```
SOCinator/
├── backend/
│   ├── main.py                 # FastAPI application
│   ├── sigma_engine.py         # Sigma rule engine
│   ├── yara_engine.py          # YARA rule engine
│   ├── pdf_generator.py        # PDF report generator
│   ├── sigma_rules/            # Sigma rule files
│   └── yara_rules/             # YARA rule files
├── frontend/
│   ├── src/
│   │   ├── components/         # React components
│   │   ├── App.jsx
│   │   └── main.jsx
│   └── package.json
└── README.md
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

MIT License

## Acknowledgments

- Sigma project for detection rules
- YARA project for file pattern matching
- MITRE ATT&CK framework

