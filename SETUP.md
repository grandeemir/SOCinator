# SOCinator Setup Guide

## Quick Start

### 1. Install System Dependencies

**Ubuntu/Debian:**
```bash
sudo apt-get update
sudo apt-get install yara python3-pip nodejs npm
```

**macOS:**
```bash
brew install yara python3 node
```

**Arch Linux:**
```bash
sudo pacman -S yara python-pip nodejs npm
```

### 2. Backend Setup

```bash
cd backend
pip install -r requirements.txt
python main.py
```

The backend will start on `http://localhost:8000`

### 3. Frontend Setup

Open a new terminal:

```bash
cd frontend
npm install
npm run dev
```

The frontend will start on `http://localhost:3000`

## Using the Application

1. Open your browser and navigate to `http://localhost:3000`
2. Click "Choose File" and select a log file or any file to scan
3. Select scan type:
   - **Both**: Scans with both Sigma and YARA rules
   - **Sigma**: Only log analysis with Sigma rules
   - **YARA**: Only file scanning with YARA rules
4. Click "🔍 Scan File"
5. Review the results in the table
6. Use filters to narrow down results by severity or rule type
7. Click "📄 Download PDF Report" to generate a PDF report

## Testing

### Test with Sample Log File

Create a test log file (`test.log`):

```
powershell.exe -Command "Invoke-WebRequest"
wmic process call create "cmd.exe /c whoami"
Failed password for user admin
Failed password for user admin
Failed password for user admin
Failed password for user admin
Failed password for user admin
Failed password for user admin
```

Upload this file and scan with "Both" to see detections.

### Test with Sample Malicious File

Create a test PHP file (`test.php`):

```php
<?php
eval(base64_decode("cGhwaW5mbygpOw=="));
system($_GET['cmd']);
?>
```

Upload this file and scan with "YARA" to detect web shell patterns.

## Troubleshooting

### YARA Installation Issues

If you get errors about YARA:
- Make sure YARA is installed: `yara --version`
- On Linux, you may need: `sudo apt-get install libyara-dev`
- On macOS: `brew install yara`

### Port Already in Use

If port 8000 or 3000 is already in use:
- Backend: Edit `backend/main.py` and change the port
- Frontend: Edit `frontend/vite.config.js` and change the port

### CORS Errors

If you see CORS errors, make sure:
- Backend is running on port 8000
- Frontend is running on port 3000
- CORS middleware is enabled in `backend/main.py`

## API Documentation

Once the backend is running, visit:
- API Docs: `http://localhost:8000/docs`
- Alternative Docs: `http://localhost:8000/redoc`

## Project Structure

```
SOCinator/
├── backend/
│   ├── main.py              # FastAPI application
│   ├── sigma_engine.py      # Sigma rule engine
│   ├── yara_engine.py       # YARA rule engine
│   ├── pdf_generator.py     # PDF report generator
│   ├── sigma_rules/         # 10 Sigma rules
│   └── yara_rules/          # 5 YARA rules
├── frontend/
│   ├── src/
│   │   ├── components/      # React components
│   │   ├── App.jsx
│   │   └── main.jsx
│   └── package.json
└── README.md
```

## Next Steps

- Add more Sigma and YARA rules
- Implement false positive detection logic
- Add user authentication
- Implement rule management interface
- Add database for storing scan history
- Enhance PDF reports with charts and graphs

