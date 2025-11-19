from fastapi import FastAPI, File, UploadFile, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from typing import List, Optional
import os
import yara
import yaml
import json
from datetime import datetime
from pydantic import BaseModel

from sigma_engine import SigmaEngine
from yara_engine import YaraEngine
from pdf_generator import generate_pdf_report

app = FastAPI(title="SOCinator - Security Analysis Tool")

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize engines
sigma_engine = SigmaEngine()
yara_engine = YaraEngine()

class ScanResult(BaseModel):
    rule_name: str
    detected_pattern: str
    mitre_attack_id: str
    severity: str
    is_false_positive: bool
    rule_type: str
    timestamp: str

class ScanResponse(BaseModel):
    results: List[ScanResult]
    total_detections: int
    high_severity: int
    medium_severity: int
    low_severity: int

@app.get("/")
async def root():
    return {"message": "SOCinator API is running"}

@app.post("/api/scan", response_model=ScanResponse)
async def scan_file(
    file: UploadFile = File(...),
    scan_type: str = "both"
):
    """
    Scan uploaded file with Sigma and/or YARA rules
    scan_type: 'sigma', 'yara', or 'both'
    """
    try:
        # Read file content
        content = await file.read()
        file_content = content.decode('utf-8', errors='ignore')
        file_name = file.filename or "unknown"
        
        results = []
        
        # Apply Sigma rules if requested
        if scan_type in ['sigma', 'both']:
            sigma_results = sigma_engine.scan_logs(file_content, file_name)
            results.extend(sigma_results)
        
        # Apply YARA rules if requested
        if scan_type in ['yara', 'both']:
            yara_results = yara_engine.scan_file(content, file_name)
            results.extend(yara_results)
        
        # Calculate statistics
        high_sev = sum(1 for r in results if r['severity'] == 'High')
        medium_sev = sum(1 for r in results if r['severity'] == 'Medium')
        low_sev = sum(1 for r in results if r['severity'] == 'Low')
        
        return ScanResponse(
            results=[ScanResult(**r) for r in results],
            total_detections=len(results),
            high_severity=high_sev,
            medium_severity=medium_sev,
            low_severity=low_sev
        )
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Scan error: {str(e)}")

@app.post("/api/generate-pdf")
async def generate_pdf(scan_results: dict):
    """
    Generate PDF report from scan results
    """
    from fastapi.responses import FileResponse
    try:
        pdf_path = generate_pdf_report(scan_results)
        return FileResponse(
            pdf_path,
            media_type="application/pdf",
            filename=os.path.basename(pdf_path)
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"PDF generation error: {str(e)}")

@app.get("/api/rules")
async def get_rules():
    """
    Get list of all available rules
    """
    sigma_rules = sigma_engine.get_rules_info()
    yara_rules = yara_engine.get_rules_info()
    
    return {
        "sigma_rules": sigma_rules,
        "yara_rules": yara_rules
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)

