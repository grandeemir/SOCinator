#!/bin/bash
# Start script for SOCinator Backend

echo "Starting SOCinator Backend..."
echo "Installing dependencies..."

pip install -r requirements.txt

echo "Starting FastAPI server on http://localhost:8000"
python main.py

