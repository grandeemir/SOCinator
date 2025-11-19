#!/bin/bash
# Start script for SOCinator Frontend

echo "Starting SOCinator Frontend..."
echo "Installing dependencies..."

npm install

echo "Starting development server on http://localhost:3000"
npm run dev

