#!/usr/bin/env bash
set -e

# Ensure we are in the repository root
dirname=$(dirname "$0")
cd "$dirname"

# Create virtual environment if missing
if [ ! -d ".venv" ]; then
  echo "Creating virtual environment..."
  python3 -m venv .venv
fi

# Activate virtual environment
source .venv/bin/activate

# Upgrade pip and install dependencies
pip install --upgrade pip
pip install -r requirements.txt

# Run the FastAPI development server
uvicorn traffic-analyzer.backend.main:app --reload
