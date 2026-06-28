#!/bin/bash
set -e

echo "Installing dependencies..."
pip install numpy matplotlib scipy --quiet

echo "Running experiments..."
python3 /output/run_all.py

echo "Done! Results saved to /output/"
ls -lh /output/
