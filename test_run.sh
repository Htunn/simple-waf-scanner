#!/bin/bash
# Quick test script for WAF scanner
# Run manually with: ./test_run.sh

echo "Testing WAF Scanner against api.simpleportchecker.com"
echo ""
echo "This will prompt for legal consent..."
echo ""

./target/release/waf-scan https://api.simpleportchecker.com \
    --concurrency 3 \
    --delay 300 \
    --output-json > test_results.json

echo ""
echo "Results saved to test_results.json"
