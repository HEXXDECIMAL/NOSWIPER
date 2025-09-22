#!/bin/bash
# Test script to debug gcloud access with detailed logging

echo "Testing gcloud access with debug logging"
echo "========================================"
echo ""
echo "This will run for 10 seconds with debug logging"
echo "Please run 'gcloud auth list' or similar command in another terminal"
echo ""
echo "Starting in 3 seconds..."
sleep 3

# Run with debug logging for 10 seconds, filtering for relevant logs
timeout 10 sudo ./target/release/noswiper-agent --monitor --debug 2>&1 | grep -E "(gcloud|Python|user_gcloud|Checking allow rule|Rule failed)" || true

echo ""
echo "Test complete. Check the output above for debug information."