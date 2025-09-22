#!/bin/bash
# Test script to run NoSwiper with debug logging

echo "Testing NoSwiper with debug logging enabled"
echo "============================================"
echo ""
echo "This will run for 10 seconds and show debug logs"
echo "Try accessing SSH keys with fish or ssh during this time"
echo ""
echo "Starting in 3 seconds..."
sleep 3

# Run with debug logging for 10 seconds
echo "Running NoSwiper with RUST_LOG=debug..."
timeout 10 sudo RUST_LOG=debug ./target/release/noswiper-agent --monitor 2>&1 | grep -E "(Checking if path|Path.*matches|Path.*does NOT|DENIED|allow_rule.rs|config.rs)" || true

echo ""
echo "Test complete. Review the output above for debug information."