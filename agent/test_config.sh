#!/bin/bash

echo "Testing NoSwiper configuration loading..."
echo ""

# Run with --show-config to see merged configuration
echo "Running: ./target/release/noswiper-agent --show-config | grep -A 5 'shell_history'"
./target/release/noswiper-agent --show-config | grep -A 5 'shell_history'

echo ""
echo "Checking that both unix.yaml and macos.yaml rules are loaded..."
echo ""

# Check for UNIX rules (from unix.yaml)
echo "Checking for UNIX rules (bash_history from unix.yaml):"
./target/release/noswiper-agent --show-config | grep -A 2 'bash_history'

echo ""
echo "Checking for macOS-specific rules (safari_passwords from macos.yaml):"
./target/release/noswiper-agent --show-config | grep -A 2 'safari_passwords'

echo ""
echo "Testing complete. Both UNIX and OS-specific rules should be visible above."