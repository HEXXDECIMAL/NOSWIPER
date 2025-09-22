#!/bin/bash

# Test script for shell history file access with -l flag

echo "Testing shell history file access restrictions..."
echo ""

# Test 1: Fish with -l flag (should be allowed)
echo "Test 1: fish -l accessing fish_history (should be ALLOWED)"
echo "Command: fish -l -c 'cat ~/.local/share/fish/fish_history'"
echo ""

# Test 2: Fish without -l flag (should be blocked)
echo "Test 2: fish without -l accessing fish_history (should be BLOCKED)"
echo "Command: fish -c 'cat ~/.local/share/fish/fish_history'"
echo ""

# Test 3: Bash with -l flag (should be allowed)
echo "Test 3: bash -l accessing .bash_history (should be ALLOWED)"
echo "Command: bash -l -c 'cat ~/.bash_history'"
echo ""

# Test 4: Bash without -l flag (should be blocked)
echo "Test 4: bash without -l accessing .bash_history (should be BLOCKED)"
echo "Command: bash -c 'cat ~/.bash_history'"
echo ""

# Test 5: Cross-shell access (should be blocked regardless of -l)
echo "Test 5: bash -l accessing fish_history (should be BLOCKED)"
echo "Command: bash -l -c 'cat ~/.local/share/fish/fish_history'"
echo ""

echo "Run the noswiper daemon with --monitor or --enforce mode,"
echo "then manually test these commands in another terminal to verify behavior."