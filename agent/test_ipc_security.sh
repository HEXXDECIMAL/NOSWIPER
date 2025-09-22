#!/bin/bash
# Test script for IPC server security improvements

echo "Testing NoSwiper IPC Security Features"
echo "======================================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m' # No Color

# Test 1: Verify socket permissions
echo -e "\n${GREEN}Test 1: Socket permissions${NC}"
sudo ./target/release/noswiper-agent --monitor &
AGENT_PID=$!
sleep 2

if [ -S /var/run/noswiper.sock ]; then
    PERMS=$(ls -l /var/run/noswiper.sock | awk '{print $1}')
    echo "Socket permissions: $PERMS"
    if [[ "$PERMS" == "srw-rw----"* ]]; then
        echo -e "${GREEN}✓ Socket has correct permissions (660)${NC}"
    else
        echo -e "${RED}✗ Socket has incorrect permissions${NC}"
    fi
else
    echo -e "${RED}✗ Socket not found${NC}"
fi

# Test 2: Try connecting as non-root/non-admin user
echo -e "\n${GREEN}Test 2: Authorization check${NC}"
echo "Attempting to connect as regular user (should fail)..."
echo '{"action": "status"}' | nc -U /var/run/noswiper.sock 2>&1 | head -1

# Test 3: Rate limiting test
echo -e "\n${GREEN}Test 3: Rate limiting${NC}"
echo "Sending rapid requests to test rate limiting..."

# Create a test client that sends many requests
cat > /tmp/test_rate_limit.py << 'EOF'
import socket
import json
import time

sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
try:
    sock.connect('/var/run/noswiper.sock')

    # Send 15 requests quickly (should trigger rate limit after 10)
    for i in range(15):
        request = json.dumps({"action": "status"}) + '\n'
        sock.send(request.encode())
        response = sock.recv(1024).decode()
        if "Rate limit" in response:
            print(f"Rate limit triggered at request {i+1}")
            break
        time.sleep(0.05)  # Small delay between requests
    else:
        print("Rate limit not triggered (may need adjustment)")

except Exception as e:
    print(f"Error: {e}")
finally:
    sock.close()
EOF

sudo python3 /tmp/test_rate_limit.py

# Test 4: Invalid JSON handling
echo -e "\n${GREEN}Test 4: Invalid JSON handling${NC}"
echo "Sending malformed JSON..."
echo 'not valid json' | sudo nc -U /var/run/noswiper.sock 2>&1 | head -1

# Test 5: Large request handling
echo -e "\n${GREEN}Test 5: Large request rejection${NC}"
echo "Sending oversized request (>64KB)..."
python3 -c "import sys; sys.stdout.write('{\"action\": \"status\", \"padding\": \"' + 'x'*70000 + '\"}\n')" | sudo nc -U /var/run/noswiper.sock 2>&1 | head -1

# Cleanup
echo -e "\n${GREEN}Cleaning up...${NC}"
sudo kill $AGENT_PID 2>/dev/null
rm -f /tmp/test_rate_limit.py

echo -e "\n${GREEN}Security tests completed!${NC}"