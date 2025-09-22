# NoSwiper Client API Documentation

## Overview

NoSwiper provides a secure UNIX socket API that allows authorized client programs to:
- Subscribe to security events in real-time
- Respond to credential access attempts
- Manage allow/deny decisions for suspended processes
- Add permanent allow rules

## Connection Details

### Socket Location
- **macOS**: `/var/run/noswiper.sock`
- **Linux/FreeBSD**: `/run/noswiper.sock`

### Permissions
- Socket permissions: `0660` (rw-rw----)
- Only accessible by root and admin/wheel group members
- Clients must run with appropriate privileges

### Protocol
- Line-based JSON over UNIX socket
- Each message is a single line of JSON terminated with `\n`
- Request/response pattern with optional event streaming

## Authentication & Security

1. **UNIX Socket Permissions**: Only root and admin group can connect
2. **Peer Credential Verification**: The server verifies the connecting process UID
3. **No Network Access**: UNIX sockets only, no TCP/IP exposure
4. **Secure File Permissions**: Custom rules file is root-owned with restricted permissions

## Message Format

All messages use JSON with a discriminator field for type identification.

### Client Requests

Clients send requests as single-line JSON messages:

```json
{ "action": "<action_type>", ...params }
```

### Server Responses

Server responds with status and optional data:

```json
{ "status": "success|error|event|status", ...data }
```

## API Operations

### 1. Subscribe to Events

Subscribe to receive real-time security events.

**Request:**
```json
{
  "action": "subscribe",
  "filter": {
    "event_types": ["access_denied", "access_allowed"],
    "min_severity": "warning"
  }
}
```

**Response:**
```json
{ "status": "success", "message": "Subscribed to events" }
```

**Subsequent Event Stream:**
```json
{
  "status": "event",
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "timestamp": "2024-01-15T10:30:45Z",
  "type": "access_denied",
  "rule_name": "ssh_keys",
  "file_path": "/Users/alice/.ssh/id_rsa",
  "process_path": "/usr/bin/malware",
  "process_pid": 12345,
  "process_cmdline": "malware --steal-creds",
  "process_euid": 501,
  "parent_pid": 1,
  "team_id": null,
  "action": "suspended"
}
```

### 2. Allow Once

Resume a suspended process, allowing it one-time access to the requested resource.

**Request:**
```json
{
  "action": "allow_once",
  "event_id": "550e8400-e29b-41d4-a716-446655440000"
}
```

**Response:**
```json
{ "status": "success", "message": "Process 12345 resumed" }
```

**Error Response:**
```json
{ "status": "error", "message": "Event not found or process not suspended" }
```

### 3. Allow Permanently

Resume the suspended process and add a permanent allow rule to prevent future blocks. The scope for the rule is automatically derived from the event details stored on the server.

**Request:**
```json
{
  "action": "allow_permanently",
  "event_id": "550e8400-e29b-41d4-a716-446655440000"
}
```

**Response:**
```json
{ "status": "success", "message": "Process resumed and permanent allow rule added" }
```

**Note:**
- The permanent rule is added to `/etc/noswiper/custom_rules.yaml` and takes effect immediately
- The scope (process path, file path, arguments) is derived from the original event stored on the server
- This approach prevents clients from injecting malicious paths or arguments

### 4. Kill Process

Terminate a suspended process instead of allowing it to continue.

**Request:**
```json
{
  "action": "kill",
  "event_id": "550e8400-e29b-41d4-a716-446655440000"
}
```

**Response:**
```json
{ "status": "success", "message": "Process 12345 killed" }
```

### 5. Get Status

Query the current status of the NoSwiper daemon.

**Request:**
```json
{ "action": "status" }
```

**Response:**
```json
{
  "status": "status",
  "mode": "enforce",
  "events_pending": 3,
  "connected_clients": 2
}
```

## Event Types

### access_denied

Emitted when a process is denied access to a protected resource.

```json
{
  "type": "access_denied",
  "rule_name": "aws_credentials",
  "file_path": "/Users/bob/.aws/credentials",
  "process_path": "/tmp/suspicious",
  "process_pid": 54321,
  "process_cmdline": "suspicious --upload",
  "process_euid": 501,
  "parent_pid": 12345,
  "team_id": null,
  "action": "blocked"
}
```

**Actions:**
- `"blocked"` - Access denied, process continues
- `"suspended"` - Process suspended awaiting decision
- `"killed"` - Process was terminated

### access_allowed

Emitted when a process is allowed access to a protected resource.

```json
{
  "type": "access_allowed",
  "rule_name": "ssh_agent",
  "file_path": "/Users/alice/.ssh/id_rsa",
  "process_path": "/usr/bin/ssh-add",
  "process_pid": 9876,
  "process_cmdline": "ssh-add",
  "process_euid": 501
}
```

## Custom Rules File Format

Permanent allow rules are stored in `/etc/noswiper/custom_rules.yaml`:

```yaml
# Custom allow rules managed by NoSwiper IPC
# DO NOT EDIT MANUALLY - Use the client API

# Added by IPC client at 2024-01-15 10:45:00 UTC
- path: "/Applications/GitClient.app/Contents/MacOS/GitClient"
  args: ["--sync"]
  # GitClient needs access for repository sync

# Added by IPC client at 2024-01-15 11:00:00 UTC
- path: "/usr/local/bin/backup-tool"
  # Backup tool needs broad access
```

## Example Client Implementation

### Python Example

```python
import json
import socket
import os

class NoSwiperClient:
    def __init__(self):
        self.socket_path = "/var/run/noswiper.sock" if os.uname().sysname == "Darwin" else "/run/noswiper.sock"
        self.socket = None

    def connect(self):
        self.socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.socket.connect(self.socket_path)

    def send_request(self, request):
        msg = json.dumps(request) + '\n'
        self.socket.send(msg.encode())
        response = self.socket.recv(4096).decode()
        return json.loads(response.strip())

    def subscribe_events(self):
        request = {"action": "subscribe"}
        return self.send_request(request)

    def allow_once(self, event_id):
        request = {"action": "allow_once", "event_id": event_id}
        return self.send_request(request)

    def allow_permanently(self, event_id):
        request = {
            "action": "allow_permanently",
            "event_id": event_id
        }
        return self.send_request(request)

# Usage
client = NoSwiperClient()
client.connect()

# Subscribe to events
client.subscribe_events()

# Handle an event
response = client.allow_once("550e8400-e29b-41d4-a716-446655440000")
print(response)
```

### Shell Example

```bash
#!/bin/bash

# Connect and get status
echo '{"action": "status"}' | nc -U /var/run/noswiper.sock

# Allow a process once
echo '{"action": "allow_once", "event_id": "EVENT_ID_HERE"}' | nc -U /var/run/noswiper.sock

# Subscribe to events (will stream)
echo '{"action": "subscribe"}' | nc -U /var/run/noswiper.sock
```

## Error Handling

All errors return a response with `status: "error"` and a descriptive message:

```json
{
  "status": "error",
  "message": "Description of what went wrong"
}
```

Common error conditions:
- Invalid JSON format
- Unknown action type
- Event ID not found
- Insufficient permissions
- Process already terminated
- Failed to write custom rules

## Best Practices

1. **Always check response status** before processing the data
2. **Handle connection drops** - The socket may close if the daemon restarts
3. **Implement reconnection logic** for long-running clients
4. **Parse events asynchronously** - Events can arrive at any time after subscribing
5. **Validate event IDs** - Store and track event IDs you've processed
6. **Log all actions** - Maintain an audit trail of allow/deny decisions
7. **Use comments** in permanent rules for documentation

## Security Considerations

1. **Privileged Operations**: This API performs privileged operations (process control, file system modifications)
2. **Audit Trail**: All API operations are logged to the system log
3. **No Remote Access**: UNIX sockets cannot be accessed remotely
4. **Rate Limiting**: Consider implementing rate limiting in production clients
5. **Validation**: The server validates all inputs, but clients should also validate

## Limitations

1. **Platform Support**: Process suspension/resumption only works on macOS with eslogger
2. **Single Response**: Each request gets exactly one response (except subscribe which streams)
3. **No Batch Operations**: Each allow/deny/kill operates on a single event
4. **Custom Rules**: Custom rules are appended only, not managed comprehensively