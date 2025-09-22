# NoSwiper Security Hardening Summary

## Overview
This document summarizes the comprehensive security hardening applied to the NoSwiper IPC server to defend against sophisticated attacks.

## Security Improvements Implemented

### 1. Authentication & Authorization
- **Peer Credential Verification**: Uses platform-specific APIs (getpeereid on macOS, SO_PEERCRED on Linux) to verify client identity
- **Access Control**: Only root (UID 0) or admin group members (GID 80 on macOS) can connect
- **No Network Exposure**: Uses UNIX domain sockets only, preventing remote attacks

### 2. Input Validation & Sanitization
- **Size Limits**: Maximum 64KB per request line to prevent memory exhaustion
- **JSON Validation**: Proper error handling for malformed JSON inputs
- **YAML Injection Prevention**: Sanitization of all strings before writing to YAML config files
  - Only alphanumeric and safe characters allowed
  - Maximum string length of 1024 characters
  - Directory traversal patterns blocked

### 3. Rate Limiting
- **Per-Client Limits**: Each client tracked by UID/PID with individual rate limits
- **Sliding Window**: 10 requests per second maximum per client
- **Automatic Cleanup**: Rate limiter entries removed when clients disconnect

### 4. Memory Protection
- **Event History Limits**: Maximum 10,000 events stored in memory
- **Automatic Expiration**: Events older than 24 hours automatically removed
- **Cleanup Task**: Background task runs every 5 minutes to clean expired data

### 5. Process Security
- **PID Reuse Protection**: Verifies process identity before SIGCONT/SIGKILL operations
- **Process Verification**: Checks process name and start time match expectations
- **Time-based Validation**: Suspended processes expire after 1 hour

### 6. File System Security
- **Secure Socket Permissions**: Uses umask(0o117) during socket creation for 660 permissions
- **Double-Check Permissions**: Explicitly sets permissions after creation
- **Custom Rules File**: Written with 644 permissions (readable but only root-writable)
- **Directory Permissions**: Config directory created with 755 permissions

### 7. Attack Surface Minimization
- **Server-Controlled Scope**: `allow_permanently` only accepts event_id
  - Server derives allow rule scope from trusted event history
  - Prevents clients from injecting malicious paths or arguments
- **Atomic Operations**: File writes use flush() and sync_all() for consistency
- **Error Information Limiting**: Generic error messages to prevent information leakage

### 8. Race Condition Prevention
- **TOCTOU Mitigation**:
  - Socket permissions set atomically with umask
  - Process verification immediately before operations
  - Event data cloned to prevent concurrent modification issues

## Security Architecture

```
Client Process
     ↓
[UNIX Socket] ← Peer Credential Check
     ↓
[Rate Limiter] ← Per-client tracking
     ↓
[Input Validation] ← Size limits, JSON parsing
     ↓
[Request Handler] ← Authorization checks
     ↓
[Event History] ← Server-controlled data only
     ↓
[Process Operations] ← PID verification
     ↓
[File Operations] ← Sanitized YAML writing
```

## Testing Recommendations

1. **Authorization Testing**: Verify non-root/non-admin users cannot connect
2. **Rate Limit Testing**: Send rapid requests to verify rate limiting works
3. **Input Fuzzing**: Test with malformed JSON, oversized requests
4. **Injection Testing**: Attempt YAML injection with special characters
5. **Resource Exhaustion**: Try to exhaust memory with many events
6. **PID Reuse**: Test process operations with recycled PIDs

## Future Enhancements

1. **Audit Logging**: Log all security-relevant operations
2. **Cryptographic Authentication**: Add HMAC or signature-based auth
3. **Privilege Separation**: Run IPC handler in separate process
4. **Sandboxing**: Use seccomp/pledge to limit syscalls
5. **Connection Limits**: Limit total concurrent connections

## Compliance

The implementation follows security best practices:
- **Defense in Depth**: Multiple layers of security controls
- **Least Privilege**: Minimum necessary permissions
- **Fail Closed**: Denies access when uncertain
- **Input Validation**: Never trusts client-provided data
- **Secure Defaults**: Safe configuration out of the box