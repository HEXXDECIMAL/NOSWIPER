# macOS Process Suspension Feature

## Overview

While `eslogger` on macOS cannot directly block file access like Linux's `fanotify`, NoSwiper implements an effective workaround using Unix signals to suspend processes that attempt unauthorized credential access.

## How It Works

### Signal-Based Process Control

NoSwiper uses standard Unix signals to control process execution:
- **SIGSTOP (Signal 19)**: Suspends a process immediately
- **SIGCONT (Signal 18)**: Resumes a suspended process

### Implementation

```rust
// Suspend a misbehaving process
kill -STOP <PID>

// Resume after user approval
kill -CONT <PID>
```

## Behavior by Mode

### Monitor Mode
- **Action**: Log only, no suspension
- **Use case**: Passive monitoring, audit trail
- **Process state**: Continues running normally

### Enforce Mode
- **Action**: Suspend violating processes indefinitely
- **Use case**: Strict security enforcement
- **Process state**: Suspended (appears frozen/hung)
- **Recovery**: Manual intervention required (kill process or restart)

### Interactive Mode
- **Action**: Suspend process and prompt user
- **Use case**: User-controlled security
- **Process state**: Suspended while waiting for decision
- **User allows**: Process resumes with `SIGCONT`
- **User denies**: Process remains suspended

## User Experience

### What Users See

When a process is suspended:
1. The command appears to "hang" or freeze
2. Terminal shows no output
3. Process cannot be interrupted with Ctrl+C (requires Ctrl+Z or kill from another terminal)

Example:
```bash
$ cat ~/.ssh/id_rsa
# Process freezes here - no output, no response
```

### Interactive Prompt with Suspension

```
============================================================
⚠️  CREDENTIAL ACCESS DETECTED
============================================================
Application: cat
Full path:   /bin/cat
Process ID:  12345
Status:      SUSPENDED (waiting for decision)
Credential:  /Users/alice/.ssh/id_rsa

This application is trying to access sensitive credentials.

Options:
  [A]llow once     - Resume process and allow access
  [D]eny (default) - Keep process suspended
  [W]hitelist      - Allow this app always
  [S]how more info - Show process state details

Decision [A/d/w/s]?
```

## Technical Details

### Process States

You can verify suspension using `ps`:
```bash
# Check process state
ps aux | grep <PID>

# State codes:
# T - Stopped/Suspended (SIGSTOP)
# R - Running
# S - Sleeping (normal idle)
# Z - Zombie
```

### Advantages
1. **Immediate effect**: Process stops before file read completes
2. **No special privileges**: Uses standard Unix signals
3. **Reversible**: Can resume process if needed
4. **User-friendly**: Clear visual feedback (process hangs)

### Limitations
1. **Not true blocking**: File may be partially read before suspension
2. **Process cleanup**: Suspended processes consume resources
3. **Terminal blocking**: May require new terminal to intervene
4. **Race condition**: Very fast reads might complete before suspension

## Comparison with Linux

| Aspect | macOS (SIGSTOP) | Linux (fanotify) |
|--------|------------------|------------------|
| Blocking mechanism | Process suspension | Kernel-level denial |
| Timing | After open() call | Before open() completes |
| Effect | Process frozen | EPERM error returned |
| Recovery | Manual resume/kill | Automatic error handling |
| Resource usage | Process remains in memory | Clean denial |

## Best Practices

### For Users
1. **Use interactive mode** for desktop systems
2. **Monitor mode** for initial testing
3. **Enforce mode** only with proper understanding
4. **Check suspended processes** regularly: `ps aux | grep " T "`

### For Administrators
1. **Set up monitoring** for suspended processes
2. **Document recovery procedures** for suspended processes
3. **Consider automatic cleanup** scripts for long-suspended processes
4. **Use with system logging** for audit trails

## Recovery Procedures

### Resume a Suspended Process
```bash
# Find suspended processes
ps aux | grep " T "

# Resume specific process
kill -CONT <PID>
```

### Kill a Suspended Process
```bash
# Terminate suspended process
kill -TERM <PID>

# Force kill if needed
kill -KILL <PID>
```

### Bulk Cleanup
```bash
# Kill all suspended cat processes (example)
ps aux | grep " T " | grep "cat" | awk '{print $2}' | xargs kill -TERM
```

## Future Improvements

### Planned Enhancements
1. **Automatic timeout**: Kill suspended processes after X minutes
2. **Process group suspension**: Suspend entire process tree
3. **Notification system**: Alert when processes are suspended
4. **Statistics tracking**: Log suspension events and durations

### ESF Migration
When Endpoint Security Framework support is added:
- True blocking before file access
- No process suspension needed
- Cleaner user experience
- Requires code signing and entitlements

## Security Considerations

### Strengths
- Effective at stopping credential theft
- Visual deterrent (obvious when blocked)
- No kernel modifications needed
- Works with existing tools

### Weaknesses
- Sophisticated malware might handle SIGSTOP
- Fast readers might complete before suspension
- Suspended processes reveal security monitoring
- Resource exhaustion possible with many suspended processes

## Example Scenarios

### Scenario 1: Malware Attempting Credential Theft
```bash
$ ./malware
# Tries to read ~/.ssh/id_rsa
# Process immediately suspended
# Admin notified via logs
# Malware effectively neutralized
```

### Scenario 2: Legitimate Tool Misuse
```bash
$ cat ~/.aws/credentials
# Process suspended
# User prompted for decision
# User denies -> process stays suspended
# User must Ctrl+Z and kill %1
```

### Scenario 3: Developer Testing
```bash
$ ssh-add ~/.ssh/id_rsa
# Recognized as legitimate
# No suspension
# Access allowed and logged
```

## Conclusion

While not as elegant as kernel-level blocking, process suspension via SIGSTOP provides an effective security measure on macOS without requiring special entitlements or kernel extensions. It offers immediate, visible protection against credential theft while maintaining system stability.