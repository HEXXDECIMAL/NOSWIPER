# Linux Implementation Details

## Architecture

The Linux implementation of NoSwiper uses `fanotify`, a powerful file access notification and permission system available in Linux kernel 2.6.37+.

## Key Components

### 1. `linux_monitor.rs`
Main Linux monitoring module that:
- Initializes fanotify with permission events
- Monitors specific credential directories (not recursive)
- Intercepts file open operations before they complete
- Can allow or deny access in real-time
- Dynamically discovers credential paths from /etc/passwd

### 2. Process Verification (Linux-specific)
Three-tier verification system:
1. **Package verification**: Checks if binary belongs to dpkg/rpm package
2. **System path verification**: Validates binary is in system directories
3. **Path allowlisting**: Checks against predefined safe paths

### 3. fanotify Integration
```rust
// Key fanotify features used:
- FAN_OPEN_PERM: Monitor file open with permission check
- FAN_CLASS_PRE_CONTENT: Intercept before file content access
- FAN_MARK_FILESYSTEM: Monitor entire filesystem recursively
- FAN_ALLOW/FAN_DENY: Real-time access control
```

## How It Works

1. **Initialization**:
   - Opens fanotify file descriptor with `fanotify_init()`
   - Discovers user home directories from `/etc/passwd`
   - Monitors specific credential directories:
     - `~/.ssh`, `~/.aws`, `~/.gnupg`, `~/.docker`
     - `~/.config/gcloud`, `~/.kube`, `~/.azure`
     - Browser credential directories
   - Configures for permission events (blocking mode)

2. **Event Loop**:
   - Reads events from fanotify fd
   - Each event contains: file descriptor, PID, and metadata
   - Resolves file path from fd via `/proc/self/fd/`
   - Resolves process path from PID via `/proc/PID/exe`

3. **Decision Making**:
   - Checks if file matches protected patterns
   - Verifies if process is allowed for that credential
   - Returns FAN_ALLOW or FAN_DENY response
   - In interactive mode, prompts user for decision

4. **Real-time Blocking**:
   - Unlike macOS eslogger, fanotify can actually prevent access
   - Process is paused until decision is made
   - Denial results in EPERM (Permission denied) error

## Advantages Over macOS Implementation

| Feature | Linux (fanotify) | macOS (eslogger) |
|---------|------------------|------------------|
| Real-time blocking | ✅ Yes | ❌ No |
| No special entitlements | ✅ Yes | ✅ Yes |
| Kernel integration | ✅ Direct | ❌ Via command |
| Performance | ✅ Excellent | ⚠️ Good |
| Process suspension | ✅ Native | ❌ Not available |

## Security Features

1. **Mandatory Access Control**: Can enforce access policies
2. **Process Authentication**: Verifies binaries via package managers
3. **Path Validation**: Ensures processes are from legitimate locations
4. **Audit Trail**: All events logged to systemd journal

## Technical Details

### fanotify Constants
```c
// Permission events
FAN_OPEN_PERM     = 0x00010000  // File open permission
FAN_ACCESS_PERM   = 0x00020000  // File access permission
FAN_OPEN_EXEC_PERM = 0x00040000 // Execute permission

// Response values
FAN_ALLOW = 0x01  // Allow the access
FAN_DENY  = 0x02  // Deny the access
FAN_AUDIT = 0x10  // Audit the access
```

### Event Structure
```rust
struct FanotifyEventMetadata {
    event_len: u32,      // Length of this event
    vers: u8,            // Version (must match kernel)
    reserved: u8,        // Reserved
    metadata_len: u16,   // Length of metadata
    mask: u64,           // Event mask
    fd: i32,             // File descriptor
    pid: i32,            // Process ID
}
```

### Response Structure
```rust
struct FanotifyResponse {
    fd: i32,             // File descriptor from event
    response: u32,       // FAN_ALLOW or FAN_DENY
}
```

## Performance Considerations

1. **Caching**: Process paths cached by PID
2. **Selective Monitoring**: Only monitors specific credential directories
3. **No Recursive Monitoring**: Avoids fanotify mark limits
4. **Early Filtering**: Non-protected files immediately allowed
5. **Efficient Verification**: Package checks cached

## fanotify Limits and Tuning

Linux imposes limits on fanotify usage to prevent resource exhaustion:

### Default Limits
- `/proc/sys/fs/fanotify/max_user_marks`: Default 8192 marks per user
- `/proc/sys/fs/fanotify/max_user_groups`: Default 128 groups per user
- `/proc/sys/fs/fanotify/max_queued_events`: Default 16384 events

### Why We Don't Use Recursive Monitoring
- Recursive monitoring (`FAN_MARK_FILESYSTEM`) is expensive
- Each directory and file consumes a mark
- Monitoring `/home` recursively could exhaust limits quickly
- Instead, we monitor specific credential directories only

### Tuning for Production
```bash
# Increase limits if needed
echo 65536 | sudo tee /proc/sys/fs/fanotify/max_user_marks
echo 1024 | sudo tee /proc/sys/fs/fanotify/max_queued_events

# Make permanent via sysctl
echo "fs.fanotify.max_user_marks = 65536" | sudo tee -a /etc/sysctl.conf
echo "fs.fanotify.max_queued_events = 1024" | sudo tee -a /etc/sysctl.conf
sudo sysctl -p
```

## Kernel Requirements

Minimum kernel version: 2.6.37
Recommended: 3.0+ for better performance
Required kernel config:
- CONFIG_FANOTIFY=y
- CONFIG_FANOTIFY_ACCESS_PERMISSIONS=y

## Future Enhancements

1. **eBPF Integration** (kernel 5.8+):
   - More granular filtering
   - Better performance
   - Custom BPF programs

2. **Namespace Awareness**:
   - Container support
   - Per-namespace policies

3. **Extended Attributes**:
   - Use xattrs for custom rules
   - Integration with SELinux labels

4. **Inotify Fallback**:
   - For systems without fanotify
   - Limited to monitoring, no blocking