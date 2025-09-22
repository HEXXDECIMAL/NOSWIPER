# EUID Ranges Added to NoSwiper Configurations

## Operating System EUID Ranges

### macOS
- **Regular Users**: `501-599`
  - macOS starts user accounts at UID 501
  - System reserves UIDs below 500
  - Range covers typical user accounts

### Linux
- **Regular Users**: `1000-65533`
  - Most distributions start user accounts at UID 1000
  - System users occupy UIDs 1-999
  - Range covers all normal user accounts

### FreeBSD
- **Regular Users**: `1001-65533`
  - FreeBSD starts user accounts at UID 1001
  - System users occupy UIDs 1-1000
  - Range covers all normal user accounts

### OpenBSD
- **Regular Users**: `1000-65533`
  - OpenBSD starts user accounts at UID 1000
  - System users occupy UIDs 1-999
  - Range covers all normal user accounts

### NetBSD
- **Regular Users**: `100-65533`
  - NetBSD starts user accounts at UID 100
  - More permissive range due to different UID allocation
  - Range covers all normal user accounts

## Special EUID Values

### Root/System Processes
- **EUID**: `0`
  - Used for system daemons like `sshd`
  - Only applied where root access is legitimately required

## Security Benefits

1. **Privilege Validation**: Ensures processes run with expected privileges
2. **Escalation Detection**: Blocks processes running with unexpected EUIDs
3. **System Process Protection**: Differentiates between user and system processes
4. **Attack Surface Reduction**: Prevents malware from accessing files with wrong privileges

## Coverage

### High Priority Protections (now with EUID ranges):
- ✅ SSH keys and tools
- ✅ Shell history files
- ✅ Cryptocurrency wallets
- ✅ Communication apps (Discord, Slack, etc.)
- ✅ Cloud credentials (AWS, GCP, Azure)
- ✅ Development tools (Git, package managers)

### Example Rule with EUID:
```yaml
- base: "ssh"
  euid: 501-599  # Only regular users on macOS
```

This prevents malware running as root or system users from accessing user SSH keys, while still allowing legitimate SSH clients to function normally.

## Implementation Notes

- EUID ranges are validated at runtime during file access attempts
- Processes outside the expected EUID range will be denied access
- This adds an additional layer of security beyond path and team ID validation
- Helps detect privilege escalation and unusual process behavior