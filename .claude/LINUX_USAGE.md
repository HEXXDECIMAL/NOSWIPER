# Linux Usage Guide for NoSwiper

## Prerequisites

### System Requirements
- Linux kernel 2.6.37+ (for fanotify support)
- Root privileges
- Rust 1.70+ (for building from source)

### Verify Kernel Support
```bash
# Check kernel version
uname -r

# Check if fanotify is available
grep CONFIG_FANOTIFY /boot/config-$(uname -r)
# Should show: CONFIG_FANOTIFY=y
```

## Building on Linux

```bash
# Clone the repository
git clone <repository-url>
cd noswiper

# Build the release binary
cargo build --release

# The binary will be at: target/release/noswiper-agent
```

## Installation

### System-wide Installation

```bash
# Install the binary
sudo cp target/release/noswiper-agent /usr/local/bin/
sudo chmod +x /usr/local/bin/noswiper-agent

# Create log directory (optional)
sudo mkdir -p /var/log/noswiper
```

### Systemd Service Setup

Create `/etc/systemd/system/noswiper.service`:

```ini
[Unit]
Description=NoSwiper Credential Protection Daemon
After=network.target
Documentation=https://github.com/yourusername/noswiper

[Service]
Type=simple
ExecStart=/usr/local/bin/noswiper-agent --enforce
Restart=always
RestartSec=10
User=root
StandardOutput=journal
StandardError=journal

# Security hardening
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=read-only
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
```

Enable and start the service:

```bash
sudo systemctl daemon-reload
sudo systemctl enable noswiper
sudo systemctl start noswiper
```

## Usage Examples

### Basic Testing

```bash
# Test in interactive mode
sudo noswiper-agent --interactive

# In another terminal, try accessing protected files
cat ~/.ssh/id_rsa
cat ~/.aws/credentials
```

### Monitor Mode (Log Only)

```bash
# Start monitoring - logs violations but doesn't block
sudo noswiper-agent --monitor

# Watch the logs in another terminal
journalctl -u noswiper -f
```

### Enforce Mode (Block Access)

```bash
# Start enforcing - actually blocks unauthorized access
sudo noswiper-agent --enforce

# Try accessing with unauthorized tool (will be blocked)
cat ~/.ssh/id_rsa
# Error: Permission denied

# But SSH will still work
ssh user@server
```

## Linux-Specific Features

### Real-time Blocking

Unlike macOS (which can only log with eslogger), Linux with fanotify can actually block file access in real-time:

```bash
# Start in enforce mode
sudo noswiper-agent --enforce

# This will be BLOCKED before the file is read
/tmp/malware ~/.ssh/id_rsa
# Error: Permission denied
```

### Process Verification

NoSwiper on Linux verifies processes through multiple methods:

1. **Package Manager Verification**:
   - Checks if binary belongs to a dpkg package (Debian/Ubuntu)
   - Checks if binary belongs to an rpm package (Red Hat/Fedora)

2. **System Path Verification**:
   - Verifies binary is in system directories (/usr/bin, /bin, etc.)

3. **Path Allowlisting**:
   - Checks against predefined safe paths

### Monitored Paths

By default, NoSwiper monitors:
- `/home/*` - All user home directories
- `/root` - Root user directory

This covers most credential storage locations.

## Logging

### View Logs

```bash
# View all NoSwiper logs
journalctl -u noswiper

# Follow logs in real-time
journalctl -u noswiper -f

# View only warnings and errors
journalctl -u noswiper -p warning

# View logs from last hour
journalctl -u noswiper --since "1 hour ago"

# Export logs to file
journalctl -u noswiper > noswiper.log
```

### Log Examples

```
INFO: Initialized fanotify with fd: 3
INFO: Monitoring path: /home
INFO: Monitoring path: /root
INFO: ALLOWED: /usr/bin/ssh -> /home/user/.ssh/id_rsa
WARN: DETECTED: /bin/cat -> /home/user/.ssh/id_rsa
ERROR: BLOCKED: /tmp/suspicious -> /home/user/.aws/credentials
```

## Testing Scenarios

### Test SSH Key Protection

```bash
# Start daemon in enforce mode
sudo noswiper-agent --enforce &

# These should WORK (allowed programs)
ssh -T git@github.com
git clone git@github.com:user/repo.git
rsync -av file.txt server:

# These should be BLOCKED
cat ~/.ssh/id_rsa  # Permission denied
cp ~/.ssh/id_rsa /tmp/  # Permission denied
```

### Test Package Manager Credentials

```bash
# These should WORK
npm install package
pip install package
docker pull image

# These should be BLOCKED
cat ~/.npmrc
cat ~/.pypirc
cat ~/.docker/config.json
```

### Test Interactive Mode

```bash
sudo noswiper-agent --interactive

# In another terminal
cat ~/.ssh/id_rsa

# You'll see a prompt in the daemon terminal:
# ============================================================
# ⚠️  CREDENTIAL ACCESS DETECTED
# ============================================================
# Application: cat
# Full path:   /usr/bin/cat
# Credential:  /home/user/.ssh/id_rsa
#
# Options:
#   [A]llow once
#   [D]eny (default)
#   [W]hitelist this app for this credential
#
# Decision [A/d/w]?
```

## Troubleshooting

### Permission Denied When Starting

```bash
# Ensure you're running as root
sudo noswiper-agent --monitor

# Check if fanotify is available
ls -la /proc/sys/fs/fanotify/
```

### No Events Detected

```bash
# Check if fanotify is working
sudo cat /proc/sys/fs/fanotify/max_user_marks
# Should return a number (default: 8192)

# Increase limits if needed
echo 65536 | sudo tee /proc/sys/fs/fanotify/max_user_marks
echo 1024 | sudo tee /proc/sys/fs/fanotify/max_queued_events
```

### Process Verification Failing

```bash
# Check if process is from a package
dpkg -S /usr/bin/ssh  # Debian/Ubuntu
rpm -qf /usr/bin/ssh   # Red Hat/Fedora

# If not from package but legitimate, add to whitelist in interactive mode
```

### High CPU Usage

```bash
# Reduce monitoring scope if needed
# Currently monitors all of /home and /root
# Future versions will allow configuration
```

## Performance Considerations

- **fanotify** is kernel-level and very efficient
- Minimal overhead for allowed programs
- Caches process verification results
- PID to executable path mappings are cached

## Security Notes

1. **Run as Root**: fanotify requires CAP_SYS_ADMIN capability
2. **Systemd Hardening**: Use the provided service file for security isolation
3. **Audit Trail**: All decisions are logged to systemd journal
4. **No Network Access**: Daemon operates entirely locally

## Distribution-Specific Notes

### Debian/Ubuntu
```bash
# Install build dependencies
sudo apt-get update
sudo apt-get install build-essential pkg-config

# Build and install
cargo build --release
sudo cp target/release/noswiper-agent /usr/local/bin/
```

### Fedora/RHEL
```bash
# Install build dependencies
sudo dnf install gcc pkg-config

# Build and install
cargo build --release
sudo cp target/release/noswiper-agent /usr/local/bin/
```

### Arch Linux
```bash
# Install build dependencies
sudo pacman -S base-devel

# Build and install
cargo build --release
sudo cp target/release/noswiper-agent /usr/local/bin/
```

## Limitations on Linux

1. **Requires Root**: fanotify needs elevated privileges
2. **No Per-User Rules**: Currently applies same rules to all users
3. **Limited to File Open**: Monitors file open, not read/write operations
4. **No Network Monitoring**: Only monitors local file access

## Future Linux Enhancements

- eBPF support for more granular monitoring (kernel 5.8+)
- Per-user rule configuration
- Integration with SELinux/AppArmor
- Memory-mapped file detection
- Container awareness (Docker/Podman)