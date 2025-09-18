# NoSwiper - Simple Rust-Based Credential Protection

NoSwiper is a minimal credential protection daemon that monitors access to sensitive files and logs/blocks unauthorized access attempts.

## Features

- **Real-time monitoring** of file access to sensitive credentials
- **Interactive CLI mode** for testing and debugging
- **Platform-specific monitoring**:
  - macOS: Uses `eslogger` (no entitlements required)
  - Linux: `fanotify` support with real-time blocking capability
- **Built-in protection** for common credentials:
  - SSH keys
  - Cloud provider credentials (AWS, GCP, Azure)
  - Package manager tokens (npm, pip, cargo, etc.)
  - Browser password stores
  - GPG keys

## Prerequisites

### macOS
- Install `eslogger` (if not already available):
  ```bash
  # eslogger is typically available on macOS 11+
  # Check with: which eslogger
  ```

### Linux
- Kernel 2.6.37+ (for fanotify support)
- Root privileges (required for fanotify)

### All Platforms
- Rust 1.70+ (for building from source)
- Root/administrator privileges (required for file monitoring)

## Building

```bash
git clone <repository-url>
cd noswiper
cargo build --release
```

## Installation

```bash
# Copy binary to system location
sudo cp target/release/noswiper-agent /usr/local/bin/

# macOS: Create log directory
sudo mkdir -p /var/log/noswiper

# Linux: The daemon will log to systemd journal
```

## Usage

### Basic Usage

```bash
# Default: Enforce mode (block unauthorized access)
sudo noswiper-agent

# Monitor mode (log only, no blocking)
sudo noswiper-agent --monitor

# Interactive mode (prompt user for decisions)
sudo noswiper-agent --interactive
```

### Command Line Options

```bash
noswiper-agent [OPTIONS]

Options:
  --monitor        Monitor-only mode (log access attempts but don't block)
  --interactive    Interactive mode (prompt user via CLI for decisions)
                   (default is enforce mode - block unauthorized access)
  --mechanism      Monitoring mechanism:
                   - auto: Automatically select best available
                   - eslogger: macOS only, no blocking capability
                   - esf: macOS only, requires entitlements (planned)
                   - fanotify: Linux only, can block access
                   - ebpf: Linux only, requires newer kernel (planned)
  --log-level      Log level: debug, info, warn, error [default: info]
  --show-config    Show current configuration and exit
  --help           Print help
  --version        Print version
```

### Testing the Daemon

1. **Start in interactive mode** (recommended for testing):
   ```bash
   sudo noswiper-agent --interactive
   ```

2. **Try accessing protected files**:
   ```bash
   # In another terminal, try to access SSH keys
   cat ~/.ssh/id_rsa

   # Or try with a random tool
   /bin/cat ~/.ssh/id_rsa
   ```

3. **See the prompt** in the daemon terminal and choose an action.

### Example Output

When a violation is detected in interactive mode:

```
============================================================
⚠️  CREDENTIAL ACCESS DETECTED
============================================================
Application: cat
Full path:   /bin/cat
Credential:  /Users/alice/.ssh/id_rsa

This application is trying to access sensitive credentials.

Options:
  [A]llow once
  [D]eny (default)
  [W]hitelist this app for this credential
  [S]how more info

Decision [A/d/w/s]?
```

## Logs

### macOS
```bash
# View logs
tail -f /var/log/noswiper/daemon.log

# Or using unified logging
log show --predicate 'subsystem == "com.noswiper.daemon"' --last 1h
```

### Linux
```bash
# View systemd journal logs
journalctl -u noswiper -f

# View recent entries
journalctl -u noswiper -n 50
```

## Configuration

NoSwiper works with sensible defaults and requires no configuration for most users. The default rules protect:

- **SSH Keys**: `~/.ssh/id_*`, `~/.ssh/*_key`
- **AWS Credentials**: `~/.aws/credentials`, `~/.aws/config`
- **Cloud Providers**: GCP, Azure credential files
- **Package Managers**: npm, pip, cargo, docker credentials
- **Browser Data**: Firefox, Chrome, Safari password stores
- **GPG Keys**: `~/.gnupg/private-keys*`

### Allowed Programs

Each credential type has a list of allowed programs. For example:
- SSH keys: `ssh`, `ssh-add`, `ssh-agent`, `git`, `rsync`, `scp`
- AWS credentials: `aws`, `terraform`, `ansible`, `packer`

## Security Model

- **Simple is secure**: Only system administrators can control the daemon
- **Fail closed**: When in doubt, deny access
- **Trust the OS**: Uses OS-provided security mechanisms
- **Path verification**: Programs must be in legitimate system locations
- **Code signature verification** (macOS): Validates signed binaries

## Development

### Running Tests

```bash
cargo test
```

### Debug Mode

```bash
# Run with debug logging
sudo noswiper-agent --interactive --log-level debug
```

### Platform-Specific Notes

#### macOS
- Uses `eslogger` by default (no entitlements required)
- **Process suspension**: Can suspend violating processes using SIGSTOP
- Validates code signatures when available
- Interactive mode: Suspends process while waiting for user decision
- Enforce mode: Suspends violating processes indefinitely

#### Linux
- Uses `fanotify` for real-time file access monitoring
- **Can actually block unauthorized access** in enforce mode
- Requires kernel 2.6.37+ (most modern Linux distributions)
- eBPF support planned for newer kernels (5.8+)
- Verifies processes via package manager (dpkg/rpm)
- Uses systemd journal for logging

## Limitations

### Current Version (0.1.0)
- **macOS**: Process suspension via SIGSTOP (not true blocking but effective)
- **Linux**: Full kernel-level blocking via fanotify
- **No GUI**: Command-line interface only
- **Basic rules**: Uses built-in rules only (no custom configuration yet)

### Future Versions
- Real-time blocking on macOS (via ESF)
- Enhanced Linux support with eBPF for newer kernels
- GUI application for desktop users
- Custom configuration files
- Encrypted IPC between daemon and UI

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## License

This project is licensed under either of:
- Apache License, Version 2.0
- MIT License

at your option.