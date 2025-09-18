# NoSwiper - Simple Rust-Based Credential Protection

NoSwiper is a minimal credential protection daemon that monitors access to sensitive files and logs/blocks unauthorized access attempts.

## Features

- **Real-time monitoring** of file access to sensitive credentials
- **Interactive CLI mode** for testing and debugging
- **Platform-specific monitoring**:
  - macOS: Uses `eslogger` (no entitlements required)
  - Linux: `fanotify` support (planned)
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
sudo cp target/release/noswiper-daemon /usr/local/bin/

# macOS: Create log directory
sudo mkdir -p /var/log/noswiper

# Linux: The daemon will log to systemd journal
```

## Usage

### Basic Usage

```bash
# Monitor mode (log only, no blocking)
sudo noswiper-daemon --monitor

# Interactive mode (prompt user for decisions)
sudo noswiper-daemon --interactive

# Enforce mode (block unauthorized access)
sudo noswiper-daemon --enforce
```

### Command Line Options

```bash
noswiper-daemon [OPTIONS]

Options:
  --monitor        Monitor-only mode (log access attempts but don't block)
  --enforce        Enforce mode (block unauthorized access)
  --interactive    Interactive mode (prompt user via CLI for decisions)
  --mechanism      Monitoring mechanism: auto, eslogger, esf, fanotify, ebpf
  --log-level      Log level: debug, info, warn, error [default: info]
  --show-config    Show current configuration and exit
  --help           Print help
  --version        Print version
```

### Testing the Daemon

1. **Start in interactive mode** (recommended for testing):
   ```bash
   sudo noswiper-daemon --interactive
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
sudo noswiper-daemon --interactive --log-level debug
```

### Platform-Specific Notes

#### macOS
- Uses `eslogger` by default (no entitlements required)
- ESF support planned (requires code signing and entitlements)
- Validates code signatures when available

#### Linux
- fanotify support planned
- eBPF support planned for newer kernels
- Uses systemd journal for logging

## Limitations

### Current Version (0.1.0)
- **Logging only on macOS**: `eslogger` cannot actually block file access, only log it
- **No GUI**: Command-line interface only
- **Basic rules**: Uses built-in rules only (no custom configuration yet)

### Future Versions
- Real-time blocking on macOS (via ESF)
- Linux support (fanotify/eBPF)
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