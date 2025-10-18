# NoSwiper

**Experimental kernel-level credential protection daemon**

> **⚠️ EXPERIMENTAL SOFTWARE** — This is a research prototype under active development. Not recommended for production use. Test thoroughly before relying on it. Use at your own risk.

NoSwiper monitors and controls access to sensitive credential files on macOS, Linux, and BSD systems. It uses kernel-level facilities to intercept file access attempts before they succeed, allowing you to define which processes can legitimately access your secrets.

---

## The Problem

Traditional file permissions can't protect you from malicious code running as your user. If an attacker compromises a process under your account, they can trivially exfiltrate credentials:

```bash
cat ~/.ssh/id_rsa
cat ~/.aws/credentials
cat ~/Library/Application\ Support/Google/Chrome/Default/Login\ Data
```

File encryption at rest doesn't help—credentials must be decrypted for use. Traditional endpoint protection relies on signatures and behavior analysis that miss novel attacks or legitimate tools used maliciously.

## The Solution

NoSwiper intercepts file open syscalls at the kernel level and applies fine-grained access rules based on:

1. **Process identity** - Which program is making the request (code signature on macOS, path on Linux)
2. **File path** - Which credential is being accessed
3. **User decisions** - Interactive approval for unexpected access patterns

When unauthorized access is attempted, NoSwiper can log, block, or prompt the user—all before the syscall completes.

---

## How It Works

### Monitoring Mechanisms

NoSwiper uses OS-native kernel facilities to monitor file access:

| Platform | Mechanism | Description |
|----------|-----------|-------------|
| **macOS** | `eslogger` | Endpoint Security Framework via Apple's eslogger utility (no entitlements needed) |
| **macOS** | ESF direct | Native Endpoint Security Framework API (faster, requires entitlements) |
| **Linux** | `fanotify` | File access notification API (older kernels, simpler) |
| **Linux** | eBPF | Extended Berkeley Packet Filter (newer kernels, more powerful) |
| **FreeBSD/NetBSD** | DTrace | Dynamic tracing framework |
| **BSD** | kqueue | Native BSD kernel event notification |

The agent automatically selects the best available mechanism for your platform, or you can override with `--mechanism`.

### Execution Flow

```
1. Process attempts: open("/Users/alice/.ssh/id_rsa", O_RDONLY)
2. Kernel intercepts → NoSwiper daemon evaluates rules
3. Decision made:
   ├─ /usr/bin/ssh (Apple-signed) → ALLOW
   ├─ /tmp/malware.sh (unknown) → DENY
   └─ /opt/custom-tool → PROMPT user
4. Syscall succeeds or fails based on decision
```

### What Gets Protected (Default Rules)

Out of the box, NoSwiper monitors these credential types:

**SSH & Version Control**
- `~/.ssh/id_*`, `~/.ssh/*_key` — SSH private keys
- `~/.gitconfig`, `~/.git-credentials` — Git credentials

**Cloud Providers**
- `~/.aws/credentials`, `~/.aws/config` — Amazon Web Services
- `~/.config/gcloud/**/credentials.db` — Google Cloud Platform
- `~/.azure/accessTokens.json` — Microsoft Azure
- `~/.kube/config` — Kubernetes cluster credentials

**Package Managers**
- `~/.npmrc` — npm registry tokens
- `~/.pypirc` — Python Package Index credentials
- `~/.cargo/credentials.toml` — Rust crate registry
- `~/.docker/config.json` — Docker Hub credentials
- `~/.gem/credentials` — RubyGems API keys

**Browser Credential Stores** (macOS & Linux paths)
- Chrome/Chromium login data and cookies
- Firefox logins.json and key databases
- Safari bookmarks and cookies

**Encryption Keys**
- `~/.gnupg/` — GPG/PGP private keys
- `~/.password-store/` — pass password manager
- `~/Library/Keychains/` — macOS Keychain (limited monitoring)

See `agent/src/defaults.rs` for the complete list of protected paths and allowed processes.

---

## Installation & Quick Start

### Building from Source

```bash
# Clone the repository
git clone https://github.com/yourusername/noswiper
cd noswiper

# Build release binary
cargo build --release

# The agent requires root privileges for kernel monitoring APIs
sudo ./target/release/noswiper-agent --help
```

### Running the Agent

The daemon supports three operating modes:

#### 1. Monitor Mode (Recommended for Testing)

Logs all credential access attempts without blocking—safe for understanding baseline behavior:

```bash
sudo ./target/release/noswiper-agent --monitor
```

Or using Make:
```bash
sudo make monitor
```

Watch logs to see what's accessing your credentials:
```
[INFO] ALLOWED: /usr/bin/ssh (Apple, signed) → ~/.ssh/id_ed25519
[WARN] WOULD_BLOCK: /tmp/suspicious.sh → ~/.aws/credentials
```

#### 2. Interactive Mode

Blocks unauthorized access and prompts via CLI for user decisions:

```bash
sudo ./target/release/noswiper-agent --interactive
```

You'll see prompts like:
```
Credential Access Request
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Process:  /usr/local/bin/ansible
File:     /Users/alice/.ssh/id_rsa
Action:   READ

Allow this access? [y/N/always]:
```

#### 3. Enforce Mode (Default)

Blocks unauthorized access silently based on configured rules:

```bash
sudo ./target/release/noswiper-agent
# Or explicitly:
sudo ./target/release/noswiper-agent --enforce
```

Or using Make:
```bash
sudo make enforce
```

### Additional Options

```bash
# Verbose output (show all file access, not just protected files)
sudo ./target/release/noswiper-agent --monitor --verbose

# Debug mode (detailed logs for protected files only)
sudo ./target/release/noswiper-agent --monitor --debug

# Show current configuration and exit
sudo ./target/release/noswiper-agent --show-config

# Validate a config file
sudo ./target/release/noswiper-agent --validate-config ~/.config/noswiper/config.yaml

# Specify monitoring mechanism
sudo ./target/release/noswiper-agent --monitor --mechanism eslogger  # macOS
sudo ./target/release/noswiper-agent --monitor --mechanism fanotify  # Linux
```

---

## User Interfaces

NoSwiper provides three UI options for different use cases:

### 1. macOS Native UI (Recommended for macOS)

A native Swift/SwiftUI menu bar application with real-time violation alerts.

**Features:**
- Lives in macOS menu bar (doesn't clutter Dock)
- Native alert dialogs using SF Symbols
- Shows process hierarchy for access attempts
- Toggle between Monitor and Enforce modes
- Auto-reconnects to daemon
- ~2MB bundle, ~15MB memory footprint

**Building and Running:**

```bash
# Build and run using Make (from project root)
make build-ui-macos
make run-ui-macos

# Or build directly
cd ui/macos
./build.sh Release
open build/NoSwiper.app
```

**Requirements:**
- macOS 13.0 or later
- Xcode Command Line Tools

**Important:** Start the daemon first:
```bash
sudo make enforce  # or sudo make monitor
```

Then launch the UI app. See `ui/macos/README.md` for detailed documentation.

### 2. Tauri UI (Cross-platform, Legacy)

Web-based UI using Rust + Tauri for macOS/Linux/Windows support.

**Building and Running:**

```bash
cd ui-tauri
npm install
npm run tauri dev      # Development mode
npm run tauri build    # Production build
```

**Note:** The macOS native UI is now the preferred option for macOS users. Tauri remains available for cross-platform scenarios or if you prefer web technologies.

### 3. CLI Mode

Terminal-based interaction using the `--interactive` flag (no separate UI process required):

```bash
sudo ./target/release/noswiper-agent --interactive
```

Best for:
- Server environments
- Testing and development
- Systems without GUI
- Automated testing workflows

---

## Configuration

### Zero-Config Operation

NoSwiper works out of the box with sensible defaults. Most users don't need custom configuration.

### Custom Configuration

Create `~/.config/noswiper/config.yaml` to override or extend defaults:

```yaml
# Example configuration
rules:
  # Allow custom deployment script to access AWS credentials
  - path: "~/.aws/credentials"
    allowed_processes:
      - "/usr/local/bin/aws"
      - "/Users/alice/bin/deploy.sh"
    action: block  # block, allow, or prompt

  # Protect additional custom credential files
  - path: "~/secrets/*.key"
    allowed_processes: []
    action: prompt  # Ask user for any access

# Logging configuration
log_level: info  # debug, info, warn, error
log_to_syslog: true
```

See the agent's `--show-config` output for the full merged configuration including defaults.

---

## Security Model

### Threat Model

**What NoSwiper Protects Against:**
- ✅ Opportunistic credential theft by malware/scripts running as your user
- ✅ Accidental credential exposure from buggy software
- ✅ Supply chain attacks in dependencies (e.g., malicious npm packages)
- ✅ Lateral movement after initial compromise (harder for attackers to grab SSH keys)

**What NoSwiper Does NOT Protect Against:**
- ❌ Kernel-level rootkits (NoSwiper runs in userspace)
- ❌ Attacks against NoSwiper itself (requires root to modify)
- ❌ Memory scraping of processes that legitimately loaded credentials
- ❌ Social engineering (user approving malicious requests in interactive mode)
- ❌ Physical access attacks (attacker with root can disable the daemon)
- ❌ Credentials already exfiltrated before NoSwiper was installed

### Known Limitations

1. **macOS Code Signatures**: Current implementation trusts process code signatures reported by the OS, which can be spoofed by root-level attackers
2. **Linux Path-Based Trust**: Executable paths can be manipulated; planned eBPF support will improve attribution
3. **TOCTOU Races**: Small time window between access check and actual file read (inherent to userspace enforcement)
4. **Post-Read Exfiltration**: NoSwiper can't prevent credentials from being exfiltrated after a legitimate process reads them
5. **No Kernel Module**: Running in userspace means sophisticated attackers with kernel access can bypass protections

### Trust Assumptions

- The NoSwiper daemon is trusted (runs as root)
- Configuration files are user-controlled (users can weaken their own protection)
- The OS kernel is trusted to accurately report process information
- Code signature verification (macOS) and path validation (Linux) are reliable

---

## Development

### Building

```bash
# Debug build (fast iteration)
cargo build

# Release build (optimized)
cargo build --release

# Build using Make
make build        # Agent + macOS UI (debug)
make release      # Agent + macOS UI (release)
make build-agent  # Agent only
```

### Testing

```bash
# Run test suite
cargo test --workspace

# Or using Make
make test
```

### Linting

```bash
# Check formatting and run clippy
cargo fmt --all --check
cargo clippy --workspace -- -D warnings

# Or using Make
make lint
```

### Platform Support Status

| Platform | Status | Notes |
|----------|--------|-------|
| macOS 13+ | ✅ Working | Primary development platform, eslogger + ESF support |
| Linux (modern) | ✅ Working | fanotify supported, eBPF in development |
| FreeBSD | 🟡 Experimental | DTrace support, needs testing |
| NetBSD | 🟡 Experimental | DTrace support, needs testing |
| OpenBSD | 🟡 Planned | kqueue support planned |
| Windows | ❌ Not supported | Would require kernel driver ($$ for signing) |

---

## Project Status

### Current State

This is experimental software suitable for:
- Security research and exploration
- Testing and evaluation
- Personal use by technically sophisticated users who understand the limitations

**Not recommended for:**
- Enterprise production deployments
- Protecting highly sensitive environments without additional layers of defense
- Users who can't tolerate occasional false positives/negatives

### Known Issues

- IPC protocol between daemon and UI is basic (planned: HMAC authentication, replay protection)
- macOS ESF direct mode requires manual entitlement configuration
- eBPF support for Linux not yet implemented
- Limited telemetry/audit logging (no structured export to SIEM yet)

### Contributing

Contributions welcome. Areas needing help:
- Testing on different OS versions and configurations
- FreeBSD/NetBSD real-world testing
- Performance benchmarking with large rule sets
- Security review of the IPC protocol
- Documentation improvements

File issues or PRs at: https://github.com/yourusername/noswiper

---

## License

See LICENSE file for details.
