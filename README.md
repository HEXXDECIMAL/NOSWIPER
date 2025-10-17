# NoSwiper

**Experimental credential protection daemon for macOS and Linux**

NoSwiper monitors access to sensitive credential files (SSH keys, cloud provider tokens, browser password stores) and blocks unauthorized programs from reading them.

## Status

**This is experimental software.** It's functional but under active development. Use at your own risk.

## How It Works

NoSwiper uses OS-level file monitoring to detect when programs try to access your credentials:
- **macOS**: Endpoint Security Framework (via `eslogger`)
- **Linux**: `fanotify` or eBPF

When unauthorized access is detected, NoSwiper can log it, block it, or prompt you to decide.

## Quick Start

```bash
# Build
cargo build --release

# Monitor mode (log only, safe for testing)
sudo ./target/release/noswiper-agent --monitor

# Interactive mode (prompts via CLI)
sudo ./target/release/noswiper-agent --interactive

# Enforce mode (blocks unauthorized access)
sudo ./target/release/noswiper-agent --enforce
```

## What It Protects

By default, NoSwiper protects:
- SSH keys (`~/.ssh/`)
- AWS credentials (`~/.aws/`)
- GCP credentials (`~/.config/gcloud/`)
- GitHub tokens (`~/.config/gh/`)
- Browser password stores
- GPG keys

## Configuration

NoSwiper works out of the box with sensible defaults. To customize, create `~/.config/noswiper/config.yaml`.

## Security Model

- Runs as root to intercept file access
- Fails closed (denies when uncertain)
- Logs all security events to system logs
- Admin users can control the daemon

## License

See LICENSE file for details.
