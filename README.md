# NoSwiper

Stop credential theft before it happens. NoSwiper monitors file access in real-time and kills processes that try to steal your SSH keys, browser cookies, and other secrets.

## What it does

Watches for unauthorized access to:
- SSH keys and cloud credentials (AWS, GCP, Azure)
- Browser password stores (Chrome, Firefox, Safari)
- Cryptocurrency wallets
- Password managers (1Password, Bitwarden, KeePass)
- Email clients, Discord, Slack tokens

When something sketchy tries to read your SSH key? SIGSTOP. Parent process gets stopped too.

## What it doesn't do (YET)

- UI - TBD (will be in Tauri)
- Persistence - TBD (soon)
- EndpointSecurityFramework support - TBD (needs permission from Apple)

## Quick Start

Run it in monitoring mode, logging violations:


```
make monitor
```

Run it in enforcement mode, stopping processes dead in their tracks:


```
make enforce
```

## Platforms

- **macOS**: Uses eslogger (no SIP disable needed). Can't actually block reads, but kills processes fast.
- **Linux**: fanotify for real kernel-level blocking
- **FreeBSD/NetBSD**: DTrace-based monitoring
- **OpenSolaris**: DTrace (the OG)

## How it works

The agent uses platform-specific APIs to monitor file operations. When a process tries to open a protected file, it checks against allow rules. No match = process gets suspended with SIGSTOP.

Rules are compiled into the binary (see `config/default.yaml`). Uses AND/OR logic:

```yaml
protected_files:
  - pattern: "~/.ssh/id_*"
    allow:
      - base: "ssh"        # Allow ssh binary
      - base: "git"        # Allow git
      - team_id: "EQHXZ8M8AV"  # Or anything signed by Google
        ppid: 1                # ...if launched by launchd
```

## Global Exclusions

Some processes need access to everything (backup tools, Apple system services). These are configured in `global_exclusions`:
- Apple system processes from `/System/*`
- Backup tools like Time Machine, rsync, Syncthing
- Cloud sync (Dropbox, Google Drive, OneDrive)

## Logs

```bash
# macOS
log stream --predicate 'process == "noswiper-agent"'

# Linux
journalctl -f | grep noswiper

# See what got blocked
grep STOPPED /var/log/system.log
```

Example output:
```
[WARN] /tmp/evil[31337/ppid:1]: open /Users/you/.ssh/id_rsa: STOPPED + parent[1]
[INFO] /usr/bin/ssh[42/ppid:100]: open /Users/you/.ssh/id_rsa: OK (allowed)
```

## Building from source

Requires Rust 1.70+. The Makefile handles the rest:

```bash
make          # Debug build
make release  # Optimized build
make monitor  # Build and run in monitor mode
```

## Configuration

Edit `config/default.yaml` and rebuild. No runtime config yet - rules are baked into the binary for security.

Key concepts:
- `base`: Process name (like "firefox")
- `path`: Full path to binary (supports wildcards)
- `team_id`: Apple developer ID (hard to spoof)
- `app_id`: Bundle ID (easier to spoof, less secure)
- `ppid`: Parent PID (1 = launchd on macOS)

## Known Issues

- macOS can't actually prevent reads, just kills processes after the fact
- Firefox shows as lowercase "firefox" not "Firefox"
- No GUI, CLI only
- Config changes require recompiling

