# NoSwiper - Simple Rust-Based Credential Protection

## Project Philosophy

NoSwiper is a minimal credential protection tool written in Rust. It monitors access to sensitive files and logs/blocks unauthorized access attempts.

**Core Principle**: Start with the simplest thing that works, then iterate.

## Minimal Architecture (Revised)

```
Phase 1: MVP with Interactive CLI
├── noswiper-daemon (runs as root)
│   ├── --monitor: Log only (default)
│   ├── --enforce: Block and log
│   └── --interactive: Block and prompt via CLI
│
Phase 2: Add GUI Agent
├── noswiper-daemon (runs as root)
│   └── IPC Server (Unix socket)
├── noswiper-agent (runs as user)
│   └── GUI dialogs + system tray
```

## Implementation Approach

### Phase 1: MVP with Interactive CLI Mode

The MVP focuses on getting core monitoring working with CLI-based interaction for testing.

### Phase 2: Proper Split Architecture

After the CLI version proves useful, add the GUI agent with secure IPC communication.

## Monitoring Mechanisms

Different platforms offer multiple ways to monitor file access:

- **macOS**: eslogger (easier, no entitlements) or ESF (faster, needs entitlements)
- **Linux**: fanotify (simpler, older kernels) or eBPF (powerful, newer kernels)

## Configuration System

### Default Configuration (Built into Binary)

The default configuration is embedded in the binary as YAML, protecting common credentials:
- SSH keys
- Cloud provider credentials (AWS, GCP, Azure)
- Package manager tokens
- Browser password stores
- GPG keys

### User Override Configuration

Users can create `~/.config/noswiper/config.yaml` to override or extend defaults.

## Process Identification Strategy

**macOS**: Try code signatures first, fall back to allowed paths
**Linux/BSD**: Use allowlisted paths

## Security Model

- **Simple is secure**: Admin users can control the daemon
- **Fail closed**: When in doubt, deny access
- **Trust the OS**: Use OS-provided security mechanisms
- **Log everything**: Security events go to native system logs

## Secure IPC Communication

Multi-layer defense:
1. Unix socket with restricted permissions
2. Peer credential verification using SO_PEERCRED
3. Admin group membership check
4. Session key generation and HMAC authentication
5. Sequence numbers prevent replay attacks

## Literal Next Steps for Implementation

1. **Create single `main.rs` that works on macOS using eslogger**
2. **Add Linux support with fanotify (simpler than eBPF)**
3. **Ship it as v0.1.0**
4. **Then iterate based on feedback**

## Testing Workflow

```bash
# Development/Testing: Use interactive mode
sudo noswiper-daemon --interactive

# Server Deployment: Enforce mode with logging
sudo noswiper-daemon --enforce

# Desktop Deployment: Daemon + Agent
sudo noswiper-daemon --enforce &
noswiper-agent  # Runs as user, shows GUI dialogs
```

## Key Design Decisions

### What We're Building
A minimal, effective credential protection daemon that:
- Monitors file access to sensitive credentials
- Blocks unauthorized access attempts
- Logs everything to system logs
- Optionally communicates with a UI for user decisions

### What We're NOT Building
- Enterprise management console
- Complex policy engine
- Cross-network communication
- Certificate-based authentication

### Platform Support Priority
1. **macOS first** - Most mature endpoint security framework
2. **Linux second** - eBPF is powerful but requires newer kernels
3. **FreeBSD later** - DTrace works but with limitations
4. **Windows maybe** - Requires driver signing ($)

## Convention Over Configuration
Most users should never need to configure anything. The defaults protect common credentials and only allow expected programs to access them.