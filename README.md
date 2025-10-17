# NoSwiper

**Experimental credential protection daemon for macOS and Linux**

NoSwiper monitors access to sensitive credential files (SSH keys, cloud provider tokens, browser password stores) and blocks unauthorized programs from reading them.

## Status

**This is experimental software.** It's functional but under active development. Use at your own risk.

## How It Works

Uses OS-level monitoring (**macOS**: ESF via `eslogger`, **Linux**: `fanotify`/eBPF) to detect credential access. Can log, block, or prompt for decisions.

## Quick Start

```bash
cargo build --release

# Run in monitor mode (safe for testing)
sudo ./target/release/noswiper-agent --monitor

# Or interactive mode (CLI prompts) or enforce mode (blocks)
sudo ./target/release/noswiper-agent --interactive
sudo ./target/release/noswiper-agent --enforce
```

## User Interface

**macOS Native UI** (Recommended): Swift/SwiftUI menu bar app with real-time alerts
**Tauri UI** (Cross-platform): Web-based UI for macOS/Linux/Windows
**CLI Mode**: Use `--interactive` flag for terminal-based prompts

```bash
# macOS Native UI
make build-ui-macos && open ui/macos/build/NoSwiper.app

# Tauri UI
cd ui-tauri && npm install && npm run tauri build
```

## What It Protects

SSH keys, AWS/GCP/Azure credentials, GitHub tokens, browser password stores, GPG keys, and more.

## Configuration

Works out of the box with sensible defaults. Customize with `~/.config/noswiper/config.yaml`.

## License

See LICENSE file for details.
