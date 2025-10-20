# NoSwiper Native macOS UI

A beautiful, native macOS application for NoSwiper credential protection, built entirely with Swift and SwiftUI.

## Features

- **Native macOS Design**: Uses SF Symbols, native alerts, and follows Apple's Human Interface Guidelines
- **Menu Bar App**: Lives in your menu bar for easy access without cluttering your dock
- **Real-time Monitoring**: Connects to NoSwiper daemon via Unix socket for instant violation alerts
- **Interactive Dialogs**: Native macOS alerts for handling credential access attempts with options to:
  - Allow Once
  - Kill Process
  - Always Allow
- **Process Hierarchy**: Shows parent process tree to understand the origin of access attempts
- **Mode Toggle**: Easy switching between Monitor and Enforce modes
- **Auto-reconnect**: Automatically reconnects to daemon if connection is lost

## Building

### Requirements

- macOS 13.0 or later
- Swift 6.2+ (included with Command Line Tools)
- Xcode Command Line Tools

### Build Commands

#### Using Make (Recommended)

```bash
# From project root
make build-ui-macos    # Debug build
make release-ui-macos  # Release build
make run-ui-macos      # Build and run
```

#### Using build script directly

```bash
cd ui/macos
./build.sh Debug      # Debug build
./build.sh Release    # Release build
```

The built application will be at `ui/macos/build/NoSwiper.app`

### Running

```bash
# From project root
make run-ui-macos

# Or directly
open ui/macos/build/NoSwiper.app
```

**Note**: The daemon must be running first:
```bash
sudo make monitor  # or make enforce
```

## Architecture

### Files

- **NoSwiperApp.swift**: Main app entry point, sets up as menu bar app
- **MenuBarController.swift**: Manages menu bar icon and dropdown menu
- **IPCClient.swift**: Unix socket communication with NoSwiper daemon
- **ViolationAlert.swift**: Native macOS alerts for credential access violations
- **ContentView.swift**: Placeholder SwiftUI view (unused in menu bar mode)

### IPC Protocol

Communicates with the NoSwiper daemon via Unix socket at `/var/run/noswiper.sock`:

- JSON messages over newline-delimited stream
- Commands: `subscribe`, `status`, `set_mode`, `allow_once`, `allow_permanently`, `kill`
- Event stream for real-time violation notifications

## Design Philosophy

This UI prioritizes:

1. **Native Feel**: Looks and feels like it was made by Apple
2. **Simplicity**: Clean, focused interface without unnecessary complexity
3. **Reliability**: Robust error handling and automatic reconnection
4. **Performance**: Lightweight, runs in background without noticeable resource usage

## Comparison with Tauri UI

| Feature | macOS Native | Tauri (ui-tauri) |
|---------|-------------|------------------|
| Technology | Swift + SwiftUI | Rust + Web |
| Bundle Size | ~2MB | ~20MB |
| Memory Usage | ~15MB | ~50MB+ |
| Native Look | ✓ Perfect | ~ Good |
| Cross-platform | macOS only | macOS/Linux/Windows |
| Build Speed | Fast (~5s) | Slower (~30s+) |
| Dependencies | System Swift | Node, WebView |

The native macOS UI is now the default for macOS users. The Tauri UI remains available in `ui-tauri/` for cross-platform scenarios or if you prefer web technologies.

## Future Enhancements

- [ ] Preferences window with configuration UI
- [ ] Notification center integration (replacing deprecated NSUserNotification)
- [ ] Statistics and activity history
- [ ] Custom rule management UI
- [ ] Launch at login option
- [ ] Menu bar icon customization
