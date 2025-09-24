#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;
use tauri::{
    menu::{MenuBuilder, MenuItemBuilder, PredefinedMenuItem},
    tray::TrayIconBuilder,
    Emitter, Manager,
};

const SOCKET_PATH: &str = "/var/run/noswiper.sock";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessTreeEntry {
    pub pid: u32,
    pub ppid: Option<u32>,
    pub name: String,
    pub path: String,
    pub cmdline: Option<String>,
    pub team_id: Option<String>,
    pub signing_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum EventType {
    #[serde(rename = "access_denied")]
    AccessDenied {
        rule_name: String,
        file_path: String,
        process_path: String,
        process_pid: u32,
        process_cmdline: Option<String>,
        process_euid: Option<u32>,
        parent_pid: Option<u32>,
        team_id: Option<String>,
        action: String,
        process_tree: Option<Vec<ProcessTreeEntry>>,
    },
    #[serde(rename = "access_allowed")]
    AccessAllowed {
        rule_name: Option<String>,
        file_path: String,
        process_path: String,
        process_pid: u32,
        process_cmdline: Option<String>,
        process_euid: Option<u32>,
        process_tree: Option<Vec<ProcessTreeEntry>>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    pub id: String,
    pub timestamp: String,
    #[serde(flatten)]
    pub event_type: EventType,
}

#[derive(Debug, Clone, Serialize)]
struct ViolationData {
    event_id: String,
    rule_name: String,
    file_path: String,
    process_path: String,
    process_pid: u32,
    process_cmdline: Option<String>,
    process_tree: Option<Vec<ProcessTreeEntry>>,
    team_id: Option<String>,
    mode: String, // "monitor" or "enforce"
}

#[derive(Debug, Clone, Serialize, Deserialize)]
enum DaemonMode {
    Monitor,
    Enforce,
}

struct AppState {
    current_mode: Arc<Mutex<DaemonMode>>,
}

// Tauri commands that can be called from the frontend
#[tauri::command]
#[allow(non_snake_case)]
fn allow_once(eventId: String) -> Result<String, String> {
    log::info!("[UI] Allow once action requested for event: {}", eventId);
    log::debug!("[UI] Preparing command for event_id: {}", eventId);

    let command = format!(r#"{{"action":"allow_once","event_id":"{}"}}"#, eventId);
    log::debug!("[UI] Sending command to daemon: {}", command);

    let result = send_daemon_command(&command).map_err(|e| {
        log::error!("[UI] Failed to send command to daemon: {}", e);
        e.to_string()
    });

    match &result {
        Ok(response) => {
            log::info!("[UI] Allow once succeeded, response: {}", response);
            // Check if response indicates success
            if response.contains("success") {
                log::info!("[UI] Daemon confirmed success for event: {}", eventId);
            } else {
                log::warn!("[UI] Unexpected response format: {}", response);
            }
        }
        Err(e) => {
            log::error!("[UI] Allow once failed for event {}: {}", eventId, e);
        }
    }
    result
}

#[tauri::command]
#[allow(non_snake_case)]
fn kill_process(eventId: String) -> Result<String, String> {
    log::info!("[UI] Kill process action requested for event: {}", eventId);
    let result = send_daemon_command(&format!(r#"{{"action":"kill","event_id":"{}"}}"#, eventId))
        .map_err(|e| e.to_string());

    match &result {
        Ok(response) => log::info!("[UI] Kill process succeeded: {}", response),
        Err(e) => log::error!("[UI] Kill process failed: {}", e),
    }
    result
}

#[tauri::command]
#[allow(non_snake_case)]
fn allow_permanently(eventId: String) -> Result<String, String> {
    log::info!(
        "[UI] Allow permanently action requested for event: {}",
        eventId
    );
    let result = send_daemon_command(&format!(
        r#"{{"action":"allow_permanently","event_id":"{}"}}"#,
        eventId
    ))
    .map_err(|e| e.to_string());

    match &result {
        Ok(response) => log::info!("[UI] Allow permanently succeeded: {}", response),
        Err(e) => log::error!("[UI] Allow permanently failed: {}", e),
    }
    result
}

#[tauri::command]
fn set_mode(mode: String) -> Result<String, String> {
    log::info!("[UI] Set mode action requested: {}", mode);
    let result = send_daemon_command(&format!(r#"{{"action":"set_mode","mode":"{}"}}"#, mode))
        .map_err(|e| e.to_string());

    match &result {
        Ok(response) => log::info!("[UI] Set mode succeeded: {}", response),
        Err(e) => log::error!("[UI] Set mode failed: {}", e),
    }
    result
}

#[tauri::command]
fn get_mode() -> Result<String, String> {
    log::debug!("[UI] Get mode action requested");
    let result = send_daemon_command(r#"{"action":"get_mode"}"#).map_err(|e| e.to_string());

    match &result {
        Ok(response) => log::debug!("[UI] Get mode response: {}", response),
        Err(e) => log::error!("[UI] Get mode failed: {}", e),
    }
    result
}

#[tauri::command]
fn get_overrides() -> Result<String, String> {
    log::debug!("[UI] Get overrides action requested");
    let result = send_daemon_command(r#"{"action":"get_overrides"}"#).map_err(|e| e.to_string());

    match &result {
        Ok(response) => {
            // Parse the response to extract the message field
            if let Ok(json) = serde_json::from_str::<serde_json::Value>(response) {
                if let Some(message) = json.get("message").and_then(|m| m.as_str()) {
                    return Ok(message.to_string());
                }
            }
            Ok(response.clone())
        }
        Err(e) => {
            log::error!("[UI] Get overrides failed: {}", e);
            Err(e.clone())
        }
    }
}

fn send_daemon_command(command: &str) -> Result<String> {
    log::info!("[UI IPC] >>> Sending command to daemon: {}", command);

    let socket_path = Path::new(SOCKET_PATH);
    if !socket_path.exists() {
        log::error!("[UI IPC] Socket not found at: {}", SOCKET_PATH);
        return Err(anyhow::anyhow!("Daemon socket not found"));
    }

    log::debug!("[UI IPC] Connecting to socket: {}", SOCKET_PATH);
    let mut stream = match UnixStream::connect(socket_path) {
        Ok(s) => {
            log::debug!("[UI IPC] Successfully connected to daemon socket");
            s
        }
        Err(e) => {
            log::error!("[UI IPC] Failed to connect to socket: {}", e);
            return Err(anyhow::anyhow!("Failed to connect to daemon: {}", e));
        }
    };

    log::debug!("[UI IPC] Writing command to socket");
    if let Err(e) = writeln!(stream, "{}", command) {
        log::error!("[UI IPC] Failed to write command: {}", e);
        return Err(anyhow::anyhow!("Failed to write to daemon: {}", e));
    }

    if let Err(e) = stream.flush() {
        log::error!("[UI IPC] Failed to flush stream: {}", e);
        return Err(anyhow::anyhow!("Failed to flush stream: {}", e));
    }

    log::debug!("[UI IPC] Reading response from daemon");
    let mut reader = BufReader::new(&stream);
    let mut response = String::new();

    match reader.read_line(&mut response) {
        Ok(0) => {
            log::error!("[UI IPC] Daemon closed connection without sending response");
            return Err(anyhow::anyhow!("Daemon closed connection"));
        }
        Ok(bytes) => {
            log::debug!("[UI IPC] Read {} bytes from daemon", bytes);
        }
        Err(e) => {
            log::error!("[UI IPC] Failed to read response: {}", e);
            return Err(anyhow::anyhow!("Failed to read response: {}", e));
        }
    }

    let trimmed = response.trim().to_string();
    log::info!("[UI IPC] <<< Received response from daemon: {}", trimmed);

    Ok(trimmed)
}

fn start_event_monitor(app_handle: tauri::AppHandle) {
    thread::spawn(move || loop {
        match connect_and_subscribe() {
            Ok(mut reader) => {
                log::info!(
                    "[UI IPC Event] Connected to daemon event stream, waiting for events..."
                );
                let mut line = String::new();

                loop {
                    line.clear();
                    match reader.read_line(&mut line) {
                        Ok(0) => {
                            log::info!("[UI IPC Event] Event stream closed by daemon");
                            break;
                        }
                        Ok(bytes) => {
                            log::info!(
                                "[UI IPC Event] <<< Received {} bytes from event stream",
                                bytes
                            );

                            // Log the complete raw data first
                            log::info!("[UI IPC Event] Complete raw data: {}", line.trim());

                            // Try to parse as generic JSON first to see the structure
                            match serde_json::from_str::<serde_json::Value>(&line) {
                                Ok(json_value) => {
                                    log::info!(
                                        "[UI IPC Event] Parsed as JSON Value: {:#?}",
                                        json_value
                                    );

                                    // Check if it's an event or a status message
                                    // Events have status="event" and a type field
                                    // Status messages have status="success"/"error" and a message field
                                    let is_event = json_value
                                        .get("status")
                                        .and_then(|s| s.as_str())
                                        .map(|s| s == "event")
                                        .unwrap_or(false);

                                    let has_type = json_value.get("type").is_some();

                                    if !is_event && json_value.get("status").is_some() && !has_type
                                    {
                                        // It's a status message (subscription confirmation, etc.)
                                        log::info!(
                                            "[UI IPC Event] Received status message: {}",
                                            line.trim()
                                        );
                                        continue; // Skip to next message
                                    }

                                    // Log the action type for debugging
                                    let action = json_value
                                        .get("action")
                                        .and_then(|a| a.as_str())
                                        .unwrap_or("");

                                    log::info!("[UI IPC Event] Event with action='{}' - showing popup even in monitor mode", action);
                                    // Show popups for all violations, even in monitor mode
                                    // The popup will show different buttons based on the mode

                                    // Try to parse as an Event
                                    match serde_json::from_value::<Event>(json_value.clone()) {
                                        Ok(event) => {
                                            log::info!(
                                                "[UI IPC Event] Successfully parsed as Event: type={:?}, id={}",
                                                match &event.event_type {
                                                    EventType::AccessDenied { .. } => "AccessDenied",
                                                    EventType::AccessAllowed { .. } => "AccessAllowed",
                                                },
                                                event.id
                                            );

                                            // Log the full event details
                                            log::debug!(
                                                "[UI IPC Event] Full event details: {:#?}",
                                                event
                                            );

                                            handle_daemon_event(event, &app_handle);
                                        }
                                        Err(e) => {
                                            log::error!(
                                                "[UI IPC Event] Failed to parse as Event: {}",
                                                e
                                            );
                                            log::error!(
                                                "[UI IPC Event] JSON structure was: {:#?}",
                                                json_value
                                            );
                                        }
                                    }
                                }
                                Err(e) => {
                                    log::error!("[UI IPC Event] Failed to parse as JSON: {}", e);
                                    log::error!("[UI IPC Event] Raw data was: {}", line.trim());
                                }
                            }
                        }
                        Err(e) => {
                            log::error!("[UI IPC Event] Error reading event stream: {}", e);
                            break;
                        }
                    }
                }
            }
            Err(e) => {
                log::error!("[UI IPC Event] Failed to connect to daemon: {}", e);
            }
        }
        log::info!("[UI IPC Event] Reconnecting to daemon in 5 seconds...");
        thread::sleep(Duration::from_secs(5));
    });
}

fn connect_and_subscribe() -> Result<BufReader<UnixStream>> {
    let socket_path = Path::new(SOCKET_PATH);

    log::info!("[UI IPC Event] Attempting to subscribe to daemon events");

    if !socket_path.exists() {
        log::error!("[UI IPC Event] Socket does not exist at: {}", SOCKET_PATH);
        return Err(anyhow::anyhow!("Socket does not exist"));
    }

    log::debug!("[UI IPC Event] Connecting to socket for event subscription");
    let mut stream = match UnixStream::connect(socket_path) {
        Ok(s) => {
            log::info!("[UI IPC Event] Successfully connected for event subscription");
            s
        }
        Err(e) => {
            log::error!("[UI IPC Event] Failed to connect for events: {}", e);
            return Err(anyhow::anyhow!("Failed to connect: {}", e));
        }
    };

    let subscribe_cmd = r#"{"action":"subscribe"}"#;
    log::info!(
        "[UI IPC Event] >>> Sending subscribe command: {}",
        subscribe_cmd
    );

    if let Err(e) = writeln!(stream, "{}", subscribe_cmd) {
        log::error!("[UI IPC Event] Failed to send subscribe command: {}", e);
        return Err(anyhow::anyhow!("Failed to subscribe: {}", e));
    }

    if let Err(e) = stream.flush() {
        log::error!("[UI IPC Event] Failed to flush subscribe command: {}", e);
        return Err(anyhow::anyhow!("Failed to flush: {}", e));
    }

    log::info!("[UI IPC Event] Successfully subscribed to daemon events");
    Ok(BufReader::new(stream))
}

fn handle_daemon_event(event: Event, app_handle: &tauri::AppHandle) {
    match event.event_type {
        EventType::AccessDenied {
            rule_name,
            file_path,
            process_path,
            process_pid,
            process_cmdline,
            process_tree,
            team_id,
            ..
        } => {
            log::info!("Access denied event: {} -> {}", process_path, file_path);

            // Get current mode from app state
            let current_mode = {
                let state = app_handle.state::<AppState>();
                let mode = state.current_mode.lock().unwrap();
                match *mode {
                    DaemonMode::Enforce => "enforce",
                    DaemonMode::Monitor => "monitor",
                }
            };

            // Log full process tree data for debugging team ID issue
            if let Some(ref tree) = process_tree {
                log::info!("[UI] Full process tree data for event {}:", event.id);
                for (i, entry) in tree.iter().enumerate() {
                    log::info!("[UI] Process tree entry [{}]:", i);
                    log::info!("[UI]   - pid: {}", entry.pid);
                    log::info!("[UI]   - ppid: {:?}", entry.ppid);
                    log::info!("[UI]   - name: {}", entry.name);
                    log::info!("[UI]   - path: {}", entry.path);
                    log::info!("[UI]   - cmdline: {:?}", entry.cmdline);
                    log::info!("[UI]   - team_id: {:?}", entry.team_id);
                    log::info!("[UI]   - signing_id: {:?}", entry.signing_id);
                }
            } else {
                log::info!("[UI] No process tree data for event {}", event.id);
            }

            // Log the main process team_id as well
            log::info!(
                "[UI] Main process {} (PID {}) team_id: {:?}",
                process_path,
                process_pid,
                team_id
            );

            let violation = ViolationData {
                event_id: event.id.clone(),
                rule_name,
                file_path,
                process_path,
                process_pid,
                process_cmdline,
                process_tree,
                team_id,
                mode: current_mode.to_string(),
            };

            // Show violation window
            let window = app_handle.get_webview_window("main");
            match window {
                Some(win) => {
                    log::info!("Reusing existing window for new violation: {}", event.id);
                    log::debug!("Emitting violation event to existing window");

                    // Emit the new violation event (will replace the previous one in UI)
                    if let Err(e) = win.emit("violation", violation.clone()) {
                        log::error!("Failed to emit violation event: {}", e);
                    } else {
                        log::info!("Successfully emitted violation event: {}", event.id);
                    }

                    // Make sure window is visible and focused
                    let _ = win.show();
                    let _ = win.set_focus();
                }
                None => {
                    log::info!("Creating new violation window");
                    // Create new window if it doesn't exist
                    // Following Apple HIG for alert windows
                    match tauri::WebviewWindowBuilder::new(
                        app_handle,
                        "main",
                        tauri::WebviewUrl::App("index.html".into()),
                    )
                    .title("NoSwiper Security Alert") // More descriptive title
                    .inner_size(520.0, 540.0) // Taller to prevent scrolling
                    .resizable(false)
                    .always_on_top(true)
                    .center()
                    .focused(true) // Ensure the window gets focus
                    .visible(true) // Make visible immediately
                    .decorations(true) // Standard window decorations
                    .closable(false) // Don't allow closing via red button
                    .build()
                    {
                        Ok(window) => {
                            log::info!("Window created, setting up event emission");

                            // Show the window first
                            let _ = window.show();
                            let _ = window.set_focus();

                            // Clone what we need for the thread
                            let violation_clone = violation.clone();
                            let window_clone = window.clone();

                            // Emit the event multiple times to ensure it's received
                            std::thread::spawn(move || {
                                // Try immediately
                                log::info!("First attempt to emit violation event");
                                if let Err(e) = window_clone.emit("violation", &violation_clone) {
                                    log::error!("First emit failed: {}", e);
                                }

                                // Try again after a short delay
                                std::thread::sleep(std::time::Duration::from_millis(500));
                                log::info!("Second attempt to emit violation event");
                                if let Err(e) = window_clone.emit("violation", &violation_clone) {
                                    log::error!("Second emit failed: {}", e);
                                }

                                // Final attempt after window should be ready
                                std::thread::sleep(std::time::Duration::from_millis(1000));
                                log::info!("Final attempt to emit violation event");
                                if let Err(e) = window_clone.emit("violation", &violation_clone) {
                                    log::error!("Final emit failed: {}", e);
                                } else {
                                    log::info!("Violation event emitted successfully");
                                }
                            });
                        }
                        Err(e) => {
                            log::error!("Failed to create window: {}", e);
                        }
                    }
                }
            }
        }
        EventType::AccessAllowed { .. } => {
            log::debug!("Access allowed event");
        }
    }
}

fn main() {
    env_logger::Builder::from_default_env()
        .filter_level(log::LevelFilter::Debug)
        .init();

    log::info!("Starting NoSwiper UI (Tauri v2)");

    // Get initial mode from daemon
    log::info!("[UI] Fetching initial mode from daemon");
    let initial_mode = match get_mode() {
        Ok(response) => {
            log::info!("[UI] Initial mode response from daemon: {}", response);
            if response.contains("enforce") {
                log::info!("[UI] Starting in Enforce mode");
                DaemonMode::Enforce
            } else {
                log::info!("[UI] Starting in Monitor mode");
                DaemonMode::Monitor
            }
        }
        Err(e) => {
            log::error!("[UI] Failed to get initial mode from daemon: {}", e);
            log::info!("[UI] Defaulting to Monitor mode");
            DaemonMode::Monitor
        }
    };

    let app_state = AppState {
        current_mode: Arc::new(Mutex::new(initial_mode.clone())),
    };

    tauri::Builder::default()
        .manage(app_state)
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_dialog::init())
        .invoke_handler(tauri::generate_handler![
            allow_once,
            kill_process,
            allow_permanently,
            set_mode,
            get_mode,
            get_overrides
        ])
        .setup(move |app| {
            // Hide from dock on macOS (menubar-only app)
            #[cfg(target_os = "macos")]
            app.set_activation_policy(tauri::ActivationPolicy::Accessory);

            let handle = app.handle().clone();

            // Create tray icon menu items following Apple HIG
            // Status item (disabled, just for information)
            let about = MenuItemBuilder::with_id("about", "NoSwiper")
                .enabled(false)
                .build(app)?;

            // Mode toggle with checkmark for enforce mode only
            let mode_text = if matches!(initial_mode, DaemonMode::Enforce) {
                "✓ Enforce strict credential access"
            } else {
                "Enforce strict credential access"
            };
            let mode_toggle = MenuItemBuilder::with_id("mode", mode_text).build(app)?;

            // Separator
            let separator1 = PredefinedMenuItem::separator(app)?;

            // Check if overrides exist
            let has_overrides = match get_overrides() {
                Ok(content) => !content.is_empty(),
                Err(_) => false,
            };

            // View Overrides (only if they exist)
            let view_overrides_item = if has_overrides {
                Some(MenuItemBuilder::with_id("overrides", "View Override Rules...")
                    .build(app)?)
            } else {
                None
            };

            // Show Last Violation (for future implementation)
            let show_violations = MenuItemBuilder::with_id("violations", "Recent Violations...")
                .enabled(false)
                .build(app)?;

            // Separator
            let separator2 = PredefinedMenuItem::separator(app)?;

            // Standard quit item (Apple HIG: always include Quit)
            let quit = MenuItemBuilder::with_id("quit", "Quit NoSwiper").build(app)?;

            // Build menu items dynamically
            let mut menu_items: Vec<&dyn tauri::menu::IsMenuItem<tauri::Wry>> = vec![
                &about,
                &separator1,
                &mode_toggle,
            ];

            if let Some(ref overrides_item) = view_overrides_item {
                menu_items.push(overrides_item);
            }

            menu_items.push(&show_violations);
            menu_items.push(&separator2);
            menu_items.push(&quit);

            let menu = MenuBuilder::new(app)
                .items(&menu_items)
                .build()?;

            // Create a template icon for macOS menubar (black and white, will adapt to dark/light mode)
            // For proper Apple HIG compliance, we should use a monochrome icon
            // This creates a simple shield icon shape
            let icon_size = 22; // Apple HIG recommends 22x22 for menubar icons
            let mut icon_pixels = Vec::with_capacity((icon_size * icon_size * 4) as usize);

            for y in 0..icon_size {
                for x in 0..icon_size {
                    let center_x = icon_size as f32 / 2.0;
                    let center_y = icon_size as f32 / 2.0;
                    let dx = x as f32 - center_x;
                    let dy = y as f32 - center_y;

                    // Create a simple shield shape
                    let in_shield = (dx.abs() < 8.0) && (dy < 8.0) && (dy > -6.0 || dx.abs() < 6.0);

                    if in_shield {
                        // Black pixel with full alpha for the icon
                        icon_pixels.extend_from_slice(&[0, 0, 0, 255]);
                    } else {
                        // Transparent pixel
                        icon_pixels.extend_from_slice(&[0, 0, 0, 0]);
                    }
                }
            }

            let icon = tauri::image::Image::new_owned(icon_pixels, icon_size, icon_size);

            let _tray = TrayIconBuilder::with_id("main")
                .icon(icon)
                .menu(&menu)
                .on_menu_event(move |app, event| match event.id.as_ref() {
                    "quit" => {
                        log::info!("[UI] Quit requested from menubar");
                        app.exit(0);
                    }
                    "overrides" => {
                        log::info!("[UI] View overrides requested from menubar");
                        // Get overrides content
                        match get_overrides() {
                            Ok(content) => {
                                if !content.is_empty() {
                                    // Check if window already exists
                                    if let Some(window) = app.get_webview_window("overrides") {
                                        // Window exists, just show it
                                        let _ = window.show();
                                        let _ = window.set_focus();
                                    } else {
                                        // Create new window
                                        match tauri::WebviewWindowBuilder::new(
                                            app,
                                            "overrides",
                                            tauri::WebviewUrl::App("overrides.html".into()),
                                        )
                                        .title("Override Rules")
                                        .inner_size(600.0, 400.0)
                                        .resizable(true)
                                        .center()
                                        .focused(true)
                                        .visible(true)
                                        .build()
                                        {
                                            Ok(window) => {
                                                // Store the content for the window to retrieve
                                                window.eval(&format!(
                                                    "window.__overridesContent = {};",
                                                    serde_json::to_string(&content).unwrap_or_else(|_| "''".to_string())
                                                )).unwrap_or_else(|e| {
                                                    log::error!("Failed to set overrides content: {}", e);
                                                });
                                            }
                                            Err(e) => {
                                                log::error!("Failed to create overrides window: {}", e);
                                            }
                                        }
                                    }
                                }
                            }
                            Err(e) => {
                                log::error!("[UI] Failed to get overrides: {}", e);
                            }
                        }
                    }
                    "mode" => {
                        log::info!("[UI] Mode toggle requested from menubar");
                        // Toggle mode
                        let state = app.state::<AppState>();
                        let mut mode = state.current_mode.lock().unwrap();
                        let current_mode_str = match *mode {
                            DaemonMode::Monitor => "monitor",
                            DaemonMode::Enforce => "enforce",
                        };
                        let new_mode = match *mode {
                            DaemonMode::Monitor => "enforce",
                            DaemonMode::Enforce => "monitor",
                        };
                        log::info!(
                            "[UI] Toggling mode from {} to {}",
                            current_mode_str,
                            new_mode
                        );

                        match set_mode(new_mode.to_string()) {
                            Ok(response) => {
                                log::info!("[UI] Mode toggle succeeded: {}", response);
                                *mode = if new_mode == "enforce" {
                                    DaemonMode::Enforce
                                } else {
                                    DaemonMode::Monitor
                                };
                                log::info!("[UI] Local mode state updated to: {}", new_mode);

                                // Rebuild the menu with the updated mode text
                                if let Some(tray) = app.tray_by_id("main") {
                                    log::info!("[UI] Rebuilding menu to reflect mode change");

                                    // Check if overrides exist
                                    let has_overrides = match get_overrides() {
                                        Ok(content) => !content.is_empty(),
                                        Err(_) => false,
                                    };

                                    // Create menu items with updated state
                                    if let Ok(about) = MenuItemBuilder::with_id("about", "NoSwiper")
                                        .enabled(false)
                                        .build(app)
                                    {
                                        let mode_text = if new_mode == "enforce" {
                                            "✓ Enforce strict credential access"
                                        } else {
                                            "Enforce strict credential access"
                                        };

                                        if let Ok(mode_toggle) = MenuItemBuilder::with_id("mode", mode_text).build(app) {
                                            if let Ok(separator1) = PredefinedMenuItem::separator(app) {
                                                // View Overrides (only if they exist)
                                                let view_overrides_item = if has_overrides {
                                                    MenuItemBuilder::with_id("overrides", "View Override Rules...")
                                                        .build(app).ok()
                                                } else {
                                                    None
                                                };

                                                if let Ok(show_violations) = MenuItemBuilder::with_id("violations", "Recent Violations...")
                                                    .enabled(false)
                                                    .build(app)
                                                {
                                                    if let Ok(separator2) = PredefinedMenuItem::separator(app) {
                                                        if let Ok(quit) = MenuItemBuilder::with_id("quit", "Quit NoSwiper").build(app) {
                                                            // Build menu items dynamically
                                                            let mut menu_items: Vec<&dyn tauri::menu::IsMenuItem<tauri::Wry>> = vec![
                                                                &about,
                                                                &separator1,
                                                                &mode_toggle,
                                                            ];

                                                            if let Some(ref overrides_item) = view_overrides_item {
                                                                menu_items.push(overrides_item);
                                                            }

                                                            menu_items.push(&show_violations);
                                                            menu_items.push(&separator2);
                                                            menu_items.push(&quit);

                                                            if let Ok(new_menu) = MenuBuilder::new(app)
                                                                .items(&menu_items)
                                                                .build()
                                                            {
                                                                if let Err(e) = tray.set_menu(Some(new_menu)) {
                                                                    log::error!("[UI] Failed to update menu: {}", e);
                                                                } else {
                                                                    log::info!("[UI] Menu rebuilt with mode: {}", mode_text);
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                } else {
                                    log::error!("[UI] Could not find tray icon to update menu");
                                }
                            }
                            Err(e) => {
                                log::error!("[UI] Failed to toggle mode: {}", e);
                            }
                        }
                    }
                    id => {
                        log::debug!("[UI] Unknown menu event: {}", id);
                    }
                })
                .build(app)?;

            // Start event monitor
            start_event_monitor(handle);

            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
