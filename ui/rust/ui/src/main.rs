//! NoSwiper UI - Cross-platform companion app for NoSwiper agent
//!
//! Provides a system tray interface and violation popup windows
//! for the NoSwiper credential protection daemon.

#![warn(missing_docs)]
#![warn(clippy::all)]
#![warn(clippy::pedantic)]
#![warn(clippy::nursery)]
#![warn(clippy::cargo)]
#![allow(clippy::multiple_crate_versions)] // Dependencies have version conflicts
#![allow(clippy::cargo_common_metadata)] // Not publishing to crates.io yet
#![allow(clippy::doc_markdown)] // Allow unformatted names in docs
#![allow(clippy::similar_names)] // pid/ppid are standard naming
#![allow(clippy::module_name_repetitions)]

mod ipc_client;
mod process_info;
mod violation_dialog;

use std::io::BufRead;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use tray_icon::{
    menu::{CheckMenuItem, Menu, MenuEvent, MenuItem, PredefinedMenuItem},
    Icon, TrayIconBuilder,
};
use winit::event_loop::{ControlFlow, EventLoop};

use ipc_client::{ClientResponse, DaemonMode, DaemonStatus, Event, EventType, IpcClient};
use process_info::{ProcessTree, SigningInfo};

/// Shared state for tracking suspended processes and daemon status
static SUSPENDED_PROCESSES: Mutex<Vec<(u32, String, String)>> = Mutex::new(Vec::new());
static CURRENT_STATUS: Mutex<Option<DaemonStatus>> = Mutex::new(None);

/// Main entry point - sets up system tray and monitors for violations
fn main() {
    // Initialize logging with info level by default, debug if RUST_LOG is set
    env_logger::Builder::from_default_env()
        .filter_level(log::LevelFilter::Info)
        .init();

    log::info!("NoSwiper UI starting...");

    let client = Arc::new(IpcClient::new());
    log::debug!("IPC client created");

    // Check initial daemon status
    let initial_status = client.get_status().ok();
    *CURRENT_STATUS.lock().unwrap() = initial_status.clone();

    // Get the current mode from the server
    let current_mode = client.get_mode().unwrap_or(DaemonMode::Monitor);
    let is_enforce = matches!(current_mode, DaemonMode::Enforce);

    // Create event loop for windowing system (required for tray icon)
    let event_loop = EventLoop::new().expect("Failed to create event loop");

    // Set up system tray menu
    let tray_menu = Menu::new();

    // Status item - shows current daemon status
    let status_text = if initial_status.is_some() {
        "🕵️ NoSwiper Active"
    } else {
        "⚠️ Agent Not Running"
    };
    let status_item = MenuItem::new(status_text, false, None);
    let separator1 = PredefinedMenuItem::separator();

    let enforce_checkbox =
        CheckMenuItem::new("Enforce access restrictions", true, is_enforce, None);
    let separator2 = PredefinedMenuItem::separator();

    // Just the quit item
    let quit_item = MenuItem::new("Quit NoSwiper UI", true, None);

    // Build menu
    log::debug!("Building menu...");
    tray_menu.append(&status_item).ok();
    tray_menu.append(&separator1).ok();
    tray_menu.append(&enforce_checkbox).ok();
    tray_menu.append(&separator2).ok();
    tray_menu.append(&quit_item).ok();
    log::debug!("Menu built successfully");

    // Create icon - use emoji text for macOS
    log::debug!("Creating tray icon...");

    // For macOS, we create a simple icon - the system will use the text we provide
    // Create a minimal 16x16 transparent icon (macOS will use our title text instead)
    let icon_size = 16;
    let icon_data = vec![0u8; icon_size * icon_size * 4]; // All transparent

    let icon = Icon::from_rgba(icon_data, icon_size as u32, icon_size as u32)
        .expect("Failed to create icon");

    log::debug!("Building tray icon...");

    // Create the tray with appropriate emoji based on status
    let tray_title = if initial_status.is_some() {
        "🕵️" // Detective emoji for active
    } else {
        "⚠️" // Warning emoji for not running
    };

    let tray = TrayIconBuilder::new()
        .with_menu(Box::new(tray_menu))
        .with_tooltip("NoSwiper - Credential Protection")
        .with_icon(icon)
        .with_title(tray_title) // This shows the emoji on macOS
        .build();

    match tray {
        Ok(_t) => {
            log::info!("System tray icon created successfully");

            // Clone references for menu IDs
            let enforce_id = enforce_checkbox.id().clone();
            let status_id = status_item.id().clone();

            // Start violation monitor in background thread
            let client_clone = client.clone();
            thread::spawn(move || {
                log::info!("Starting violation monitor thread");
                violation_monitor(client_clone, enforce_id, status_id);
            });

            // Start status monitoring in a separate thread
            let client_status = client.clone();
            thread::spawn(move || {
                let mut last_ok = true;

                loop {
                    match client_status.get_status() {
                        Ok(status) => {
                            *CURRENT_STATUS.lock().unwrap() = Some(status.clone());
                            if !last_ok {
                                last_ok = true;
                                log::info!("Agent is now running");
                            }

                            log::trace!(
                                "Daemon status: mode={:?}, events_pending={}",
                                status.mode,
                                status.violations_count
                            );
                        }
                        Err(e) => {
                            *CURRENT_STATUS.lock().unwrap() = None;
                            if last_ok {
                                last_ok = false;
                                log::warn!("Agent is not running or not accessible: {}", e);

                                // Run diagnostics on first failure
                                let diagnostics = client_status.diagnose_connection();
                                log::warn!("Connection diagnostics:\n{}", diagnostics);
                            }
                        }
                    }
                    thread::sleep(Duration::from_secs(30)); // Check less frequently to avoid reconnection spam
                }
            });

            // Run event loop
            log::info!("Starting event loop...");
            let client_ref = client;

            #[allow(deprecated)] // tray-icon still uses the old API
            let _ = event_loop.run(move |_event, control_flow| {
                control_flow.set_control_flow(ControlFlow::Wait);

                // Process menu events
                if let Ok(event) = MenuEvent::receiver().try_recv() {
                    log::debug!("Menu event received");

                    if event.id == enforce_checkbox.id() {
                        // Toggle between monitor and enforce modes
                        let current_is_enforce = enforce_checkbox.is_checked();
                        let new_mode = if current_is_enforce {
                            // Currently enforcing, switch to monitor
                            DaemonMode::Monitor
                        } else {
                            // Currently monitoring, switch to enforce
                            DaemonMode::Enforce
                        };

                        log::info!("Setting mode to: {:?}", new_mode);
                        if let Err(e) = client_ref.set_mode(new_mode) {
                            log::error!("Failed to set mode: {}", e);
                            // Revert checkbox state on failure
                            enforce_checkbox.set_checked(current_is_enforce);
                        } else {
                            // Update checkbox to reflect new state
                            enforce_checkbox.set_checked(!current_is_enforce);
                        }
                    } else if event.id == quit_item.id() {
                        log::info!("Quitting NoSwiper UI");
                        std::process::exit(0);
                    }
                }
            });
        }
        Err(e) => {
            log::error!("Failed to create system tray icon: {}", e);
            eprintln!("Failed to create system tray icon: {}", e);
            eprintln!("Make sure you're running on a desktop environment with system tray support");
            std::process::exit(1);
        }
    }
}

/// Monitor for violations and daemon status
fn violation_monitor(
    client: Arc<IpcClient>,
    _enforce_menu_id: tray_icon::menu::MenuId,
    _status_menu_id: tray_icon::menu::MenuId,
) {
    let mut processed_violations = Vec::new();

    log::info!("Violation monitor started");

    // Try to subscribe to events
    let event_reader = match client.subscribe_to_events() {
        Ok(reader) => {
            log::info!("Successfully subscribed to agent events");
            Some(reader)
        }
        Err(e) => {
            log::error!("Failed to subscribe to events: {}", e);

            // Run diagnostics to help the user understand the issue
            let diagnostics = client.diagnose_connection();
            log::error!("Connection diagnostics:\n{}", diagnostics);

            // Also print to stderr so it's visible even without debug logs
            eprintln!("\n{}", diagnostics);

            None
        }
    };

    // This status monitoring thread will be started inside the tray Ok block
    // to avoid duplication

    // Process events if we have a subscription
    if let Some(mut reader) = event_reader {
        log::info!("Starting event processing loop");
        let mut lines_read = 0;
        let mut events_received = 0;
        let mut last_log_time = std::time::Instant::now();

        loop {
            let mut line = String::new();
            match reader.read_line(&mut line) {
                Ok(0) => {
                    log::warn!("Event stream closed (EOF), attempting to reconnect...");
                    thread::sleep(Duration::from_secs(2));

                    // Try to reconnect
                    match client.subscribe_to_events() {
                        Ok(new_reader) => {
                            reader = new_reader;
                            log::info!("Reconnected to event stream");
                            lines_read = 0;
                            events_received = 0;
                        }
                        Err(e) => {
                            log::error!("Failed to reconnect: {}", e);
                            thread::sleep(Duration::from_secs(5));
                        }
                    }
                }
                Ok(bytes_read) => {
                    lines_read += 1;

                    // Log raw data periodically
                    if !line.trim().is_empty() {
                        log::debug!("Received line ({} bytes): {}", bytes_read, line.trim());

                        // Parse the event
                        match serde_json::from_str::<ClientResponse>(&line) {
                            Ok(ClientResponse::Event(event)) => {
                                events_received += 1;
                                log::info!(
                                    "Event #{} received: {:?}",
                                    events_received,
                                    event.event_type
                                );
                                handle_event(event, &mut processed_violations, &client);
                            }
                            Ok(ClientResponse::Success { message }) => {
                                log::debug!("Received success response: {}", message);
                            }
                            Ok(ClientResponse::Error { message }) => {
                                log::warn!("Received error from daemon: {}", message);
                            }
                            Ok(ClientResponse::Status {
                                mode,
                                events_pending,
                                connected_clients,
                            }) => {
                                log::debug!(
                                    "Received status: mode={}, pending={}, clients={}",
                                    mode,
                                    events_pending,
                                    connected_clients
                                );
                            }

                            Err(e) => {
                                log::warn!("Failed to parse JSON: {} (line: {})", e, line.trim());
                            }
                        }
                    }

                    // Log stats every 30 seconds
                    if last_log_time.elapsed() > Duration::from_secs(30) {
                        log::info!(
                            "Event stream stats: {} lines read, {} events received",
                            lines_read,
                            events_received
                        );
                        last_log_time = std::time::Instant::now();
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    // This is expected when there are no events - just continue
                    thread::sleep(Duration::from_millis(100));
                }
                Err(e) if e.kind() == std::io::ErrorKind::TimedOut => {
                    // Also expected for timeouts - just continue
                    thread::sleep(Duration::from_millis(100));
                }
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                    log::warn!("Unexpected EOF on event stream, reconnecting...");
                    thread::sleep(Duration::from_secs(1));

                    match client.subscribe_to_events() {
                        Ok(new_reader) => {
                            reader = new_reader;
                            log::info!("Reconnected after unexpected EOF");
                            lines_read = 0;
                            events_received = 0;
                        }
                        Err(e) => {
                            log::error!("Failed to reconnect after EOF: {}", e);
                            thread::sleep(Duration::from_secs(5));
                        }
                    }
                }
                Err(e) => {
                    log::error!(
                        "Unexpected error reading event stream: {} (kind: {:?})",
                        e,
                        e.kind()
                    );
                    thread::sleep(Duration::from_secs(2));
                }
            }
        }
    } else {
        // Fallback: poll for status only
        loop {
            thread::sleep(Duration::from_secs(5));
        }
    }
}

/// Handle an event from the agent
fn handle_event(event: Event, processed_violations: &mut Vec<String>, client: &Arc<IpcClient>) {
    // Skip if already processed
    if processed_violations.contains(&event.id) {
        return;
    }

    match &event.event_type {
        EventType::AccessDenied {
            process_path,
            process_pid,
            file_path,
            action,
            ..
        } => {
            log::warn!(
                "Access denied: {} (PID: {}) accessing {}",
                process_path,
                process_pid,
                file_path
            );

            processed_violations.push(event.id.clone());

            // Extract process name from path
            let process_name = process_path
                .rsplit('/')
                .next()
                .unwrap_or("unknown")
                .to_string();

            // Track suspended process
            {
                let mut suspended = SUSPENDED_PROCESSES.lock().unwrap();
                suspended.push((*process_pid, process_name.clone(), process_path.clone()));
                // Keep only last 10 suspended processes
                if suspended.len() > 10 {
                    suspended.remove(0);
                }
                log::info!("Tracked suspended process, total: {}", suspended.len());
            }

            // Get process info (for console output)
            let process_tree = process_info::get_process_tree(*process_pid);
            let signing_info = process_info::get_signing_info(process_path);

            // Create a simplified violation for notification
            let violation = ipc_client::Violation {
                id: event.id.clone(),
                pid: *process_pid,
                process_name,
                process_path: process_path.clone(),
                file_path: file_path.clone(),
                timestamp: event.timestamp.clone(),
                action_taken: action.clone(),
            };

            // Show console notification for debugging
            show_violation_notification_console(&violation, &process_tree, &signing_info, client);

            // Create and show violation dialog
            let event_id = event.id.clone();
            let event_type = event.event_type.clone();
            let client_clone = Arc::clone(client);

            // Spawn a new thread for the dialog to avoid blocking event processing
            thread::spawn(move || {
                log::info!("Opening violation dialog for event {}", event_id);
                if let Some(dialog) =
                    violation_dialog::ViolationDialog::new(event_id, &event_type, client_clone)
                {
                    dialog.show();
                } else {
                    log::error!("Failed to create violation dialog");
                }
            });
        }
        EventType::AccessAllowed { .. } => {
            // Log allowed access but don't show notification
            log::debug!("Access allowed: {:?}", event);
        }
    }

    // Clean up old violations list periodically
    if processed_violations.len() > 100 {
        processed_violations.drain(0..50);
    }
}

/// Show a console notification for a violation (for debugging)
fn show_violation_notification_console(
    violation: &ipc_client::Violation,
    process_tree: &ProcessTree,
    signing_info: &Option<SigningInfo>,
    client: &Arc<IpcClient>,
) {
    eprintln!("\n=== 🕵️ SECURITY VIOLATION DETECTED ===");
    eprintln!(
        "Process: {} (PID: {})",
        violation.process_name, violation.pid
    );
    eprintln!("Path: {}", violation.process_path);
    eprintln!("Attempted to access: {}", violation.file_path);

    // Process tree
    eprintln!("\nProcess Hierarchy:");
    eprintln!("▶ {} ({})", violation.process_name, violation.pid);
    for (i, ancestor) in process_tree.ancestors.iter().enumerate().take(3) {
        let indent = "  ".repeat(i + 1);
        eprintln!("{}└─ {} ({})", indent, ancestor.name, ancestor.pid);
    }

    // Signing info
    if let Some(info) = signing_info {
        if info.signed {
            eprintln!("\n✓ Signed: {}", info.signature_status);
            if let Some(team) = &info.team_id {
                eprintln!("Team ID: {}", team);
            }
            if let Some(authority) = &info.authority {
                eprintln!("Authority: {}", authority);
            }
        } else {
            eprintln!("\n⚠️ UNSIGNED or invalid signature");
        }
    }

    eprintln!("\n[Process suspended - violation window would appear here]");
    eprintln!("[In production: Allow Once / Kill Process / Always Allow buttons]");
    eprintln!("=====================================\n");

    // TODO: Here we would create a proper violation window with buttons
    // For now, auto-allow after showing the notification
    if let Ok(_) = client.continue_process(&violation.id) {
        log::info!("Auto-allowed process {} for demo", violation.process_name);
    }
}
