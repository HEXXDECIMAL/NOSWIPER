//! NoSwiper UI - Cross-platform companion app for NoSwiper agent
//!
//! Provides a system tray interface and violation popup windows
//! for the NoSwiper credential protection daemon.

#![warn(missing_docs)]
#![warn(clippy::all)]
#![warn(clippy::pedantic)]
#![warn(clippy::nursery)]
#![warn(clippy::cargo)]
#![allow(clippy::module_name_repetitions)]

mod ipc_client;
mod process_info;

use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;
use std::io::BufRead;

use tray_icon::{
    menu::{CheckMenuItem, Menu, MenuEvent, MenuItem, PredefinedMenuItem},
    Icon, TrayIconBuilder,
};
use winit::event_loop::{ControlFlow, EventLoop};

use ipc_client::{DaemonMode, DaemonStatus, IpcClient, Event, EventType, ClientResponse};
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

    // Mode items with checkboxes
    let is_monitor = initial_status.as_ref().map_or(false, |s| matches!(s.mode, DaemonMode::Monitor));
    let is_enforce = initial_status.as_ref().map_or(false, |s| matches!(s.mode, DaemonMode::Enforce));

    let monitor_item = CheckMenuItem::new("Monitor Mode", true, is_monitor, None);
    let enforce_item = CheckMenuItem::new("Enforce Mode", true, is_enforce, None);
    let separator2 = PredefinedMenuItem::separator();

    // Just the quit item
    let quit_item = MenuItem::new("Quit NoSwiper UI", true, None);

    // Build menu
    log::debug!("Building menu...");
    tray_menu.append(&status_item).ok();
    tray_menu.append(&separator1).ok();
    tray_menu.append(&monitor_item).ok();
    tray_menu.append(&enforce_item).ok();
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
            let monitor_id = monitor_item.id().clone();
            let enforce_id = enforce_item.id().clone();
            let status_id = status_item.id().clone();

            // Start violation monitor in background thread
            let client_clone = client.clone();
            thread::spawn(move || {
                log::info!("Starting violation monitor thread");
                violation_monitor(client_clone, monitor_id, enforce_id, status_id);
            });

            // Run event loop
            log::info!("Starting event loop...");
            let client_ref = client;

            let _ = event_loop.run(move |_event, control_flow| {
                control_flow.set_control_flow(ControlFlow::Wait);

                // Process menu events
                if let Ok(event) = MenuEvent::receiver().try_recv() {
                    log::debug!("Menu event received");

                    if event.id == monitor_item.id() {
                        log::info!("Setting monitor mode");
                        if let Err(e) = client_ref.set_mode(DaemonMode::Monitor) {
                            log::error!("Failed to set monitor mode: {}", e);
                        } else {
                            // Update checkboxes
                            monitor_item.set_checked(true);
                            enforce_item.set_checked(false);
                        }
                    } else if event.id == enforce_item.id() {
                        log::info!("Setting enforce mode");
                        if let Err(e) = client_ref.set_mode(DaemonMode::Enforce) {
                            log::error!("Failed to set enforce mode: {}", e);
                        } else {
                            // Update checkboxes
                            monitor_item.set_checked(false);
                            enforce_item.set_checked(true);
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
    _monitor_menu_id: tray_icon::menu::MenuId,
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
            None
        }
    };

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
                    log::trace!("Daemon status: mode={:?}, events_pending={}",
                        status.mode, status.violations_count);
                }
                Err(_) => {
                    *CURRENT_STATUS.lock().unwrap() = None;
                    if last_ok {
                        last_ok = false;
                        log::warn!("Agent is not running or not accessible");
                    }
                }
            }
            thread::sleep(Duration::from_secs(5));
        }
    });

    // Process events if we have a subscription
    if let Some(mut reader) = event_reader {

        loop {
            let mut line = String::new();
            match reader.read_line(&mut line) {
                Ok(0) => {
                    log::warn!("Event stream closed, attempting to reconnect...");
                    thread::sleep(Duration::from_secs(2));

                    // Try to reconnect
                    match client.subscribe_to_events() {
                        Ok(new_reader) => {
                            reader = new_reader;
                            log::info!("Reconnected to event stream");
                            continue;
                        }
                        Err(e) => {
                            log::error!("Failed to reconnect: {}", e);
                            thread::sleep(Duration::from_secs(5));
                        }
                    }
                }
                Ok(_) => {
                    // Parse the event
                    match serde_json::from_str::<ClientResponse>(&line) {
                        Ok(ClientResponse::Event(event)) => {
                            handle_event(event, &mut processed_violations, &client);
                        }
                        Ok(other) => {
                            log::debug!("Received non-event response: {:?}", other);
                        }
                        Err(e) => {
                            log::warn!("Failed to parse event: {} (line: {})", e, line.trim());
                        }
                    }
                }
                Err(e) => {
                    log::error!("Error reading event stream: {}", e);
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
fn handle_event(
    event: Event,
    processed_violations: &mut Vec<String>,
    client: &Arc<IpcClient>,
) {
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
            log::warn!("Access denied: {} (PID: {}) accessing {}",
                process_path, process_pid, file_path);

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
                suspended.push((
                    *process_pid,
                    process_name.clone(),
                    process_path.clone()
                ));
                // Keep only last 10 suspended processes
                if suspended.len() > 10 {
                    suspended.remove(0);
                }
                log::info!("Tracked suspended process, total: {}", suspended.len());
            }

            // Get process info
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

            // Show native notification
            show_violation_notification(&violation, &process_tree, &signing_info, client);
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


/// Show a native notification for a violation
/// In production, this would create a proper window
fn show_violation_notification(
    violation: &ipc_client::Violation,
    process_tree: &ProcessTree,
    signing_info: &Option<SigningInfo>,
    client: &Arc<IpcClient>,
) {
    eprintln!("\n=== 🕵️ SECURITY VIOLATION DETECTED ===");
    eprintln!("Process: {} (PID: {})", violation.process_name, violation.pid);
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