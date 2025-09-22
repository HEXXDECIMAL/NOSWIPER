use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

/// Process information for JSON logs
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessDetails {
    pub pid: u32,
    pub ppid: Option<u32>,
    pub euid: Option<u32>,
    pub path: String,
    pub command_line: Option<String>,
    pub team_id: Option<String>,
    pub signing_id: Option<String>,
    pub is_platform_binary: Option<bool>,
}

/// Security event for JSON logging
#[derive(Debug, Serialize, Deserialize)]
pub struct SecurityEvent {
    pub timestamp: DateTime<Utc>,
    pub event_type: String,  // "allow" or "deny"
    pub mode: String,         // "monitor" or "enforce"
    pub rule_name: Option<String>,
    pub file_path: String,
    pub access_type: String,  // "open", "exec", etc.
    pub process: ProcessDetails,
    pub process_tree: Vec<ProcessDetails>,  // Parent, grandparent, etc.
    pub action_taken: Option<String>,  // "logged", "blocked", "suspended", etc.
}

/// JSON logger that writes to OS-appropriate locations
pub struct JsonLogger {
    log_file: Mutex<PathBuf>,
}

impl JsonLogger {
    /// Create a new JSON logger with OS-appropriate log path
    pub fn new() -> Result<Self> {
        let log_path = Self::get_log_path()?;

        // Ensure the directory exists
        if let Some(parent) = log_path.parent() {
            fs::create_dir_all(parent)?;
        }

        Ok(Self {
            log_file: Mutex::new(log_path),
        })
    }

    /// Get the OS-appropriate log file path
    pub fn get_log_path() -> Result<PathBuf> {
        let path = if cfg!(target_os = "macos") {
            // macOS: /Library/Logs/NoSwiper/events.json
            PathBuf::from("/Library/Logs/NoSwiper/events.json")
        } else if cfg!(target_os = "linux") {
            // Linux: /var/log/noswiper/events.json
            PathBuf::from("/var/log/noswiper/events.json")
        } else if cfg!(target_os = "freebsd") {
            // FreeBSD: /var/log/noswiper/events.json
            PathBuf::from("/var/log/noswiper/events.json")
        } else {
            // Fallback: current directory
            PathBuf::from("./noswiper_events.json")
        };

        Ok(path)
    }

    /// Log a security event to the JSON file
    pub fn log_event(&self, event: &SecurityEvent) -> Result<()> {
        let log_path = self.log_file.lock().unwrap();

        // Serialize the event to JSON
        let json_line = serde_json::to_string(event)?;

        // Open file in append mode
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&*log_path)?;

        // Write the JSON line
        writeln!(file, "{}", json_line)?;

        Ok(())
    }

    /// Build a security event for an allowed access
    pub fn build_allow_event(
        rule_name: Option<String>,
        file_path: &Path,
        access_type: &str,
        process: ProcessDetails,
        parent: Option<ProcessDetails>,
        mode: &str,
    ) -> SecurityEvent {
        let mut process_tree = Vec::new();
        if let Some(p) = parent {
            process_tree.push(p);
        }

        SecurityEvent {
            timestamp: Utc::now(),
            event_type: "allow".to_string(),
            mode: mode.to_string(),
            rule_name,
            file_path: file_path.display().to_string(),
            access_type: access_type.to_string(),
            process,
            process_tree,
            action_taken: Some("logged".to_string()),
        }
    }

    /// Build a security event for a denied access
    pub fn build_deny_event(
        rule_name: String,
        file_path: &Path,
        access_type: &str,
        process: ProcessDetails,
        process_tree: Vec<ProcessDetails>,
        mode: &str,
        action_taken: &str,
    ) -> SecurityEvent {
        SecurityEvent {
            timestamp: Utc::now(),
            event_type: "deny".to_string(),
            mode: mode.to_string(),
            rule_name: Some(rule_name),
            file_path: file_path.display().to_string(),
            access_type: access_type.to_string(),
            process,
            process_tree,
            action_taken: Some(action_taken.to_string()),
        }
    }
}

impl Default for JsonLogger {
    fn default() -> Self {
        Self::new().unwrap_or_else(|_| Self {
            log_file: Mutex::new(PathBuf::from("./noswiper_events.json")),
        })
    }
}