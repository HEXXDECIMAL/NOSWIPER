//! Process information gathering module
//!
//! Provides functions to get process trees and code signing information
//! for processes that trigger violations.

use serde::Serialize;
use std::process::Command;

#[derive(Clone, Debug, Serialize)]
pub struct ProcessTree {
    pub pid: u32,
    pub name: String,
    pub path: String,
    pub ppid: u32,
    pub parent_name: Option<String>,
    pub ancestors: Vec<ProcessInfo>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ProcessInfo {
    pub pid: u32,
    pub ppid: u32,
    pub name: String,
    pub path: String,
}

pub fn get_process_tree(pid: u32) -> ProcessTree {
    let mut ancestors = Vec::new();
    let mut current_pid = pid;
    let mut process_path = String::new();
    let mut process_name = String::new();
    let mut ppid = 0u32;

    // Get process info and walk up the tree
    loop {
        let info = get_process_info(current_pid);

        if ancestors.is_empty() {
            // First iteration - save main process info
            process_path = info.path.clone();
            process_name = info.name.clone();
            ppid = info.ppid;
        } else {
            ancestors.push(info.clone());
        }

        if info.ppid == 0 || info.ppid == 1 || ancestors.len() >= 10 {
            break;
        }

        current_pid = info.ppid;
    }

    let parent_name = if !ancestors.is_empty() {
        Some(ancestors[0].name.clone())
    } else {
        None
    };

    ProcessTree {
        pid,
        name: process_name,
        path: process_path,
        ppid,
        parent_name,
        ancestors,
    }
}

#[cfg(target_os = "macos")]
fn get_process_info(pid: u32) -> ProcessInfo {
    // Use ps to get process info on macOS
    let output = Command::new("ps")
        .args(["-p", &pid.to_string(), "-o", "pid=,ppid=,comm="])
        .output();

    if let Ok(output) = output {
        if output.status.success() {
            let line = String::from_utf8_lossy(&output.stdout);
            let parts: Vec<&str> = line.trim().split_whitespace().collect();

            if parts.len() >= 3 {
                let ppid = parts[1].parse().unwrap_or(0);
                let name = parts[2..].join(" ");

                // Try to get full path
                let path = get_process_path_macos(pid).unwrap_or_else(|| name.clone());

                return ProcessInfo {
                    pid,
                    ppid,
                    name,
                    path,
                };
            }
        }
    }

    ProcessInfo {
        pid,
        ppid: 0,
        name: "unknown".to_string(),
        path: "unknown".to_string(),
    }
}

#[cfg(target_os = "macos")]
fn get_process_path_macos(pid: u32) -> Option<String> {
    let output = Command::new("lsof")
        .args(["-p", &pid.to_string(), "-Fn"])
        .output()
        .ok()?;

    if output.status.success() {
        let content = String::from_utf8_lossy(&output.stdout);
        for line in content.lines() {
            if line.starts_with("n/") && line.len() > 2 {
                let path = &line[1..];
                if path.ends_with(".app") || path.contains("/bin/") || path.contains("/sbin/") {
                    return Some(path.to_string());
                }
            }
        }
    }
    None
}

#[cfg(target_os = "linux")]
fn get_process_info(pid: u32) -> ProcessInfo {
    use std::fs;

    let stat_path = format!("/proc/{}/stat", pid);
    let cmdline_path = format!("/proc/{}/cmdline", pid);
    let exe_path = format!("/proc/{}/exe", pid);

    let ppid = fs::read_to_string(&stat_path)
        .ok()
        .and_then(|content| {
            let parts: Vec<&str> = content.split(')').collect();
            if parts.len() >= 2 {
                let fields: Vec<&str> = parts[1].trim().split_whitespace().collect();
                fields.get(1).and_then(|p| p.parse().ok())
            } else {
                None
            }
        })
        .unwrap_or(0);

    let name = fs::read_to_string(&cmdline_path)
        .ok()
        .and_then(|content| {
            content.split('\0')
                .next()
                .map(|s| s.rsplit('/').next().unwrap_or(s).to_string())
        })
        .unwrap_or_else(|| "unknown".to_string());

    let path = fs::read_link(&exe_path)
        .ok()
        .and_then(|p| p.to_str().map(String::from))
        .unwrap_or_else(|| name.clone());

    ProcessInfo {
        pid,
        ppid,
        name,
        path,
    }
}

/// Represents code signing information for a binary
#[derive(Clone, Debug)]
pub struct SigningInfo {
    /// Whether the binary is signed
    pub signed: bool,
    /// Status of the signature
    pub signature_status: String,
    /// Team ID from the signature
    pub team_id: Option<String>,
    /// Signing authority
    pub authority: Option<String>,
}

/// Get code signing information for a binary
pub fn get_signing_info(path: &str) -> Option<SigningInfo> {
    #[cfg(target_os = "macos")]
    {
        get_signing_info_macos(path)
    }

    #[cfg(not(target_os = "macos"))]
    {
        // Linux doesn't have code signing in the same way
        None
    }
}

#[cfg(target_os = "macos")]
fn get_signing_info_macos(path: &str) -> Option<SigningInfo> {
    let output = Command::new("codesign")
        .args(["-dv", "--verbose=4", path])
        .output()
        .ok()?;

    // codesign writes to stderr, not stdout
    let content = String::from_utf8_lossy(&output.stderr);
    let lines: Vec<&str> = content.lines().collect();

    let signed = output.status.success();
    let mut signature_status = if signed {
        "Valid".to_string()
    } else {
        "Invalid or unsigned".to_string()
    };

    let mut team_id = None;
    let mut authority = None;

    for line in lines {
        if line.starts_with("TeamIdentifier=") {
            team_id = Some(line.replace("TeamIdentifier=", ""));
        } else if line.starts_with("Authority=") && authority.is_none() {
            authority = Some(line.replace("Authority=", ""));
        } else if line.contains("expired") {
            signature_status = "Expired".to_string();
        }
    }

    Some(SigningInfo {
        signed,
        signature_status,
        team_id,
        authority,
    })
}