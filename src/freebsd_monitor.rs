#[cfg(target_os = "freebsd")]
use crate::cli::Mode;
use crate::config::Config;
use crate::rules::{Decision, RuleEngine};
use anyhow::Result;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncBufReadExt, BufReader};

pub struct FreeBSDMonitor {
    rule_engine: RuleEngine,
    mode: Mode,
    verbose: bool,
    stop_parent: bool,
    dtrace_script: String,
}

impl FreeBSDMonitor {
    pub fn new(mode: Mode, verbose: bool, stop_parent: bool) -> Self {
        // Load config from embedded YAML
        let config = Config::default().expect("Failed to load default config");

        // Create DTrace script for monitoring file opens
        let dtrace_script = r#"
syscall::open:entry,
syscall::openat:entry
/execname != "dtrace"/
{
    printf("{\"event\":\"open\",\"pid\":%d,\"ppid\":%d,\"execname\":\"%s\",\"path\":\"%s\",\"file\":\"%s\"}\n",
        pid, ppid, execname, curpsinfo->pr_psargs, copyinstr(arg1));
}

proc:::exec-success
/execname != "dtrace"/
{
    printf("{\"event\":\"exec\",\"pid\":%d,\"ppid\":%d,\"execname\":\"%s\",\"args\":\"%s\"}\n",
        pid, ppid, execname, curpsinfo->pr_psargs);
}
"#.to_string();

        Self {
            rule_engine: RuleEngine::new(config),
            mode,
            verbose,
            stop_parent,
            dtrace_script,
        }
    }

    pub async fn start(&mut self) -> Result<()> {
        log::info!("Starting FreeBSD monitor with DTrace");

        // Check if DTrace is available
        if !self.check_dtrace_available() {
            return Err(anyhow::anyhow!(
                "DTrace not available. Please ensure DTrace is enabled in your kernel."
            ));
        }

        // Start DTrace with our script
        let mut child = tokio::process::Command::new("dtrace")
            .arg("-q") // Quiet mode
            .arg("-n")
            .arg(&self.dtrace_script)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()?;

        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| anyhow::anyhow!("Failed to capture dtrace stdout"))?;

        let mut reader = BufReader::new(stdout);
        let mut line = String::new();

        log::info!("Monitoring file access with DTrace...");

        while reader.read_line(&mut line).await? > 0 {
            if line.trim().is_empty() {
                line.clear();
                continue;
            }

            // Parse DTrace output (JSON format)
            match serde_json::from_str::<serde_json::Value>(&line) {
                Ok(json) => {
                    if let Some(event_type) = json.get("event").and_then(|e| e.as_str()) {
                        match event_type {
                            "open" => self.handle_open_event(&json).await?,
                            "exec" => self.handle_exec_event(&json).await?,
                            _ => {}
                        }
                    }
                }
                Err(e) => {
                    log::debug!("Failed to parse DTrace output: {} - Line: {}", e, line);
                }
            }

            line.clear();
        }

        Ok(())
    }

    async fn handle_open_event(&mut self, json: &serde_json::Value) -> Result<()> {
        let pid = json.get("pid").and_then(|p| p.as_u64()).map(|p| p as u32);
        let ppid = json.get("ppid").and_then(|p| p.as_u64()).map(|p| p as u32);

        let process_name = json
            .get("execname")
            .and_then(|e| e.as_str())
            .unwrap_or("unknown");

        let file_path = json.get("file").and_then(|f| f.as_str()).unwrap_or("");

        // Get full process path from procfs
        let process_path = if let Some(pid) = pid {
            self.get_process_path(pid)
                .unwrap_or_else(|| PathBuf::from(process_name))
        } else {
            PathBuf::from(process_name)
        };

        let file_path_buf = PathBuf::from(file_path);

        // Check if this is a protected file
        if !self.rule_engine.is_protected_file(&file_path_buf) {
            if self.verbose {
                log::info!(
                    "{}[{}/ppid:{}]: open {}: OK (not monitored)",
                    process_path.display(),
                    pid.map_or(String::from("?"), |p| p.to_string()),
                    ppid.map_or(String::from("?"), |p| p.to_string()),
                    file_path
                );
            }
            return Ok(());
        }

        // Build process tree for logging
        let process_tree = if let Some(pid) = pid {
            self.build_process_tree(pid, 2)
        } else {
            String::from("Process tree unavailable")
        };

        log::info!(
            "PROTECTED FILE ACCESS: {} (PID {}) -> {}\nProcess tree:\n{}",
            process_path.display(),
            pid.map_or(String::from("?"), |p| p.to_string()),
            file_path,
            process_tree
        );

        // Get process info for context
        let (uid, _cmdline) = if let Some(p) = pid {
            self.get_process_info(p)
        } else {
            (None, None)
        };

        // Create process context for the new rule system
        use crate::process_context::ProcessContext;
        let context = ProcessContext {
            path: process_path.clone(),
            pid,
            ppid,
            team_id: None, // Not available on FreeBSD
            app_id: None,  // Not available on FreeBSD
            args: None,    // Could get from procstat
            uid,
            euid: uid,     // Using same as UID for simplicity
        };

        // Check if access is allowed using new context-aware method
        let decision = self
            .rule_engine
            .check_access_with_context(&context, &file_path_buf);

        match decision {
            Decision::Allow => {
                log::info!(
                    "{}[{}/ppid:{}]: open {}: OK (allowed)",
                    process_path.display(),
                    pid.map_or(String::from("?"), |p| p.to_string()),
                    ppid.map_or(String::from("?"), |p| p.to_string()),
                    file_path
                );
            }
            Decision::NotProtected => {
                // Not a protected file, don't log
            }
            Decision::Deny => {
                match self.mode {
                    Mode::Monitor => {
                        log::warn!(
                            "{}[{}/ppid:{}]: open {}: DETECTED (monitor mode)",
                            process_path.display(),
                            pid.map_or(String::from("?"), |p| p.to_string()),
                            ppid.map_or(String::from("?"), |p| p.to_string()),
                            file_path
                        );
                    }
                    Mode::Enforce => {
                        if let Some(pid) = pid {
                            let stopped = self.stop_process(pid);

                            // Also stop parent if requested
                            let parent_stopped = if self.stop_parent {
                                if let Some(ppid) = ppid {
                                    if ppid > 1 {
                                        self.stop_process(ppid)
                                    } else {
                                        false
                                    }
                                } else {
                                    false
                                }
                            } else {
                                false
                            };

                            if stopped {
                                log::error!(
                                    "{}[{}/ppid:{}]: open {}: STOPPED{}",
                                    process_path.display(),
                                    pid,
                                    ppid.map_or(String::from("?"), |p| p.to_string()),
                                    file_path,
                                    if parent_stopped {
                                        format!(" + parent[{}]", ppid.unwrap())
                                    } else {
                                        String::new()
                                    }
                                );
                            } else {
                                log::error!(
                                    "{}[{}/ppid:{}]: open {}: VIOLATION (process exited)",
                                    process_path.display(),
                                    pid,
                                    ppid.map_or(String::from("?"), |p| p.to_string()),
                                    file_path
                                );
                            }
                        }
                    }
                    Mode::Interactive => {
                        // Similar to Linux/macOS implementation
                        todo!("Interactive mode for FreeBSD")
                    }
                }
            }
        }

        Ok(())
    }

    async fn handle_exec_event(&mut self, json: &serde_json::Value) -> Result<()> {
        let args = json.get("args").and_then(|a| a.as_str()).unwrap_or("");

        // Check if args contain protected paths
        let args_vec: Vec<String> = args.split_whitespace().map(String::from).collect();

        for arg in &args_vec {
            let expanded = shellexpand::tilde(arg).to_string();
            let path = PathBuf::from(&expanded);

            if self.rule_engine.is_protected_file(&path) {
                let pid = json.get("pid").and_then(|p| p.as_u64()).map(|p| p as u32);

                let ppid = json.get("ppid").and_then(|p| p.as_u64()).map(|p| p as u32);

                let process_name = json
                    .get("execname")
                    .and_then(|e| e.as_str())
                    .unwrap_or("unknown");

                log::warn!(
                    "{}[{}/ppid:{}]: exec with {}: DETECTED",
                    process_name,
                    pid.map_or(String::from("?"), |p| p.to_string()),
                    ppid.map_or(String::from("?"), |p| p.to_string()),
                    path.display()
                );

                if self.mode == Mode::Enforce {
                    if let Some(pid) = pid {
                        self.stop_process(pid);
                    }
                }
                break;
            }
        }

        Ok(())
    }

    fn check_dtrace_available(&self) -> bool {
        Command::new("which")
            .arg("dtrace")
            .output()
            .map(|output| output.status.success())
            .unwrap_or(false)
    }

    fn get_process_path(&self, pid: u32) -> Option<PathBuf> {
        // On FreeBSD, we can use procstat or read from /proc if mounted
        Command::new("procstat")
            .args(&["-b", &pid.to_string()])
            .output()
            .ok()
            .and_then(|output| {
                if output.status.success() {
                    let stdout = String::from_utf8_lossy(&output.stdout);
                    // Parse procstat output to get binary path
                    stdout
                        .lines()
                        .nth(1) // Skip header
                        .and_then(|line| {
                            let parts: Vec<&str> = line.split_whitespace().collect();
                            parts.get(2).map(|path| PathBuf::from(path))
                        })
                } else {
                    None
                }
            })
            .or_else(|| {
                // Fallback to /proc if available
                std::fs::read_link(format!("/proc/{}/file", pid)).ok()
            })
    }

    fn stop_process(&self, pid: u32) -> bool {
        unsafe {
            // Send SIGSTOP to the process
            libc::kill(pid as libc::pid_t, libc::SIGSTOP) == 0
        }
    }

    /// Get parent PID using procstat
    fn get_parent_pid(&self, pid: u32) -> Option<u32> {
        Command::new("procstat")
            .args(&["-h", "ppid", &pid.to_string()])
            .output()
            .ok()
            .and_then(|output| {
                if output.status.success() {
                    let stdout = String::from_utf8_lossy(&output.stdout);
                    stdout
                        .split_whitespace()
                        .nth(1) // Second field is PPID
                        .and_then(|ppid_str| ppid_str.parse::<u32>().ok())
                } else {
                    None
                }
            })
    }

    /// Get process info including UID
    fn get_process_info(&self, pid: u32) -> (Option<u32>, Option<String>) {
        // Get UID using procstat
        let uid = Command::new("procstat")
            .args(&["-h", "cred", &pid.to_string()])
            .output()
            .ok()
            .and_then(|output| {
                if output.status.success() {
                    let stdout = String::from_utf8_lossy(&output.stdout);
                    // Format: PID COMM EUID RUID SVUID EGID RGID SVGID GROUPS
                    stdout
                        .split_whitespace()
                        .nth(3) // RUID is 4th field
                        .and_then(|uid_str| uid_str.parse::<u32>().ok())
                } else {
                    None
                }
            });

        // Get command line
        let cmdline = Command::new("procstat")
            .args(&["-h", "args", &pid.to_string()])
            .output()
            .ok()
            .and_then(|output| {
                if output.status.success() {
                    let stdout = String::from_utf8_lossy(&output.stdout);
                    // Skip PID and get rest
                    let parts: Vec<&str> = stdout.split_whitespace().collect();
                    if parts.len() > 1 {
                        Some(parts[1..].join(" "))
                    } else {
                        None
                    }
                } else {
                    None
                }
            });

        (uid, cmdline)
    }

    /// Build a visual process tree for logging
    fn build_process_tree(&self, pid: u32, max_levels: usize) -> String {
        let mut tree = Vec::new();
        let mut current_pid = Some(pid);
        let mut level = 0;

        while let Some(p) = current_pid {
            if level >= max_levels || p <= 1 {
                break;
            }

            let indent = "  ".repeat(level);
            let prefix = if level == 0 { "→" } else { "└─" };

            let (uid, cmdline) = self.get_process_info(p);
            let process_path = self.get_process_path(p)
                .map(|p| p.to_string_lossy().into_owned())
                .unwrap_or_else(|| "?".to_string());

            let display_cmd = cmdline.unwrap_or_else(|| process_path.clone());

            tree.push(format!(
                "{}{} [{}] {} (uid={})",
                indent,
                prefix,
                p,
                if display_cmd.len() > 100 {
                    format!("{}...", &display_cmd[..100])
                } else {
                    display_cmd
                },
                uid.unwrap_or(0)
            ));

            // Get parent PID for next iteration
            current_pid = self.get_parent_pid(p);
            level += 1;
        }

        if tree.is_empty() {
            tree.push(format!("→ [{}] (process info unavailable)", pid));
        }

        tree.join("\n")
    }

    /// Discover protected files from YAML configuration
    fn discover_protected_files(&self) -> Vec<PathBuf> {
        let mut paths = Vec::new();

        // Get user home directories
        let users = self.get_user_homes();

        // Process each protected file pattern from the YAML configuration
        for protected_file in &self.rule_engine.config.protected_files {
            for pattern_str in protected_file.patterns() {
                // Expand patterns for all users
                for user_home in &users {
                    let expanded_pattern = pattern_str.replacen('~', &user_home.to_string_lossy(), 1);

                    // Use glob to find matching files
                    if let Ok(entries) = glob::glob(&expanded_pattern) {
                        for entry in entries.flatten() {
                            if entry.is_file() && entry.exists() {
                                paths.push(entry);
                            }
                        }
                    }
                }
            }
        }

        // Remove duplicates
        paths.sort();
        paths.dedup();
        paths
    }

    /// Get user home directories on FreeBSD
    fn get_user_homes(&self) -> Vec<PathBuf> {
        let mut homes = Vec::new();

        // Read /etc/passwd
        if let Ok(passwd) = std::fs::read_to_string("/etc/passwd") {
            for line in passwd.lines() {
                let parts: Vec<&str> = line.split(':').collect();
                if parts.len() >= 6 {
                    let home = parts[5];
                    if home.starts_with("/home/") || home == "/root" {
                        let home_path = PathBuf::from(home);
                        if home_path.exists() {
                            homes.push(home_path);
                        }
                    }
                }
            }
        }

        homes
    }
}
