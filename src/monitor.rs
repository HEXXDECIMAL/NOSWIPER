use crate::cli::{Mechanism, Mode};
use crate::config::Config;
use crate::rules::{Decision, RuleEngine};
use anyhow::Result;
use serde::Deserialize;
use std::path::{Path, PathBuf};
use std::process::Command;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command as TokioCommand;

#[cfg(target_os = "linux")]
use crate::linux_monitor::LinuxMonitor;

#[cfg(target_os = "freebsd")]
use crate::freebsd_monitor::FreeBSDMonitor;

pub struct Monitor {
    rule_engine: RuleEngine,
    mode: Mode,
    mechanism: Mechanism,
    verbose: bool,
    stop_parent: bool,
}

// These structs are for potential future use with typed JSON parsing
// Currently we parse JSON dynamically for flexibility
#[allow(dead_code)]
#[derive(Deserialize, Debug)]
struct EsloggerEvent {
    process: serde_json::Value,
    event: serde_json::Value,
}

impl Monitor {
    pub fn new(mode: Mode, mechanism: Mechanism, verbose: bool, stop_parent: bool) -> Self {
        // Load config from embedded YAML
        let config = Config::default().expect("Failed to load default config");

        Self {
            rule_engine: RuleEngine::new(config),
            mode,
            mechanism,
            verbose,
            stop_parent,
        }
    }

    pub async fn start(&mut self) -> Result<()> {
        log::info!("Starting NoSwiper agent in {} mode", self.mode);
        log::info!("Using monitoring mechanism: {}", self.mechanism);

        if let Mode::Interactive = self.mode {
            self.print_interactive_banner();
        }

        match self.mechanism {
            #[cfg(target_os = "macos")]
            Mechanism::Eslogger => self.monitor_with_eslogger().await,
            #[cfg(target_os = "macos")]
            Mechanism::Esf => self.monitor_with_esf().await,
            #[cfg(target_os = "linux")]
            Mechanism::Fanotify => self.monitor_with_fanotify().await,
            #[cfg(target_os = "linux")]
            Mechanism::Ebpf => self.monitor_with_ebpf().await,
            #[cfg(target_os = "freebsd")]
            Mechanism::Dtrace => self.monitor_with_dtrace().await,
            #[cfg(target_os = "freebsd")]
            Mechanism::Kqueue => self.monitor_with_kqueue().await,
            Mechanism::Auto => self.monitor_with_auto().await,
        }
    }

    fn print_interactive_banner(&self) {
        println!("NoSwiper running in interactive mode");
        println!("Access prompts will appear in this terminal");
        println!("Press Ctrl+C to exit\n");
    }

    #[cfg(target_os = "macos")]
    async fn monitor_with_eslogger(&mut self) -> Result<()> {
        log::info!("Using eslogger mechanism");
        log::info!("Note: eslogger requires Full Disk Access permission on macOS");

        // Check if eslogger is available
        if !self.check_eslogger_available() {
            return Err(anyhow::anyhow!(
                "eslogger not found. Please install it or use a different mechanism."
            ));
        }

        // Subscribe to both 'open' and 'exec' events
        let eslogger_args = ["open", "exec", "--format", "json"];
        let eslogger_cmd = format!("eslogger {}", eslogger_args.join(" "));

        log::info!("Starting eslogger with command: {}", eslogger_cmd);

        // Start eslogger process
        let mut child = TokioCommand::new("eslogger")
            .args(&eslogger_args)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .map_err(|e| {
                anyhow::anyhow!("Failed to spawn eslogger process: {}. Command was: {}", e, eslogger_cmd)
            })?;

        log::info!("Started eslogger process with PID: {:?}", child.id());

        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| anyhow::anyhow!("Failed to capture eslogger stdout"))?;

        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| anyhow::anyhow!("Failed to capture eslogger stderr"))?;

        // Spawn a task to read stderr and collect error messages
        let stderr_reader = BufReader::new(stderr);
        let mut stderr_lines = stderr_reader.lines();
        let (stderr_tx, mut stderr_rx) = tokio::sync::mpsc::channel::<String>(10);
        tokio::spawn(async move {
            while let Ok(Some(line)) = stderr_lines.next_line().await {
                log::error!("eslogger stderr: {}", line);
                let _ = stderr_tx.send(line).await;
            }
        });

        // Use unbuffered reading for lower latency
        let reader = BufReader::new(stdout);
        let mut lines = reader.lines();
        let mut event_count = 0;

        log::info!("Listening for file access events...");

        // Check if we're getting any output at all
        tokio::spawn(async move {
            tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
            log::warn!("If you don't see any events after 5 seconds, try opening files in another terminal");
        });

        while let Some(line) = lines.next_line().await? {
            if line.trim().is_empty() {
                continue;
            }

            event_count += 1;

            // Log progress periodically
            if event_count % 1000 == 0 {
                log::debug!("Processed {} eslogger events", event_count);
            }

            // Clone data for parallel processing
            let line_clone = line.clone();

            // Parse the event to determine its type
            let json_result = serde_json::from_str::<serde_json::Value>(&line);
            match json_result {
                Ok(json) => {
                    // Check if this is an open event
                    if json.get("event").and_then(|e| e.get("open")).is_some() {
                        match self.parse_open_event(&json) {
                            Ok(Some((process_path, file_path, pid, ppid, signing_info))) => {
                                // For protected files, handle immediately
                                if self.rule_engine.is_protected_file(&file_path) {
                                    // Handle synchronously for speed
                                    self.handle_file_access_with_signing(&process_path, &file_path, pid, ppid, signing_info)
                                        .await?;
                                } else {
                                    // Log non-critical events asynchronously
                                    let process_display = process_path.display().to_string();
                                    let pid_str = pid.map_or(String::from("?"), |p| p.to_string());
                                    let file_display = file_path.display().to_string();
                                    let verbose = self.verbose;

                                    tokio::spawn(async move {
                                        if verbose {
                                            log::info!("{}[{}]: open {}: OK", process_display, pid_str, file_display);
                                        }
                                    });
                                }
                            }
                            Ok(None) => {
                                log::trace!("Open event parsed but not relevant (directory or filtered)");
                            }
                            Err(e) => {
                                log::debug!("Failed to parse open event: {}", e);
                            }
                        }
                    }
                    // Check if this is an exec event
                    else if json.get("event").and_then(|e| e.get("exec")).is_some() {
                        match self.parse_exec_event(&json) {
                            Ok(Some((process_path, args, pid, ppid, signing_info))) => {
                                // Check if any argument contains a protected path
                                if let Some(protected_path) = self.check_args_for_protected_paths(&args) {
                                    self.handle_exec_with_protected_path(&process_path, &args, &protected_path, pid, ppid, signing_info)
                                        .await?;
                                }
                            }
                            Ok(None) => {
                                log::trace!("Exec event parsed but not relevant");
                            }
                            Err(e) => {
                                log::debug!("Failed to parse exec event: {}", e);
                            }
                        }
                    } else {
                        log::trace!("Event is neither open nor exec");
                    }
                }
                Err(e) => {
                    // Log parsing errors at higher level for first few events
                    if event_count <= 10 {
                        log::warn!("Failed to parse eslogger event #{}: {}", event_count, e);
                    } else {
                        log::debug!("Failed to parse eslogger event: {} - Event: {}", e, line_clone);
                    }
                }
            }
        }

        // Wait for child process and capture any remaining output
        let exit_status = child.wait().await?;
        if !exit_status.success() {
            log::error!("eslogger exited with non-zero status: {}", exit_status);
            log::error!("Command was: {}", "eslogger open --format json");

            // Collect any stderr messages to provide better error context
            let mut stderr_messages = Vec::new();
            while let Ok(msg) = stderr_rx.try_recv() {
                stderr_messages.push(msg);
            }

            // Check for specific error conditions
            let error_msg = if stderr_messages.iter().any(|m| m.contains("TCC Full Disk Access") || m.contains("ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED")) {
                log::error!("eslogger requires Full Disk Access permission in macOS System Preferences");
                "eslogger requires Full Disk Access permission. Please:\n\
                1. Open System Preferences -> Security & Privacy -> Privacy tab\n\
                2. Select 'Full Disk Access' from the left sidebar\n\
                3. Click the lock to make changes\n\
                4. Add Terminal.app (or your terminal emulator) to the list\n\
                5. Restart your terminal and try again"
            } else if stderr_messages.iter().any(|m| m.contains("Not privileged") || m.contains("ES_NEW_CLIENT_RESULT_ERR_NOT_PRIVILEGED")) {
                log::error!("eslogger needs to be run with root privileges");
                "eslogger needs root privileges. Please run with: sudo {}"
            } else {
                log::error!("eslogger failed with unknown error");
                "eslogger exited with error: {}. Command was: eslogger open --format json"
            };

            return Err(anyhow::anyhow!("{}", error_msg.replace("{}", &exit_status.to_string())));
        }

        Ok(())
    }

    fn check_eslogger_available(&self) -> bool {
        // First check if eslogger exists
        let exists = Command::new("which")
            .arg("eslogger")
            .output()
            .map(|output| output.status.success())
            .unwrap_or(false);

        if exists {
            log::debug!("eslogger found at /usr/bin/eslogger");
        } else {
            log::error!("eslogger not found in PATH");
        }

        exists
    }

    fn parse_open_event(&self, json: &serde_json::Value) -> Result<Option<(PathBuf, PathBuf, Option<u32>, Option<u32>, Option<String>)>> {

        // This function assumes it's already been verified as an open event

        // Check if this is a directory (st_mode & 0170000 == 0040000)
        let is_directory = json.get("event")
            .and_then(|e| e.get("open"))
            .and_then(|o| o.get("file"))
            .and_then(|f| f.get("stat"))
            .and_then(|s| s.get("st_mode"))
            .and_then(|m| m.as_u64())
            .map(|mode| (mode & 0o170000) == 0o040000)
            .unwrap_or(false);

        if is_directory {
            log::trace!("Skipping directory open");
            return Ok(None);
        }

        // Extract process executable path - handle nested structure
        let process_path = json.get("process")
            .and_then(|p| p.get("executable"))
            .and_then(|e| {
                // The path is nested in an object
                e.get("path").and_then(|p| p.as_str())
            })
            .ok_or_else(|| anyhow::anyhow!("No process path in event"))?;

        // Extract file path from the nested structure
        let file_path = json.get("event")
            .and_then(|e| e.get("open"))
            .and_then(|o| o.get("file"))
            .and_then(|f| f.get("path"))
            .and_then(|p| p.as_str())
            .ok_or_else(|| anyhow::anyhow!("No file path in event"))?;

        // Extract PID from audit_token
        let pid = json.get("process")
            .and_then(|p| p.get("audit_token"))
            .and_then(|t| t.get("pid"))
            .and_then(|p| p.as_u64())
            .map(|p| p as u32);

        // Extract parent PID (ppid)
        let ppid = json.get("process")
            .and_then(|p| p.get("ppid"))
            .and_then(|p| p.as_u64())
            .map(|p| p as u32);

        // Extract signing info from eslogger (no filesystem access!)
        let app_id = json.get("process")
            .and_then(|p| p.get("signing_id"))
            .and_then(|s| s.as_str());

        let team_id = json.get("process")
            .and_then(|p| p.get("team_id"))
            .and_then(|t| t.as_str());

        // Combine signing info into a single string
        let signing_info = match (app_id, team_id) {
            (Some(aid), Some(tid)) => Some(format!("{} [{}]", aid, tid)),
            (Some(aid), None) => Some(aid.to_string()),
            (None, Some(tid)) => Some(format!("[{}]", tid)),
            (None, None) => None,
        };

        Ok(Some((
            PathBuf::from(process_path),
            PathBuf::from(file_path),
            pid,
            ppid,
            signing_info,
        )))
    }

    fn parse_exec_event(&self, json: &serde_json::Value) -> Result<Option<(PathBuf, Vec<String>, Option<u32>, Option<u32>, Option<String>)>> {
        // Extract process executable path
        let process_path = json.get("event")
            .and_then(|e| e.get("exec"))
            .and_then(|e| e.get("target"))
            .and_then(|t| t.get("executable"))
            .and_then(|e| e.get("path"))
            .and_then(|p| p.as_str())
            .ok_or_else(|| anyhow::anyhow!("No process path in exec event"))?;

        // Extract command-line arguments
        let args = json.get("event")
            .and_then(|e| e.get("exec"))
            .and_then(|e| e.get("args"))
            .and_then(|a| a.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str())
                    .map(|s| s.to_string())
                    .collect::<Vec<String>>()
            })
            .unwrap_or_else(Vec::new);

        // Extract PID from audit_token
        let pid = json.get("process")
            .and_then(|p| p.get("audit_token"))
            .and_then(|t| t.get("pid"))
            .and_then(|p| p.as_u64())
            .map(|p| p as u32);

        // Extract parent PID (ppid)
        let ppid = json.get("process")
            .and_then(|p| p.get("ppid"))
            .and_then(|p| p.as_u64())
            .map(|p| p as u32);

        // Extract signing info
        let app_id = json.get("process")
            .and_then(|p| p.get("signing_id"))
            .and_then(|s| s.as_str());

        let team_id = json.get("process")
            .and_then(|p| p.get("team_id"))
            .and_then(|t| t.as_str());

        let signing_info = match (app_id, team_id) {
            (Some(aid), Some(tid)) => Some(format!("{} [{}]", aid, tid)),
            (Some(aid), None) => Some(aid.to_string()),
            (None, Some(tid)) => Some(format!("[{}]", tid)),
            (None, None) => None,
        };

        Ok(Some((
            PathBuf::from(process_path),
            args,
            pid,
            ppid,
            signing_info,
        )))
    }

    fn check_args_for_protected_paths(&self, args: &[String]) -> Option<PathBuf> {
        for arg in args {
            // Expand tilde in the argument
            let expanded = shellexpand::tilde(arg).to_string();
            let path = PathBuf::from(&expanded);

            // Check if this path or any of its parent directories are protected
            // This catches both direct references and references to files within protected dirs
            if self.rule_engine.is_protected_file(&path) {
                return Some(path);
            }

            // Also check if the argument contains a protected path as a substring
            // This catches cases like "data=@~/.ssh/id_rsa" or "--file=/home/user/.aws/credentials"
            for protected_pattern in &self.rule_engine.get_protected_patterns() {
                let expanded_pattern = shellexpand::tilde(protected_pattern).to_string();
                if expanded.contains(&expanded_pattern) {
                    return Some(PathBuf::from(expanded_pattern));
                }
            }
        }
        None
    }

    async fn handle_exec_with_protected_path(
        &mut self,
        process_path: &Path,
        args: &[String],
        protected_path: &Path,
        pid: Option<u32>,
        ppid: Option<u32>,
        signing_info: Option<String>,
    ) -> Result<()> {
        // Resolve symlinks to get real paths
        let real_process_path = self.normalize_path(process_path);
        let real_protected_path = self.normalize_path(protected_path);

        // Get code signing info
        let pid_str = pid.map_or(String::from("?"), |p| p.to_string());
        let ppid_str = ppid.map_or(String::from("?"), |p| p.to_string());

        let signer_info = signing_info
            .as_ref()
            .map(|s| format!(" [{}]", s))
            .unwrap_or_default();

        // Create process context for exec event checking
        use crate::process_context::ProcessContext;
        let context = ProcessContext {
            path: real_process_path.clone(),
            pid,
            ppid,
            team_id: None, // TODO: Parse from signing_info
            app_id: None,  // TODO: Parse from signing_info
            args: None,    // TODO: Get command-line args
            uid: None,     // TODO: Get user ID
        };

        // Check if this process is allowed to access the protected path
        let decision = self
            .rule_engine
            .check_access_with_context(&context, &real_protected_path);

        match decision {
            Decision::Allow => {
                // Always log allowed exec with protected paths
                log::info!(
                    "{}[{}/ppid:{}]{}: exec with {}: OK (allowed)",
                    real_process_path.display(),
                    pid_str,
                    ppid_str,
                    signer_info,
                    real_protected_path.display()
                );
            }
            Decision::Deny => {
                match self.mode {
                    Mode::Monitor => {
                        // Build log message
                        let mut log_msg = format!(
                            "{}[{}/ppid:{}]{}: exec with {}: DETECTED (monitor mode)",
                            real_process_path.display(),
                            pid_str,
                            ppid_str,
                            signer_info,
                            real_protected_path.display()
                        );

                        // Add command line
                        log_msg.push_str(&format!("\n  Args: {}", args.join(" ")));

                        // Get parent command line if available
                        let parent_cmdline = if let Some(ppid) = ppid {
                            if ppid > 1 {
                                self.get_process_cmdline(ppid)
                            } else {
                                None
                            }
                        } else {
                            None
                        };

                        if let Some(parent_cmd) = parent_cmdline {
                            log_msg.push_str(&format!("\n  ↳ Parent: {}", parent_cmd));
                        }

                        log::warn!("{}", log_msg);
                    }
                    Mode::Enforce => {
                        #[cfg(target_os = "macos")]
                        if let Some(pid) = pid {
                            // Suspend the process immediately
                            let stopped = self.suspend_process(pid);

                            // Always try to suspend parent if requested, even if child already exited
                            let (parent_stopped, parent_cmdline) = if self.stop_parent {
                                if let Some(ppid) = ppid {
                                    if ppid > 1 {
                                        if self.suspend_process(ppid) {
                                            let parent_cmd = self.get_process_cmdline(ppid);
                                            if let Some(ref cmd) = parent_cmd {
                                                log::info!("Stopped parent process (PID {}): {}", ppid, cmd);
                                            } else {
                                                log::info!("Stopped parent process (PID {})", ppid);
                                            }
                                            (true, parent_cmd)
                                        } else {
                                            log::debug!("Failed to stop parent process (PID {})", ppid);
                                            (false, None)
                                        }
                                    } else {
                                        (false, None)
                                    }
                                } else {
                                    (false, None)
                                }
                            } else {
                                (false, None)
                            };

                            if stopped {
                                let parent_info = if parent_stopped {
                                    format!(" + parent[{}]", ppid.unwrap())
                                } else {
                                    String::new()
                                };

                                // Build log message
                                let mut log_msg = format!(
                                    "{}[{}/ppid:{}]{}: exec with {}: STOPPED{}",
                                    real_process_path.display(),
                                    pid,
                                    ppid.map_or(String::from("?"), |p| p.to_string()),
                                    signer_info,
                                    real_protected_path.display(),
                                    parent_info
                                );

                                log_msg.push_str(&format!("\n  Args: {}", args.join(" ")));

                                if let Some(parent_cmd) = parent_cmdline {
                                    log_msg.push_str(&format!("\n  ↳ Parent: {}", parent_cmd));
                                }

                                log::error!("{}", log_msg);
                            } else {
                                // Process exited but try to stop parent anyway
                                let parent_stopped = if self.stop_parent {
                                    if let Some(ppid) = ppid {
                                        if ppid > 1 {
                                            if self.suspend_process(ppid) {
                                                let parent_cmd = self.get_process_cmdline(ppid);
                                                if let Some(ref cmd) = parent_cmd {
                                                    log::info!("Stopped parent process (PID {}): {}", ppid, cmd);
                                                } else {
                                                    log::info!("Stopped parent process (PID {})", ppid);
                                                }
                                                true
                                            } else {
                                                log::debug!("Failed to stop parent process (PID {})", ppid);
                                                false
                                            }
                                        } else {
                                            false
                                        }
                                    } else {
                                        false
                                    }
                                } else {
                                    false
                                };

                                let parent_info = if parent_stopped {
                                    format!(" (parent[{}] stopped)", ppid.unwrap())
                                } else {
                                    String::new()
                                };

                                log::error!(
                                    "{}[{}/ppid:{}]{}: exec with {}: VIOLATION (process exited){}",
                                    real_process_path.display(),
                                    pid,
                                    ppid.map_or(String::from("?"), |p| p.to_string()),
                                    signer_info,
                                    real_protected_path.display(),
                                    parent_info
                                );
                            }
                        }
                    }
                    Mode::Interactive => {
                        // Similar to open, but for exec
                        #[cfg(target_os = "macos")]
                        if let Some(pid) = pid {
                            if self.suspend_process(pid) {
                                log::warn!(
                                    "{}[{}]{}: exec with {}: SUSPENDED (waiting for user)",
                                    real_process_path.display(),
                                    pid,
                                    signer_info,
                                    real_protected_path.display()
                                );
                            }
                        }

                        let allow = self
                            .handle_interactive_prompt_with_pid(
                                &real_process_path,
                                &real_protected_path,
                                pid,
                            )
                            .await?;

                        #[cfg(target_os = "macos")]
                        if let Some(pid) = pid {
                            if allow {
                                self.resume_process(pid);
                                log::info!(
                                    "{}[{}]{}: exec with {}: RESUMED (user allowed)",
                                    real_process_path.display(),
                                    pid,
                                    signer_info,
                                    real_protected_path.display()
                                );
                            } else {
                                log::error!(
                                    "{}[{}]{}: exec with {}: STOPPED (user denied)",
                                    real_process_path.display(),
                                    pid,
                                    signer_info,
                                    real_protected_path.display()
                                );
                            }
                        }
                    }
                }
            }
        }

        Ok(())
    }

    async fn handle_file_access_with_signing(
        &mut self,
        process_path: &Path,
        file_path: &Path,
        pid: Option<u32>,
        ppid: Option<u32>,
        signing_info: Option<String>,
    ) -> Result<()> {
        // Resolve symlinks to get real paths
        let real_file_path = self.normalize_path(file_path);
        let real_process_path = self.normalize_path(process_path);

        // Get code signing info

        let pid_str = pid.map_or(String::from("?"), |p| p.to_string());
        let ppid_str = ppid.map_or(String::from("?"), |p| p.to_string());

        // Use signing info from eslogger - NEVER access the binary!
        let signer_info = signing_info
            .as_ref()
            .map(|s| format!(" [{}]", s))
            .unwrap_or_default();

        // Log ALL file opens, not just protected ones
        let is_protected = self.rule_engine.is_protected_file(&real_file_path);

        if !is_protected {
            // Log non-protected file access only in verbose mode
            if self.verbose {
                log::info!(
                    "{}[{}/ppid:{}]{}: open {}: OK (not monitored)",
                    real_process_path.display(),
                    pid_str,
                    ppid_str,
                    signer_info,
                    real_file_path.display()
                );
            }
            return Ok(());
        }

        // Protected file access detected - will check rules

        // Create process context for the new rule system
        use crate::process_context::ProcessContext;
        let context = ProcessContext {
            path: real_process_path.clone(),
            pid,
            ppid,
            team_id: None, // TODO: Parse from signing_info
            app_id: None,  // TODO: Parse from signing_info
            args: None,    // TODO: Get command-line args
            uid: None,     // TODO: Get user ID
        };

        // Check if access is allowed using new context-aware method
        let decision = self
            .rule_engine
            .check_access_with_context(&context, &real_file_path);


        match decision {
            Decision::Allow => {
                // Always log allowed access to protected files (they're on our monitoring list)
                log::info!(
                    "{}[{}/ppid:{}]{}: open {}: OK (allowed)",
                    real_process_path.display(),
                    pid_str,
                    ppid_str,
                    signer_info,
                    real_file_path.display()
                );
            }
            Decision::Deny => {
                match self.mode {
                    Mode::Monitor => {
                        // Get command-line args if we can
                        let cmdline = if let Some(pid) = pid {
                            self.get_process_cmdline(pid)
                        } else {
                            None
                        };

                        // Get parent command line if available
                        let parent_cmdline = if let Some(ppid) = ppid {
                            if ppid > 1 {  // Don't try for init
                                self.get_process_cmdline(ppid)
                            } else {
                                None
                            }
                        } else {
                            None
                        };

                        // Build log message
                        let mut log_msg = format!(
                            "{}[{}/ppid:{}]{}: open {}: DETECTED (monitor mode)",
                            real_process_path.display(),
                            pid_str,
                            ppid_str,
                            signer_info,
                            real_file_path.display()
                        );

                        if let Some(cmdline) = cmdline {
                            log_msg.push_str(&format!("\n  Args: {}", cmdline));
                        }

                        if let Some(parent_cmd) = parent_cmdline {
                            log_msg.push_str(&format!("\n  ↳ Parent: {}", parent_cmd));
                        }

                        log::warn!("{}", log_msg);
                    }
                    Mode::Enforce => {
                        // On macOS with eslogger, we can suspend the process
                        #[cfg(target_os = "macos")]
                        if let Some(pid) = pid {
                            // Suspend the process
                            let stopped = self.suspend_process(pid);

                            // Always try to suspend parent if requested, even if child already exited
                            let (parent_stopped, parent_cmdline) = if self.stop_parent {
                                if let Some(ppid) = ppid {
                                    if ppid > 1 {  // Don't try to stop init (pid 1)
                                        if self.suspend_process(ppid) {
                                            // Get parent command line after stopping it
                                            let parent_cmd = self.get_process_cmdline(ppid);
                                            if let Some(ref cmd) = parent_cmd {
                                                log::info!("Stopped parent process (PID {}): {}", ppid, cmd);
                                            } else {
                                                log::info!("Stopped parent process (PID {})", ppid);
                                            }
                                            (true, parent_cmd)
                                        } else {
                                            log::debug!("Failed to stop parent process (PID {})", ppid);
                                            (false, None)
                                        }
                                    } else {
                                        (false, None)
                                    }
                                } else {
                                    (false, None)
                                }
                            } else {
                                (false, None)
                            };

                            if stopped {
                                // Get command-line args after stopping the process
                                let cmdline = self.get_process_cmdline(pid);

                                let parent_info = if parent_stopped {
                                    format!(" + parent[{}]", ppid.unwrap())
                                } else {
                                    String::new()
                                };

                                // Build log message with command lines
                                let mut log_msg = format!(
                                    "{}[{}/ppid:{}]{}: open {}: STOPPED{}",
                                    real_process_path.display(),
                                    pid,
                                    ppid.map_or(String::from("?"), |p| p.to_string()),
                                    signer_info,
                                    real_file_path.display(),
                                    parent_info
                                );

                                if let Some(cmdline) = cmdline {
                                    log_msg.push_str(&format!("\n  Args: {}", cmdline));
                                }

                                if let Some(parent_cmd) = parent_cmdline {
                                    log_msg.push_str(&format!("\n  ↳ Parent: {}", parent_cmd));
                                }

                                log::error!("{}", log_msg);
                            } else {
                                // Process exited but try to stop parent anyway
                                let parent_stopped = if self.stop_parent {
                                    if let Some(ppid) = ppid {
                                        if ppid > 1 {
                                            if self.suspend_process(ppid) {
                                                let parent_cmd = self.get_process_cmdline(ppid);
                                                if let Some(ref cmd) = parent_cmd {
                                                    log::info!("Stopped parent process (PID {}): {}", ppid, cmd);
                                                } else {
                                                    log::info!("Stopped parent process (PID {})", ppid);
                                                }
                                                true
                                            } else {
                                                log::debug!("Failed to stop parent process (PID {})", ppid);
                                                false
                                            }
                                        } else {
                                            false
                                        }
                                    } else {
                                        false
                                    }
                                } else {
                                    false
                                };

                                let parent_info = if parent_stopped {
                                    format!(" (parent[{}] stopped)", ppid.unwrap())
                                } else {
                                    String::new()
                                };

                                log::error!(
                                    "{}[{}/ppid:{}]{}: open {}: VIOLATION (process exited){}",
                                    real_process_path.display(),
                                    pid,
                                    ppid.map_or(String::from("?"), |p| p.to_string()),
                                    signer_info,
                                    real_file_path.display(),
                                    parent_info
                                );
                            }
                        } else {
                            log::error!(
                                "{}[?]{}: open {}: BLOCKED (no PID)",
                                real_process_path.display(),
                                signer_info,
                                real_file_path.display()
                            );
                        }

                        #[cfg(not(target_os = "macos"))]
                        {
                            log::error!(
                                "{}[{}]: open {}: BLOCKED",
                                real_process_path.display(),
                                pid_str,
                                real_file_path.display()
                            );
                        }
                    }
                    Mode::Interactive => {
                        // Suspend process while waiting for user decision
                        #[cfg(target_os = "macos")]
                        if let Some(pid) = pid {
                            if self.suspend_process(pid) {
                                log::warn!(
                                    "{}[{}]{}: open {}: SUSPENDED (waiting for user)",
                                    real_process_path.display(),
                                    pid,
                                    signer_info,
                                    real_file_path.display()
                                );
                            }
                        }

                        let allow = self
                            .handle_interactive_prompt_with_pid(
                                &real_process_path,
                                &real_file_path,
                                pid,
                            )
                            .await?;

                        // Resume or terminate based on decision
                        #[cfg(target_os = "macos")]
                        if let Some(pid) = pid {
                            if allow {
                                self.resume_process(pid);
                                log::info!(
                                    "{}[{}]{}: open {}: RESUMED (user allowed)",
                                    real_process_path.display(),
                                    pid,
                                    signer_info,
                                    real_file_path.display()
                                );
                            } else {
                                log::error!(
                                    "{}[{}]{}: open {}: STOPPED (user denied)",
                                    real_process_path.display(),
                                    pid,
                                    signer_info,
                                    real_file_path.display()
                                );
                            }
                        }
                    }
                }
            }
        }

        Ok(())
    }

    fn normalize_path(&self, path: &Path) -> PathBuf {
        // Try to resolve symlinks to get the real path
        match path.canonicalize() {
            Ok(canonical) => canonical,
            Err(_) => {
                // If canonicalize fails, try to resolve parent directory
                if let Some(parent) = path.parent() {
                    if let Ok(canonical_parent) = parent.canonicalize() {
                        if let Some(filename) = path.file_name() {
                            return canonical_parent.join(filename);
                        }
                    }
                }
                // Fall back to original path
                path.to_path_buf()
            }
        }
    }

    #[cfg(target_os = "macos")]
    fn suspend_process(&self, pid: u32) -> bool {
        // Use libc kill directly for lower latency
        unsafe {
            // Try to suspend immediately without checking first (faster)
            let result = libc::kill(pid as libc::pid_t, libc::SIGSTOP);

            if result == 0 {
                log::debug!("Successfully suspended process PID {}", pid);
                return true;
            }

            // Check errno to understand why it failed
            let errno = *libc::__error();
            match errno {
                libc::ESRCH => {
                    log::debug!("Process PID {} no longer exists (already exited)", pid);
                }
                libc::EPERM => {
                    log::error!("Permission denied suspending PID {} (may be protected by SIP)", pid);
                }
                _ => {
                    log::error!("Failed to suspend PID {}: errno {}", pid, errno);
                }
            }
            false
        }
    }

    #[cfg(target_os = "macos")]
    fn get_process_cmdline(&self, pid: u32) -> Option<String> {
        use std::process::Command;

        // Use ps to get command-line arguments
        match Command::new("ps")
            .args(["-o", "command=", "-p", &pid.to_string()])
            .output()
        {
            Ok(output) => {
                if output.status.success() {
                    let cmdline = String::from_utf8_lossy(&output.stdout).trim().to_string();
                    if !cmdline.is_empty() {
                        Some(cmdline)
                    } else {
                        None
                    }
                } else {
                    None
                }
            }
            Err(_) => None,
        }
    }

    #[cfg(not(target_os = "macos"))]
    fn get_process_cmdline(&self, pid: u32) -> Option<String> {
        // On Linux, read from /proc/PID/cmdline
        use std::fs;

        let cmdline_path = format!("/proc/{}/cmdline", pid);
        match fs::read_to_string(&cmdline_path) {
            Ok(cmdline) => {
                // Replace null bytes with spaces
                let cmdline = cmdline.replace('\0', " ").trim().to_string();
                if !cmdline.is_empty() {
                    Some(cmdline)
                } else {
                    None
                }
            }
            Err(_) => None,
        }
    }

    #[cfg(target_os = "macos")]
    #[allow(dead_code)]
    fn _suspend_process_fallback(&self, pid: u32) -> bool {
        use std::process::Command;

        // Fallback to command if needed
        match Command::new("kill")
            .args(["-STOP", &pid.to_string()])
            .output()
        {
            Ok(output) => {
                if output.status.success() {
                    log::debug!("Successfully suspended process PID {}", pid);
                    true
                } else {
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    if stderr.contains("No such process") {
                        log::debug!("Process PID {} exited before we could suspend it", pid);
                    } else if stderr.contains("Operation not permitted") {
                        log::error!("Permission denied suspending PID {} (may be protected)", pid);
                    } else {
                        log::error!("Failed to suspend PID {}: {}", pid, stderr.trim());
                    }
                    false
                }
            }
            Err(e) => {
                log::error!("Failed to run kill command: {}", e);
                false
            }
        }
    }

    #[cfg(target_os = "macos")]
    fn resume_process(&self, pid: u32) -> bool {
        use std::process::Command;

        match Command::new("kill")
            .args(["-CONT", &pid.to_string()])
            .output()
        {
            Ok(output) => {
                if output.status.success() {
                    log::debug!("Successfully resumed process PID {}", pid);
                    true
                } else {
                    log::error!("Failed to resume process PID {}: {:?}", pid, output);
                    false
                }
            }
            Err(e) => {
                log::error!("Failed to run kill command: {}", e);
                false
            }
        }
    }

    async fn handle_interactive_prompt_with_pid(
        &mut self,
        process_path: &Path,
        file_path: &Path,
        pid: Option<u32>,
    ) -> Result<bool> {
        loop {
            let app_name = process_path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("unknown");

            println!("\n{}", "=".repeat(60));
            println!("⚠️  CREDENTIAL ACCESS DETECTED");
            println!("{}", "=".repeat(60));
            println!("Application: {}", app_name);
            println!("Full path:   {}", process_path.display());
            if let Some(pid) = pid {
                println!("Process ID:  {}", pid);
                #[cfg(target_os = "macos")]
                println!("Status:      SUSPENDED (waiting for decision)");
            }
            println!("Credential:  {}", file_path.display());
            println!();
            println!("This application is trying to access sensitive credentials.");
            println!();
            println!("Options:");
            println!("  [A]llow once");
            println!("  [D]eny (default)");
            println!("  [W]hitelist this app for this credential");
            println!("  [S]how more info");
            println!();
            print!("Decision [A/d/w/s]? ");

            use std::io::{self, Write};
            io::stdout().flush()?;

            let mut input = String::new();
            io::stdin().read_line(&mut input)?;

            match input.trim().to_lowercase().chars().next() {
                Some('a') => {
                    println!("✓ Allowed once\n");
                    log::info!(
                        "User allowed access: {} -> {}",
                        app_name,
                        file_path.display()
                    );
                    return Ok(true);
                }
                Some('w') => {
                    println!("✓ Added to whitelist\n");
                    self.rule_engine
                        .add_runtime_exception(process_path.to_path_buf(), file_path.to_path_buf());
                    log::info!("User whitelisted: {} -> {}", app_name, file_path.display());
                    return Ok(true);
                }
                Some('s') => {
                    self.show_process_info(process_path);
                    if let Some(pid) = pid {
                        self.show_process_status(pid);
                    }
                    // Continue the loop to re-prompt
                    continue;
                }
                _ => {
                    println!("✗ Denied\n");
                    log::warn!(
                        "User denied access: {} -> {}",
                        app_name,
                        file_path.display()
                    );
                    return Ok(false);
                }
            }
        }
    }

    fn show_process_info(&self, process_path: &Path) {
        println!("\nAdditional Information:");
        println!("  Full path: {}", process_path.display());

        // We no longer access the filesystem for process info
        // All information comes from eslogger events
        println!("  Note: Code signing info available in event logs");
    }

    fn show_process_status(&self, pid: u32) {
        #[cfg(target_os = "macos")]
        {
            println!("  Process Status:");
            if let Ok(output) = Command::new("ps")
                .args(["-p", &pid.to_string(), "-o", "state="])
                .output()
            {
                let state = String::from_utf8_lossy(&output.stdout).trim().to_string();
                match state.chars().next() {
                    Some('T') => println!("    State: Suspended (SIGSTOP)"),
                    Some('R') => println!("    State: Running"),
                    Some('S') => println!("    State: Sleeping"),
                    Some('Z') => println!("    State: Zombie"),
                    _ => println!("    State: {}", state),
                }
            }
        }
    }

    #[cfg(target_os = "macos")]
    async fn monitor_with_esf(&mut self) -> Result<()> {
        Err(anyhow::anyhow!(
            "ESF monitoring not yet implemented. Use --mechanism eslogger for now."
        ))
    }

    #[cfg(target_os = "linux")]
    async fn monitor_with_fanotify(&mut self) -> Result<()> {
        log::info!("Using fanotify mechanism");

        // Use the Linux-specific monitor implementation
        let mut linux_monitor = LinuxMonitor::new(self.mode.clone(), self.verbose, self.stop_parent);
        linux_monitor.start().await
    }

    #[cfg(target_os = "linux")]
    async fn monitor_with_ebpf(&mut self) -> Result<()> {
        Err(anyhow::anyhow!(
            "eBPF monitoring not yet implemented. Use --mechanism auto for now."
        ))
    }

    #[cfg(target_os = "freebsd")]
    async fn monitor_with_dtrace(&mut self) -> Result<()> {
        log::info!("Using DTrace mechanism for FreeBSD");

        let mut monitor = FreeBSDMonitor::new(self.mode, self.verbose, self.stop_parent);
        monitor.start().await
    }

    #[cfg(target_os = "freebsd")]
    async fn monitor_with_kqueue(&mut self) -> Result<()> {
        Err(anyhow::anyhow!(
            "kqueue monitoring not yet implemented. Use --mechanism dtrace for now."
        ))
    }

    async fn monitor_with_auto(&mut self) -> Result<()> {
        #[cfg(target_os = "macos")]
        {
            log::info!("Auto-selecting eslogger for macOS");
            self.mechanism = Mechanism::Eslogger;
            self.monitor_with_eslogger().await
        }

        #[cfg(target_os = "linux")]
        {
            log::info!("Auto-selecting fanotify for Linux");
            self.mechanism = Mechanism::Fanotify;
            self.monitor_with_fanotify().await
        }

        #[cfg(target_os = "freebsd")]
        {
            log::info!("Auto-selecting DTrace for FreeBSD");
            self.mechanism = Mechanism::Dtrace;
            self.monitor_with_dtrace().await
        }

        #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "freebsd")))]
        {
            Err(anyhow::anyhow!(
                "No monitoring mechanism available for this platform"
            ))
        }
    }

    // REMOVED: get_code_signer - We should NEVER access binaries!
    // All signing info comes from eslogger events to avoid filesystem access
}
