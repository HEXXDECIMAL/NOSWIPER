use crate::cli::{Mechanism, Mode};
use crate::config::Config;
use crate::ipc_server::{Event, EventType, IpcServer, ProcessTreeEntry, SuspendedProcess};
use crate::json_logger::{JsonLogger, ProcessDetails};
#[cfg(target_os = "macos")]
use crate::rules::Decision;
use crate::rules::RuleEngine;
use crate::types::ExecEvent;
use anyhow::Result;
#[cfg(target_os = "macos")]
use serde::Deserialize;
#[cfg(target_os = "macos")]
use std::collections::HashMap;
use std::path::Path;
#[cfg(target_os = "macos")]
use std::path::PathBuf;
#[cfg(target_os = "macos")]
use std::process::Command;
use std::sync::Arc;
#[cfg(target_os = "macos")]
use std::sync::Mutex;
#[cfg(target_os = "macos")]
use std::time::{Duration, Instant};
#[cfg(target_os = "macos")]
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::sync::RwLock;

#[cfg(target_os = "macos")]
use tokio::process::Command as TokioCommand;

// Type aliases to reduce complexity
#[cfg(target_os = "macos")]
#[allow(dead_code)] // Will be used to simplify function signatures
type OpenEventResult = Option<(
    PathBuf,
    PathBuf,
    Option<u32>,
    Option<u32>,
    Option<u32>,
    Option<String>,
)>;

#[cfg(target_os = "macos")]
#[allow(dead_code)] // Will be used to simplify function signatures
type ExecEventResult = Option<(
    PathBuf,
    Vec<String>,
    Option<u32>,
    Option<u32>,
    Option<u32>,
    Option<String>,
)>;

#[cfg(target_os = "linux")]
use crate::linux_monitor::LinuxMonitor;

#[cfg(target_os = "freebsd")]
use crate::freebsd_monitor::FreeBSDMonitor;

/// Cached information about a process
#[cfg(target_os = "macos")]
#[derive(Debug, Clone)]
struct ProcessInfo {
    #[allow(dead_code)]
    pid: u32,
    ppid: Option<u32>,
    euid: Option<u32>,
    path: PathBuf,
    args: Vec<String>,
    command_line: String,
    team_id: Option<String>,
    signing_id: Option<String>,
    is_platform_binary: bool,
    last_seen: Instant,
}

#[cfg(target_os = "macos")]
impl ProcessInfo {
    fn new(pid: u32, path: PathBuf) -> Self {
        Self {
            pid,
            ppid: None,
            euid: None,
            path,
            args: Vec::new(),
            command_line: String::new(),
            team_id: None,
            signing_id: None,
            is_platform_binary: false,
            last_seen: Instant::now(),
        }
    }
}

pub struct Monitor {
    rule_engine: RuleEngine,
    mode: Arc<RwLock<Mode>>,
    mechanism: Mechanism,
    verbose: bool,
    #[allow(dead_code)] // Used in future functionality
    debug: bool,
    stop_parent: bool,
    json_logger: JsonLogger,
    ipc_server: Arc<IpcServer>,
    #[cfg(target_os = "macos")]
    process_cache: HashMap<u32, ProcessInfo>,
    #[cfg(target_os = "macos")]
    cache_ttl: Duration,
    #[cfg(target_os = "macos")]
    vendor_cache: Arc<Mutex<HashMap<String, Option<String>>>>, // team_id -> vendor_name cache
}

// These structs are for potential future use with typed JSON parsing
// Currently we parse JSON dynamically for flexibility
#[cfg(target_os = "macos")]
#[allow(dead_code)]
#[derive(Deserialize, Debug)]
struct EsloggerEvent {
    process: serde_json::Value,
    event: serde_json::Value,
}

impl Monitor {
    pub fn new(
        mode: Mode,
        mechanism: Mechanism,
        verbose: bool,
        debug: bool,
        stop_parent: bool,
    ) -> Self {
        // Load config from embedded YAML
        let config = Config::load_default().expect("Failed to load default config");

        // Create JSON logger and log its location
        let json_logger = JsonLogger::new().unwrap_or_default();
        if let Ok(log_path) = JsonLogger::get_log_path() {
            log::info!("JSON event log: {}", log_path.display());
        }

        // Create shared mode
        let shared_mode = Arc::new(RwLock::new(mode));

        // Create IPC server with shared mode and log its location
        let ipc_server =
            Arc::new(IpcServer::new(shared_mode.clone()).expect("Failed to create IPC server"));
        if let Ok(socket_path) = IpcServer::get_socket_path() {
            log::info!("IPC socket: {}", socket_path.display());
        }

        Self {
            rule_engine: RuleEngine::with_debug(config, debug),
            mode: shared_mode,
            mechanism,
            verbose,
            debug,
            stop_parent,
            json_logger,
            ipc_server,
            #[cfg(target_os = "macos")]
            process_cache: HashMap::new(),
            #[cfg(target_os = "macos")]
            cache_ttl: Duration::from_secs(300), // 5 minute TTL for process cache
            #[cfg(target_os = "macos")]
            vendor_cache: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub async fn start(&mut self) -> Result<()> {
        let mode = self.mode.read().await;
        log::info!("Starting NoSwiper agent in {} mode", *mode);
        drop(mode);
        log::info!("Using monitoring mechanism: {}", self.mechanism);

        // Start IPC server in background
        let ipc_server = Arc::clone(&self.ipc_server);
        tokio::spawn(async move {
            if let Err(e) = ipc_server.start().await {
                log::error!("IPC server error: {}", e);
            }
        });

        if let Mode::Interactive = *self.mode.read().await {
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
            .args(eslogger_args)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .map_err(|e| {
                anyhow::anyhow!(
                    "Failed to spawn eslogger process: {}. Command was: {}",
                    e,
                    eslogger_cmd
                )
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

        // Track events in first few seconds
        let event_count_shared = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
        let event_count_clone = event_count_shared.clone();

        // Report event rate after initial period
        tokio::spawn(async move {
            tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
            let count = event_count_clone.load(std::sync::atomic::Ordering::Relaxed);
            log::info!(
                "Processed {} events in first 5 seconds (averaging {:.1} events/sec)",
                count,
                count as f64 / 5.0
            );
        });

        while let Some(line) = lines.next_line().await? {
            if line.trim().is_empty() {
                continue;
            }

            event_count += 1;

            // Update shared counter for first 5 seconds
            if event_count <= 10000 {
                // Reasonable cap to avoid overflow
                event_count_shared.store(event_count, std::sync::atomic::Ordering::Relaxed);
            }

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
                            Ok(Some((process_path, file_path, pid, ppid, euid, signing_info))) => {
                                // Cache process info
                                if let Some(p) = pid {
                                    // Extract team_id, signing_id, and is_platform_binary from JSON
                                    let team_id = json
                                        .get("process")
                                        .and_then(|p| p.get("team_id"))
                                        .and_then(|t| t.as_str());
                                    let signing_id = json
                                        .get("process")
                                        .and_then(|p| p.get("signing_id"))
                                        .and_then(|s| s.as_str());
                                    let is_platform_binary = json
                                        .get("process")
                                        .and_then(|p| p.get("is_platform_binary"))
                                        .and_then(|b| b.as_bool())
                                        .unwrap_or(false);

                                    self.cache_process_info(
                                        p,
                                        &process_path,
                                        ppid,
                                        euid,
                                        &[], // No args for open events
                                        team_id,
                                        signing_id,
                                        is_platform_binary,
                                    );
                                }

                                // For protected files, handle immediately
                                if self.rule_engine.is_protected_file(&file_path) {
                                    // Handle synchronously for speed
                                    self.handle_file_access_with_signing(
                                        &process_path,
                                        &file_path,
                                        pid,
                                        ppid,
                                        euid,
                                        signing_info,
                                    )
                                    .await?;
                                } else {
                                    // Log non-critical events asynchronously
                                    let process_display = process_path.display().to_string();
                                    let pid_str = match (euid, pid) {
                                        (Some(e), Some(p)) => format!("{}@{}", e, p),
                                        (None, Some(p)) => p.to_string(),
                                        _ => String::from("?"),
                                    };
                                    let ppid_str = match ppid {
                                        Some(p) => p.to_string(),
                                        None => String::from("?"),
                                    };
                                    let file_display = file_path.display().to_string();
                                    let verbose = self.verbose;

                                    tokio::spawn(async move {
                                        if verbose {
                                            log::info!(
                                                "{}[{}->{}]: open {}: OK",
                                                process_display,
                                                pid_str,
                                                ppid_str,
                                                file_display
                                            );
                                        }
                                    });
                                }
                            }
                            Ok(None) => {
                                log::trace!(
                                    "Open event parsed but not relevant (directory or filtered)"
                                );
                            }
                            Err(e) => {
                                log::debug!("Failed to parse open event: {}", e);
                            }
                        }
                    }
                    // Check if this is an exec event
                    else if json.get("event").and_then(|e| e.get("exec")).is_some() {
                        match self.parse_exec_event(&json) {
                            Ok(Some((process_path, args, pid, ppid, euid, signing_info))) => {
                                // Cache process info with args
                                if let Some(p) = pid {
                                    // Extract team_id, signing_id, and is_platform_binary from JSON
                                    let team_id = json
                                        .get("process")
                                        .and_then(|p| p.get("team_id"))
                                        .and_then(|t| t.as_str());
                                    let signing_id = json
                                        .get("process")
                                        .and_then(|p| p.get("signing_id"))
                                        .and_then(|s| s.as_str());
                                    let is_platform_binary = json
                                        .get("process")
                                        .and_then(|p| p.get("is_platform_binary"))
                                        .and_then(|b| b.as_bool())
                                        .unwrap_or(false);

                                    self.cache_process_info(
                                        p,
                                        &process_path,
                                        ppid,
                                        euid,
                                        &args,
                                        team_id,
                                        signing_id,
                                        is_platform_binary,
                                    );
                                }

                                // Check if any argument contains a protected path
                                if let Some(protected_path) =
                                    self.check_args_for_protected_paths(&args)
                                {
                                    let event = ExecEvent::new(
                                        process_path.clone(),
                                        args.clone(),
                                        protected_path,
                                        pid,
                                        ppid,
                                        euid,
                                        signing_info,
                                    );
                                    self.handle_exec_with_protected_path(event).await?;
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
                        log::debug!(
                            "Failed to parse eslogger event: {} - Event: {}",
                            e,
                            line_clone
                        );
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
            let error_msg = if stderr_messages.iter().any(|m| {
                m.contains("TCC Full Disk Access")
                    || m.contains("ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED")
            }) {
                log::error!(
                    "eslogger requires Full Disk Access permission in macOS System Preferences"
                );
                "eslogger requires Full Disk Access permission. Please:\n\
                1. Open System Preferences -> Security & Privacy -> Privacy tab\n\
                2. Select 'Full Disk Access' from the left sidebar\n\
                3. Click the lock to make changes\n\
                4. Add Terminal.app (or your terminal emulator) to the list\n\
                5. Restart your terminal and try again"
            } else if stderr_messages.iter().any(|m| {
                m.contains("Not privileged")
                    || m.contains("ES_NEW_CLIENT_RESULT_ERR_NOT_PRIVILEGED")
            }) {
                log::error!("eslogger needs to be run with root privileges");
                "eslogger needs root privileges. Please run with: sudo {}"
            } else {
                log::error!("eslogger failed with unknown error");
                "eslogger exited with error: {}. Command was: eslogger open --format json"
            };

            return Err(anyhow::anyhow!(
                "{}",
                error_msg.replace("{}", &exit_status.to_string())
            ));
        }

        Ok(())
    }

    #[cfg(target_os = "macos")]
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

    #[cfg(target_os = "macos")]
    fn parse_open_event(&self, json: &serde_json::Value) -> Result<OpenEventResult> {
        // This function assumes it's already been verified as an open event

        // Check if this is a directory (st_mode & 0170000 == 0040000)
        let is_directory = json
            .get("event")
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
        let process_path = json
            .get("process")
            .and_then(|p| p.get("executable"))
            .and_then(|e| {
                // The path is nested in an object
                e.get("path").and_then(|p| p.as_str())
            })
            .ok_or_else(|| anyhow::anyhow!("No process path in event"))?;

        // Extract file path from the nested structure
        let file_path = json
            .get("event")
            .and_then(|e| e.get("open"))
            .and_then(|o| o.get("file"))
            .and_then(|f| f.get("path"))
            .and_then(|p| p.as_str())
            .ok_or_else(|| anyhow::anyhow!("No file path in event"))?;

        // Extract PID from audit_token
        let pid = json
            .get("process")
            .and_then(|p| p.get("audit_token"))
            .and_then(|t| t.get("pid"))
            .and_then(|p| p.as_u64())
            .map(|p| p as u32);

        // Extract EUID from audit_token
        let euid = json
            .get("process")
            .and_then(|p| p.get("audit_token"))
            .and_then(|t| t.get("euid"))
            .and_then(|e| e.as_u64())
            .map(|e| e as u32);

        // Extract parent PID (ppid)
        let ppid = json
            .get("process")
            .and_then(|p| p.get("ppid"))
            .and_then(|p| p.as_u64())
            .map(|p| p as u32);

        // Extract signing info from eslogger (no filesystem access!)
        let app_id = json
            .get("process")
            .and_then(|p| p.get("signing_id"))
            .and_then(|s| s.as_str());

        let team_id = json
            .get("process")
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
            euid,
            signing_info,
        )))
    }

    #[cfg(target_os = "macos")]
    fn parse_exec_event(&self, json: &serde_json::Value) -> Result<ExecEventResult> {
        // Extract process executable path
        let process_path = json
            .get("event")
            .and_then(|e| e.get("exec"))
            .and_then(|e| e.get("target"))
            .and_then(|t| t.get("executable"))
            .and_then(|e| e.get("path"))
            .and_then(|p| p.as_str())
            .ok_or_else(|| anyhow::anyhow!("No process path in exec event"))?;

        // Extract command-line arguments
        let args = json
            .get("event")
            .and_then(|e| e.get("exec"))
            .and_then(|e| e.get("args"))
            .and_then(|a| a.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str())
                    .map(|s| s.to_string())
                    .collect::<Vec<String>>()
            })
            .unwrap_or_default();

        // Extract PID from audit_token
        let pid = json
            .get("process")
            .and_then(|p| p.get("audit_token"))
            .and_then(|t| t.get("pid"))
            .and_then(|p| p.as_u64())
            .map(|p| p as u32);

        // Extract EUID from audit_token
        let euid = json
            .get("process")
            .and_then(|p| p.get("audit_token"))
            .and_then(|t| t.get("euid"))
            .and_then(|e| e.as_u64())
            .map(|e| e as u32);

        // Extract parent PID (ppid)
        let ppid = json
            .get("process")
            .and_then(|p| p.get("ppid"))
            .and_then(|p| p.as_u64())
            .map(|p| p as u32);

        // Extract signing info
        let app_id = json
            .get("process")
            .and_then(|p| p.get("signing_id"))
            .and_then(|s| s.as_str());

        let team_id = json
            .get("process")
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
            euid,
            signing_info,
        )))
    }

    #[cfg(target_os = "macos")]
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

    #[cfg(target_os = "macos")]
    async fn handle_exec_with_protected_path(&mut self, event: ExecEvent) -> Result<()> {
        // Resolve symlinks to get real paths
        let real_process_path = self.normalize_path(&event.process_path);
        let real_protected_path = self.normalize_path(event.protected_path.as_path());

        // Get code signing info (no longer need PID strings for simplified logs)

        #[cfg(target_os = "macos")]
        let _signer_info = event
            .signing_info
            .as_ref()
            .map(|s| format!(" [{}]", s))
            .unwrap_or_default();

        #[cfg(not(target_os = "macos"))]
        let _signer_info = String::new();

        // Create process context for exec event checking
        use crate::process_context::ProcessContext;

        // Parse signing info to extract app_id and team_id
        let (app_id, team_id) = parse_signing_info(event.signing_info.as_deref());

        // Get platform_binary from cache if available
        let platform_binary = event
            .pid()
            .and_then(|p| self.process_cache.get(&p))
            .map(|entry| entry.is_platform_binary);

        let context = ProcessContext {
            path: real_process_path.clone(),
            pid: event.pid(),
            ppid: event.ppid(),
            team_id: team_id.clone(),
            app_id,
            args: Some(event.args.to_vec()),
            uid: None, // TODO: Get user ID
            euid: event.euid(),
            platform_binary,
        };

        // Check if this process is allowed to access the protected path
        let decision = self
            .rule_engine
            .check_access_with_context(&context, &real_protected_path);

        // Read mode once for the entire decision handling
        let current_mode = *self.mode.read().await;

        match decision {
            Decision::Allow(rule_name) => {
                // This is a protected file that was allowed access - log it
                let prefix = if let Some(ref name) = rule_name {
                    format!("OK[{}]", name)
                } else {
                    "OK".to_string()
                };
                let log_msg = self.build_compact_log_message(
                    &prefix,
                    &real_protected_path,
                    "exec",
                    event.pid(),
                    event.ppid(),
                    event.euid(),
                    &real_process_path,
                );
                log::info!("{}", log_msg);
            }
            Decision::NotProtected => {
                // Not a protected file, don't log unless debugging
                if self.debug {
                    log::trace!("File '{}' is not protected", real_protected_path.display());
                }
            }
            Decision::Deny(rule_name) => {
                match current_mode {
                    Mode::Monitor => {
                        let log_msg = self.build_compact_log_message(
                            &format!("DETECTED[{}]", rule_name),
                            &real_protected_path,
                            "exec",
                            event.pid(),
                            event.ppid(),
                            event.euid(),
                            &real_process_path,
                        );
                        log::warn!("{}", log_msg);

                        // Send event to IPC server for UI notification
                        if let Some(pid) = event.pid() {
                            // Build command line from args
                            let cmdline = if event.args.is_empty() {
                                real_process_path.display().to_string()
                            } else {
                                format!("{} {}", real_process_path.display(), event.args.join(" "))
                            };

                            let process_tree = self.build_process_tree_for_event(pid, 5);

                            let event = Event {
                                id: IpcServer::generate_event_id(),
                                timestamp: chrono::Utc::now(),
                                event_type: EventType::AccessDenied {
                                    rule_name: rule_name.clone(),
                                    file_path: real_protected_path.display().to_string(),
                                    process_path: real_process_path.display().to_string(),
                                    process_pid: pid,
                                    process_cmdline: Some(cmdline),
                                    process_euid: event.euid(),
                                    parent_pid: event.ppid(),
                                    team_id: team_id.clone(),
                                    action: "detected".to_string(),
                                    process_tree: Some(process_tree),
                                },
                            };

                            let ipc_server = Arc::clone(&self.ipc_server);
                            tokio::spawn(async move {
                                if let Err(e) = ipc_server.add_event(event).await {
                                    log::warn!("Failed to send event to IPC server: {} (UI may not receive notification)", e);
                                }
                            });
                        }
                    }
                    Mode::Enforce => {
                        #[cfg(target_os = "macos")]
                        if let Some(pid) = event.pid() {
                            // Suspend the process immediately
                            let stopped = self.suspend_process(pid);

                            // Always try to suspend parent if requested, even if child already exited
                            let (parent_stopped, _parent_cmdline) = if self.stop_parent {
                                if let Some(ppid) = event.ppid() {
                                    if ppid > 1 {
                                        if self.suspend_process(ppid) {
                                            let parent_cmd = self.get_process_cmdline(ppid);
                                            if let Some(ref cmd) = parent_cmd {
                                                log::info!(
                                                    "Stopped parent process (PID {}): {}",
                                                    ppid,
                                                    cmd
                                                );
                                            } else {
                                                log::info!("Stopped parent process (PID {})", ppid);
                                            }
                                            (true, parent_cmd)
                                        } else {
                                            log::debug!(
                                                "Failed to stop parent process (PID {})",
                                                ppid
                                            );
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
                                // Log the blocked event with process tree
                                log::error!(
                                    "BLOCKED: {} {}: {}",
                                    real_protected_path.display(),
                                    "exec",
                                    real_process_path.display()
                                );

                                // Log the process tree
                                let tree =
                                    self.build_process_tree_string(Some(pid), event.ppid(), 3);
                                for line in tree {
                                    log::error!("{}", line);
                                }

                                if parent_stopped {
                                    log::error!("  Status: Process and parent stopped");
                                } else {
                                    log::error!("  Status: Process stopped");
                                }
                            } else {
                                // Process exited but try to stop parent anyway
                                let parent_stopped = if self.stop_parent {
                                    if let Some(ppid) = event.ppid() {
                                        if ppid > 1 {
                                            if self.suspend_process(ppid) {
                                                let parent_cmd = self.get_process_cmdline(ppid);
                                                if let Some(ref cmd) = parent_cmd {
                                                    log::info!(
                                                        "Stopped parent process (PID {}): {}",
                                                        ppid,
                                                        cmd
                                                    );
                                                } else {
                                                    log::info!(
                                                        "Stopped parent process (PID {})",
                                                        ppid
                                                    );
                                                }
                                                true
                                            } else {
                                                log::debug!(
                                                    "Failed to stop parent process (PID {})",
                                                    ppid
                                                );
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

                                // Log the blocked event with process tree
                                log::error!(
                                    "BLOCKED: {} {}: {}",
                                    real_protected_path.display(),
                                    "exec",
                                    real_process_path.display()
                                );

                                // Log the process tree
                                let tree =
                                    self.build_process_tree_string(Some(pid), event.ppid(), 3);
                                for line in tree {
                                    log::error!("{}", line);
                                }

                                if parent_stopped {
                                    log::error!("  Status: Process exited, parent stopped");
                                } else {
                                    log::error!(
                                        "  Status: Process exited before it could be stopped"
                                    );
                                }
                            }
                        }
                    }
                    Mode::Interactive => {
                        // Similar to open, but for exec
                        #[cfg(target_os = "macos")]
                        if let Some(pid) = event.pid() {
                            if self.suspend_process(pid) {
                                let mut log_msg = self.build_compact_log_message(
                                    "SUSPENDED",
                                    &real_protected_path,
                                    "exec",
                                    Some(pid),
                                    event.ppid(),
                                    event.euid(),
                                    &real_process_path,
                                );
                                log_msg.push_str(" (waiting for user)");
                                log::warn!("{}", log_msg);
                            }
                        }

                        let _allow = self
                            .handle_interactive_prompt_with_pid(
                                &real_process_path,
                                &real_protected_path,
                                event.pid(),
                            )
                            .await?;

                        #[cfg(target_os = "macos")]
                        if let Some(pid) = event.pid() {
                            if _allow {
                                self.resume_process(pid);
                                let mut log_msg = self.build_compact_log_message(
                                    "RESUMED",
                                    &real_protected_path,
                                    "exec",
                                    Some(pid),
                                    event.ppid(),
                                    event.euid(),
                                    &real_process_path,
                                );
                                log_msg.push_str(" (user allowed)");
                                log::info!("{}", log_msg);
                            } else {
                                let mut log_msg = self.build_compact_log_message(
                                    "STOPPED",
                                    &real_protected_path,
                                    "exec",
                                    Some(pid),
                                    event.ppid(),
                                    event.euid(),
                                    &real_process_path,
                                );
                                log_msg.push_str(" (user denied)");
                                log::error!("{}", log_msg);
                            }
                        }
                    }
                }
            }
        }

        Ok(())
    }

    #[cfg(target_os = "macos")]
    async fn handle_file_access_with_signing(
        &mut self,
        process_path: &Path,
        file_path: &Path,
        pid: Option<u32>,
        ppid: Option<u32>,
        euid: Option<u32>,
        signing_info: Option<String>,
    ) -> Result<()> {
        // Resolve symlinks to get real paths
        let real_file_path = self.normalize_path(file_path);
        let real_process_path = self.normalize_path(process_path);

        // Get code signing info (no longer need PID strings for simplified logs)

        // Use signing info from eslogger - NEVER access the binary!
        #[cfg(target_os = "macos")]
        let _signer_info = signing_info
            .as_ref()
            .map(|s| format!(" [{}]", s))
            .unwrap_or_default();

        #[cfg(not(target_os = "macos"))]
        let _signer_info = String::new();

        // Log ALL file opens, not just protected ones
        let is_protected = self.rule_engine.is_protected_file(&real_file_path);

        if !is_protected {
            // Log non-protected file access only in verbose mode
            if self.verbose {
                log::info!(
                    "OK: {} -> {} (not monitored)",
                    real_process_path
                        .file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or("unknown"),
                    real_file_path.display()
                );
            }
            return Ok(());
        }

        // Protected file access detected - will check rules

        // Create process context for the new rule system
        use crate::process_context::ProcessContext;

        // Parse signing info to extract app_id and team_id
        let (app_id, team_id) = parse_signing_info(signing_info.as_deref());

        // Get platform_binary from cache if available
        let platform_binary = pid
            .and_then(|p| self.process_cache.get(&p))
            .map(|entry| entry.is_platform_binary);

        let context = ProcessContext {
            path: real_process_path.clone(),
            pid,
            ppid,
            team_id,
            app_id,
            args: None, // TODO: Get command-line args
            uid: None,  // TODO: Get user ID
            euid,
            platform_binary,
        };

        // Check if access is allowed using new context-aware method
        let decision = self
            .rule_engine
            .check_access_with_context(&context, &real_file_path);

        // Read mode once for the entire decision handling
        let current_mode = *self.mode.read().await;

        match decision {
            Decision::Allow(rule_name) => {
                // This is a protected file that was allowed access - log it
                let prefix = if let Some(ref name) = rule_name {
                    format!("OK[{}]", name)
                } else {
                    "OK".to_string()
                };
                let log_msg = self.build_compact_log_message(
                    &prefix,
                    &real_file_path,
                    "open",
                    pid,
                    ppid,
                    euid,
                    &real_process_path,
                );
                log::info!("{}", log_msg);

                // Log to JSON with parent process info
                if let Some(p) = pid {
                    let process = if let Some(cached) = self.process_cache.get(&p) {
                        ProcessDetails {
                            pid: p,
                            ppid: cached.ppid,
                            euid: cached.euid,
                            path: cached.path.display().to_string(),
                            command_line: Some(cached.command_line.clone()),
                            team_id: cached.team_id.clone(),
                            signing_id: cached.signing_id.clone(),
                            is_platform_binary: Some(cached.is_platform_binary),
                        }
                    } else {
                        ProcessDetails {
                            pid: p,
                            ppid,
                            euid,
                            path: real_process_path.display().to_string(),
                            command_line: self.get_process_cmdline(p),
                            team_id: None,
                            signing_id: None,
                            is_platform_binary: None,
                        }
                    };

                    let parent = ppid.and_then(|pp| {
                        self.process_cache.get(&pp).map(|cached| ProcessDetails {
                            pid: pp,
                            ppid: cached.ppid,
                            euid: cached.euid,
                            path: cached.path.display().to_string(),
                            command_line: Some(cached.command_line.clone()),
                            team_id: cached.team_id.clone(),
                            signing_id: cached.signing_id.clone(),
                            is_platform_binary: Some(cached.is_platform_binary),
                        })
                    });

                    let event = JsonLogger::build_allow_event(
                        rule_name.clone(),
                        &real_file_path,
                        "open",
                        process,
                        parent,
                        &current_mode.to_string(),
                    );

                    if let Err(e) = self.json_logger.log_event(&event) {
                        log::debug!("Failed to write JSON log: {}", e);
                    }
                }
            }
            Decision::NotProtected => {
                // Not a protected file, don't log unless debugging
                if self.debug {
                    log::trace!("File '{}' is not protected", real_file_path.display());
                }
            }
            Decision::Deny(rule_name) => {
                // Log to JSON with 5 levels of process tree for denied access
                if let Some(p) = pid {
                    let process = if let Some(cached) = self.process_cache.get(&p) {
                        ProcessDetails {
                            pid: p,
                            ppid: cached.ppid,
                            euid: cached.euid,
                            path: cached.path.display().to_string(),
                            command_line: Some(cached.command_line.clone()),
                            team_id: cached.team_id.clone(),
                            signing_id: cached.signing_id.clone(),
                            is_platform_binary: Some(cached.is_platform_binary),
                        }
                    } else {
                        ProcessDetails {
                            pid: p,
                            ppid,
                            euid,
                            path: real_process_path.display().to_string(),
                            command_line: self.get_process_cmdline(p),
                            team_id: None,
                            signing_id: None,
                            is_platform_binary: None,
                        }
                    };

                    // Collect 5 levels of process tree for deny events
                    let process_tree = self.collect_process_tree(ppid, 5);

                    let action_taken = match current_mode {
                        Mode::Monitor => "logged",
                        Mode::Enforce => "blocked",
                        Mode::Interactive => "prompted",
                    };

                    let event = JsonLogger::build_deny_event(
                        rule_name.clone(),
                        &real_file_path,
                        "open",
                        process,
                        process_tree,
                        &current_mode.to_string(),
                        action_taken,
                    );

                    if let Err(e) = self.json_logger.log_event(&event) {
                        log::debug!("Failed to write JSON log: {}", e);
                    }

                    // Send event to IPC server
                    let event_id = IpcServer::generate_event_id();
                    let process_tree = self.build_process_tree_for_event(p, 5);

                    let ipc_event = Event {
                        id: event_id.clone(),
                        timestamp: chrono::Utc::now(),
                        event_type: EventType::AccessDenied {
                            rule_name: rule_name.clone(),
                            file_path: real_file_path.display().to_string(),
                            process_path: real_process_path.display().to_string(),
                            process_pid: p,
                            process_cmdline: self.get_process_cmdline(p),
                            process_euid: euid,
                            parent_pid: ppid,
                            team_id: self.process_cache.get(&p).and_then(|e| e.team_id.clone()),
                            action: action_taken.to_string(),
                            process_tree: Some(process_tree),
                        },
                    };

                    let ipc_server = Arc::clone(&self.ipc_server);
                    tokio::spawn(async move {
                        if let Err(e) = ipc_server.add_event(ipc_event).await {
                            log::debug!("Failed to send event to IPC server: {}", e);
                        }
                    });

                    // Register suspended process if in enforce mode
                    if matches!(*self.mode.read().await, Mode::Enforce) {
                        let suspended = SuspendedProcess {
                            pid: p,
                            ppid,
                            path: real_process_path.clone(),
                            file_accessed: real_file_path.clone(),
                            timestamp: chrono::Utc::now(),
                        };

                        let ipc_server = Arc::clone(&self.ipc_server);
                        let event_id_clone = event_id.clone();
                        tokio::spawn(async move {
                            if let Err(e) = ipc_server
                                .register_suspended_process(event_id_clone, suspended)
                                .await
                            {
                                log::debug!("Failed to register suspended process: {}", e);
                            }
                        });
                    }
                }

                match current_mode {
                    Mode::Monitor => {
                        let log_msg = self.build_compact_log_message(
                            &format!("DETECTED[{}]", rule_name),
                            &real_file_path,
                            "open",
                            pid,
                            ppid,
                            euid,
                            &real_process_path,
                        );
                        log::warn!("{}", log_msg);
                    }
                    Mode::Enforce => {
                        // On macOS with eslogger, we can suspend the process
                        #[cfg(target_os = "macos")]
                        if let Some(pid) = pid {
                            // Suspend the process
                            let stopped = self.suspend_process(pid);

                            // Always try to suspend parent if requested, even if child already exited
                            let (parent_stopped, _parent_cmdline) = if self.stop_parent {
                                if let Some(ppid) = ppid {
                                    if ppid > 1 {
                                        // Don't try to stop init (pid 1)
                                        if self.suspend_process(ppid) {
                                            // Get parent command line after stopping it
                                            let parent_cmd = self.get_process_cmdline(ppid);
                                            if let Some(ref cmd) = parent_cmd {
                                                log::info!(
                                                    "Stopped parent process (PID {}): {}",
                                                    ppid,
                                                    cmd
                                                );
                                            } else {
                                                log::info!("Stopped parent process (PID {})", ppid);
                                            }
                                            (true, parent_cmd)
                                        } else {
                                            log::debug!(
                                                "Failed to stop parent process (PID {})",
                                                ppid
                                            );
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
                                // Log the blocked event with process tree
                                log::error!(
                                    "BLOCKED: {} {}: {}",
                                    real_file_path.display(),
                                    "open",
                                    real_process_path.display()
                                );

                                // Log the process tree
                                let tree = self.build_process_tree_string(Some(pid), ppid, 3);
                                for line in tree {
                                    log::error!("{}", line);
                                }

                                if parent_stopped {
                                    log::error!("  Status: Process and parent stopped");
                                } else {
                                    log::error!("  Status: Process stopped");
                                }
                            } else {
                                // Process exited - still log with parent/grandparent info
                                // Try to stop parent if requested
                                let parent_stopped = if self.stop_parent {
                                    if let Some(ppid) = ppid {
                                        if ppid > 1 {
                                            if self.suspend_process(ppid) {
                                                let parent_cmd = self.get_process_cmdline(ppid);
                                                if let Some(ref cmd) = parent_cmd {
                                                    log::info!(
                                                        "Stopped parent process (PID {}): {}",
                                                        ppid,
                                                        cmd
                                                    );
                                                } else {
                                                    log::info!(
                                                        "Stopped parent process (PID {})",
                                                        ppid
                                                    );
                                                }
                                                true
                                            } else {
                                                log::debug!(
                                                    "Failed to stop parent process (PID {})",
                                                    ppid
                                                );
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

                                // Log the blocked event with process tree
                                log::error!(
                                    "BLOCKED: {} {}: {}",
                                    real_file_path.display(),
                                    "open",
                                    real_process_path.display()
                                );

                                // Log the process tree
                                let tree = self.build_process_tree_string(Some(pid), ppid, 3);
                                for line in tree {
                                    log::error!("{}", line);
                                }

                                if parent_stopped {
                                    log::error!("  Status: Process exited, parent stopped");
                                } else {
                                    log::error!(
                                        "  Status: Process exited before it could be stopped"
                                    );
                                }
                            }
                        } else {
                            // No PID available
                            log::error!(
                                "BLOCKED: {} {}: {} (no PID available)",
                                real_file_path.display(),
                                "open",
                                real_process_path.display()
                            );
                        }

                        #[cfg(not(target_os = "macos"))]
                        {
                            let log_msg = self.build_compact_log_message(
                                "BLOCKED",
                                &real_file_path,
                                "open",
                                pid,
                                ppid,
                                euid,
                                &real_process_path,
                            );
                            log::error!("{}", log_msg);
                        }
                    }
                    Mode::Interactive => {
                        // Suspend process while waiting for user decision
                        #[cfg(target_os = "macos")]
                        if let Some(pid) = pid {
                            if self.suspend_process(pid) {
                                let mut log_msg = self.build_compact_log_message(
                                    "SUSPENDED",
                                    &real_file_path,
                                    "open",
                                    Some(pid),
                                    ppid,
                                    euid,
                                    &real_process_path,
                                );
                                log_msg.push_str(" (waiting for user)");
                                log::warn!("{}", log_msg);
                            }
                        }

                        let _allow = self
                            .handle_interactive_prompt_with_pid(
                                &real_process_path,
                                &real_file_path,
                                pid,
                            )
                            .await?;

                        // Resume or terminate based on decision
                        #[cfg(target_os = "macos")]
                        if let Some(pid) = pid {
                            if _allow {
                                self.resume_process(pid);
                                let mut log_msg = self.build_compact_log_message(
                                    "RESUMED",
                                    &real_file_path,
                                    "open",
                                    Some(pid),
                                    ppid,
                                    euid,
                                    &real_process_path,
                                );
                                log_msg.push_str(" (user allowed)");
                                log::info!("{}", log_msg);
                            } else {
                                let mut log_msg = self.build_compact_log_message(
                                    "STOPPED",
                                    &real_file_path,
                                    "open",
                                    Some(pid),
                                    ppid,
                                    euid,
                                    &real_process_path,
                                );
                                log_msg.push_str(" (user denied)");
                                log::error!("{}", log_msg);
                            }
                        }
                    }
                }
            }
        }

        Ok(())
    }

    #[cfg(target_os = "macos")]
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

    /// Build a visual process tree showing up to 5 levels of parent processes
    /// Also accepts ppid to start from parent if main process has exited
    #[cfg(target_os = "macos")]
    #[allow(dead_code)]
    fn build_process_tree_with_parent(
        &self,
        pid: Option<u32>,
        ppid: Option<u32>,
        euid: Option<u32>,
        process_name: &str,
        args: &str,
        max_levels: usize,
    ) -> String {
        use std::process::Command;

        let mut tree = Vec::new();
        let mut current_pid = pid;
        let mut level = 0;

        // If the main process is not available but we have ppid, add a placeholder for it
        if let Some(p) = pid {
            // Try to get info for the main process first
            let output = Command::new("ps")
                .args(["-p", &p.to_string(), "-o", "pid=,ppid=,uid=,comm=,args="])
                .output();

            if let Ok(output) = output {
                if output.stdout.is_empty() {
                    // Process has exited, add a placeholder with the info we have
                    let uid_str = if let Some(e) = euid {
                        format!("{}@{}", e, p)
                    } else {
                        format!("?@{}", p)
                    };
                    tree.push(format!(
                        "→ {} {} [{}] (exited)",
                        process_name, args, uid_str
                    ));

                    // Start from parent
                    current_pid = ppid;
                    level = 1;
                }
            }
        }

        while let Some(p) = current_pid {
            if level >= max_levels || p <= 1 {
                break;
            }

            // Get process info using ps
            let output = Command::new("ps")
                .args(["-p", &p.to_string(), "-o", "pid=,ppid=,uid=,comm=,args="])
                .output();

            if let Ok(output) = output {
                let stdout = String::from_utf8_lossy(&output.stdout);
                let line = stdout.trim();

                if !line.is_empty() {
                    // Parse ps output: pid ppid uid comm args...
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 4 {
                        let pid_val = parts[0];
                        let ppid_val = parts[1].parse::<u32>().unwrap_or(0);
                        let uid_val = parts[2];

                        // Find where args start (after comm)
                        let args_start = line.find(parts[3]).unwrap_or(0);
                        let args = if args_start > 0 {
                            &line[args_start..]
                        } else {
                            parts[3]
                        };

                        // Format with proper indentation
                        let indent = "  ".repeat(level);
                        let prefix = if level == 0 { "→" } else { "↳" };

                        // Use provided euid for first level, otherwise use uid from ps
                        let uid_str = if level == 0 && euid.is_some() {
                            format!("{}@{}", euid.unwrap(), pid_val)
                        } else {
                            format!("{}@{}", uid_val, pid_val)
                        };

                        // Truncate args if too long
                        let display_args = if args.len() > 100 {
                            format!("{}...", &args[..97])
                        } else {
                            args.to_string()
                        };

                        tree.push(format!(
                            "{}{} {} [{}]",
                            indent, prefix, display_args, uid_str
                        ));

                        // Move to parent
                        current_pid = if ppid_val > 1 { Some(ppid_val) } else { None };
                    } else {
                        break;
                    }
                } else {
                    break;
                }
            } else {
                break;
            }

            level += 1;
        }

        if tree.is_empty() {
            return String::from("  (Process tree unavailable)");
        }

        tree.join("\n")
    }

    /// Simple wrapper for compatibility
    #[cfg(target_os = "macos")]
    #[allow(dead_code)]
    fn build_process_tree(&self, pid: Option<u32>, euid: Option<u32>, max_levels: usize) -> String {
        // For simple calls without extra info
        self.build_process_tree_with_parent(pid, None, euid, "unknown", "", max_levels)
    }

    /// Collect process tree details for JSON logging
    #[cfg(target_os = "macos")]
    fn collect_process_tree(&self, pid: Option<u32>, max_levels: usize) -> Vec<ProcessDetails> {
        let mut tree = Vec::new();
        let mut current_pid = pid;
        let mut level = 0;

        while let Some(p) = current_pid {
            if level >= max_levels {
                break;
            }

            // Get process info from cache or system
            let process_info = if let Some(cached) = self.process_cache.get(&p) {
                ProcessDetails {
                    pid: p,
                    ppid: cached.ppid,
                    euid: cached.euid,
                    path: cached.path.display().to_string(),
                    command_line: Some(cached.command_line.clone()),
                    team_id: cached.team_id.clone(),
                    signing_id: cached.signing_id.clone(),
                    is_platform_binary: Some(cached.is_platform_binary),
                }
            } else {
                // Try to get basic info from ps
                let cmd_line = self.get_process_cmdline(p);
                ProcessDetails {
                    pid: p,
                    ppid: None,
                    euid: None,
                    path: cmd_line.clone().unwrap_or_else(|| "unknown".to_string()),
                    command_line: cmd_line,
                    team_id: None,
                    signing_id: None,
                    is_platform_binary: None,
                }
            };

            // Get parent PID for next iteration
            current_pid = process_info.ppid;
            tree.push(process_info);
            level += 1;
        }

        tree
    }

    // Helper function to build process tree string for blocked events
    fn build_process_tree_string(
        &self,
        pid: Option<u32>,
        ppid: Option<u32>,
        max_levels: usize,
    ) -> Vec<String> {
        let mut tree = Vec::new();
        let mut current_ppid = ppid;
        let mut level = 0;

        // Start with the blocked process
        if let Some(p) = pid {
            if let Some(cached) = self.process_cache.get(&p) {
                let team_str = if let Some(tid) = &cached.team_id {
                    format!("{}:", tid)
                } else if cached.is_platform_binary {
                    "Apple:".to_string()
                } else {
                    String::new()
                };
                tree.push(format!(
                    "  Process: {} [{}{}@{}]",
                    cached.command_line,
                    team_str,
                    p,
                    cached.euid.unwrap_or(0)
                ));
                current_ppid = cached.ppid;
            } else if let Some(cmdline) = self.get_process_cmdline(p) {
                tree.push(format!("  Process: {} [{}]", cmdline, p));
            }
        }

        // Walk up the process tree
        let mut current_pid = current_ppid;
        while let Some(p) = current_pid {
            if level >= max_levels || p <= 1 {
                break;
            }

            let indent = "  ".repeat(level + 1);
            if let Some(cached) = self.process_cache.get(&p) {
                let team_str = if let Some(tid) = &cached.team_id {
                    format!("{}:", tid)
                } else if cached.is_platform_binary {
                    "Apple:".to_string()
                } else {
                    String::new()
                };
                tree.push(format!(
                    "{}  Parent: {} [{}{}@{}]",
                    indent,
                    cached.command_line,
                    team_str,
                    p,
                    cached.euid.unwrap_or(0)
                ));
                current_pid = cached.ppid;
            } else if let Some(cmdline) = self.get_process_cmdline(p) {
                tree.push(format!("{}  Parent: {} [{}]", indent, cmdline, p));
                // Try to get ppid from ps
                current_pid = None; // Stop if we can't get more info
            } else {
                break;
            }
            level += 1;
        }

        tree
    }

    // Helper function to build compact log message format
    #[allow(clippy::too_many_arguments)]
    fn build_compact_log_message(
        &self,
        decision: &str,
        file_path: &Path,
        event_type: &str,
        pid: Option<u32>,
        ppid: Option<u32>,
        euid: Option<u32>,
        process_path: &Path,
    ) -> String {
        // Get process info
        let process_name = process_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("unknown");

        let cmdline = if let Some(p) = pid {
            self.get_process_cmdline(p)
        } else {
            None
        };

        // Get team ID for the process
        let process_entry = pid.and_then(|p| self.process_cache.get(&p));

        // Build team ID part - prefix with * if platform binary
        let is_platform = process_entry.map(|e| e.is_platform_binary).unwrap_or(false);
        let team_id_str = if let Some(tid) = process_entry.and_then(|e| e.team_id.as_deref()) {
            if is_platform {
                format!("*{}:", tid) // Platform binary with team ID
            } else {
                format!("{}:", tid) // Regular signed binary
            }
        } else if is_platform {
            "*Apple:".to_string() // Platform binary without explicit team ID
        } else {
            String::new() // Unsigned binary
        };

        // Get parent info
        let parent_info = if let Some(pp) = ppid {
            if pp > 0 {
                let parent_entry = self.process_cache.get(&pp);
                let parent_cmd = self.get_process_cmdline(pp);
                let parent_name = parent_entry
                    .and_then(|e| e.path.file_name())
                    .and_then(|n| n.to_str())
                    .unwrap_or("unknown");

                if let Some(cmd) = parent_cmd {
                    format!("→{}", cmd)
                } else {
                    format!("→{}", parent_name)
                }
            } else {
                String::new()
            }
        } else {
            String::new()
        };

        // Build the compact log format:
        // DECISION: /path/to/file event_type: process args [teamid:pid@uid]→parent
        format!(
            "{}: {} {}: {} [{}{}@{}]{}",
            decision,
            file_path.display(),
            event_type,
            cmdline.as_deref().unwrap_or(process_name),
            team_id_str,
            pid.unwrap_or(0),
            euid.unwrap_or(0),
            parent_info
        )
    }

    #[cfg(not(target_os = "macos"))]
    #[allow(dead_code)] // Will be used for process investigation
    fn build_process_tree(&self, pid: Option<u32>, euid: Option<u32>, max_levels: usize) -> String {
        // Linux implementation using /proc
        let mut tree = Vec::new();
        let mut current_pid = pid;
        let mut level = 0;

        while let Some(p) = current_pid {
            if level >= max_levels || p <= 1 {
                break;
            }

            // Read /proc/PID/stat for ppid
            let stat_path = format!("/proc/{}/stat", p);
            let cmdline_path = format!("/proc/{}/cmdline", p);
            let status_path = format!("/proc/{}/status", p);

            // Get command line
            let cmdline = std::fs::read_to_string(&cmdline_path)
                .unwrap_or_default()
                .replace('\0', " ")
                .trim()
                .to_string();

            // Get PPID from stat (4th field after comm)
            let mut ppid_val = 0u32;
            if let Ok(stat) = std::fs::read_to_string(&stat_path) {
                // Format: pid (comm) state ppid ...
                if let Some(start) = stat.rfind(')') {
                    let fields: Vec<&str> = stat[start + 1..].split_whitespace().collect();
                    if fields.len() > 2 {
                        ppid_val = fields[1].parse().unwrap_or(0);
                    }
                }
            }

            // Get UID from status
            let mut uid_val = 0u32;
            if let Ok(status) = std::fs::read_to_string(&status_path) {
                for line in status.lines() {
                    if line.starts_with("Uid:") {
                        let parts: Vec<&str> = line.split_whitespace().collect();
                        if parts.len() > 2 {
                            // effective UID is the second value
                            uid_val = parts[2].parse().unwrap_or(0);
                        }
                        break;
                    }
                }
            }

            // Format with proper indentation
            let indent = "  ".repeat(level);
            let prefix = if level == 0 { "→" } else { "↳" };

            // Use provided euid for first level if available
            let uid_str = if level == 0 && euid.is_some() {
                format!("{}@{}", euid.unwrap(), p)
            } else {
                format!("{}@{}", uid_val, p)
            };

            let display_cmd = if cmdline.is_empty() {
                format!("(unknown) [{}]", uid_str)
            } else {
                format!("{} [{}]", cmdline, uid_str)
            };

            tree.push(format!("{}{} {}", indent, prefix, display_cmd));

            // Move to parent
            current_pid = if ppid_val > 1 { Some(ppid_val) } else { None };
            level += 1;
        }

        if tree.is_empty() {
            return String::from("  (Process tree unavailable)");
        }

        tree.join("\n")
    }

    /// Update the process cache with new information
    #[cfg(target_os = "macos")]
    #[allow(clippy::too_many_arguments)] // TODO: Complete refactor to use parameter struct
    fn cache_process_info(
        &mut self,
        pid: u32,
        path: &Path,
        ppid: Option<u32>,
        euid: Option<u32>,
        args: &[String],
        team_id: Option<&str>,
        signing_id: Option<&str>,
        is_platform_binary: bool,
    ) {
        // Clean up old entries periodically
        if self.process_cache.len() > 1000 {
            self.cleanup_process_cache();
        }

        let entry = self
            .process_cache
            .entry(pid)
            .or_insert_with(|| ProcessInfo::new(pid, path.to_path_buf()));

        // Update with latest information
        entry.path = path.to_path_buf();
        entry.last_seen = Instant::now();

        if let Some(ppid) = ppid {
            entry.ppid = Some(ppid);
        }

        if let Some(euid) = euid {
            entry.euid = Some(euid);
        }

        if !args.is_empty() {
            entry.args = args.to_vec();
            entry.command_line = args.join(" ");
        }

        if let Some(tid) = team_id {
            entry.team_id = Some(tid.to_string());
        }

        if let Some(sid) = signing_id {
            entry.signing_id = Some(sid.to_string());
        }

        entry.is_platform_binary = is_platform_binary;

        log::trace!(
            "Cached process info for PID {}: {} (ppid: {:?}, euid: {:?})",
            pid,
            path.display(),
            ppid,
            euid
        );
    }

    /// Clean up old entries from the process cache
    #[cfg(target_os = "macos")]
    fn cleanup_process_cache(&mut self) {
        let now = Instant::now();
        let before_size = self.process_cache.len();

        self.process_cache
            .retain(|_pid, info| now.duration_since(info.last_seen) < self.cache_ttl);

        let removed = before_size - self.process_cache.len();
        if removed > 0 {
            log::debug!("Cleaned up {} old process cache entries", removed);
        }
    }

    /// Build a process tree using cached information first, falling back to ps if needed
    #[cfg(target_os = "macos")]
    #[allow(dead_code)]
    fn build_process_tree_from_cache(
        &self,
        pid: Option<u32>,
        ppid: Option<u32>,
        euid: Option<u32>,
        process_name: &str,
        args: &str,
        max_levels: usize,
    ) -> String {
        let mut tree = Vec::new();
        let mut current_pid = pid;
        let mut level = 0;

        // Start with the current process (might be exited)
        if let Some(p) = pid {
            let display_args = if !args.is_empty() {
                args.to_string()
            } else if !process_name.is_empty() && process_name != "unknown" {
                process_name.to_string()
            } else {
                "(exited)".to_string()
            };

            let uid_str = if let Some(e) = euid {
                format!("{}@{}", e, p)
            } else {
                p.to_string()
            };

            tree.push(format!("→ {} [{}]", display_args, uid_str));

            // Move to parent for next iteration
            current_pid = ppid;
            level = 1;
        }

        // Walk up the tree using cache first
        while let Some(p) = current_pid {
            if level >= max_levels {
                break;
            }

            // Skip PID 0 but allow PID 1 (init/launchd)
            if p == 0 {
                break;
            }

            // Special handling for PID 1 (init/launchd)
            if p == 1 {
                let indent = "  ".repeat(level);
                let prefix = "↳";

                // Try cache first for PID 1
                if let Some(cached_info) = self.process_cache.get(&p) {
                    let display = if !cached_info.command_line.is_empty() {
                        cached_info.command_line.clone()
                    } else {
                        cached_info.path.display().to_string()
                    };
                    let uid_str = if let Some(e) = cached_info.euid {
                        format!("{}@{}", e, p)
                    } else {
                        format!("0@{}", p) // PID 1 always runs as root
                    };
                    tree.push(format!("{}{} {} [{}]", indent, prefix, display, uid_str));
                } else {
                    // PID 1 is always launchd on macOS, init on Linux
                    #[cfg(target_os = "macos")]
                    tree.push(format!("{}{} /sbin/launchd [0@1]", indent, prefix));
                    #[cfg(not(target_os = "macos"))]
                    tree.push(format!("{}{} /sbin/init [0@1]", indent, prefix));
                }
                break; // Stop after PID 1
            }

            // Check cache first
            if let Some(cached_info) = self.process_cache.get(&p) {
                let indent = "  ".repeat(level);
                let prefix = "↳";

                let display = if !cached_info.command_line.is_empty() {
                    cached_info.command_line.clone()
                } else {
                    cached_info.path.display().to_string()
                };

                let uid_str = if let Some(e) = cached_info.euid {
                    format!("{}@{}", e, p)
                } else {
                    p.to_string()
                };

                tree.push(format!("{}{} {} [{}]", indent, prefix, display, uid_str));

                current_pid = cached_info.ppid;
            } else {
                // Fall back to ps for uncached processes
                #[cfg(target_os = "macos")]
                {
                    let output = Command::new("ps")
                        .args(["-p", &p.to_string(), "-o", "ppid=,uid=,command="])
                        .output();

                    if let Ok(output) = output {
                        if let Ok(line) = String::from_utf8(output.stdout) {
                            let line = line.trim();
                            if !line.is_empty() {
                                let parts: Vec<&str> = line
                                    .splitn(3, ' ')
                                    .map(|s| s.trim())
                                    .filter(|s| !s.is_empty())
                                    .collect();

                                if parts.len() >= 2 {
                                    let ppid_val = parts[0].parse::<u32>().unwrap_or(0);
                                    let uid_val = parts[1].parse::<u32>().unwrap_or(0);
                                    let cmdline = parts.get(2).unwrap_or(&"").to_string();

                                    let indent = "  ".repeat(level);
                                    let prefix = "↳";
                                    let uid_str = format!("{}@{}", uid_val, p);

                                    tree.push(format!(
                                        "{}{} {} [{}]",
                                        indent, prefix, cmdline, uid_str
                                    ));

                                    // Continue to parent, including PID 1 (but not 0)
                                    current_pid = if ppid_val > 0 { Some(ppid_val) } else { None };
                                } else {
                                    break;
                                }
                            } else {
                                break;
                            }
                        } else {
                            break;
                        }
                    } else {
                        break;
                    }
                }
                #[cfg(not(target_os = "macos"))]
                {
                    // Linux: use /proc filesystem
                    break; // TODO: Implement Linux fallback
                }
            }

            level += 1;
        }

        if tree.is_empty() {
            return String::from("  (Process tree unavailable)");
        }

        tree.join("\n")
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
                    log::error!(
                        "Permission denied suspending PID {} (may be protected by SIP)",
                        pid
                    );
                }
                _ => {
                    log::error!("Failed to suspend PID {}: errno {}", pid, errno);
                }
            }
            false
        }
    }

    #[cfg(target_os = "macos")]
    fn build_process_tree_for_event(&self, pid: u32, max_depth: usize) -> Vec<ProcessTreeEntry> {
        let mut tree = Vec::new();
        let mut current_pid = Some(pid);
        let mut depth = 0;

        while let Some(p) = current_pid {
            if depth >= max_depth || p <= 1 {
                break;
            }

            // Get process info from cache or via ps
            let (name, path, cmdline, ppid, team_id, signing_id) =
                if let Some(info) = self.process_cache.get(&p) {
                    // Use cached info
                    let name = info
                        .path
                        .file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or("unknown")
                        .to_string();
                    (
                        name,
                        info.path.display().to_string(),
                        Some(info.command_line.clone()),
                        info.ppid,
                        info.team_id.clone(),
                        info.signing_id.clone(),
                    )
                } else {
                    // Get info via ps
                    let cmdline = self.get_process_cmdline(p);

                    // Extract name and path from cmdline
                    let (name, path) = if let Some(ref cmd) = cmdline {
                        let first_arg = cmd.split_whitespace().next().unwrap_or("unknown");
                        let name = std::path::Path::new(first_arg)
                            .file_name()
                            .and_then(|n| n.to_str())
                            .unwrap_or("unknown")
                            .to_string();
                        (name, first_arg.to_string())
                    } else {
                        ("unknown".to_string(), "".to_string())
                    };

                    // Get parent PID via ps
                    let ppid = std::process::Command::new("ps")
                        .args(["-o", "ppid=", "-p", &p.to_string()])
                        .output()
                        .ok()
                        .and_then(|output| {
                            String::from_utf8_lossy(&output.stdout)
                                .trim()
                                .parse::<u32>()
                                .ok()
                        });

                    (name, path, cmdline, ppid, None, None)
                };

            // Extract vendor name if we have a team_id
            let vendor_name = if team_id.is_some() && !path.is_empty() {
                self.get_vendor_name(&path)
            } else {
                None
            };

            tree.push(ProcessTreeEntry {
                pid: p,
                ppid,
                name,
                path,
                cmdline,
                team_id,
                signing_id,
                vendor_name,
            });

            current_pid = ppid;
            depth += 1;
        }

        tree
    }

    #[cfg(not(target_os = "macos"))]
    fn build_process_tree_for_event(&self, _pid: u32, _max_depth: usize) -> Vec<ProcessTreeEntry> {
        // TODO: Implement for Linux/BSD
        Vec::new()
    }

    #[cfg(target_os = "macos")]
    fn get_vendor_name(&self, path: &str) -> Option<String> {
        use std::process::Command;

        // Try to run codesign to get the Authority information
        match Command::new("codesign").args(["-dvvv", path]).output() {
            Ok(output) => {
                // codesign writes to stderr, not stdout
                let output_str = String::from_utf8_lossy(&output.stderr);

                // Look for the first Authority line which contains the vendor name
                // Format: "Authority=Developer ID Application: Mozilla Corporation (43AQ936H96)"
                for line in output_str.lines() {
                    if line.starts_with("Authority=Developer ID Application: ") {
                        // Extract vendor name between ": " and " ("
                        if let Some(start) = line.find(": ") {
                            let vendor_part = &line[start + 2..];
                            if let Some(end) = vendor_part.find(" (") {
                                let vendor = vendor_part[..end].trim().to_string();

                                // Also extract team ID and cache it
                                if let Some(team_start) = vendor_part.find("(") {
                                    if let Some(team_end) = vendor_part.find(")") {
                                        let team_id =
                                            vendor_part[team_start + 1..team_end].to_string();
                                        if let Ok(mut cache) = self.vendor_cache.lock() {
                                            cache.insert(team_id.clone(), Some(vendor.clone()));
                                            log::debug!(
                                                "Cached vendor '{}' for team ID '{}'",
                                                vendor,
                                                team_id
                                            );
                                        }
                                    }
                                }

                                return Some(vendor);
                            }
                        }
                    } else if line.starts_with("Authority=") && line.contains("Apple") {
                        // This is an Apple system binary
                        return Some("Apple".to_string());
                    }
                }

                // If we didn't find a vendor name, check if it's unsigned
                if output_str.contains("code object is not signed at all") {
                    return None;
                }

                // Check for ad-hoc signing
                if output_str.contains("Signature=adhoc") {
                    return Some("Ad-hoc Signed".to_string());
                }

                None
            }
            Err(e) => {
                log::debug!("Failed to run codesign for '{}': {}", path, e);
                None
            }
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
    #[allow(dead_code)] // Will be used for process investigation
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
                        log::error!(
                            "Permission denied suspending PID {} (may be protected)",
                            pid
                        );
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

    #[allow(dead_code)] // Will be used for interactive mode
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
                        // Show process tree
                        println!("\n  Process Tree (5 levels):");
                        let tree = self.build_process_tree(Some(pid), None, 5);
                        for line in tree.lines() {
                            println!("    {}", line);
                        }
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

    #[allow(dead_code)] // Will be used for debugging
    fn show_process_info(&self, process_path: &Path) {
        println!("\nAdditional Information:");
        println!("  Full path: {}", process_path.display());

        // We no longer access the filesystem for process info
        // All information comes from eslogger events
        println!("  Note: Code signing info available in event logs");
    }

    #[allow(dead_code)] // Will be used for debugging
    fn show_process_status(&self, #[allow(unused_variables)] pid: u32) {
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
        let mut linux_monitor = LinuxMonitor::new(Mode::Monitor, self.verbose, self.stop_parent)?; // TODO: pass shared mode
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

        let mut monitor = FreeBSDMonitor::new(Mode::Monitor, self.verbose, self.stop_parent); // TODO: pass shared mode
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

/// Parse signing info string to extract app_id and team_id
///
/// Signing info format can be:
/// - "app_id [team_id]" - Both app and team ID
/// - "team_id" - Just team ID
/// - None - No signing info
///
/// Returns (app_id, team_id) tuple
fn parse_signing_info(signing_info: Option<&str>) -> (Option<String>, Option<String>) {
    match signing_info {
        Some(info) if !info.is_empty() => {
            // Check for format: "app_id [team_id]"
            if let Some(bracket_pos) = info.find('[') {
                let app_id = info[..bracket_pos].trim();
                let team_id = info[bracket_pos + 1..].trim_end_matches(']').trim();

                (
                    if app_id.is_empty() {
                        None
                    } else {
                        Some(app_id.to_string())
                    },
                    if team_id.is_empty() {
                        None
                    } else {
                        Some(team_id.to_string())
                    },
                )
            } else {
                // Just team_id
                (None, Some(info.to_string()))
            }
        }
        _ => (None, None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_signing_info() {
        // Test app_id and team_id
        assert_eq!(
            parse_signing_info(Some("com.apple.Safari [com.apple]")),
            (
                Some("com.apple.Safari".to_string()),
                Some("com.apple".to_string())
            )
        );

        // Test just team_id
        assert_eq!(
            parse_signing_info(Some("2FNC3A47ZF")),
            (None, Some("2FNC3A47ZF".to_string()))
        );

        // Test empty
        assert_eq!(parse_signing_info(None), (None, None));

        // Test empty string
        assert_eq!(parse_signing_info(Some("")), (None, None));
    }
}
