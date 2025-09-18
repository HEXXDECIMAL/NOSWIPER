use crate::cli::{Mechanism, Mode};
use crate::rules::{Decision, RuleEngine};
use anyhow::Result;
use serde::Deserialize;
use std::path::{Path, PathBuf};
use std::process::Command;
use tokio::io::{BufReader, AsyncBufReadExt};
use tokio::process::Command as TokioCommand;

pub struct Monitor {
    rule_engine: RuleEngine,
    mode: Mode,
    mechanism: Mechanism,
}

#[derive(Deserialize, Debug)]
struct EsloggerEvent {
    #[serde(rename = "process")]
    process_info: ProcessInfo,
    #[serde(rename = "event")]
    event_info: EventInfo,
}

#[derive(Deserialize, Debug)]
struct ProcessInfo {
    #[serde(rename = "executable")]
    executable_path: Option<String>,
    #[serde(rename = "name")]
    name: Option<String>,
    #[serde(rename = "pid")]
    pid: Option<u32>,
}

#[derive(Deserialize, Debug)]
struct EventInfo {
    #[serde(rename = "type")]
    event_type: String,
    #[serde(rename = "file")]
    file_info: Option<FileInfo>,
}

#[derive(Deserialize, Debug)]
struct FileInfo {
    #[serde(rename = "path")]
    path: Option<String>,
}

impl Monitor {
    pub fn new(mode: Mode, mechanism: Mechanism) -> Self {
        Self {
            rule_engine: RuleEngine::new(),
            mode,
            mechanism,
        }
    }

    pub async fn start(&mut self) -> Result<()> {
        log::info!("Starting NoSwiper daemon in {} mode", self.mode);
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

        // Check if eslogger is available
        if !self.check_eslogger_available() {
            return Err(anyhow::anyhow!(
                "eslogger not found. Please install it or use a different mechanism."
            ));
        }

        // Start eslogger process
        let mut child = TokioCommand::new("eslogger")
            .args(&["file", "--format", "json"])
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()?;

        log::info!("Started eslogger process");

        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| anyhow::anyhow!("Failed to capture eslogger stdout"))?;

        let reader = BufReader::new(stdout);
        let mut lines = reader.lines();

        while let Some(line) = lines.next_line().await? {
            if line.trim().is_empty() {
                continue;
            }

            match self.parse_eslogger_event(&line) {
                Ok(Some((process_path, file_path))) => {
                    self.handle_file_access(&process_path, &file_path).await?;
                }
                Ok(None) => {
                    // Event parsed but not relevant (not a file access we care about)
                }
                Err(e) => {
                    log::debug!("Failed to parse eslogger event: {} - {}", e, line);
                }
            }
        }

        let exit_status = child.wait().await?;
        if !exit_status.success() {
            return Err(anyhow::anyhow!("eslogger exited with error: {}", exit_status));
        }

        Ok(())
    }

    fn check_eslogger_available(&self) -> bool {
        Command::new("which")
            .arg("eslogger")
            .output()
            .map(|output| output.status.success())
            .unwrap_or(false)
    }

    fn parse_eslogger_event(&self, line: &str) -> Result<Option<(PathBuf, PathBuf)>> {
        let event: EsloggerEvent = serde_json::from_str(line)?;

        // We only care about file access events
        if event.event_info.event_type != "file_open" {
            return Ok(None);
        }

        let process_path = event
            .process_info
            .executable_path
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("No process path in event"))?;

        let file_path = event
            .event_info
            .file_info
            .as_ref()
            .and_then(|f| f.path.as_ref())
            .ok_or_else(|| anyhow::anyhow!("No file path in event"))?;

        Ok(Some((PathBuf::from(process_path), PathBuf::from(file_path))))
    }

    async fn handle_file_access(&mut self, process_path: &Path, file_path: &Path) -> Result<()> {
        // Resolve symlinks to get real paths
        let real_file_path = self.normalize_path(file_path);
        let real_process_path = self.normalize_path(process_path);

        // Check if this file should be protected
        if !self.rule_engine.is_protected_file(&real_file_path) {
            return Ok(());
        }

        log::debug!(
            "File access detected: {} -> {}",
            real_process_path.display(),
            real_file_path.display()
        );

        // Check if access is allowed
        let decision = self
            .rule_engine
            .check_access(&real_process_path, &real_file_path);

        match decision {
            Decision::Allow => {
                log::info!(
                    "ALLOWED: {} -> {}",
                    real_process_path.display(),
                    real_file_path.display()
                );
            }
            Decision::Deny => {
                match self.mode {
                    Mode::Monitor => {
                        log::warn!(
                            "DETECTED: {} -> {}",
                            real_process_path.display(),
                            real_file_path.display()
                        );
                    }
                    Mode::Enforce => {
                        log::error!(
                            "BLOCKED: {} -> {}",
                            real_process_path.display(),
                            real_file_path.display()
                        );
                        // Note: With eslogger we can only log, not actually block
                        // For real blocking, we'd need ESF
                    }
                    Mode::Interactive => {
                        self.handle_interactive_prompt(&real_process_path, &real_file_path)
                            .await?;
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

    async fn handle_interactive_prompt(
        &mut self,
        process_path: &Path,
        file_path: &Path,
    ) -> Result<()> {
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
                    log::info!("User allowed access: {} -> {}", app_name, file_path.display());
                    return Ok(());
                }
                Some('w') => {
                    println!("✓ Added to whitelist\n");
                    self.rule_engine
                        .add_runtime_exception(process_path.to_path_buf(), file_path.to_path_buf());
                    log::info!(
                        "User whitelisted: {} -> {}",
                        app_name,
                        file_path.display()
                    );
                    return Ok(());
                }
                Some('s') => {
                    self.show_process_info(process_path);
                    // Continue the loop to re-prompt
                    continue;
                }
                _ => {
                    println!("✗ Denied\n");
                    log::warn!("User denied access: {} -> {}", app_name, file_path.display());
                    return Ok(());
                }
            }
        }
    }

    fn show_process_info(&self, process_path: &Path) {
        println!("\nAdditional Information:");
        println!("  Full path: {}", process_path.display());

        // Try to get more info about the process
        if let Ok(metadata) = std::fs::metadata(process_path) {
            if let Ok(modified) = metadata.modified() {
                if let Ok(system_time) = modified.duration_since(std::time::UNIX_EPOCH) {
                    let datetime = chrono::DateTime::from_timestamp(system_time.as_secs() as i64, 0);
                    if let Some(dt) = datetime {
                        println!("  Modified: {}", dt.format("%Y-%m-%d %H:%M:%S"));
                    }
                }
            }
        }

        #[cfg(target_os = "macos")]
        {
            // Try to get code signature info on macOS
            if let Ok(output) = Command::new("codesign")
                .args(&["-dvvv", process_path.to_str().unwrap_or("")])
                .output()
            {
                if output.status.success() {
                    println!("  Code signature: Signed");
                    let info = String::from_utf8_lossy(&output.stderr);
                    for line in info.lines() {
                        if line.contains("Authority=") {
                            println!("  Signer: {}", line.trim());
                            break;
                        }
                    }
                } else {
                    println!("  Code signature: Unsigned");
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
        Err(anyhow::anyhow!(
            "fanotify monitoring not yet implemented. Use --mechanism auto for now."
        ))
    }

    #[cfg(target_os = "linux")]
    async fn monitor_with_ebpf(&mut self) -> Result<()> {
        Err(anyhow::anyhow!(
            "eBPF monitoring not yet implemented. Use --mechanism auto for now."
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

        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
        {
            Err(anyhow::anyhow!(
                "No monitoring mechanism available for this platform"
            ))
        }
    }
}