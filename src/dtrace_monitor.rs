#[cfg(any(target_os = "freebsd", target_os = "netbsd", target_os = "illumos", target_os = "solaris"))]
use crate::cli::Mode;
use crate::config::Config;
use crate::rules::{Decision, RuleEngine};
use anyhow::Result;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Command;
use tokio::io::{AsyncBufReadExt, BufReader};

pub struct DTraceMonitor {
    rule_engine: RuleEngine,
    mode: Mode,
    verbose: bool,
    stop_parent: bool,
    dtrace_script: String,
    platform: Platform,
}

#[derive(Clone, Copy)]
enum Platform {
    FreeBSD,
    NetBSD,
    Illumos,
    Solaris,
}

impl Platform {
    fn detect() -> Self {
        #[cfg(target_os = "freebsd")]
        return Platform::FreeBSD;

        #[cfg(target_os = "netbsd")]
        return Platform::NetBSD;

        #[cfg(target_os = "illumos")]
        return Platform::Illumos;

        #[cfg(target_os = "solaris")]
        return Platform::Solaris;

        #[cfg(not(any(target_os = "freebsd", target_os = "netbsd", target_os = "illumos", target_os = "solaris")))]
        Platform::FreeBSD // Default fallback
    }

    fn dtrace_script(&self) -> String {
        match self {
            Platform::FreeBSD | Platform::NetBSD => {
                // BSD-style DTrace script
                r#"
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
"#.to_string()
            }
            Platform::Illumos | Platform::Solaris => {
                // Solaris/illumos-style DTrace script
                // Note: Solaris uses slightly different probe names
                r#"
syscall:::entry
/probefunc == "open" || probefunc == "openat"/
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
"#.to_string()
            }
        }
    }

    fn get_process_path(&self, pid: u32) -> Option<PathBuf> {
        match self {
            Platform::FreeBSD => {
                // Use procstat on FreeBSD
                Command::new("procstat")
                    .args(&["-b", &pid.to_string()])
                    .output()
                    .ok()
                    .and_then(|output| {
                        if output.status.success() {
                            let stdout = String::from_utf8_lossy(&output.stdout);
                            stdout.lines()
                                .nth(1)  // Skip header
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
            Platform::NetBSD => {
                // NetBSD has /proc/[pid]/exe
                std::fs::read_link(format!("/proc/{}/exe", pid))
                    .or_else(|_| std::fs::read_link(format!("/proc/{}/file", pid)))
                    .ok()
            }
            Platform::Illumos | Platform::Solaris => {
                // Solaris/illumos use /proc/[pid]/path/a.out
                std::fs::read_link(format!("/proc/{}/path/a.out", pid))
                    .or_else(|_| {
                        // Alternative: use pargs command
                        Command::new("pargs")
                            .args(&["-c", &pid.to_string()])
                            .output()
                            .ok()
                            .and_then(|output| {
                                if output.status.success() {
                                    let stdout = String::from_utf8_lossy(&output.stdout);
                                    stdout.lines()
                                        .next()
                                        .map(|line| PathBuf::from(line.trim()))
                                } else {
                                    None
                                }
                            })
                    })
                    .ok()
            }
        }
    }
}

impl DTraceMonitor {
    pub fn new(mode: Mode, verbose: bool, stop_parent: bool) -> Self {
        // Load config from embedded YAML
        let config = Config::default().expect("Failed to load default config");
        let platform = Platform::detect();
        let dtrace_script = platform.dtrace_script();

        Self {
            rule_engine: RuleEngine::new(config),
            mode,
            verbose,
            stop_parent,
            dtrace_script,
            platform,
        }
    }

    pub async fn start(&mut self) -> Result<()> {
        log::info!("Starting DTrace monitor on {:?}", self.platform as u8);

        // Check if DTrace is available
        if !self.check_dtrace_available() {
            return Err(anyhow::anyhow!(
                "DTrace not available. Please ensure DTrace is enabled in your kernel."
            ));
        }

        // Start DTrace with our script
        let mut child = tokio::process::Command::new("dtrace")
            .arg("-q")  // Quiet mode
            .arg("-n")
            .arg(&self.dtrace_script)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()?;

        let stdout = child.stdout.take()
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
        let pid = json.get("pid")
            .and_then(|p| p.as_u64())
            .map(|p| p as u32);

        let ppid = json.get("ppid")
            .and_then(|p| p.as_u64())
            .map(|p| p as u32);

        let process_name = json.get("execname")
            .and_then(|e| e.as_str())
            .unwrap_or("unknown");

        let file_path = json.get("file")
            .and_then(|f| f.as_str())
            .unwrap_or("");

        // Get full process path
        let process_path = if let Some(pid) = pid {
            self.platform.get_process_path(pid).unwrap_or_else(|| PathBuf::from(process_name))
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

        // Check if access is allowed
        let decision = self.rule_engine.check_access(&process_path, &file_path_buf, None);

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
                                    if parent_stopped { format!(" + parent[{}]", ppid.unwrap()) } else { String::new() }
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
                        // Interactive mode implementation would go here
                        todo!("Interactive mode for DTrace platforms")
                    }
                }
            }
        }

        Ok(())
    }

    async fn handle_exec_event(&mut self, json: &serde_json::Value) -> Result<()> {
        let args = json.get("args")
            .and_then(|a| a.as_str())
            .unwrap_or("");

        // Check if args contain protected paths
        let args_vec: Vec<String> = args.split_whitespace().map(String::from).collect();

        for arg in &args_vec {
            let expanded = shellexpand::tilde(arg).to_string();
            let path = PathBuf::from(&expanded);

            if self.rule_engine.is_protected_file(&path) {
                let pid = json.get("pid")
                    .and_then(|p| p.as_u64())
                    .map(|p| p as u32);

                let ppid = json.get("ppid")
                    .and_then(|p| p.as_u64())
                    .map(|p| p as u32);

                let process_name = json.get("execname")
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

    fn stop_process(&self, pid: u32) -> bool {
        unsafe {
            // Send SIGSTOP to the process
            libc::kill(pid as libc::pid_t, libc::SIGSTOP) == 0
        }
    }
}