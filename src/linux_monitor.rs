#[cfg(target_os = "linux")]
use crate::cli::Mode;
use crate::config::Config;
use crate::rules::{Decision, RuleEngine};
use anyhow::Result;
use nix::libc;
use std::collections::HashMap;
use std::io;
use std::mem;
use std::path::{Path, PathBuf};

// Fanotify constants not in nix crate
const FAN_OPEN_PERM: u64 = 0x00010000;
const FAN_ACCESS_PERM: u64 = 0x00020000;
const FAN_OPEN_EXEC_PERM: u64 = 0x00040000;

const FAN_EVENT_ON_CHILD: u64 = 0x08000000;
const FAN_UNLIMITED_QUEUE: u32 = 0x00000010;
const FAN_UNLIMITED_MARKS: u32 = 0x00000020;
const FAN_ENABLE_AUDIT: u32 = 0x00000040;

const FAN_MARK_ADD: u32 = 0x00000001;
const FAN_MARK_MOUNT: u32 = 0x00000010;
const FAN_MARK_FILESYSTEM: u32 = 0x00000100;

const FAN_ALLOW: u32 = 0x01;
const FAN_DENY: u32 = 0x02;
const FAN_AUDIT: u32 = 0x10;

const FAN_CLASS_NOTIF: u32 = 0x00000000;
const FAN_CLASS_CONTENT: u32 = 0x00000004;
const FAN_CLASS_PRE_CONTENT: u32 = 0x00000008;

const FAN_CLOEXEC: u32 = 0x00000001;
const FAN_NONBLOCK: u32 = 0x00000002;

// Fanotify event metadata structure
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct FanotifyEventMetadata {
    pub event_len: u32,
    pub vers: u8,
    pub reserved: u8,
    pub metadata_len: u16,
    pub mask: u64,
    pub fd: i32,
    pub pid: i32,
}

// Fanotify response structure
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct FanotifyResponse {
    pub fd: i32,
    pub response: u32,
}

pub struct LinuxMonitor {
    rule_engine: RuleEngine,
    mode: Mode,
    verbose: bool,
    stop_parent: bool,
    fanotify_fd: Option<i32>,
    watched_paths: Vec<PathBuf>,
    pid_cache: HashMap<i32, PathBuf>,
}

impl LinuxMonitor {
    pub fn new(mode: Mode, verbose: bool, stop_parent: bool) -> Self {
        // Load config from embedded YAML
        let config = Config::default().expect("Failed to load default config");

        Self {
            rule_engine: RuleEngine::new(config),
            mode,
            verbose,
            stop_parent,
            fanotify_fd: None,
            watched_paths: vec![],
            pid_cache: HashMap::new(),
        }
    }

    fn get_credential_paths(&self) -> Vec<PathBuf> {
        let mut paths = Vec::new();

        // Get all user home directories from /etc/passwd
        let users = self.get_system_users();

        for user_home in users {
            // SSH keys
            paths.push(user_home.join(".ssh"));

            // Cloud credentials
            paths.push(user_home.join(".aws"));
            paths.push(user_home.join(".azure"));
            paths.push(user_home.join(".config/gcloud"));

            // Kubernetes
            paths.push(user_home.join(".kube"));

            // Package managers
            paths.push(user_home.join(".docker"));
            paths.push(user_home.join(".npm"));

            // GPG
            paths.push(user_home.join(".gnupg"));
            paths.push(user_home.join(".gnupg/private-keys-v1.d"));

            // Password stores
            paths.push(user_home.join(".password-store"));
            paths.push(user_home.join(".local/share/keyrings"));

            // Browsers (Linux paths)
            paths.push(user_home.join(".mozilla/firefox"));
            paths.push(user_home.join(".config/google-chrome"));
            paths.push(user_home.join(".config/chromium"));
        }

        // Root paths
        paths.push(PathBuf::from("/root/.ssh"));
        paths.push(PathBuf::from("/root/.aws"));
        paths.push(PathBuf::from("/root/.gnupg"));

        // System-wide credentials
        paths.push(PathBuf::from("/etc/ssl/private"));

        // Remove duplicates and non-existent paths
        paths.sort();
        paths.dedup();

        paths
    }

    fn get_system_users(&self) -> Vec<PathBuf> {
        let mut users = Vec::new();

        // Parse /etc/passwd to find user home directories
        if let Ok(passwd) = std::fs::read_to_string("/etc/passwd") {
            for line in passwd.lines() {
                let parts: Vec<&str> = line.split(':').collect();
                if parts.len() >= 6 {
                    let uid: i32 = parts[2].parse().unwrap_or(-1);
                    let home = parts[5];

                    // Only monitor real user directories (UID >= 1000 typically)
                    // or root (UID 0)
                    if (uid >= 1000 || uid == 0) && home.starts_with("/home/") {
                        users.push(PathBuf::from(home));
                    }
                }
            }
        }

        users
    }

    pub async fn start(&mut self) -> Result<()> {
        log::info!("Starting Linux fanotify monitor in {} mode", self.mode);

        // Initialize fanotify
        self.init_fanotify()?;

        // Add paths to monitor
        self.add_watched_paths()?;

        // Start monitoring loop
        self.monitor_loop().await
    }

    fn init_fanotify(&mut self) -> Result<()> {
        // Initialize fanotify with permission events
        let flags = FAN_CLASS_PRE_CONTENT | FAN_CLOEXEC | FAN_UNLIMITED_QUEUE | FAN_UNLIMITED_MARKS;
        let event_f_flags = libc::O_RDONLY | libc::O_LARGEFILE;

        let fd = unsafe { libc::fanotify_init(flags, event_f_flags as u32) };

        if fd < 0 {
            return Err(anyhow::anyhow!(
                "Failed to initialize fanotify: {}",
                io::Error::last_os_error()
            ));
        }

        self.fanotify_fd = Some(fd);
        log::info!("Initialized fanotify with fd: {}", fd);

        Ok(())
    }

    fn add_watched_paths(&mut self) -> Result<()> {
        let fd = self
            .fanotify_fd
            .ok_or_else(|| anyhow::anyhow!("Fanotify not initialized"))?;

        // Get home directory for current users
        // TODO: Periodically refresh watches to detect newly created secret files
        let credential_paths = self.get_credential_paths();

        log::info!(
            "Found {} credential paths to monitor",
            credential_paths.len()
        );

        for path in &credential_paths {
            if !path.exists() {
                log::debug!("Path does not exist, skipping: {}", path.display());
                continue;
            }

            // Only monitor specific directories, not recursively
            let mask = FAN_OPEN_PERM;
            let flags = FAN_MARK_ADD;
            let dirfd = libc::AT_FDCWD;

            let path_cstr = std::ffi::CString::new(path.to_str().unwrap())?;

            let ret = unsafe { libc::fanotify_mark(fd, flags, mask, dirfd, path_cstr.as_ptr()) };

            if ret < 0 {
                let err = io::Error::last_os_error();
                if err.raw_os_error() == Some(libc::ENOSPC) {
                    log::error!("Reached fanotify marks limit. Consider increasing /proc/sys/fs/fanotify/max_user_marks");
                    break;
                }
                log::debug!(
                    "Failed to add fanotify mark for {}: {}",
                    path.display(),
                    err
                );
            } else {
                log::debug!("Monitoring: {}", path.display());
                self.watched_paths.push(path.clone());
            }
        }

        if self.watched_paths.is_empty() {
            return Err(anyhow::anyhow!("No paths could be monitored"));
        }

        // Log all watched paths in sorted order for easy diffing
        let mut watched_sorted = self.watched_paths.clone();
        watched_sorted.sort();

        log::info!("Monitoring {} paths:", watched_sorted.len());
        for path in &watched_sorted {
            log::info!("  - {}", path.display());
        }

        Ok(())
    }

    async fn monitor_loop(&mut self) -> Result<()> {
        let fd = self
            .fanotify_fd
            .ok_or_else(|| anyhow::anyhow!("Fanotify not initialized"))?;

        let mut buffer = vec![0u8; 8192];

        loop {
            // Read events from fanotify
            let len =
                unsafe { libc::read(fd, buffer.as_mut_ptr() as *mut libc::c_void, buffer.len()) };

            if len < 0 {
                let err = io::Error::last_os_error();
                if err.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(anyhow::anyhow!("Failed to read fanotify events: {}", err));
            }

            if len == 0 {
                continue;
            }

            // Process events
            let mut offset = 0;
            while offset < len as usize {
                let metadata =
                    unsafe { &*(buffer.as_ptr().add(offset) as *const FanotifyEventMetadata) };

                if metadata.vers != libc::FANOTIFY_METADATA_VERSION as u8 {
                    log::warn!("Unsupported fanotify metadata version: {}", metadata.vers);
                    break;
                }

                // Handle the event
                self.handle_event(metadata).await?;

                offset += metadata.event_len as usize;
            }
        }
    }

    async fn handle_event(&mut self, metadata: &FanotifyEventMetadata) -> Result<()> {
        // Get the file path from the file descriptor
        let file_path = self.get_path_from_fd(metadata.fd)?;

        // Check if this is a protected file
        if !self.rule_engine.is_protected_file(&file_path) {
            // Allow and close fd
            self.respond_to_event(metadata.fd, FAN_ALLOW)?;
            unsafe { libc::close(metadata.fd) };
            return Ok(());
        }

        // Get process information
        let process_path = self.get_process_path(metadata.pid)?;

        log::debug!(
            "File access detected: {} (PID {}) -> {}",
            process_path.display(),
            metadata.pid,
            file_path.display()
        );

        // Create process context for the new rule system
        use crate::process_context::ProcessContext;
        let context = ProcessContext {
            path: process_path.clone(),
            pid: Some(metadata.pid as u32),
            ppid: None, // TODO: Get parent PID on Linux
            team_id: None, // Not available on Linux
            app_id: None,  // Not available on Linux
            args: None,    // TODO: Get command-line args on Linux
            uid: None,     // TODO: Get user ID on Linux
            euid: None,    // TODO: Get effective user ID on Linux
        };

        // Check if access is allowed using new context-aware method
        let decision = self.rule_engine.check_access_with_context(&context, &file_path);

        match decision {
            Decision::Allow => {
                log::info!(
                    "ALLOWED: {} -> {}",
                    process_path.display(),
                    file_path.display()
                );
                self.respond_to_event(metadata.fd, FAN_ALLOW)?;
            }
            Decision::Deny => {
                match self.mode {
                    Mode::Monitor => {
                        log::warn!(
                            "DETECTED: {} -> {}",
                            process_path.display(),
                            file_path.display()
                        );
                        // In monitor mode, allow but log
                        self.respond_to_event(metadata.fd, FAN_ALLOW)?;
                    }
                    Mode::Enforce => {
                        log::error!(
                            "BLOCKED: {} -> {}",
                            process_path.display(),
                            file_path.display()
                        );
                        // Actually block the access
                        self.respond_to_event(metadata.fd, FAN_DENY)?;
                    }
                    Mode::Interactive => {
                        let allow = self
                            .handle_interactive_prompt(&process_path, &file_path)
                            .await?;
                        if allow {
                            self.respond_to_event(metadata.fd, FAN_ALLOW)?;
                        } else {
                            self.respond_to_event(metadata.fd, FAN_DENY)?;
                        }
                    }
                }
            }
        }

        // Close the file descriptor
        unsafe { libc::close(metadata.fd) };

        Ok(())
    }

    fn get_path_from_fd(&self, fd: i32) -> Result<PathBuf> {
        let proc_path = format!("/proc/self/fd/{}", fd);
        let path = std::fs::read_link(proc_path)?;
        Ok(path)
    }

    fn get_process_path(&mut self, pid: i32) -> Result<PathBuf> {
        // Check cache first
        if let Some(path) = self.pid_cache.get(&pid) {
            return Ok(path.clone());
        }

        // Read from /proc/PID/exe
        let proc_exe = format!("/proc/{}/exe", pid);
        match std::fs::read_link(&proc_exe) {
            Ok(path) => {
                self.pid_cache.insert(pid, path.clone());
                Ok(path)
            }
            Err(e) => {
                log::debug!("Failed to read process path for PID {}: {}", pid, e);
                // Try cmdline as fallback
                let proc_cmdline = format!("/proc/{}/cmdline", pid);
                match std::fs::read_to_string(&proc_cmdline) {
                    Ok(cmdline) => {
                        let parts: Vec<&str> = cmdline.split('\0').collect();
                        if !parts.is_empty() && !parts[0].is_empty() {
                            let path = PathBuf::from(parts[0]);
                            self.pid_cache.insert(pid, path.clone());
                            Ok(path)
                        } else {
                            Err(anyhow::anyhow!("Empty cmdline for PID {}", pid))
                        }
                    }
                    Err(e) => Err(anyhow::anyhow!(
                        "Failed to read cmdline for PID {}: {}",
                        pid,
                        e
                    )),
                }
            }
        }
    }

    fn respond_to_event(&self, fd: i32, response: u32) -> Result<()> {
        let fanotify_fd = self
            .fanotify_fd
            .ok_or_else(|| anyhow::anyhow!("Fanotify not initialized"))?;

        let response = FanotifyResponse { fd, response };

        let ret = unsafe {
            libc::write(
                fanotify_fd,
                &response as *const _ as *const libc::c_void,
                mem::size_of::<FanotifyResponse>(),
            )
        };

        if ret < 0 {
            return Err(anyhow::anyhow!(
                "Failed to send fanotify response: {}",
                io::Error::last_os_error()
            ));
        }

        Ok(())
    }

    async fn handle_interactive_prompt(
        &mut self,
        process_path: &Path,
        file_path: &Path,
    ) -> Result<bool> {
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
        println!();
        print!("Decision [A/d/w]? ");

        use std::io::{self as stdio, Write};
        stdio::stdout().flush()?;

        let mut input = String::new();
        stdio::stdin().read_line(&mut input)?;

        match input.trim().to_lowercase().chars().next() {
            Some('a') => {
                println!("✓ Allowed once\n");
                log::info!(
                    "User allowed access: {} -> {}",
                    app_name,
                    file_path.display()
                );
                Ok(true)
            }
            Some('w') => {
                println!("✓ Added to whitelist\n");
                self.rule_engine
                    .add_runtime_exception(process_path.to_path_buf(), file_path.to_path_buf());
                log::info!("User whitelisted: {} -> {}", app_name, file_path.display());
                Ok(true)
            }
            _ => {
                println!("✗ Denied\n");
                log::warn!(
                    "User denied access: {} -> {}",
                    app_name,
                    file_path.display()
                );
                Ok(false)
            }
        }
    }
}

impl Drop for LinuxMonitor {
    fn drop(&mut self) {
        if let Some(fd) = self.fanotify_fd {
            unsafe { libc::close(fd) };
            log::info!("Closed fanotify fd: {}", fd);
        }
    }
}
