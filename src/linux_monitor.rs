#[cfg(target_os = "linux")]
use crate::cli::Mode;
use crate::config::Config;
use crate::rules::{Decision, RuleEngine};
use anyhow::Result;
use glob;
use nix::libc;
use std::collections::HashMap;
use std::io;
use std::mem;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

// Fanotify constants not in nix crate - only keep the ones we actually use
const FAN_OPEN_PERM: u64 = 0x00010000;

const FAN_UNLIMITED_QUEUE: u32 = 0x00000010;
const FAN_UNLIMITED_MARKS: u32 = 0x00000020;

const FAN_MARK_ADD: u32 = 0x00000001;

const FAN_ALLOW: u32 = 0x01;
const FAN_DENY: u32 = 0x02;

const FAN_CLASS_PRE_CONTENT: u32 = 0x00000008;

const FAN_CLOEXEC: u32 = 0x00000001;

// Fanotify event metadata structure - must match kernel struct exactly!
// From /usr/include/linux/fanotify.h
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct FanotifyEventMetadata {
    pub event_len: u32,      // Total length of this event metadata
    pub vers: u8,             // Version (FANOTIFY_METADATA_VERSION)
    pub reserved: u8,         // Reserved, should be 0
    pub metadata_len: u16,    // Length of this structure (should be 24)
    pub mask: u64,           // Event mask
    pub fd: i32,             // File descriptor of the accessed file
    pub pid: i32,            // PID of the accessing process
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
    #[allow(dead_code)] // Will be used for verbose logging
    verbose: bool,
    #[allow(dead_code)] // Will be used for parent process stopping
    stop_parent: bool,
    fanotify_fd: Option<i32>,
    watched_paths: Arc<Mutex<Vec<PathBuf>>>,
    pid_cache: HashMap<i32, PathBuf>,
}

impl LinuxMonitor {
    pub fn new(mode: Mode, verbose: bool, stop_parent: bool) -> Result<Self> {
        // Load config from embedded YAML
        let config = Config::default()
            .map_err(|e| anyhow::anyhow!("Failed to load default config: {}", e))?;

        Ok(Self {
            rule_engine: RuleEngine::new(config),
            mode,
            verbose,
            stop_parent,
            fanotify_fd: None,
            watched_paths: Arc::new(Mutex::new(Vec::new())),
            pid_cache: HashMap::new(),
        })
    }

    /// Discovers protected files by expanding patterns from the configuration
    fn get_protected_file_paths(&self) -> Vec<PathBuf> {
        let mut paths = Vec::new();
        let users = self.get_system_users();

        log::debug!("Expanding patterns for {} users", users.len());

        let protected_files_count = self.rule_engine.config.protected_files.len();
        log::debug!("Configuration has {} protected file groups", protected_files_count);

        // Process each protected file pattern from the YAML configuration
        for protected_file in &self.rule_engine.config.protected_files {
            let patterns = protected_file.patterns();
            log::debug!("Checking {} patterns from group", patterns.len());

            for pattern_str in patterns {
                // For each pattern, expand it for all users and find matching files
                let expanded_paths = self.expand_pattern_for_users(&pattern_str, &users);
                if !expanded_paths.is_empty() {
                    log::debug!("Pattern '{}' matched {} files", pattern_str, expanded_paths.len());
                    for path in &expanded_paths {
                        log::debug!("  - {}", path.display());
                    }
                }
                paths.extend(expanded_paths);
            }
        }

        // Remove duplicates and sort for consistent logging
        paths.sort();
        paths.dedup();

        log::info!("Total protected files discovered: {}", paths.len());
        paths
    }

    /// Expands a single pattern for all users and returns matching files
    fn expand_pattern_for_users(&self, pattern: &str, users: &[PathBuf]) -> Vec<PathBuf> {
        let mut paths = Vec::new();

        // If pattern starts with ~, expand for each user
        if pattern.starts_with('~') {
            log::debug!("Expanding ~ pattern '{}' for {} users", pattern, users.len());
            for user_home in users {
                // Skip problematic home directories
                let home_str = user_home.to_string_lossy();
                if home_str == "/" || home_str == "/bin" || home_str == "/sbin" || home_str == "/usr/games" {
                    log::debug!("  Skipping system path: {}", home_str);
                    continue;
                }

                let expanded_pattern = pattern.replacen('~', &home_str, 1);
                log::debug!("  Expanding '{}' -> '{}'", pattern, expanded_pattern);

                // Skip patterns that would scan entire filesystem
                if expanded_pattern.starts_with("//**") || expanded_pattern.contains("//") {
                    log::warn!("  Skipping dangerous pattern: {}", expanded_pattern);
                    continue;
                }

                let found = self.glob_pattern(&expanded_pattern);
                if !found.is_empty() {
                    log::info!("    User {}: found {} files",
                        user_home.display(), found.len());
                }
                paths.extend(found);
            }
            // Also expand for root if not already covered
            let root_pattern = pattern.replacen('~', "/root", 1);
            let found = self.glob_pattern(&root_pattern);
            if !found.is_empty() {
                log::debug!("Root: pattern '{}' found {} files", pattern, found.len());
            }
            paths.extend(found);
        } else {
            // Absolute pattern, use as-is
            paths.extend(self.glob_pattern(pattern));
        }

        paths
    }

    /// Uses glob to find files matching a pattern
    fn glob_pattern(&self, pattern: &str) -> Vec<PathBuf> {
        log::debug!("Glob checking pattern: {}", pattern);

        // Skip patterns that would scan too much
        if pattern.contains("**") && (pattern.contains("/./") || pattern.starts_with("/**")) {
            log::warn!("  Skipping overly broad pattern: {}", pattern);
            return Vec::new();
        }

        match glob::glob(pattern) {
            Ok(entries) => {
                let mut results = Vec::new();
                let mut count = 0;
                const MAX_GLOB_RESULTS: usize = 1000;

                for entry in entries {
                    count += 1;
                    if count > MAX_GLOB_RESULTS {
                        log::warn!("  Pattern {} matched too many files (>{} ), stopping", pattern, MAX_GLOB_RESULTS);
                        break;
                    }

                    match entry {
                        Ok(path) => {
                            log::debug!("  Glob found path: {} (is_file: {}, exists: {})",
                                path.display(), path.is_file(), path.exists());
                            if path.is_file() {
                                results.push(path);
                            }
                        }
                        Err(e) => {
                            log::debug!("  Glob error: {}", e);
                        }
                    }
                }
                if results.is_empty() {
                    log::debug!("  No files matched pattern: {}", pattern);
                }
                results
            }
            Err(e) => {
                log::warn!("Invalid glob pattern '{}': {}", pattern, e);
                Vec::new()
            }
        }
    }

    /// Get all users from the system database without any filtering
    /// Returns vector of (UID, home_directory) tuples
    fn get_all_user_homes(&self) -> Vec<(u32, PathBuf)> {
        let mut users = Vec::new();

        unsafe {
            // Reset to start of user database
            libc::setpwent();

            // Iterate through all users in the database
            loop {
                let pwd_ptr = libc::getpwent();
                if pwd_ptr.is_null() {
                    break;
                }

                let pwd = &*pwd_ptr;
                let uid = pwd.pw_uid;

                // Get home directory path
                if !pwd.pw_dir.is_null() {
                    let home_cstr = std::ffi::CStr::from_ptr(pwd.pw_dir);
                    if let Ok(home_str) = home_cstr.to_str() {
                        let home_path = PathBuf::from(home_str);
                        if home_path.exists() {
                            users.push((uid, home_path));
                        }
                    }
                }
            }

            // Close the user database
            libc::endpwent();
        }

        users
    }

    /// Gets home directories of all users from the system database
    fn get_system_users(&self) -> Vec<PathBuf> {
        let mut users = Vec::new();

        // Use getpwent() to get all users and count them
        let all_user_homes = self.get_all_user_homes();
        let total_user_count = all_user_homes.len();

        if total_user_count >= 500 {
            // Large database (likely LDAP/AD): only use users with active processes
            log::info!(
                "Large user database detected ({} users >= 500), filtering to active process UIDs only",
                total_user_count
            );
            let active_uids = self.get_active_uids();
            for (uid, home) in all_user_homes {
                if active_uids.contains(&uid) {
                    users.push(home);
                }
            }
        } else {
            // Small database: use all users
            log::info!(
                "Small user database detected ({} users < 500), using all users",
                total_user_count
            );
            users.extend(all_user_homes.into_iter().map(|(_, home)| home));
        }

        // Sort and deduplicate
        users.sort();
        users.dedup();

        log::info!("Discovered {} user home directories", users.len());
        for (i, user_home) in users.iter().take(10).enumerate() {
            log::info!("  {}: {}", i + 1, user_home.display());
        }
        if users.len() > 10 {
            log::info!("  ... and {} more", users.len() - 10);
        }

        users
    }

    /// Gets unique UIDs from all running processes
    fn get_active_uids(&self) -> Vec<u32> {
        let mut uids = std::collections::HashSet::new();

        // Read all /proc/*/status files to get UIDs from running processes
        if let Ok(proc_entries) = std::fs::read_dir("/proc") {
            for entry in proc_entries.flatten() {
                if let Some(name) = entry.file_name().to_str() {
                    // Skip non-numeric directories (only process PIDs)
                    if name.chars().all(|c| c.is_ascii_digit()) {
                        let status_path = entry.path().join("status");
                        if let Ok(status_content) = std::fs::read_to_string(&status_path) {
                            // Parse Uid line from /proc/PID/status
                            for line in status_content.lines() {
                                if line.starts_with("Uid:") {
                                    let parts: Vec<&str> = line.split_whitespace().collect();
                                    if parts.len() >= 2 {
                                        // Real UID is the first number after "Uid:"
                                        if let Ok(uid) = parts[1].parse::<u32>() {
                                            uids.insert(uid);
                                        }
                                    }
                                    break;
                                }
                            }
                        }
                    }
                }
            }
        }

        let mut uid_vec: Vec<u32> = uids.into_iter().collect();
        uid_vec.sort();
        uid_vec
    }

    pub async fn start(&mut self) -> Result<()> {
        log::info!("Starting Linux fanotify monitor in {} mode", self.mode);

        // Initialize fanotify
        self.init_fanotify()?;

        // Add protected files to monitor
        self.add_watched_files()?;

        // Start background task for periodic file discovery
        let watched_paths_clone = Arc::clone(&self.watched_paths);
        let rule_engine_clone = self.rule_engine.clone();
        let fanotify_fd = self.fanotify_fd;

        tokio::spawn(async move {
            Self::periodic_file_discovery(watched_paths_clone, rule_engine_clone, fanotify_fd)
                .await;
        });

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

    /// Adds protected files to fanotify monitoring
    fn add_watched_files(&mut self) -> Result<()> {
        let fd = self
            .fanotify_fd
            .ok_or_else(|| anyhow::anyhow!("Fanotify not initialized"))?;

        // Discover all protected files using YAML configuration patterns
        let protected_files = self.get_protected_file_paths();

        log::info!("Found {} protected files to monitor", protected_files.len());

        let mut successful_watches = 0;
        let mut failed_watches = 0;
        let total = protected_files.len();
        let mut current = 0;

        for file_path in &protected_files {
            current += 1;
            if current % 100 == 0 || current == total {
                log::info!("Processing file {}/{}", current, total);
            }
            log::debug!("Checking existence of: {}", file_path.display());
            if !file_path.exists() {
                log::warn!("File does not exist, skipping: {}", file_path.display());
                continue;
            }
            log::debug!("File exists, will add watch: {}", file_path.display());

            if self.add_file_watch(fd, file_path)? {
                log::debug!("Getting mutex lock to add path to watched list...");
                match self.watched_paths.lock() {
                    Ok(mut guard) => {
                        guard.push(file_path.clone());
                        successful_watches += 1;
                        log::debug!("Added path to watched list");
                    }
                    Err(e) => {
                        log::error!("Failed to acquire mutex lock: {}", e);
                        return Err(anyhow::anyhow!("Mutex lock poisoned: {}", e));
                    }
                }
            } else {
                failed_watches += 1;
            }
        }

        if successful_watches == 0 {
            log::warn!("No files are being monitored! Check that credential files exist.");
            log::info!("Looking for patterns like: ~/.ssh/id_*, ~/.netrc, ~/.aws/credentials");
            log::info!("Try creating test files: touch ~/.ssh/id_rsa ~/.netrc");
        } else {
            log::info!(
                "Successfully monitoring {} files ({} failed)",
                successful_watches,
                failed_watches
            );

            // Log ALL watched files for verification
            log::info!("Getting final mutex lock to log watched files...");
            let watched_paths = match self.watched_paths.lock() {
                Ok(guard) => guard,
                Err(e) => {
                    log::error!("Failed to get final mutex lock: {}", e);
                    return Err(anyhow::anyhow!("Mutex lock poisoned: {}", e));
                }
            };
            let mut watched_sorted = watched_paths.clone();
            watched_sorted.sort();

            log::info!("=== FINAL LIST OF MONITORED FILES ===");
            for (i, path) in watched_sorted.iter().enumerate() {
                log::info!("  Watch #{}: {}", i + 1, path.display());
            }
            log::info!("=== END OF MONITORED FILES LIST ===");
            log::info!("Total files being monitored: {}", watched_sorted.len());
        }

        Ok(())
    }

    /// Adds a single file to fanotify monitoring
    fn add_file_watch(&self, fd: i32, file_path: &Path) -> Result<bool> {
        let mask = FAN_OPEN_PERM;
        let flags = FAN_MARK_ADD;
        let dirfd = libc::AT_FDCWD;

        let path_str = file_path.to_str().ok_or_else(|| {
            anyhow::anyhow!("Path contains invalid UTF-8: {}", file_path.display())
        })?;
        let path_cstr = std::ffi::CString::new(path_str).map_err(|e| {
            anyhow::anyhow!("Path contains null bytes: {} ({})", file_path.display(), e)
        })?;

        let ret = unsafe { libc::fanotify_mark(fd, flags, mask, dirfd, path_cstr.as_ptr()) };

        if ret < 0 {
            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::ENOSPC) {
                log::error!("Reached fanotify marks limit. Consider increasing /proc/sys/fs/fanotify/max_user_marks");
                return Ok(false);
            }
            log::debug!(
                "Failed to add fanotify mark for {}: {}",
                file_path.display(),
                err
            );
            return Ok(false);
        }

        log::debug!("Added watch for: {}", file_path.display());
        Ok(true)
    }

    /// Periodically discovers and adds watches for newly created protected files
    async fn periodic_file_discovery(
        watched_paths: Arc<Mutex<Vec<PathBuf>>>,
        rule_engine: RuleEngine,
        fanotify_fd: Option<i32>,
    ) {
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(60)); // Check every minute

        loop {
            interval.tick().await;

            if let Some(fd) = fanotify_fd {
                // Create a temporary monitor instance to access discovery methods
                let temp_monitor = LinuxMonitor {
                    rule_engine: rule_engine.clone(),
                    mode: Mode::Monitor, // Doesn't matter for discovery
                    verbose: false,
                    stop_parent: false,
                    fanotify_fd: Some(fd),
                    watched_paths: Arc::clone(&watched_paths),
                    pid_cache: HashMap::new(),
                };

                // Discover current protected files
                let current_files = temp_monitor.get_protected_file_paths();
                let mut new_files = Vec::new();

                // Check which files are not yet being watched
                {
                    let watched = match watched_paths.lock() {
                        Ok(guard) => guard,
                        Err(e) => {
                            log::error!("Mutex lock poisoned during file discovery: {}", e);
                            continue;
                        }
                    };
                    for file_path in current_files {
                        if !watched.contains(&file_path) && file_path.exists() {
                            new_files.push(file_path);
                        }
                    }
                }

                if !new_files.is_empty() {
                    log::info!("Discovered {} new protected files", new_files.len());

                    let mut successful_new_watches = 0;
                    for file_path in new_files {
                        if let Ok(true) = temp_monitor.add_file_watch(fd, &file_path) {
                            match watched_paths.lock() {
                                Ok(mut guard) => {
                                    guard.push(file_path.clone());
                                    successful_new_watches += 1;
                                    log::info!("Added watch for new file: {}", file_path.display());
                                }
                                Err(e) => {
                                    log::error!("Failed to update watched paths: {}", e);
                                }
                            }
                        }
                    }

                    if successful_new_watches > 0 {
                        log::info!(
                            "Successfully added {} new file watches",
                            successful_new_watches
                        );
                    }
                }
            }
        }
    }

    async fn monitor_loop(&mut self) -> Result<()> {
        let fd = self
            .fanotify_fd
            .ok_or_else(|| anyhow::anyhow!("Fanotify not initialized"))?;

        let mut buffer = vec![0u8; 8192];

        log::info!("Starting fanotify monitor loop, watching for events on fd {}", fd);

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

            log::info!("Received fanotify event(s), {} bytes", len);

            // Dump the first few bytes for debugging
            if len > 0 && len <= 100 {
                let hex: Vec<String> = buffer[..len as usize].iter()
                    .map(|b| format!("{:02x}", b))
                    .collect();
                log::debug!("Raw event data: {}", hex.join(" "));
            }

            // Process events
            let mut offset = 0;
            while offset < len as usize {
                if offset + std::mem::size_of::<FanotifyEventMetadata>() > len as usize {
                    log::warn!("Not enough data for complete event at offset {}", offset);
                    break;
                }

                let metadata =
                    unsafe { &*(buffer.as_ptr().add(offset) as *const FanotifyEventMetadata) };

                log::debug!("Reading event at offset {}: vers={}, event_len={}",
                    offset, metadata.vers, metadata.event_len);

                if metadata.vers != libc::FANOTIFY_METADATA_VERSION as u8 {
                    log::warn!("Unsupported fanotify metadata version: {} (expected {})",
                        metadata.vers, libc::FANOTIFY_METADATA_VERSION);
                    break;
                }

                log::debug!("Event metadata: fd={}, pid={}, mask=0x{:x}, event_len={}, vers={}, metadata_len={}",
                    metadata.fd, metadata.pid, metadata.mask, metadata.event_len,
                    metadata.vers, metadata.metadata_len);

                // Sanity checks
                if metadata.event_len == 0 || metadata.event_len as usize > buffer.len() {
                    log::error!("Invalid event_len: {}", metadata.event_len);
                    break;
                }

                if metadata.fd < 0 {
                    log::warn!("Invalid fd in event: {}", metadata.fd);
                    offset += metadata.event_len as usize;
                    continue;
                }

                // Handle the event - don't propagate errors, just log them
                if let Err(e) = self.handle_event(metadata).await {
                    log::error!("Error handling event: {}", e);
                    // For permission events, we MUST respond even on error
                    if metadata.mask & FAN_OPEN_PERM != 0 {
                        // Try to send ALLOW response and close fd
                        let _ = self.respond_to_event(metadata.fd, FAN_ALLOW);
                        // NEVER close the fanotify fd!
                        if metadata.fd != fd {
                            unsafe { libc::close(metadata.fd) };
                        } else {
                            log::error!("NOT closing fd {} as it's the fanotify fd!", metadata.fd);
                        }
                    }
                }

                offset += metadata.event_len as usize;
            }
        }
    }

    async fn handle_event(&mut self, metadata: &FanotifyEventMetadata) -> Result<()> {
        log::info!("Handling fanotify event for PID {} (mask: 0x{:x}, fd={})",
            metadata.pid, metadata.mask, metadata.fd);

        // Sanity check - event fd should not be the same as fanotify fd
        if let Some(fanotify_fd) = self.fanotify_fd {
            if metadata.fd == fanotify_fd {
                log::error!("BUG: Event fd {} is same as fanotify fd!", metadata.fd);
            }
        }

        // Get the file path from the file descriptor
        let file_path = self.get_path_from_fd(metadata.fd)?;

        log::info!("Event file path: {}", file_path.display());

        // Check if this is a protected file
        if !self.rule_engine.is_protected_file(&file_path) {
            log::debug!("File is not protected, allowing access");
            // Allow and close fd
            self.respond_to_event(metadata.fd, FAN_ALLOW)?;
            unsafe { libc::close(metadata.fd) };
            return Ok(());
        }

        // Get process information - handle case where process already exited
        let process_path = match self.get_process_path(metadata.pid) {
            Ok(path) => path,
            Err(e) => {
                // Process may have already exited - this is normal for short-lived processes
                log::warn!("Process PID {} already exited, allowing access: {}", metadata.pid, e);
                // IMPORTANT: Must respond BEFORE closing the fd
                self.respond_to_event(metadata.fd, FAN_ALLOW)?;
                unsafe { libc::close(metadata.fd) };
                return Ok(());
            }
        };

        log::info!(
            "PROTECTED FILE ACCESS: {} (PID {}) -> {}",
            process_path.display(),
            metadata.pid,
            file_path.display()
        );

        // Create process context for the new rule system
        use crate::process_context::ProcessContext;
        let context = ProcessContext {
            path: process_path.clone(),
            pid: Some(metadata.pid as u32),
            ppid: None,    // TODO: Get parent PID on Linux
            team_id: None, // Not available on Linux
            app_id: None,  // Not available on Linux
            args: None,    // TODO: Get command-line args on Linux
            uid: None,     // TODO: Get user ID on Linux
            euid: None,    // TODO: Get effective user ID on Linux
        };

        // Check if access is allowed using new context-aware method
        let decision = self
            .rule_engine
            .check_access_with_context(&context, &file_path);

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

        // Special case for kernel threads (PID 0)
        if pid == 0 {
            return Ok(PathBuf::from("[kernel]"));
        }

        // Read from /proc/PID/exe
        let proc_exe = format!("/proc/{}/exe", pid);
        match std::fs::read_link(&proc_exe) {
            Ok(path) => {
                // Some paths have " (deleted)" suffix if the binary was deleted
                let path_str = path.to_string_lossy();
                let clean_path = if path_str.ends_with(" (deleted)") {
                    PathBuf::from(path_str.trim_end_matches(" (deleted)"))
                } else {
                    path
                };
                self.pid_cache.insert(pid, clean_path.clone());
                Ok(clean_path)
            }
            Err(_) => {
                // Try cmdline as fallback
                let proc_cmdline = format!("/proc/{}/cmdline", pid);
                match std::fs::read_to_string(&proc_cmdline) {
                    Ok(cmdline) if !cmdline.is_empty() => {
                        let parts: Vec<&str> = cmdline.split('\0').collect();
                        if !parts.is_empty() && !parts[0].is_empty() {
                            let path = PathBuf::from(parts[0]);
                            self.pid_cache.insert(pid, path.clone());
                            Ok(path)
                        } else {
                            Err(anyhow::anyhow!("Process {} has empty cmdline", pid))
                        }
                    }
                    _ => {
                        // Process doesn't exist or we can't read it
                        Err(anyhow::anyhow!("Process {} not found or not readable", pid))
                    }
                }
            }
        }
    }

    fn respond_to_event(&self, fd: i32, response: u32) -> Result<()> {
        let fanotify_fd = self
            .fanotify_fd
            .ok_or_else(|| anyhow::anyhow!("Fanotify not initialized"))?;

        log::debug!("Responding to fanotify: event_fd={}, response={}, fanotify_fd={}",
            fd, if response == FAN_ALLOW { "ALLOW" } else { "DENY" }, fanotify_fd);

        let response = FanotifyResponse { fd, response };

        let ret = unsafe {
            libc::write(
                fanotify_fd,
                &response as *const _ as *const libc::c_void,
                mem::size_of::<FanotifyResponse>(),
            )
        };

        if ret < 0 {
            let err = io::Error::last_os_error();
            log::error!("Failed to write response: ret={}, err={}, fanotify_fd={}, event_fd={}",
                ret, err, fanotify_fd, fd);
            return Err(anyhow::anyhow!(
                "Failed to send fanotify response: {}",
                err
            ));
        }

        log::debug!("Successfully sent fanotify response");
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
