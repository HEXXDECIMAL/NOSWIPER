use crate::cli::Mode;
use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{broadcast, Mutex, RwLock};
use tokio::time::{interval, Duration};
use uuid::Uuid;

/// Entry in a process tree showing ancestry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessTreeEntry {
    pub pid: u32,
    pub ppid: Option<u32>,
    pub name: String,
    pub path: String,
    pub cmdline: Option<String>,
    pub team_id: Option<String>,
    pub signing_id: Option<String>,
    pub vendor_name: Option<String>, // e.g. "Mozilla Corporation"
}

/// Event types that can occur
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum EventType {
    #[serde(rename = "access_denied")]
    AccessDenied {
        rule_name: String,
        file_path: String,
        process_path: String,
        process_pid: u32,
        process_cmdline: Option<String>,
        process_euid: Option<u32>,
        parent_pid: Option<u32>,
        team_id: Option<String>,
        action: String,                              // "blocked", "suspended", etc.
        process_tree: Option<Vec<ProcessTreeEntry>>, // Full process ancestry
    },
    #[serde(rename = "access_allowed")]
    AccessAllowed {
        rule_name: Option<String>,
        file_path: String,
        process_path: String,
        process_pid: u32,
        process_cmdline: Option<String>,
        process_euid: Option<u32>,
        process_tree: Option<Vec<ProcessTreeEntry>>, // Full process ancestry
    },
}

/// Event that can be sent to clients
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    pub id: String, // Unique event ID (UUID)
    pub timestamp: DateTime<Utc>,
    #[serde(flatten)]
    pub event_type: EventType,
}

/// Client request types
#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "action")]
pub enum ClientRequest {
    /// Subscribe to event stream
    #[serde(rename = "subscribe")]
    Subscribe {
        #[serde(default)]
        filter: Option<EventFilter>,
    },

    /// Allow a suspended process once
    #[serde(rename = "allow_once")]
    AllowOnce { event_id: String },

    /// Allow permanently and add to allow list
    #[serde(rename = "allow_permanently")]
    AllowPermanently { event_id: String },

    /// Kill the suspended process
    #[serde(rename = "kill")]
    Kill { event_id: String },

    /// Get current status
    #[serde(rename = "status")]
    Status,

    /// Set enforcement mode
    #[serde(rename = "set_mode")]
    SetMode { mode: String }, // "monitor" or "enforce"

    /// Get current enforcement mode
    #[serde(rename = "get_mode")]
    GetMode,

    /// Get override rules
    #[serde(rename = "get_overrides")]
    GetOverrides,
}

/// Response to client requests
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "status")]
pub enum ClientResponse {
    #[serde(rename = "success")]
    Success { message: String },

    #[serde(rename = "error")]
    Error { message: String },

    #[serde(rename = "event")]
    Event(Event),

    #[serde(rename = "status")]
    Status {
        mode: String,
        events_pending: usize,
        connected_clients: usize,
    },
}

/// Filter for event subscriptions
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct EventFilter {
    #[serde(default)]
    pub event_types: Vec<String>, // "access_denied", "access_allowed"
    #[serde(default)]
    pub min_severity: Option<String>,
}

/// Scope for permanent allow rules
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AllowScope {
    pub process_path: String,
    pub process_args: Option<Vec<String>>,
    pub file_path: String,
    pub team_id: Option<String>,
    pub signing_id: Option<String>,
    pub parent_path: Option<String>,
    pub parent_team_id: Option<String>,
    pub comment: Option<String>,
}

/// Suspended process information
#[derive(Debug, Clone)]
pub struct SuspendedProcess {
    pub pid: u32,
    #[allow(dead_code)]
    pub ppid: Option<u32>,
    #[allow(dead_code)]
    pub path: PathBuf,
    #[allow(dead_code)]
    pub file_accessed: PathBuf,
    #[allow(dead_code)]
    pub timestamp: DateTime<Utc>,
}

/// Rate limiter for client operations
#[derive(Debug, Clone)]
struct RateLimiter {
    last_request: std::time::Instant,
    request_count: usize,
}

impl RateLimiter {
    fn new() -> Self {
        Self {
            last_request: std::time::Instant::now(),
            request_count: 0,
        }
    }

    fn check_rate_limit(&mut self) -> bool {
        const MAX_REQUESTS_PER_SECOND: usize = 10;
        const WINDOW_SECONDS: u64 = 1;

        let now = std::time::Instant::now();
        let elapsed = now.duration_since(self.last_request);

        if elapsed.as_secs() >= WINDOW_SECONDS {
            // Reset window
            self.last_request = now;
            self.request_count = 1;
            true
        } else {
            self.request_count += 1;
            self.request_count <= MAX_REQUESTS_PER_SECOND
        }
    }
}

/// IPC Server that manages client connections and events
pub struct IpcServer {
    socket_path: PathBuf,
    event_queue: Arc<Mutex<Vec<Event>>>,
    event_history: Arc<RwLock<HashMap<String, Event>>>,
    suspended_processes: Arc<RwLock<HashMap<String, SuspendedProcess>>>,
    client_count: Arc<Mutex<usize>>,
    client_rate_limiters: Arc<RwLock<HashMap<String, RateLimiter>>>, // Track per-client rate limits
    event_sender: broadcast::Sender<Event>,
    mode: Arc<RwLock<Mode>>, // Shared enforcement mode
}

impl IpcServer {
    /// Create a new IPC server
    pub fn new(mode: Arc<RwLock<Mode>>) -> Result<Self> {
        let socket_path = Self::get_socket_path()?;

        // Remove existing socket if it exists
        if socket_path.exists() {
            fs::remove_file(&socket_path).ok();
        }

        // Create broadcast channel with reasonable buffer
        let (event_sender, _) = broadcast::channel(1000);

        Ok(Self {
            socket_path,
            event_queue: Arc::new(Mutex::new(Vec::new())),
            event_history: Arc::new(RwLock::new(HashMap::new())),
            suspended_processes: Arc::new(RwLock::new(HashMap::new())),
            client_count: Arc::new(Mutex::new(0)),
            client_rate_limiters: Arc::new(RwLock::new(HashMap::new())),
            event_sender,
            mode,
        })
    }

    /// Get the OS-appropriate socket path
    pub fn get_socket_path() -> Result<PathBuf> {
        let path = if cfg!(target_os = "macos") {
            PathBuf::from("/var/run/noswiper.sock")
        } else {
            // Linux/FreeBSD
            PathBuf::from("/run/noswiper.sock")
        };

        // Ensure directory exists
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }

        Ok(path)
    }

    /// Start the IPC server
    pub async fn start(self: Arc<Self>) -> Result<()> {
        // Ensure socket doesn't exist (prevent hijacking)
        if self.socket_path.exists() {
            fs::remove_file(&self.socket_path)?;
        }

        // Set umask to ensure secure permissions from the start
        let listener = {
            #[cfg(unix)]
            {
                use libc::{chown, getgrnam, umask};
                use std::ffi::CString;

                unsafe {
                    let old_mask = umask(0o117); // Temporarily set umask for socket creation
                    let listener = UnixListener::bind(&self.socket_path)?;
                    umask(old_mask); // Restore original umask

                    // Set proper group ownership based on OS
                    let admin_group = if cfg!(target_os = "macos") {
                        "admin"
                    } else if cfg!(target_os = "linux") {
                        // Try sudo first, fall back to wheel
                        "sudo"
                    } else {
                        "wheel" // Default for BSD variants
                    };

                    // Get the group ID for the admin group
                    let group_name = CString::new(admin_group).unwrap();
                    let group_info = getgrnam(group_name.as_ptr());

                    if !group_info.is_null() {
                        let gid = (*group_info).gr_gid;
                        let socket_path_c =
                            CString::new(self.socket_path.to_str().unwrap()).unwrap();

                        // Change group ownership to admin group, keep root as owner
                        if chown(socket_path_c.as_ptr(), 0, gid) != 0 {
                            log::warn!(
                                "Failed to set socket group to {}: {}",
                                admin_group,
                                std::io::Error::last_os_error()
                            );
                        } else {
                            log::info!("Socket group set to {} (gid: {})", admin_group, gid);
                        }
                    } else {
                        // If primary admin group doesn't exist, try fallback
                        if cfg!(target_os = "linux") && admin_group == "sudo" {
                            // Try wheel as fallback on Linux
                            let wheel_group = CString::new("wheel").unwrap();
                            let wheel_info = getgrnam(wheel_group.as_ptr());

                            if !wheel_info.is_null() {
                                let gid = (*wheel_info).gr_gid;
                                let socket_path_c =
                                    CString::new(self.socket_path.to_str().unwrap()).unwrap();

                                if chown(socket_path_c.as_ptr(), 0, gid) == 0 {
                                    log::info!(
                                        "Socket group set to wheel (gid: {}) as fallback",
                                        gid
                                    );
                                } else {
                                    log::warn!(
                                        "Failed to set socket group: {}",
                                        std::io::Error::last_os_error()
                                    );
                                }
                            } else {
                                log::warn!(
                                    "Neither sudo nor wheel groups found on this Linux system"
                                );
                            }
                        } else {
                            log::warn!("Admin group '{}' not found on this system", admin_group);
                        }
                    }

                    // Set permissions to rw-rw---- (owner and group can read/write)
                    let metadata = fs::metadata(&self.socket_path)?;
                    let mut permissions = metadata.permissions();
                    permissions.set_mode(0o660); // rw-rw----
                    fs::set_permissions(&self.socket_path, permissions)?;

                    log::info!("Socket permissions set to 0660 (rw-rw----)");
                    listener
                }
            }

            #[cfg(not(unix))]
            {
                return Err(anyhow::anyhow!("IPC server requires Unix sockets"));
            }
        };

        log::info!("IPC server listening on: {}", self.socket_path.display());

        // Spawn cleanup task
        let server_cleanup = Arc::clone(&self);
        tokio::spawn(async move {
            let mut cleanup_interval = interval(Duration::from_secs(300)); // Every 5 minutes
            loop {
                cleanup_interval.tick().await;
                server_cleanup.cleanup_expired().await;
            }
        });

        // Accept connections
        loop {
            let (stream, _) = listener.accept().await?;
            let server = Arc::clone(&self);

            // Handle each client in a separate task
            tokio::spawn(async move {
                if let Err(e) = server.handle_client(stream).await {
                    log::error!("Client handler error: {}", e);
                }
            });
        }
    }

    /// Handle a client connection
    async fn handle_client(self: Arc<Self>, mut stream: UnixStream) -> Result<()> {
        let client_id: String;

        // Verify peer credentials (only root or admin group)
        #[cfg(target_os = "macos")]
        {
            use libc::{getgrnam, getpeereid, gid_t, uid_t};
            use std::ffi::CString;
            use std::os::unix::io::AsRawFd;

            let fd = stream.as_raw_fd();
            let mut uid: uid_t = 0;
            let mut gid: gid_t = 0;

            unsafe {
                let ret = getpeereid(fd, &mut uid, &mut gid);
                if ret != 0 {
                    return Err(anyhow::anyhow!("Failed to get peer credentials"));
                }

                // Allow root immediately
                if uid == 0 {
                    client_id = format!("uid_{}", uid);
                } else {
                    // Check if user is in admin group
                    let admin_group_name = CString::new("admin").unwrap();
                    let admin_group = getgrnam(admin_group_name.as_ptr());

                    if admin_group.is_null() {
                        return Err(anyhow::anyhow!("Admin group not found"));
                    }

                    let admin_gid = (*admin_group).gr_gid;

                    // Check if the user's primary group is admin
                    if gid == admin_gid {
                        client_id = format!("uid_{}", uid);
                    } else {
                        // Check if user is a member of admin group
                        // Note: getgrouplist requires username, so we'd need getpwuid first
                        // For simplicity, we'll check primary group and allow socket group access
                        // The socket permissions (660 with admin group) will handle access control
                        client_id = format!("uid_{}", uid);
                        log::info!(
                            "Client uid {} connected (will rely on socket permissions)",
                            uid
                        );
                    }
                }
            }
        }

        #[cfg(target_os = "linux")]
        {
            use libc::{getgrnam, getsockopt, SOL_SOCKET, SO_PEERCRED};
            use std::ffi::CString;
            use std::os::unix::io::AsRawFd;

            #[repr(C)]
            struct ucred {
                pid: libc::pid_t,
                uid: libc::uid_t,
                gid: libc::gid_t,
            }

            let fd = stream.as_raw_fd();
            let mut cred = ucred {
                pid: 0,
                uid: 0,
                gid: 0,
            };
            let mut cred_len = std::mem::size_of::<ucred>() as libc::socklen_t;

            unsafe {
                let ret = getsockopt(
                    fd,
                    SOL_SOCKET,
                    SO_PEERCRED,
                    &mut cred as *mut _ as *mut libc::c_void,
                    &mut cred_len,
                );

                if ret != 0 {
                    return Err(anyhow::anyhow!("Failed to get peer credentials"));
                }

                // Allow root immediately
                if cred.uid == 0 {
                    client_id = format!("pid_{}", cred.pid);
                } else {
                    // Check if user is in sudo or wheel group
                    // The socket permissions (660 with sudo/wheel group) will handle access control
                    // We just log the connection here
                    client_id = format!("pid_{}_uid_{}", cred.pid, cred.uid);
                    log::info!(
                        "Client uid {} (pid {}) connected (relying on socket permissions)",
                        cred.uid,
                        cred.pid
                    );
                }
            }
        }

        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
        {
            // For other platforms, use a default client ID
            client_id = "default".to_string();
        }

        // Initialize rate limiter for this client
        {
            let mut limiters = self.client_rate_limiters.write().await;
            limiters
                .entry(client_id.clone())
                .or_insert_with(RateLimiter::new);
        }

        // Increment client count
        {
            let mut count = self.client_count.lock().await;
            *count += 1;
        }

        // Create a reader and writer with size limits
        let (reader, mut writer) = stream.split();
        let mut reader = BufReader::new(reader);
        let mut line = String::with_capacity(4096); // Pre-allocate reasonable size

        const MAX_LINE_SIZE: usize = 65536; // 64KB max per line

        // Handle client requests
        loop {
            line.clear();

            // Read with size limit
            let mut total_read = 0;
            loop {
                let bytes_read = reader.read_line(&mut line).await?;
                if bytes_read == 0 {
                    break; // EOF
                }
                total_read += bytes_read;

                if total_read > MAX_LINE_SIZE {
                    return Err(anyhow::anyhow!(
                        "Request too large (max {}KB)",
                        MAX_LINE_SIZE / 1024
                    ));
                }

                if line.ends_with('\n') {
                    break; // Complete line
                }
            }

            if total_read == 0 {
                break; // Client disconnected
            }

            // Check rate limit
            {
                let mut limiters = self.client_rate_limiters.write().await;
                if let Some(limiter) = limiters.get_mut(&client_id) {
                    if !limiter.check_rate_limit() {
                        let response = ClientResponse::Error {
                            message: "Rate limit exceeded. Please slow down.".to_string(),
                        };
                        let response_json = serde_json::to_string(&response)? + "\n";
                        writer.write_all(response_json.as_bytes()).await?;
                        writer.flush().await?;
                        continue;
                    }
                }
            }

            // Parse the request
            let request: ClientRequest = match serde_json::from_str(&line) {
                Ok(req) => req,
                Err(e) => {
                    let response = ClientResponse::Error {
                        message: format!("Invalid JSON: {}", e),
                    };
                    let response_json = serde_json::to_string(&response)? + "\n";
                    writer.write_all(response_json.as_bytes()).await?;
                    writer.flush().await?;
                    continue;
                }
            };

            // Special handling for Subscribe request - enter streaming mode
            if matches!(request, ClientRequest::Subscribe { .. }) {
                // Send initial success response
                let response = ClientResponse::Success {
                    message: "Subscribed to events".to_string(),
                };
                let response_json = serde_json::to_string(&response)? + "\n";
                writer.write_all(response_json.as_bytes()).await?;
                writer.flush().await?;

                // Clone event sender to create a new receiver for this client
                let mut event_rx = self.event_sender.subscribe();

                // Stream events to client
                loop {
                    tokio::select! {
                        // Check for new events
                        result = event_rx.recv() => {
                            match result {
                                Ok(event) => {
                                    let event_response = ClientResponse::Event(event);
                                    let event_json = serde_json::to_string(&event_response)? + "\n";
                                    if let Err(e) = writer.write_all(event_json.as_bytes()).await {
                                        log::debug!("Client disconnected while streaming: {}", e);
                                        break;
                                    }
                                    if let Err(e) = writer.flush().await {
                                        log::debug!("Client disconnected while flushing: {}", e);
                                        break;
                                    }
                                }
                                Err(e) => {
                                    log::debug!("Event channel error (likely no senders): {}", e);
                                    // Continue listening - channel might reconnect
                                }
                            }
                        }
                        // Check if client disconnected
                        result = reader.read_line(&mut line) => {
                            match result {
                                Ok(0) => {
                                    log::debug!("Client disconnected (EOF)");
                                    break;
                                }
                                Ok(_) => {
                                    log::debug!("Client sent request while subscribed, ignoring");
                                    line.clear(); // Clear the line buffer for next read
                                }
                                Err(e) => {
                                    log::debug!("Error reading from client: {}", e);
                                    break;
                                }
                            }
                        }
                    }
                }
                break; // Exit the main loop after streaming ends
            }

            // Handle non-subscribe requests normally
            let response = self.handle_request(request).await;

            // Send response
            let response_json = serde_json::to_string(&response)? + "\n";
            writer.write_all(response_json.as_bytes()).await?;
            writer.flush().await?;
        }

        // Cleanup: decrement client count and remove rate limiter
        {
            let mut count = self.client_count.lock().await;
            *count = count.saturating_sub(1);
        }

        {
            let mut limiters = self.client_rate_limiters.write().await;
            limiters.remove(&client_id);
        }

        Ok(())
    }

    /// Handle a client request
    async fn handle_request(&self, request: ClientRequest) -> ClientResponse {
        match request {
            ClientRequest::Subscribe { filter: _ } => {
                // For subscribe, we'll need to implement streaming
                // This is a simplified version
                ClientResponse::Success {
                    message: "Subscribed to events".to_string(),
                }
            }

            ClientRequest::AllowOnce { event_id } => self.handle_allow_once(&event_id).await,

            ClientRequest::AllowPermanently { event_id } => {
                self.handle_allow_permanently(&event_id).await
            }

            ClientRequest::Kill { event_id } => self.handle_kill(&event_id).await,

            ClientRequest::Status => {
                let events_pending = self.event_queue.lock().await.len();
                let connected_clients = *self.client_count.lock().await;
                let current_mode = self.mode.read().await;

                ClientResponse::Status {
                    mode: format!("{:?}", *current_mode).to_lowercase(),
                    events_pending,
                    connected_clients,
                }
            }

            ClientRequest::GetMode => {
                let current_mode = self.mode.read().await;
                ClientResponse::Success {
                    message: format!("{:?}", *current_mode).to_lowercase(),
                }
            }

            ClientRequest::SetMode { mode } => match mode.to_lowercase().as_str() {
                "monitor" => {
                    let mut current_mode = self.mode.write().await;
                    *current_mode = Mode::Monitor;
                    log::info!("Switched to Monitor mode");
                    ClientResponse::Success {
                        message: "Mode set to monitor".to_string(),
                    }
                }
                "enforce" => {
                    let mut current_mode = self.mode.write().await;
                    *current_mode = Mode::Enforce;
                    log::info!("Switched to Enforce mode");
                    ClientResponse::Success {
                        message: "Mode set to enforce".to_string(),
                    }
                }
                _ => ClientResponse::Error {
                    message: format!("Invalid mode: {}. Use 'monitor' or 'enforce'", mode),
                },
            },

            ClientRequest::GetOverrides => self.handle_get_overrides().await,
        }
    }

    /// Get the OS-appropriate path for custom rules
    fn get_custom_rules_path() -> PathBuf {
        if cfg!(target_os = "macos") {
            PathBuf::from("/Library/Application Support/NoSwiper/overrides.yaml")
        } else if cfg!(target_os = "linux") {
            PathBuf::from("/etc/noswiper/custom_rules.yaml")
        } else if cfg!(target_os = "freebsd") {
            PathBuf::from("/usr/local/etc/noswiper/custom_rules.yaml")
        } else {
            PathBuf::from("/etc/noswiper/custom_rules.yaml")
        }
    }

    /// Handle get overrides request
    async fn handle_get_overrides(&self) -> ClientResponse {
        let config_path = Self::get_custom_rules_path();

        // Check if file exists
        if !config_path.exists() {
            return ClientResponse::Success {
                message: String::new(), // Empty string means no overrides
            };
        }

        // Read the file
        match fs::read_to_string(&config_path) {
            Ok(content) => {
                if content.trim().is_empty()
                    || content
                        .trim()
                        .lines()
                        .all(|line| line.trim().starts_with('#'))
                {
                    // File exists but has no actual rules (only comments)
                    ClientResponse::Success {
                        message: String::new(),
                    }
                } else {
                    ClientResponse::Success { message: content }
                }
            }
            Err(e) => ClientResponse::Error {
                message: format!("Failed to read override rules: {}", e),
            },
        }
    }

    /// Handle allow once request
    async fn handle_allow_once(&self, event_id: &str) -> ClientResponse {
        let mut suspended = self.suspended_processes.write().await;

        if let Some(process) = suspended.get(event_id).cloned() {
            // First try to resume the child process
            let child_exists =
                Self::verify_process_identity(process.pid, &process.path, &process.timestamp);

            #[cfg(target_os = "macos")]
            {
                // Try to resume the child process first
                let child_result = if child_exists {
                    Some(
                        std::process::Command::new("kill")
                            .args(["-CONT", &process.pid.to_string()])
                            .output(),
                    )
                } else {
                    None
                };

                // Handle child process result or try parent
                match child_result {
                    Some(Ok(output)) if output.status.success() => {
                        suspended.remove(event_id);
                        ClientResponse::Success {
                            message: format!("Process {} resumed", process.pid),
                        }
                    }
                    Some(Ok(_)) | Some(Err(_)) | None => {
                        // Child failed or doesn't exist, try parent
                        if let Some(ppid) = process.ppid {
                            if ppid > 1 {
                                // Get parent process name for message
                                let parent_name = std::process::Command::new("ps")
                                    .args(["-p", &ppid.to_string(), "-o", "comm="])
                                    .output()
                                    .ok()
                                    .and_then(|o| String::from_utf8(o.stdout).ok())
                                    .map(|s| s.trim().to_string())
                                    .unwrap_or_else(|| format!("PID {}", ppid));

                                let parent_result = std::process::Command::new("kill")
                                    .args(["-CONT", &ppid.to_string()])
                                    .output();

                                match parent_result {
                                    Ok(output) if output.status.success() => {
                                        suspended.remove(event_id);
                                        let child_name = process
                                            .path
                                            .file_name()
                                            .and_then(|n| n.to_str())
                                            .unwrap_or("unknown");

                                        if !child_exists {
                                            ClientResponse::Success {
                                                message: format!(
                                                    "Child process {} ({}) had already exited. Resumed parent process {} ({})",
                                                    child_name, process.pid, parent_name, ppid
                                                ),
                                            }
                                        } else {
                                            ClientResponse::Success {
                                                message: format!(
                                                    "Resumed parent process {} ({}) after child {} ({}) failed to resume",
                                                    parent_name, ppid, child_name, process.pid
                                                ),
                                            }
                                        }
                                    }
                                    Ok(output) => ClientResponse::Error {
                                        message: format!(
                                            "Failed to resume parent process: {}",
                                            String::from_utf8_lossy(&output.stderr)
                                        ),
                                    },
                                    Err(e) => ClientResponse::Error {
                                        message: format!("Failed to resume parent process: {}", e),
                                    },
                                }
                            } else {
                                ClientResponse::Error {
                                    message:
                                        "Process no longer exists and no valid parent to resume"
                                            .to_string(),
                                }
                            }
                        } else {
                            ClientResponse::Error {
                                message:
                                    "Process no longer exists and no parent information available"
                                        .to_string(),
                            }
                        }
                    }
                }
            }

            #[cfg(not(target_os = "macos"))]
            {
                ClientResponse::Error {
                    message: "Process resumption not implemented for this platform".to_string(),
                }
            }
        } else {
            ClientResponse::Error {
                message: format!("Event {} not found or process not suspended", event_id),
            }
        }
    }

    /// Handle allow permanently request
    async fn handle_allow_permanently(&self, event_id: &str) -> ClientResponse {
        // Get the event from history to derive the scope
        let event = {
            let history = self.event_history.read().await;
            history.get(event_id).cloned()
        };

        if let Some(event) = event {
            // Extract process and file information from the event
            let (process_path, file_path, process_cmdline, team_id, process_tree) = match &event
                .event_type
            {
                EventType::AccessDenied {
                    process_path,
                    file_path,
                    process_cmdline,
                    team_id,
                    process_tree,
                    ..
                } => (
                    process_path.clone(),
                    file_path.clone(),
                    process_cmdline.clone(),
                    team_id.clone(),
                    process_tree.clone(),
                ),
                EventType::AccessAllowed { .. } => {
                    return ClientResponse::Error {
                        message: "Cannot create allow rule for already-allowed access".to_string(),
                    };
                }
            };

            // First, allow the process once
            let allow_result = self.handle_allow_once(event_id).await;

            // Then add to permanent allow list
            if matches!(allow_result, ClientResponse::Success { .. }) {
                // Build a smart comment that includes context
                let mut comment_parts = vec![format!("Auto-generated from event {}", event_id)];

                // Extract parent information if available
                let (parent_path, parent_team_id) = if let Some(tree) = &process_tree {
                    if tree.len() > 1 {
                        // Get parent (second entry in tree)
                        if let Some(parent) = tree.get(1) {
                            comment_parts.push(format!("Parent: {} ({})", parent.name, parent.pid));
                            if let Some(parent_team) = &parent.team_id {
                                comment_parts.push(format!("Parent Team ID: {}", parent_team));
                            } else if let Some(parent_signing) = &parent.signing_id {
                                comment_parts
                                    .push(format!("Parent Signing ID: {}", parent_signing));
                            }
                            (Some(parent.path.clone()), parent.team_id.clone())
                        } else {
                            (None, None)
                        }
                    } else {
                        (None, None)
                    }
                } else {
                    (None, None)
                };

                // Add team ID to comment if available
                if let Some(team) = &team_id {
                    comment_parts.push(format!("Process Team ID: {}", team));
                }

                // Extract signing_id from the process tree if available
                let signing_id = process_tree
                    .as_ref()
                    .and_then(|tree| tree.first())
                    .and_then(|entry| entry.signing_id.clone());

                // Create scope from the verified event data with enhanced context
                let scope = AllowScope {
                    process_path,
                    process_args: process_cmdline.map(|cmd| {
                        // Extract arguments from command line
                        cmd.split_whitespace()
                            .skip(1) // Skip the program name
                            .map(String::from)
                            .collect()
                    }),
                    file_path,
                    team_id,
                    signing_id,
                    parent_path,
                    parent_team_id,
                    comment: Some(comment_parts.join(", ")),
                };

                if let Err(e) = self.add_permanent_allow_rule(scope).await {
                    return ClientResponse::Error {
                        message: format!("Process resumed but failed to add permanent rule: {}", e),
                    };
                }

                ClientResponse::Success {
                    message: "Process resumed and permanent allow rule added".to_string(),
                }
            } else {
                allow_result
            }
        } else {
            ClientResponse::Error {
                message: format!("Event {} not found", event_id),
            }
        }
    }

    /// Handle kill request
    async fn handle_kill(&self, event_id: &str) -> ClientResponse {
        let mut suspended = self.suspended_processes.write().await;

        if let Some(process) = suspended.get(event_id).cloned() {
            // First try to kill the child process
            let child_exists =
                Self::verify_process_identity(process.pid, &process.path, &process.timestamp);

            // Try to kill the child process first
            let child_result = if child_exists {
                Some(
                    std::process::Command::new("kill")
                        .args(["-KILL", &process.pid.to_string()])
                        .output(),
                )
            } else {
                None
            };

            // Handle child process result or try parent
            match child_result {
                Some(Ok(output)) if output.status.success() => {
                    suspended.remove(event_id);
                    ClientResponse::Success {
                        message: format!("Process {} killed", process.pid),
                    }
                }
                Some(Ok(_)) | Some(Err(_)) | None => {
                    // Child failed or doesn't exist, try parent
                    if let Some(ppid) = process.ppid {
                        if ppid > 1 {
                            // Get parent process name for message
                            let parent_name = std::process::Command::new("ps")
                                .args(["-p", &ppid.to_string(), "-o", "comm="])
                                .output()
                                .ok()
                                .and_then(|o| String::from_utf8(o.stdout).ok())
                                .map(|s| s.trim().to_string())
                                .unwrap_or_else(|| format!("PID {}", ppid));

                            let parent_result = std::process::Command::new("kill")
                                .args(["-KILL", &ppid.to_string()])
                                .output();

                            match parent_result {
                                Ok(output) if output.status.success() => {
                                    suspended.remove(event_id);
                                    let child_name = process
                                        .path
                                        .file_name()
                                        .and_then(|n| n.to_str())
                                        .unwrap_or("unknown");

                                    if !child_exists {
                                        ClientResponse::Success {
                                            message: format!(
                                                "Child process {} ({}) had already exited. Killed parent process {} ({})",
                                                child_name, process.pid, parent_name, ppid
                                            ),
                                        }
                                    } else {
                                        ClientResponse::Success {
                                            message: format!(
                                                "Killed parent process {} ({}) after child {} ({}) failed to be killed",
                                                parent_name, ppid, child_name, process.pid
                                            ),
                                        }
                                    }
                                }
                                Ok(output) => ClientResponse::Error {
                                    message: format!(
                                        "Failed to kill parent process: {}",
                                        String::from_utf8_lossy(&output.stderr)
                                    ),
                                },
                                Err(e) => ClientResponse::Error {
                                    message: format!("Failed to kill parent process: {}", e),
                                },
                            }
                        } else {
                            ClientResponse::Error {
                                message: "Process no longer exists and no valid parent to kill"
                                    .to_string(),
                            }
                        }
                    } else {
                        ClientResponse::Error {
                            message: "Process no longer exists and no parent information available"
                                .to_string(),
                        }
                    }
                }
            }
        } else {
            ClientResponse::Error {
                message: format!("Event {} not found or process not suspended", event_id),
            }
        }
    }

    /// Verify process identity to prevent PID reuse attacks
    fn verify_process_identity(pid: u32, expected_path: &Path, start_time: &DateTime<Utc>) -> bool {
        #[cfg(target_os = "macos")]
        {
            // Get process info and verify it matches
            let output = std::process::Command::new("ps")
                .args(["-p", &pid.to_string(), "-o", "comm=,lstart="])
                .output();

            if let Ok(output) = output {
                if output.status.success() {
                    let info = String::from_utf8_lossy(&output.stdout);
                    // Check if process path matches (basic check)
                    if let Some(expected_name) = expected_path.file_name() {
                        let expected_name_str = expected_name.to_string_lossy();
                        if info.contains(&*expected_name_str) {
                            // Additional check: verify the process hasn't been running too long
                            // (suspended process should be relatively recent)
                            let elapsed = Utc::now().signed_duration_since(*start_time);
                            if elapsed.num_hours() < 24 {
                                return true;
                            }
                        }
                    }
                }
            }
        }

        #[cfg(not(target_os = "macos"))]
        {
            // Linux: Check /proc/[pid]/exe symlink
            let proc_exe = format!("/proc/{}/exe", pid);
            if let Ok(exe_path) = std::fs::read_link(&proc_exe) {
                if exe_path == *expected_path {
                    return true;
                }
            }
        }

        false
    }

    /// Add a permanent allow rule to the custom config
    async fn add_permanent_allow_rule(&self, scope: AllowScope) -> Result<()> {
        let config_path = Self::get_custom_rules_path();

        // Validate and sanitize inputs to prevent YAML injection
        let sanitized_path = Self::sanitize_yaml_string(&scope.process_path);
        let sanitized_file = Self::sanitize_yaml_string(&scope.file_path);

        // Validate path doesn't contain directory traversal
        if sanitized_path.contains("../") || sanitized_path.contains("..\\") {
            return Err(anyhow::anyhow!(
                "Invalid path: contains directory traversal"
            ));
        }

        // Ensure directory exists with secure permissions
        if let Some(parent) = config_path.parent() {
            fs::create_dir_all(parent)?;

            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let metadata = fs::metadata(parent)?;
                let mut perms = metadata.permissions();
                perms.set_mode(0o755); // rwxr-xr-x
                fs::set_permissions(parent, perms)?;
            }
        }

        // Create YAML content for the new rule (safely)
        let mut rule_yaml = String::new();
        rule_yaml.push_str(&format!(
            "\n# Added by IPC client at {}\n",
            Utc::now().format("%Y-%m-%d %H:%M:%S UTC")
        ));
        rule_yaml.push_str(&format!("- path: \"{}\"\n", sanitized_path));
        rule_yaml.push_str(&format!("  file: \"{}\"\n", sanitized_file));

        // Add team_id constraint if available
        if let Some(ref team_id) = scope.team_id {
            let sanitized_team = Self::sanitize_yaml_string(team_id);
            rule_yaml.push_str(&format!("  team_id: \"{}\"\n", sanitized_team));
        }

        // Add signing_id constraint if available (and no team_id)
        if scope.team_id.is_none() {
            if let Some(ref signing_id) = scope.signing_id {
                let sanitized_signing = Self::sanitize_yaml_string(signing_id);
                rule_yaml.push_str(&format!("  signing_id: \"{}\"\n", sanitized_signing));
            }
        }

        // Add parent_path constraint if available
        if let Some(ref parent_path) = scope.parent_path {
            let sanitized_parent = Self::sanitize_yaml_string(parent_path);
            rule_yaml.push_str(&format!("  parent_path: \"{}\"\n", sanitized_parent));
        }

        // Add parent_team_id constraint if available
        if let Some(ref parent_team_id) = scope.parent_team_id {
            let sanitized_parent_team = Self::sanitize_yaml_string(parent_team_id);
            rule_yaml.push_str(&format!(
                "  parent_team_id: \"{}\"\n",
                sanitized_parent_team
            ));
        }

        if let Some(ref args) = scope.process_args {
            // Sanitize each argument
            let sanitized_args: Vec<String> = args
                .iter()
                .map(|arg| Self::sanitize_yaml_string(arg))
                .collect();
            rule_yaml.push_str(&format!("  args: {:?}\n", sanitized_args));
        }

        if let Some(ref comment) = scope.comment {
            let sanitized_comment = Self::sanitize_yaml_string(comment)
                .chars()
                .take(200) // Limit comment length
                .collect::<String>();
            rule_yaml.push_str(&format!("  # {}\n", sanitized_comment));
        }

        // Append to file with secure permissions
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&config_path)?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let metadata = file.metadata()?;
            let mut perms = metadata.permissions();
            perms.set_mode(0o644); // rw-r--r--
            fs::set_permissions(&config_path, perms)?;
        }

        file.write_all(rule_yaml.as_bytes())?;
        file.flush()?;
        file.sync_all()?; // Ensure data is written to disk

        Ok(())
    }

    /// Sanitize strings for safe YAML inclusion
    fn sanitize_yaml_string(input: &str) -> String {
        input
            .chars()
            .filter(|c| {
                // Allow only safe characters
                c.is_alphanumeric() || matches!(c, '/' | '\\' | '.' | '-' | '_' | ' ' | ':')
            })
            .take(1024) // Limit length
            .collect()
    }

    /// Add an event to the queue and history
    pub async fn add_event(&self, event: Event) -> Result<()> {
        // Add to queue
        self.event_queue.lock().await.push(event.clone());

        // Send through channel for streaming to subscribed clients
        // It's OK if no receivers are listening (broadcast channel behavior)
        let _ = self.event_sender.send(event.clone());

        // Add to history with size limit (prevent memory exhaustion)
        {
            let mut history = self.event_history.write().await;

            // Limit history size to prevent memory exhaustion
            const MAX_HISTORY_SIZE: usize = 10000;

            // If we're at the limit, remove old events
            if history.len() >= MAX_HISTORY_SIZE {
                // Remove events older than 24 hours
                let cutoff = Utc::now() - chrono::Duration::hours(24);
                history.retain(|_, e| e.timestamp > cutoff);

                // If still too many, remove oldest
                if history.len() >= MAX_HISTORY_SIZE {
                    let mut events: Vec<_> = history
                        .iter()
                        .map(|(id, e)| (id.clone(), e.timestamp))
                        .collect();
                    events.sort_by_key(|e| e.1);

                    // Remove oldest 10%
                    let remove_count = MAX_HISTORY_SIZE / 10;
                    for (id, _) in events.into_iter().take(remove_count) {
                        history.remove(&id);
                    }
                }
            }

            history.insert(event.id.clone(), event.clone());
        }

        // Send to subscribers
        self.event_sender.send(event)?;

        Ok(())
    }

    /// Clean up expired events and suspended processes
    pub async fn cleanup_expired(&self) {
        // Clean up suspended processes older than 1 hour
        let cutoff = Utc::now() - chrono::Duration::hours(1);

        let mut suspended = self.suspended_processes.write().await;
        suspended.retain(|_, process| process.timestamp > cutoff);

        // Clean up old events from history
        let mut history = self.event_history.write().await;
        history.retain(|_, event| event.timestamp > cutoff);
    }

    /// Register a suspended process
    pub async fn register_suspended_process(
        &self,
        event_id: String,
        process: SuspendedProcess,
    ) -> Result<()> {
        self.suspended_processes
            .write()
            .await
            .insert(event_id, process);
        Ok(())
    }

    /// Generate a unique event ID
    pub fn generate_event_id() -> String {
        Uuid::new_v4().to_string()
    }
}

impl Default for IpcServer {
    fn default() -> Self {
        Self::new(Arc::new(RwLock::new(Mode::Monitor))).expect("Failed to create IPC server")
    }
}
