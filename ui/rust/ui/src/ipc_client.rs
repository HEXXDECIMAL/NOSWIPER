//! IPC client for communication with NoSwiper daemon
//!
//! Provides Unix socket-based communication with the NoSwiper agent daemon.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

const SOCKET_PATH: &str = "/var/run/noswiper.sock";
const TIMEOUT: Duration = Duration::from_secs(5);

/// Entry in a process tree showing ancestry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessTreeEntry {
    pub pid: u32,
    pub ppid: Option<u32>,
    pub name: String,
    pub path: String,
    pub cmdline: Option<String>,
}

/// Event types from the agent
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
        action: String,
        process_tree: Option<Vec<ProcessTreeEntry>>,
    },
    #[serde(rename = "access_allowed")]
    AccessAllowed {
        rule_name: Option<String>,
        file_path: String,
        process_path: String,
        process_pid: u32,
        process_cmdline: Option<String>,
        process_euid: Option<u32>,
        process_tree: Option<Vec<ProcessTreeEntry>>,
    },
}

/// Event from the agent
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    pub id: String,
    pub timestamp: String,
    #[serde(flatten)]
    pub event_type: EventType,
}

/// Represents a security violation (simplified from Event)
#[derive(Debug, Clone)]
pub struct Violation {
    pub id: String,
    pub pid: u32,
    pub process_name: String,
    pub process_path: String,
    pub file_path: String,
    #[allow(dead_code)] // Will be used in future UI features
    pub timestamp: String,
    #[allow(dead_code)] // Will be used in future UI features
    pub action_taken: String,
}

/// Operating mode of the NoSwiper daemon
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum DaemonMode {
    Monitor,
    Enforce,
}

/// Current status of the NoSwiper daemon
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaemonStatus {
    pub mode: DaemonMode,
    pub running: bool,
    pub version: String,
    pub uptime_seconds: u64,
    pub violations_count: u64,
}

/// Client request types (matching agent's protocol)
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "action")]
pub enum ClientRequest {
    #[serde(rename = "subscribe")]
    Subscribe { filter: Option<serde_json::Value> },
    #[serde(rename = "allow_once")]
    AllowOnce { event_id: String },
    #[serde(rename = "allow_permanently")]
    AllowPermanently { event_id: String },
    #[serde(rename = "kill")]
    Kill { event_id: String },
    #[serde(rename = "status")]
    Status,
}

/// Response from the agent
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

/// Client for communicating with the NoSwiper daemon
pub struct IpcClient {
    socket_path: String,
}

impl IpcClient {
    pub fn new() -> Self {
        Self {
            socket_path: SOCKET_PATH.to_string(),
        }
    }

    /// Run comprehensive diagnostics and return detailed information
    pub fn diagnose_connection(&self) -> String {
        let mut report = Vec::new();
        let socket_path = Path::new(&self.socket_path);

        report.push(format!("=== NoSwiper Connection Diagnostics ==="));
        report.push(format!("Socket path: {}", self.socket_path));
        report.push(format!(
            "Current user: {}",
            std::env::var("USER").unwrap_or_else(|_| "unknown".to_string())
        ));
        report.push(String::new());

        // Check 1: Socket existence
        if !socket_path.exists() {
            report.push(format!("❌ Socket does NOT exist"));
            report.push(format!("   This means the daemon is not running."));
            report.push(format!(
                "   Solution: Run 'sudo noswiper-agent' to start the daemon"
            ));

            // Check if parent directory exists
            if let Some(parent) = socket_path.parent() {
                if !parent.exists() {
                    report.push(format!(
                        "   Note: Parent directory {} doesn't exist",
                        parent.display()
                    ));
                }
            }
        } else {
            report.push(format!("✓ Socket exists"));

            // Check 2: Socket metadata
            match std::fs::metadata(socket_path) {
                Ok(metadata) => {
                    report.push(format!("✓ Can read socket metadata"));
                    report.push(format!("   Permissions: {:?}", metadata.permissions()));

                    // Check 3: Connection attempt
                    match UnixStream::connect(socket_path) {
                        Ok(mut stream) => {
                            report.push(format!("✓ Successfully connected to socket"));

                            // Check 4: Try a status request
                            stream.set_read_timeout(Some(Duration::from_secs(2))).ok();
                            stream.set_write_timeout(Some(Duration::from_secs(2))).ok();

                            let request = ClientRequest::Status;
                            let request_json = serde_json::to_string(&request).unwrap() + "\n";

                            match stream.write_all(request_json.as_bytes()) {
                                Ok(_) => {
                                    let _ = stream.flush();
                                    report.push(format!("✓ Sent status request"));

                                    use std::io::BufRead;
                                    let reader = std::io::BufReader::new(&stream);
                                    let mut lines = reader.lines();

                                    if let Some(Ok(line)) = lines.next() {
                                        match serde_json::from_str::<ClientResponse>(&line) {
                                            Ok(ClientResponse::Status {
                                                mode,
                                                events_pending,
                                                connected_clients,
                                            }) => {
                                                report.push(format!("✓ Daemon is responding"));
                                                report.push(format!("   Mode: {}", mode));
                                                report.push(format!(
                                                    "   Pending events: {}",
                                                    events_pending
                                                ));
                                                report.push(format!(
                                                    "   Connected clients: {}",
                                                    connected_clients
                                                ));
                                            }
                                            Ok(other) => {
                                                report.push(format!(
                                                    "⚠️  Unexpected response: {:?}",
                                                    other
                                                ));
                                            }
                                            Err(e) => {
                                                report.push(format!(
                                                    "❌ Invalid response format: {}",
                                                    e
                                                ));
                                                report.push(format!("   Raw response: {}", line));
                                            }
                                        }
                                    } else {
                                        report.push(format!("❌ No response from daemon"));
                                        report.push(format!(
                                            "   Daemon may not be implementing IPC correctly"
                                        ));
                                    }
                                }
                                Err(e) => {
                                    report.push(format!("❌ Failed to send request: {}", e));
                                }
                            }
                        }
                        Err(e) => {
                            report.push(format!("❌ Cannot connect to socket: {}", e));
                            report.push(format!("   Possible causes:"));
                            report.push(format!("   1. Daemon crashed but left socket file"));
                            report.push(format!(
                                "   2. Permission denied (try running UI as root for testing)"
                            ));
                            report.push(format!("   3. Daemon is not accepting connections"));
                            report.push(format!("   Solution: sudo killall noswiper-agent && sudo rm {} && sudo noswiper-agent",
                                self.socket_path));
                        }
                    }
                }
                Err(e) => {
                    report.push(format!("❌ Cannot read socket metadata: {}", e));
                    report.push(format!(
                        "   This is unusual - check file system permissions"
                    ));
                }
            }
        }

        report.push(String::new());
        report.push(format!("=== End Diagnostics ==="));

        report.join("\n")
    }

    fn send_request(&self, request: &ClientRequest) -> Result<ClientResponse> {
        let socket_path = Path::new(&self.socket_path);

        // Check if socket exists
        if !socket_path.exists() {
            return Err(anyhow::anyhow!(
                "NoSwiper daemon socket not found at {}. Is the daemon running?",
                self.socket_path
            ));
        }

        // Check socket permissions
        let metadata = std::fs::metadata(socket_path).context(format!(
            "Cannot read socket metadata at {}",
            self.socket_path
        ))?;

        // Connect to socket
        let mut stream = UnixStream::connect(socket_path).with_context(|| {
            format!(
                "Failed to connect to NoSwiper daemon at {}. \
                     Socket exists but connection failed. \
                     Check if daemon is listening and you have permissions. \
                     Socket permissions: {:?}",
                self.socket_path,
                metadata.permissions()
            )
        })?;

        stream.set_read_timeout(Some(TIMEOUT))?;
        stream.set_write_timeout(Some(TIMEOUT))?;

        // Send request as newline-delimited JSON (matching agent's protocol)
        let request_json = serde_json::to_string(request)? + "\n";
        stream.write_all(request_json.as_bytes())?;
        stream.flush()?;

        // Read response (newline-delimited)
        use std::io::BufRead;
        let reader = std::io::BufReader::new(&stream);
        let mut lines = reader.lines();

        if let Some(Ok(line)) = lines.next() {
            let response: ClientResponse = serde_json::from_str(&line)?;
            Ok(response)
        } else {
            Err(anyhow::anyhow!("No response from daemon"))
        }
    }

    pub fn get_status(&self) -> Result<DaemonStatus> {
        match self.send_request(&ClientRequest::Status)? {
            ClientResponse::Status {
                mode,
                events_pending,
                connected_clients: _,
            } => {
                Ok(DaemonStatus {
                    mode: match mode.as_str() {
                        "enforce" => DaemonMode::Enforce,
                        _ => DaemonMode::Monitor,
                    },
                    running: true,
                    version: "0.1.0".to_string(),
                    uptime_seconds: 0, // Not provided by agent
                    violations_count: events_pending as u64,
                })
            }
            ClientResponse::Error { message } => {
                Err(anyhow::anyhow!("Failed to get status: {}", message))
            }
            _ => Err(anyhow::anyhow!("Unexpected response type")),
        }
    }

    pub fn set_mode(&self, mode: DaemonMode) -> Result<()> {
        let socket_path = Path::new(&self.socket_path);

        if !socket_path.exists() {
            return Err(anyhow::anyhow!(
                "Socket does not exist at {}",
                self.socket_path
            ));
        }

        let mut stream =
            UnixStream::connect(&self.socket_path).context("Failed to connect to agent socket")?;

        let mode_str = match mode {
            DaemonMode::Monitor => "monitor",
            DaemonMode::Enforce => "enforce",
        };

        let request = json!({
            "action": "set_mode",
            "mode": mode_str
        });

        writeln!(stream, "{}", request)?;
        stream.flush()?;

        let mut reader = BufReader::new(&stream);
        let mut response_line = String::new();
        reader.read_line(&mut response_line)?;

        let response: serde_json::Value = serde_json::from_str(&response_line)?;

        if response["status"] == "success" {
            Ok(())
        } else {
            let error_msg = response["message"].as_str().unwrap_or("Unknown error");
            Err(anyhow::anyhow!("Failed to set mode: {}", error_msg))
        }
    }

    /// Get the current enforcement mode from the daemon
    pub fn get_mode(&self) -> Result<DaemonMode> {
        let socket_path = Path::new(&self.socket_path);

        if !socket_path.exists() {
            return Err(anyhow::anyhow!(
                "Socket does not exist at {}",
                self.socket_path
            ));
        }

        let mut stream =
            UnixStream::connect(&self.socket_path).context("Failed to connect to agent socket")?;

        let request = json!({
            "action": "get_mode"
        });

        writeln!(stream, "{}", request)?;
        stream.flush()?;

        let mut reader = BufReader::new(&stream);
        let mut response_line = String::new();
        reader.read_line(&mut response_line)?;

        let response: serde_json::Value = serde_json::from_str(&response_line)?;

        if response["status"] == "success" {
            let mode_str = response["message"].as_str().unwrap_or("monitor");
            match mode_str {
                "enforce" => Ok(DaemonMode::Enforce),
                _ => Ok(DaemonMode::Monitor),
            }
        } else {
            // Default to monitor mode if we can't get the mode
            Ok(DaemonMode::Monitor)
        }
    }

    /// Get recent violations from the daemon
    pub fn get_violations(&self, limit: Option<usize>) -> Result<Vec<Event>> {
        let socket_path = Path::new(&self.socket_path);

        if !socket_path.exists() {
            return Err(anyhow::anyhow!(
                "Socket does not exist at {}",
                self.socket_path
            ));
        }

        let mut stream =
            UnixStream::connect(&self.socket_path).context("Failed to connect to agent socket")?;

        stream.set_read_timeout(Some(TIMEOUT))?;
        stream.set_write_timeout(Some(TIMEOUT))?;

        let mut request = json!({
            "action": "get_violations"
        });

        if let Some(limit) = limit {
            request["limit"] = json!(limit);
        }

        writeln!(stream, "{}", request)?;
        stream.flush()?;

        let mut reader = BufReader::new(&stream);
        let mut response_line = String::new();
        reader.read_line(&mut response_line)?;

        let response: serde_json::Value = serde_json::from_str(&response_line)?;

        if response["status"] == "violations" {
            if let Some(events) = response["events"].as_array() {
                let violations: Vec<Event> = events
                    .iter()
                    .filter_map(|e| serde_json::from_value(e.clone()).ok())
                    .collect();
                Ok(violations)
            } else {
                Ok(Vec::new())
            }
        } else {
            let error_msg = response["message"].as_str().unwrap_or("Unknown error");
            Err(anyhow::anyhow!("Failed to get violations: {}", error_msg))
        }
    }

    /// Subscribe to events and return a stream reader
    pub fn subscribe_to_events(&self) -> Result<std::io::BufReader<UnixStream>> {
        let socket_path = Path::new(&self.socket_path);

        if !socket_path.exists() {
            return Err(anyhow::anyhow!(
                "NoSwiper daemon socket not found at {}.\n\
                 Possible causes:\n\
                 1. The daemon is not running (run: sudo noswiper-agent)\n\
                 2. The daemon is using a different socket path\n\
                 3. The socket was deleted",
                self.socket_path
            ));
        }

        // Check socket permissions before connecting
        let metadata = std::fs::metadata(socket_path).context(format!(
            "Cannot read socket metadata at {}",
            self.socket_path
        ))?;

        let mut stream = UnixStream::connect(socket_path).with_context(|| {
            format!(
                "Failed to connect to NoSwiper daemon at {}.\n\
                 Socket exists but connection failed.\n\
                 Possible causes:\n\
                 1. Permission denied (current user: {})\n\
                 2. Daemon is not accepting connections\n\
                 3. Socket is stale (daemon crashed)\n\
                 Socket permissions: {:?}\n\
                 Try: sudo killall noswiper-agent && sudo noswiper-agent",
                self.socket_path,
                std::env::var("USER").unwrap_or_else(|_| "unknown".to_string()),
                metadata.permissions()
            )
        })?;

        stream.set_read_timeout(Some(TIMEOUT))?;
        stream.set_write_timeout(Some(TIMEOUT))?;

        // Send subscribe request
        let request = ClientRequest::Subscribe { filter: None };
        let request_json = serde_json::to_string(&request)? + "\n";
        stream.write_all(request_json.as_bytes())?;
        stream.flush()?;

        // Return the stream reader for continuous event reading
        Ok(std::io::BufReader::new(stream))
    }

    pub fn continue_process(&self, event_id: &str) -> Result<()> {
        match self.send_request(&ClientRequest::AllowOnce {
            event_id: event_id.to_string(),
        })? {
            ClientResponse::Success { .. } => Ok(()),
            ClientResponse::Error { message } => {
                Err(anyhow::anyhow!("Failed to continue process: {}", message))
            }
            _ => Err(anyhow::anyhow!("Unexpected response type")),
        }
    }

    #[allow(dead_code)] // Will be used when interactive mode is implemented
    pub fn kill_process(&self, event_id: &str) -> Result<()> {
        match self.send_request(&ClientRequest::Kill {
            event_id: event_id.to_string(),
        })? {
            ClientResponse::Success { .. } => Ok(()),
            ClientResponse::Error { message } => {
                Err(anyhow::anyhow!("Failed to kill process: {}", message))
            }
            _ => Err(anyhow::anyhow!("Unexpected response type")),
        }
    }

    #[allow(dead_code)] // Will be used for permanent allow list management
    pub fn add_to_whitelist(&self, event_id: &str) -> Result<()> {
        match self.send_request(&ClientRequest::AllowPermanently {
            event_id: event_id.to_string(),
        })? {
            ClientResponse::Success { .. } => Ok(()),
            ClientResponse::Error { message } => {
                Err(anyhow::anyhow!("Failed to add to whitelist: {}", message))
            }
            _ => Err(anyhow::anyhow!("Unexpected response type")),
        }
    }

    #[allow(dead_code)] // Will be used for daemon control features
    pub fn stop_daemon(&self) -> Result<()> {
        // Note: The current agent doesn't support stop via IPC
        Err(anyhow::anyhow!("Stop command not supported via IPC"))
    }
}
