//! IPC client for communication with NoSwiper daemon
//!
//! Provides Unix socket-based communication with the NoSwiper agent daemon.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

const SOCKET_PATH: &str = "/var/run/noswiper.sock";
const TIMEOUT: Duration = Duration::from_secs(5);

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
    },
    #[serde(rename = "access_allowed")]
    AccessAllowed {
        rule_name: Option<String>,
        file_path: String,
        process_path: String,
        process_pid: u32,
        process_cmdline: Option<String>,
        process_euid: Option<u32>,
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
    pub timestamp: String,
    pub action_taken: String,
}

/// Operating mode of the NoSwiper daemon
#[derive(Debug, Clone, Serialize, Deserialize)]
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


    fn send_request(&self, request: &ClientRequest) -> Result<ClientResponse> {
        let socket_path = Path::new(&self.socket_path);

        if !socket_path.exists() {
            return Err(anyhow::anyhow!("NoSwiper daemon not running (socket not found)"));
        }

        let mut stream = UnixStream::connect(socket_path)
            .context("Failed to connect to NoSwiper daemon")?;

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
            ClientResponse::Status { mode, events_pending, connected_clients: _ } => {
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
            _ => Err(anyhow::anyhow!("Unexpected response type"))
        }
    }

    pub fn set_mode(&self, _mode: DaemonMode) -> Result<()> {
        // Note: The current agent doesn't support mode changes via IPC
        // This would need to be implemented in the agent
        Err(anyhow::anyhow!("Mode changes not yet supported via IPC"))
    }

    pub fn get_violations(&self, _limit: usize) -> Result<Vec<Violation>> {
        // Subscribe to events and collect violations
        // For now, we'll need to maintain a separate connection for streaming
        // This is a temporary implementation until we refactor to use streaming
        Ok(Vec::new())
    }

    /// Subscribe to events and return a stream reader
    pub fn subscribe_to_events(&self) -> Result<std::io::BufReader<UnixStream>> {
        let socket_path = Path::new(&self.socket_path);

        if !socket_path.exists() {
            return Err(anyhow::anyhow!("NoSwiper daemon not running (socket not found)"));
        }

        let mut stream = UnixStream::connect(socket_path)
            .context("Failed to connect to NoSwiper daemon")?;

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
            event_id: event_id.to_string()
        })? {
            ClientResponse::Success { .. } => Ok(()),
            ClientResponse::Error { message } => {
                Err(anyhow::anyhow!("Failed to continue process: {}", message))
            }
            _ => Err(anyhow::anyhow!("Unexpected response type"))
        }
    }

    pub fn kill_process(&self, event_id: &str) -> Result<()> {
        match self.send_request(&ClientRequest::Kill {
            event_id: event_id.to_string()
        })? {
            ClientResponse::Success { .. } => Ok(()),
            ClientResponse::Error { message } => {
                Err(anyhow::anyhow!("Failed to kill process: {}", message))
            }
            _ => Err(anyhow::anyhow!("Unexpected response type"))
        }
    }

    pub fn add_to_whitelist(&self, event_id: &str) -> Result<()> {
        match self.send_request(&ClientRequest::AllowPermanently {
            event_id: event_id.to_string()
        })? {
            ClientResponse::Success { .. } => Ok(()),
            ClientResponse::Error { message } => {
                Err(anyhow::anyhow!("Failed to add to whitelist: {}", message))
            }
            _ => Err(anyhow::anyhow!("Unexpected response type"))
        }
    }

    pub fn stop_daemon(&self) -> Result<()> {
        // Note: The current agent doesn't support stop via IPC
        Err(anyhow::anyhow!("Stop command not supported via IPC"))
    }

}