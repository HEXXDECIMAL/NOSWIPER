//! Type safety improvements for NoSwiper.
//!
//! This module provides newtypes and type-safe wrappers around common primitives
//! to prevent type confusion and improve API clarity.

use serde::{Deserialize, Serialize};
use std::fmt;
use std::path::{Path, PathBuf};

/// A process identifier with type safety.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ProcessId(pub u32);

impl ProcessId {
    /// Create a new ProcessId.
    pub fn new(pid: u32) -> Self {
        Self(pid)
    }

    /// Get the raw PID value.
    pub fn as_u32(&self) -> u32 {
        self.0
    }
}

impl fmt::Display for ProcessId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<u32> for ProcessId {
    fn from(pid: u32) -> Self {
        Self(pid)
    }
}

impl From<ProcessId> for u32 {
    fn from(pid: ProcessId) -> Self {
        pid.0
    }
}

/// A user identifier with type safety.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct UserId(pub u32);

impl UserId {
    /// Create a new UserId.
    pub fn new(uid: u32) -> Self {
        Self(uid)
    }

    /// Get the raw UID value.
    pub fn as_u32(&self) -> u32 {
        self.0
    }
}

impl fmt::Display for UserId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<u32> for UserId {
    fn from(uid: u32) -> Self {
        Self(uid)
    }
}

impl From<UserId> for u32 {
    fn from(uid: UserId) -> Self {
        uid.0
    }
}

/// An event identifier for tracking security events.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EventId(String);

impl EventId {
    /// Create a new EventId.
    pub fn new(id: String) -> Self {
        Self(id)
    }

    /// Generate a new random EventId.
    pub fn generate() -> Self {
        Self(uuid::Uuid::new_v4().to_string())
    }

    /// Get the raw string value.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for EventId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<String> for EventId {
    fn from(id: String) -> Self {
        Self(id)
    }
}

impl From<EventId> for String {
    fn from(id: EventId) -> Self {
        id.0
    }
}

/// A rule name for identifying which protection rule was triggered.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RuleName(String);

impl RuleName {
    /// Create a new RuleName.
    pub fn new(name: String) -> Self {
        Self(name)
    }

    /// Get the raw string value.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for RuleName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<String> for RuleName {
    fn from(name: String) -> Self {
        Self(name)
    }
}

impl From<&str> for RuleName {
    fn from(name: &str) -> Self {
        Self(name.to_string())
    }
}

impl From<RuleName> for String {
    fn from(name: RuleName) -> Self {
        name.0
    }
}

/// A team identifier for code signing validation.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TeamId(String);

impl TeamId {
    /// Create a new TeamId.
    pub fn new(id: String) -> Self {
        Self(id)
    }

    /// Get the raw string value.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for TeamId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<String> for TeamId {
    fn from(id: String) -> Self {
        Self(id)
    }
}

impl From<&str> for TeamId {
    fn from(id: &str) -> Self {
        Self(id.to_string())
    }
}

impl From<TeamId> for String {
    fn from(id: TeamId) -> Self {
        id.0
    }
}

/// A file path with enhanced semantics for protected files.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ProtectedFilePath(PathBuf);

impl ProtectedFilePath {
    /// Create a new ProtectedFilePath.
    pub fn new(path: PathBuf) -> Self {
        Self(path)
    }

    /// Get the underlying PathBuf.
    pub fn as_path(&self) -> &Path {
        &self.0
    }

    /// Get the underlying PathBuf by value.
    pub fn into_path_buf(self) -> PathBuf {
        self.0
    }

    /// Check if this path exists on the filesystem.
    pub fn exists(&self) -> bool {
        self.0.exists()
    }

    /// Get the file name component.
    pub fn file_name(&self) -> Option<&std::ffi::OsStr> {
        self.0.file_name()
    }

    /// Get the parent directory.
    pub fn parent(&self) -> Option<&Path> {
        self.0.parent()
    }
}

impl fmt::Display for ProtectedFilePath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0.display())
    }
}

impl From<PathBuf> for ProtectedFilePath {
    fn from(path: PathBuf) -> Self {
        Self(path)
    }
}

impl From<&Path> for ProtectedFilePath {
    fn from(path: &Path) -> Self {
        Self(path.to_path_buf())
    }
}

impl From<ProtectedFilePath> for PathBuf {
    fn from(path: ProtectedFilePath) -> Self {
        path.0
    }
}

impl AsRef<Path> for ProtectedFilePath {
    fn as_ref(&self) -> &Path {
        &self.0
    }
}

/// Parameters for handling exec events with protected paths.
///
/// This struct groups related parameters to reduce function argument counts.
#[derive(Debug, Clone)]
pub struct ExecEvent {
    pub process_path: PathBuf,
    pub args: Vec<String>,
    pub protected_path: ProtectedFilePath,
    pub process_id: Option<ProcessId>,
    pub parent_process_id: Option<ProcessId>,
    pub effective_user_id: Option<UserId>,
    pub signing_info: Option<String>,
}

impl ExecEvent {
    /// Create a new ExecEvent.
    pub fn new(
        process_path: PathBuf,
        args: Vec<String>,
        protected_path: PathBuf,
        process_id: Option<u32>,
        parent_process_id: Option<u32>,
        effective_user_id: Option<u32>,
        signing_info: Option<String>,
    ) -> Self {
        Self {
            process_path,
            args,
            protected_path: ProtectedFilePath::new(protected_path),
            process_id: process_id.map(ProcessId::new),
            parent_process_id: parent_process_id.map(ProcessId::new),
            effective_user_id: effective_user_id.map(UserId::new),
            signing_info,
        }
    }

    /// Get the process ID as Option<u32>.
    pub fn pid(&self) -> Option<u32> {
        self.process_id.map(|p| p.as_u32())
    }

    /// Get the parent process ID as Option<u32>.
    pub fn ppid(&self) -> Option<u32> {
        self.parent_process_id.map(|p| p.as_u32())
    }

    /// Get the effective user ID as Option<u32>.
    pub fn euid(&self) -> Option<u32> {
        self.effective_user_id.map(|u| u.as_u32())
    }
}
