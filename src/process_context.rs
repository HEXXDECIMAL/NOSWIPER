use std::path::PathBuf;

/// Context information about a process
#[derive(Debug, Clone)]
#[allow(dead_code)]  // Will be used when monitor is updated
pub struct ProcessContext {
    /// Full path to the process executable
    pub path: PathBuf,

    /// Process ID
    pub pid: Option<u32>,

    /// Parent process ID
    pub ppid: Option<u32>,

    /// Apple Team ID (secure, assigned by Apple)
    pub team_id: Option<String>,

    /// App ID / Bundle ID (can be set by developer, less secure)
    pub app_id: Option<String>,

    /// Command-line arguments
    pub args: Option<Vec<String>>,

    /// User ID
    pub uid: Option<u32>,
}

impl ProcessContext {
    /// Create a new process context
    #[allow(dead_code)]
    pub fn new(path: PathBuf) -> Self {
        Self {
            path,
            pid: None,
            ppid: None,
            team_id: None,
            app_id: None,
            args: None,
            uid: None,
        }
    }

    /// Set PID
    #[allow(dead_code)] pub fn with_pid(mut self, pid: u32) -> Self {
        self.pid = Some(pid);
        self
    }

    /// Set PPID
    #[allow(dead_code)] pub fn with_ppid(mut self, ppid: u32) -> Self {
        self.ppid = Some(ppid);
        self
    }

    /// Set team ID
    #[allow(dead_code)] pub fn with_team_id(mut self, team_id: impl Into<String>) -> Self {
        self.team_id = Some(team_id.into());
        self
    }

    /// Set app ID
    #[allow(dead_code)] pub fn with_app_id(mut self, app_id: impl Into<String>) -> Self {
        self.app_id = Some(app_id.into());
        self
    }

    /// Set args
    #[allow(dead_code)] pub fn with_args(mut self, args: Vec<String>) -> Self {
        self.args = Some(args);
        self
    }

    /// Set UID
    #[allow(dead_code)] pub fn with_uid(mut self, uid: u32) -> Self {
        self.uid = Some(uid);
        self
    }

}