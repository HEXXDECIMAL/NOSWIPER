//! Process context information and utilities for system process identification.
//!
//! This module provides the [`ProcessContext`] type which encapsulates all relevant
//! information about a process that might be accessing protected files.

use std::path::PathBuf;

/// Context information about a process attempting to access protected files.
///
/// This type serves as the primary data structure for process identification
/// and authorization decisions. It contains both required and optional fields
/// to support various platforms and monitoring mechanisms.
#[derive(Debug, Clone, PartialEq, Eq)]
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

    /// Effective User ID
    pub euid: Option<u32>,

    /// Whether this is an Apple platform binary
    pub platform_binary: Option<bool>,
}

impl ProcessContext {
    /// Creates a new process context with the specified executable path.
    ///
    /// All optional fields are initialized to `None` and can be set using
    /// the builder pattern methods.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use std::path::PathBuf;
    /// use noswiper::process_context::ProcessContext;
    ///
    /// let context = ProcessContext::new(PathBuf::from("/usr/bin/ssh"))
    ///     .with_pid(1234)
    ///     .with_uid(501);
    /// ```
    #[allow(dead_code)] // Public API, used in tests and by monitors
    pub fn new(path: PathBuf) -> Self {
        Self {
            path,
            pid: None,
            ppid: None,
            team_id: None,
            app_id: None,
            args: None,
            uid: None,
            euid: None,
            platform_binary: None,
        }
    }

    /// Sets the process ID for this context.
    #[allow(dead_code)] // Public API, used in tests and by monitors
    pub fn with_pid(mut self, pid: u32) -> Self {
        self.pid = Some(pid);
        self
    }

    /// Sets the parent process ID for this context.
    #[allow(dead_code)] // Public API, used in tests and by monitors
    pub fn with_ppid(mut self, ppid: u32) -> Self {
        self.ppid = Some(ppid);
        self
    }

    /// Sets the Apple Team ID for this context (macOS only).
    ///
    /// The Team ID is a secure identifier assigned by Apple that cannot be spoofed,
    /// making it highly reliable for application identification.
    #[allow(dead_code)] // Public API, used in tests and by monitors
    pub fn with_team_id(mut self, team_id: impl Into<String>) -> Self {
        self.team_id = Some(team_id.into());
        self
    }

    /// Sets the application/bundle ID for this context.
    ///
    /// Note: Application IDs can be set by developers and may be less secure
    /// than Team IDs for authorization decisions.
    #[allow(dead_code)] // Public API, used in tests and by monitors
    pub fn with_app_id(mut self, app_id: impl Into<String>) -> Self {
        self.app_id = Some(app_id.into());
        self
    }

    /// Sets the command-line arguments for this context.
    #[allow(dead_code)] // Public API, used in tests and by monitors
    pub fn with_args(mut self, args: Vec<String>) -> Self {
        self.args = Some(args);
        self
    }

    /// Sets the user ID for this context.
    #[allow(dead_code)] // Public API, used in tests and by monitors
    pub fn with_uid(mut self, uid: u32) -> Self {
        self.uid = Some(uid);
        self
    }

    /// Sets the effective user ID for this context.
    #[allow(dead_code)] // Public API, used in tests and by monitors
    pub fn with_euid(mut self, euid: u32) -> Self {
        self.euid = Some(euid);
        self
    }

    /// Sets whether this is a platform binary.
    #[allow(dead_code)] // Public API, used in tests and by monitors
    pub fn with_platform_binary(mut self, platform_binary: bool) -> Self {
        self.platform_binary = Some(platform_binary);
        self
    }
}

/// Retrieves the home directory path for a given user ID.
///
/// This function safely queries the system's user database to find the home
/// directory associated with the specified UID. On Unix systems, it uses
/// the `getpwuid` system call with proper error handling.
///
/// # Arguments
///
/// * `uid` - The user ID to look up
///
/// # Returns
///
/// * `Some(PathBuf)` - The home directory path if found
/// * `None` - If the user doesn't exist or has no home directory
///
/// # Safety
///
/// This function uses unsafe code internally but provides a safe interface.
/// All unsafe operations are properly bounds-checked and error-handled.
pub fn get_home_for_uid(uid: u32) -> Option<PathBuf> {
    #[cfg(unix)]
    {
        use std::ffi::CStr;
        use std::os::unix::ffi::OsStringExt;

        // SAFETY: getpwuid is thread-safe and we check all returned pointers
        unsafe {
            let pwd = libc::getpwuid(uid);
            if pwd.is_null() {
                return None;
            }

            let home_dir = (*pwd).pw_dir;
            if home_dir.is_null() {
                return None;
            }

            // SAFETY: pw_dir is guaranteed to be a valid C string by getpwuid
            let home_cstr = CStr::from_ptr(home_dir);
            let home_bytes = home_cstr.to_bytes();
            let home_osstring = std::ffi::OsString::from_vec(home_bytes.to_vec());
            Some(PathBuf::from(home_osstring))
        }
    }

    #[cfg(not(unix))]
    {
        // Home directory lookup not implemented for non-Unix platforms
        None
    }
}
