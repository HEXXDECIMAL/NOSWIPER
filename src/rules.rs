use crate::defaults::{
    build_protection_rules, is_excluded_path, LINUX_COMMON_PATHS, MACOS_COMMON_PATHS,
};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, PartialEq)]
pub enum Decision {
    Allow,
    Deny,
}

#[derive(Clone)]
pub struct RuleEngine {
    // Pattern -> allowed programs
    protection_rules: HashMap<String, Vec<String>>,
    // Runtime exceptions (process_path, file_path) -> expires_at
    runtime_exceptions: HashMap<(PathBuf, PathBuf), Option<Instant>>,
}

impl RuleEngine {
    pub fn new() -> Self {
        Self {
            protection_rules: build_protection_rules(),
            runtime_exceptions: HashMap::new(),
        }
    }

    /// Check if a file path should be protected
    pub fn is_protected_file(&self, file_path: &Path) -> bool {
        let file_str = file_path.to_string_lossy();

        // First check if it's explicitly excluded
        if is_excluded_path(&file_str) {
            return false;
        }

        // Check if any protection pattern matches
        for pattern_str in self.protection_rules.keys() {
            if let Ok(pattern) = glob::Pattern::new(pattern_str) {
                if pattern.matches_path(file_path) {
                    return true;
                }
            }
        }

        false
    }

    /// Check if a process is allowed to access a file
    pub fn check_access(&self, process_path: &Path, file_path: &Path) -> Decision {
        // First check runtime exceptions
        let exception_key = (process_path.to_path_buf(), file_path.to_path_buf());
        if let Some(expires_at) = self.runtime_exceptions.get(&exception_key) {
            if expires_at.is_none_or(|exp| Instant::now() < exp) {
                log::debug!("Access allowed by runtime exception");
                return Decision::Allow;
            }
        }

        // Find the protection rule that matches this file
        for (pattern_str, allowed_programs) in &self.protection_rules {
            if let Ok(pattern) = glob::Pattern::new(pattern_str) {
                if pattern.matches_path(file_path) {
                    return self.check_process_allowed(process_path, allowed_programs);
                }
            }
        }

        // If no pattern matched, allow by default
        Decision::Allow
    }

    fn check_process_allowed(&self, process_path: &Path, allowed_programs: &[String]) -> Decision {
        // Get the process name
        let process_name = process_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("");

        // Check if the process name matches any allowed program
        for allowed_program in allowed_programs {
            if process_name.contains(allowed_program) {
                // Additional verification based on platform
                if self.verify_process_legitimacy(process_path, allowed_program) {
                    log::debug!(
                        "Process {} allowed for program {}",
                        process_path.display(),
                        allowed_program
                    );
                    return Decision::Allow;
                }
            }
        }

        log::debug!(
            "Process {} not in allowed programs: {:?}",
            process_path.display(),
            allowed_programs
        );
        Decision::Deny
    }

    fn verify_process_legitimacy(&self, process_path: &Path, _program_name: &str) -> bool {
        // Resolve symlinks to get the real path
        let real_path = match process_path.canonicalize() {
            Ok(p) => p,
            Err(_) => {
                // On Linux, /proc/PID/exe might point to deleted files
                // In that case, use the original path
                #[cfg(target_os = "linux")]
                {
                    if process_path.to_string_lossy().contains("(deleted)") {
                        log::warn!(
                            "Process executable has been deleted: {}",
                            process_path.display()
                        );
                        return false;
                    }
                }
                log::warn!("Cannot resolve path: {}", process_path.display());
                return false;
            }
        };

        // Check if the process is in a legitimate location
        self.is_in_allowed_paths(&real_path)
    }

    fn is_in_allowed_paths(&self, process_path: &Path) -> bool {
        let path_str = process_path.to_string_lossy();

        let allowed_paths = if cfg!(target_os = "macos") {
            MACOS_COMMON_PATHS
        } else if cfg!(target_os = "linux") {
            LINUX_COMMON_PATHS
        } else {
            // For other platforms, be more restrictive
            &["/usr/bin/*", "/bin/*"]
        };

        for allowed_pattern in allowed_paths {
            if let Ok(pattern) = glob::Pattern::new(allowed_pattern) {
                if pattern.matches(&path_str) {
                    log::debug!(
                        "Process path {} matches allowed pattern {}",
                        path_str,
                        allowed_pattern
                    );
                    return true;
                }
            }
        }

        // Additional verification for macOS code signatures
        #[cfg(target_os = "macos")]
        {
            if self.verify_macos_signature(process_path) {
                log::debug!(
                    "Process {} verified by code signature",
                    process_path.display()
                );
                return true;
            }
        }

        // Additional verification for Linux - check if it's a system package
        #[cfg(target_os = "linux")]
        {
            if self.verify_linux_package(process_path) {
                log::debug!(
                    "Process {} verified as system package",
                    process_path.display()
                );
                return true;
            }
        }

        log::debug!("Process path {} not in allowed paths", path_str);
        false
    }

    #[cfg(target_os = "macos")]
    fn verify_macos_signature(&self, process_path: &Path) -> bool {
        use std::process::Command;

        // Try to verify the code signature
        match Command::new("codesign")
            .args(["--verify", "--strict", process_path.to_str().unwrap_or("")])
            .output()
        {
            Ok(output) => {
                if output.status.success() {
                    log::debug!("Code signature verified for {}", process_path.display());
                    true
                } else {
                    log::debug!(
                        "Code signature verification failed for {}",
                        process_path.display()
                    );
                    false
                }
            }
            Err(e) => {
                log::debug!("Failed to run codesign: {}", e);
                false
            }
        }
    }

    #[cfg(target_os = "linux")]
    fn verify_linux_package(&self, process_path: &Path) -> bool {
        use std::process::Command;

        // Check if the binary belongs to a system package
        // Try dpkg first (Debian/Ubuntu)
        if let Ok(output) = Command::new("dpkg")
            .args(&["-S", process_path.to_str().unwrap_or("")])
            .output()
        {
            if output.status.success() {
                log::debug!(
                    "Process {} verified as dpkg package",
                    process_path.display()
                );
                return true;
            }
        }

        // Try rpm (Red Hat/Fedora)
        if let Ok(output) = Command::new("rpm")
            .args(&["-qf", process_path.to_str().unwrap_or("")])
            .output()
        {
            if output.status.success() {
                log::debug!("Process {} verified as rpm package", process_path.display());
                return true;
            }
        }

        // Check if it's in a system directory even if not in a package
        let system_dirs = ["/usr/bin", "/bin", "/usr/sbin", "/sbin"];
        let path_str = process_path.to_string_lossy();
        for dir in &system_dirs {
            if path_str.starts_with(dir) {
                log::debug!(
                    "Process {} in system directory {}",
                    process_path.display(),
                    dir
                );
                return true;
            }
        }

        false
    }

    /// Add a runtime exception (temporary allow)
    pub fn add_runtime_exception(&mut self, process_path: PathBuf, file_path: PathBuf) {
        self.add_runtime_exception_with_duration(process_path, file_path, None);
    }

    /// Add a runtime exception with duration
    pub fn add_runtime_exception_with_duration(
        &mut self,
        process_path: PathBuf,
        file_path: PathBuf,
        duration: Option<Duration>,
    ) {
        let expires_at = duration.map(|d| Instant::now() + d);
        let key = (process_path.clone(), file_path.clone());

        self.runtime_exceptions.insert(key, expires_at);

        log::info!(
            "Added runtime exception: {} can access {} {}",
            process_path.display(),
            file_path.display(),
            if let Some(dur) = duration {
                format!("for {:?}", dur)
            } else {
                "permanently".to_string()
            }
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_ssh_key_protection() {
        let engine = RuleEngine::new();

        // Use shellexpand to match how the actual code works
        let ssh_key = PathBuf::from(shellexpand::tilde("~/.ssh/id_rsa").to_string());
        assert!(engine.is_protected_file(&ssh_key));

        // Public key should not be protected
        let pub_key = PathBuf::from(shellexpand::tilde("~/.ssh/id_rsa.pub").to_string());
        assert!(!engine.is_protected_file(&pub_key));
    }

    #[test]
    fn test_ssh_access_allowed() {
        let engine = RuleEngine::new();

        let ssh_key = PathBuf::from(shellexpand::tilde("~/.ssh/id_rsa").to_string());
        let ssh_binary = PathBuf::from("/usr/bin/ssh");

        // This would normally check if /usr/bin/ssh is legitimate
        // In a real test environment, we'd mock this
        let decision = engine.check_access(&ssh_binary, &ssh_key);

        // SSH should be allowed to access SSH keys (if in legitimate location)
        if engine.is_in_allowed_paths(&ssh_binary) {
            assert_eq!(decision, Decision::Allow);
        }
    }

    #[test]
    fn test_unknown_binary_blocked() {
        let engine = RuleEngine::new();

        let ssh_key = PathBuf::from(shellexpand::tilde("~/.ssh/id_rsa").to_string());
        let malware = PathBuf::from("/tmp/malware");

        // Check if this is a protected file first
        if engine.is_protected_file(&ssh_key) {
            let decision = engine.check_access(&malware, &ssh_key);
            assert_eq!(decision, Decision::Deny);
        } else {
            // If not protected, it would be allowed
            let decision = engine.check_access(&malware, &ssh_key);
            assert_eq!(decision, Decision::Allow);
        }
    }

    #[test]
    fn test_runtime_exception() {
        let mut engine = RuleEngine::new();

        let ssh_key = PathBuf::from(shellexpand::tilde("~/.ssh/id_rsa").to_string());
        let custom_tool = PathBuf::from("/tmp/backup-tool");

        // Should be denied initially if this is a protected file
        if engine.is_protected_file(&ssh_key) {
            let decision = engine.check_access(&custom_tool, &ssh_key);
            assert_eq!(decision, Decision::Deny);

            // Add runtime exception
            engine.add_runtime_exception(custom_tool.clone(), ssh_key.clone());

            // Should be allowed now
            let decision = engine.check_access(&custom_tool, &ssh_key);
            assert_eq!(decision, Decision::Allow);
        } else {
            // If the file isn't protected, test a different scenario
            // Use a hardcoded path we know will be protected
            let protected_file = PathBuf::from(shellexpand::tilde("~/.ssh/id_ed25519").to_string());
            if engine.is_protected_file(&protected_file) {
                let decision = engine.check_access(&custom_tool, &protected_file);
                assert_eq!(decision, Decision::Deny);

                engine.add_runtime_exception(custom_tool.clone(), protected_file.clone());

                let decision = engine.check_access(&custom_tool, &protected_file);
                assert_eq!(decision, Decision::Allow);
            }
        }
    }
}
