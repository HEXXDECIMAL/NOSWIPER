use crate::defaults::{build_protection_rules, is_excluded_path, MACOS_COMMON_PATHS, LINUX_COMMON_PATHS};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, PartialEq)]
pub enum Decision {
    Allow,
    Deny,
}

pub struct RuleEngine {
    // Pattern -> allowed programs
    protection_rules: HashMap<String, Vec<String>>,
    // Runtime exceptions (process_path, file_path) -> expires_at
    runtime_exceptions: HashMap<(PathBuf, PathBuf), Option<Instant>>,
}

#[derive(Debug)]
struct RuntimeException {
    process_path: PathBuf,
    file_path: PathBuf,
    expires_at: Option<Instant>,
    added_by: String,
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
            if expires_at.map_or(true, |exp| Instant::now() < exp) {
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
                    log::debug!("Process path {} matches allowed pattern {}", path_str, allowed_pattern);
                    return true;
                }
            }
        }

        // Additional verification for macOS code signatures
        #[cfg(target_os = "macos")]
        {
            if self.verify_macos_signature(process_path) {
                log::debug!("Process {} verified by code signature", process_path.display());
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
            .args(&["--verify", "--strict", process_path.to_str().unwrap_or("")])
            .output()
        {
            Ok(output) => {
                if output.status.success() {
                    log::debug!("Code signature verified for {}", process_path.display());
                    true
                } else {
                    log::debug!("Code signature verification failed for {}", process_path.display());
                    false
                }
            }
            Err(e) => {
                log::debug!("Failed to run codesign: {}", e);
                false
            }
        }
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

    /// Clean up expired runtime exceptions
    pub fn cleanup_expired_exceptions(&mut self) {
        let now = Instant::now();
        self.runtime_exceptions.retain(|_key, expires_at| {
            expires_at.map_or(true, |exp| now < exp)
        });
    }

    /// Get statistics about the rule engine
    pub fn get_stats(&self) -> RuleStats {
        let active_exceptions = self.runtime_exceptions
            .values()
            .filter(|expires_at| expires_at.map_or(true, |exp| Instant::now() < exp))
            .count();

        RuleStats {
            protection_rules_count: self.protection_rules.len(),
            runtime_exceptions_count: self.runtime_exceptions.len(),
            active_exceptions_count: active_exceptions,
        }
    }
}

#[derive(Debug)]
pub struct RuleStats {
    pub protection_rules_count: usize,
    pub runtime_exceptions_count: usize,
    pub active_exceptions_count: usize,
}

impl std::fmt::Display for RuleStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Protection rules: {}, Runtime exceptions: {} ({} active)",
            self.protection_rules_count,
            self.runtime_exceptions_count,
            self.active_exceptions_count
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_ssh_key_protection() {
        let mut engine = RuleEngine::new();

        // SSH key should be protected
        let ssh_key = PathBuf::from("/Users/test/.ssh/id_rsa");
        assert!(engine.is_protected_file(&ssh_key));

        // Public key should not be protected
        let pub_key = PathBuf::from("/Users/test/.ssh/id_rsa.pub");
        assert!(!engine.is_protected_file(&pub_key));
    }

    #[test]
    fn test_ssh_access_allowed() {
        let engine = RuleEngine::new();

        let ssh_key = PathBuf::from("/Users/test/.ssh/id_rsa");
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

        let ssh_key = PathBuf::from("/Users/test/.ssh/id_rsa");
        let malware = PathBuf::from("/tmp/malware");

        let decision = engine.check_access(&malware, &ssh_key);
        assert_eq!(decision, Decision::Deny);
    }

    #[test]
    fn test_runtime_exception() {
        let mut engine = RuleEngine::new();

        let ssh_key = PathBuf::from("/Users/test/.ssh/id_rsa");
        let custom_tool = PathBuf::from("/tmp/backup-tool");

        // Should be denied initially
        let decision = engine.check_access(&custom_tool, &ssh_key);
        assert_eq!(decision, Decision::Deny);

        // Add runtime exception
        engine.add_runtime_exception(custom_tool.clone(), ssh_key.clone());

        // Should be allowed now
        let decision = engine.check_access(&custom_tool, &ssh_key);
        assert_eq!(decision, Decision::Allow);
    }
}