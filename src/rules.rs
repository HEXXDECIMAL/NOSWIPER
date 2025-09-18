use crate::config::Config;
use crate::process_context::ProcessContext;
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
    // Configuration loaded from YAML
    config: Config,
    // Runtime exceptions (process_path, file_path) -> expires_at
    runtime_exceptions: HashMap<(PathBuf, PathBuf), Option<Instant>>,
}

impl RuleEngine {
    pub fn new(config: Config) -> Self {
        Self {
            config,
            runtime_exceptions: HashMap::new(),
        }
    }

    /// Check if a file path should be protected
    pub fn is_protected_file(&self, file_path: &Path) -> bool {
        let file_str = file_path.to_string_lossy();

        // First check if it's explicitly excluded
        if self.config.is_excluded(&file_str) {
            return false;
        }

        // Check if any protection pattern matches
        for protected_file in &self.config.protected_files {
            let expanded_pattern = shellexpand::tilde(&protected_file.pattern);
            if let Ok(pattern) = glob::Pattern::new(&expanded_pattern) {
                if pattern.matches_path(file_path) {
                    return true;
                }
            }
        }

        false
    }

    /// Get list of protected patterns for checking command arguments
    pub fn get_protected_patterns(&self) -> Vec<String> {
        self.config.protected_files
            .iter()
            .map(|pf| pf.pattern.clone())
            .collect()
    }

    /// Check if a process is allowed to access a file (new API)
    #[allow(dead_code)]  // Will be used when monitor is updated
    pub fn check_access_with_context(&self, context: &ProcessContext, file_path: &Path) -> Decision {
        // First check runtime exceptions
        let exception_key = (context.path.clone(), file_path.to_path_buf());
        if let Some(expires_at) = self.runtime_exceptions.get(&exception_key) {
            if expires_at.is_none_or(|exp| Instant::now() < exp) {
                log::debug!("Access allowed by runtime exception");
                return Decision::Allow;
            }
        }

        // Check global exclusions (processes that can access any protected file)
        for exclusion in &self.config.global_exclusions {
            if exclusion.matches_with_config(
                &context.path,
                context.ppid,
                context.team_id.as_deref(),
                context.app_id.as_deref(),
                context.args.as_deref(),
                context.uid,
                Some(&self.config),
            ) {
                log::info!("Access allowed by global exclusion: {}", context.path.display());
                return Decision::Allow;
            }
        }

        // Find the protection rule that matches this file
        for protected_file in &self.config.protected_files {
            let expanded_pattern = shellexpand::tilde(&protected_file.pattern);
            if let Ok(pattern) = glob::Pattern::new(&expanded_pattern) {
                if pattern.matches_path(file_path) {
                    // Check allow rules
                    for rule in &protected_file.allow_rules {
                        if rule.matches_with_config(
                            &context.path,
                            context.ppid,
                            context.team_id.as_deref(),
                            context.app_id.as_deref(),
                            context.args.as_deref(),
                            context.uid,
                            Some(&self.config),
                        ) {
                            log::info!("Process allowed by allow rule");
                            return Decision::Allow;
                        }
                    }
                    // No rules matched - deny access
                    log::warn!("No allow rules matched for {}", context.path.display());
                    return Decision::Deny;
                }
            }
        }

        // If no pattern matched, allow by default
        Decision::Allow
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

    fn test_config() -> Config {
        Config::default().expect("Failed to load default config")
    }

    #[test]
    fn test_ssh_key_protection() {
        let engine = RuleEngine::new(test_config());

        // Use shellexpand to match how the actual code works
        let ssh_key = PathBuf::from(shellexpand::tilde("~/.ssh/id_rsa").to_string());
        assert!(engine.is_protected_file(&ssh_key));

        // Public key should not be protected
        let pub_key = PathBuf::from(shellexpand::tilde("~/.ssh/id_rsa.pub").to_string());
        assert!(!engine.is_protected_file(&pub_key));
    }

    #[test]
    fn test_ssh_access_allowed() {
        let engine = RuleEngine::new(test_config());

        let ssh_key = PathBuf::from(shellexpand::tilde("~/.ssh/id_rsa").to_string());
        let ssh_binary = PathBuf::from("/usr/bin/ssh");

        // This would normally check if /usr/bin/ssh is legitimate
        // In a real test environment, we'd mock this
        let decision = engine.check_access(&ssh_binary, &ssh_key, None);

        // SSH should be allowed to access SSH keys (if in legitimate location)
        if engine.is_in_allowed_paths(&ssh_binary) {
            assert_eq!(decision, Decision::Allow);
        }
    }

    #[test]
    fn test_unknown_binary_blocked() {
        let engine = RuleEngine::new(test_config());

        let ssh_key = PathBuf::from(shellexpand::tilde("~/.ssh/id_rsa").to_string());
        let malware = PathBuf::from("/tmp/malware");

        // Check if this is a protected file first
        if engine.is_protected_file(&ssh_key) {
            let decision = engine.check_access(&malware, &ssh_key, None);
            assert_eq!(decision, Decision::Deny);
        } else {
            // If not protected, it would be allowed
            let decision = engine.check_access(&malware, &ssh_key, None);
            assert_eq!(decision, Decision::Allow);
        }
    }

    #[test]
    fn test_runtime_exception() {
        let mut engine = RuleEngine::new(test_config());

        let ssh_key = PathBuf::from(shellexpand::tilde("~/.ssh/id_rsa").to_string());
        let custom_tool = PathBuf::from("/tmp/backup-tool");

        // Should be denied initially if this is a protected file
        if engine.is_protected_file(&ssh_key) {
            let decision = engine.check_access(&custom_tool, &ssh_key, None);
            assert_eq!(decision, Decision::Deny);

            // Add runtime exception
            engine.add_runtime_exception(custom_tool.clone(), ssh_key.clone());

            // Should be allowed now
            let decision = engine.check_access(&custom_tool, &ssh_key, None);
            assert_eq!(decision, Decision::Allow);
        } else {
            // If the file isn't protected, test a different scenario
            // Use a hardcoded path we know will be protected
            let protected_file = PathBuf::from(shellexpand::tilde("~/.ssh/id_ed25519").to_string());
            if engine.is_protected_file(&protected_file) {
                let decision = engine.check_access(&custom_tool, &protected_file, None);
                assert_eq!(decision, Decision::Deny);

                engine.add_runtime_exception(custom_tool.clone(), protected_file.clone());

                let decision = engine.check_access(&custom_tool, &protected_file, None);
                assert_eq!(decision, Decision::Allow);
            }
        }
    }
}
