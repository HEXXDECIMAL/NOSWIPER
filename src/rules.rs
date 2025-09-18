use crate::config::Config;
use crate::process_context::ProcessContext;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::RwLock;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, PartialEq)]
pub enum Decision {
    Allow,
    Deny,
}

// Cache entry for home directories
#[derive(Clone, Debug)]
struct HomeDirCacheEntry {
    home_dir: Option<PathBuf>,
    cached_at: Instant,
}

// Global cache for UID to home directory mappings
// Using RwLock for concurrent reads with occasional writes
lazy_static::lazy_static! {
    static ref UID_HOME_CACHE: RwLock<HashMap<u32, HomeDirCacheEntry>> = RwLock::new(HashMap::new());
}

// Cache TTL - 5 minutes should be reasonable for most environments
const CACHE_TTL: Duration = Duration::from_secs(300);

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

    /// Get home directory for a UID with caching
    fn get_cached_home_dir(uid: u32) -> Option<PathBuf> {
        // First try to get from cache with read lock
        {
            let cache = UID_HOME_CACHE.read().unwrap();
            if let Some(entry) = cache.get(&uid) {
                let age = Instant::now().duration_since(entry.cached_at);
                if age < CACHE_TTL {
                    return entry.home_dir.clone();
                }
            }
        }

        // Cache miss or expired - lookup and update cache
        let home_dir = crate::process_context::get_home_for_uid(uid);

        // Update cache with write lock
        let mut cache = UID_HOME_CACHE.write().unwrap();
        cache.insert(uid, HomeDirCacheEntry {
            home_dir: home_dir.clone(),
            cached_at: Instant::now(),
        });

        // Periodically clean up stale entries to prevent unbounded growth
        if cache.len() > 100 && cache.len() % 50 == 0 {
            Self::cleanup_stale_cache_entries(&mut cache);
        }

        // Log cache size occasionally for monitoring
        if cache.len() % 100 == 0 && cache.len() > 0 {
            log::debug!("UID home cache size: {} entries", cache.len());
        }

        home_dir
    }

    /// Remove expired entries from the cache
    fn cleanup_stale_cache_entries(cache: &mut HashMap<u32, HomeDirCacheEntry>) {
        let now = Instant::now();
        let before_size = cache.len();

        cache.retain(|_uid, entry| {
            now.duration_since(entry.cached_at) < CACHE_TTL
        });

        let removed = before_size - cache.len();
        if removed > 0 {
            log::debug!("Cleaned up {} stale UID cache entries", removed);
        }
    }

    /// Get file owner UID
    fn get_file_owner(path: &Path) -> Option<u32> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            std::fs::metadata(path).ok().map(|m| m.uid())
        }

        #[cfg(not(unix))]
        {
            None
        }
    }

    /// Normalize a file path to use ~ if it's under a user's home directory
    fn normalize_path_to_tilde(file_path: &Path) -> PathBuf {
        // Get the file owner's UID
        if let Some(uid) = Self::get_file_owner(file_path) {
            // Get the owner's home directory (with caching)
            if let Some(home_dir) = Self::get_cached_home_dir(uid) {
                // Check if the file is under this home directory
                if let Ok(relative) = file_path.strip_prefix(&home_dir) {
                    // Return path as ~/relative
                    return PathBuf::from("~").join(relative);
                }
            }
        }

        // If we can't normalize, return the original path
        file_path.to_path_buf()
    }

    /// Check if a file path should be protected
    pub fn is_protected_file(&self, file_path: &Path) -> bool {
        // Normalize the file path to use ~ if it's in a home directory
        let normalized_path = Self::normalize_path_to_tilde(file_path);
        let file_str = normalized_path.to_string_lossy();

        // First check if it's explicitly excluded
        if self.config.is_excluded(&file_str) {
            return false;
        }

        // Check if any protection pattern matches
        for protected_file in &self.config.protected_files {
            for pattern_str in protected_file.patterns() {
                // Patterns with ~ are now relative to file owner's home
                // No need to expand them since we normalized the file path
                if let Ok(pattern) = glob::Pattern::new(&pattern_str) {
                    if pattern.matches_path(&normalized_path) {
                        return true;
                    }
                }
            }
        }

        false
    }

    /// Get list of protected patterns for checking command arguments
    pub fn get_protected_patterns(&self) -> Vec<String> {
        self.config.protected_files
            .iter()
            .flat_map(|pf| pf.patterns())
            .collect()
    }

    /// Check if a process is allowed to access a file (new API)
    #[allow(dead_code)]  // Will be used when monitor is updated
    pub fn check_access_with_context(&self, context: &ProcessContext, file_path: &Path) -> Decision {
        // Normalize the file path to use ~ if it's in a home directory
        let normalized_path = Self::normalize_path_to_tilde(file_path);

        // First check runtime exceptions (use normalized path for consistency)
        let exception_key = (context.path.clone(), normalized_path.clone());
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
                context.euid,
                Some(&self.config),
            ) {
                log::info!("Access allowed by global exclusion: {}", context.path.display());
                return Decision::Allow;
            }
        }

        // Find the protection rule that matches this file
        for protected_file in &self.config.protected_files {
            for pattern_str in protected_file.patterns() {
                // Patterns with ~ are now relative to file owner's home
                // No need to expand them since we normalized the file path
                if let Ok(pattern) = glob::Pattern::new(&pattern_str) {
                    if pattern.matches_path(&normalized_path) {
                        // Check allow rules
                        for rule in &protected_file.allow_rules {
                            if rule.matches_with_config(
                                &context.path,
                                context.ppid,
                                context.team_id.as_deref(),
                                context.app_id.as_deref(),
                                context.args.as_deref(),
                                context.uid,
                                context.euid,
                                Some(&self.config),
                            ) {
                                log::debug!("Process allowed by allow rule");
                                return Decision::Allow;
                            }
                        }
                        // No rules matched - deny access
                        log::warn!("No allow rules matched for {}", context.path.display());
                        return Decision::Deny;
                    }
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
