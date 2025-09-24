//! Configuration management for NoSwiper credential protection.
//!
//! This module handles loading and validating configuration from embedded YAML files
//! or user-provided configuration files. The configuration defines which files to
//! protect and which processes are allowed to access them.

use crate::allow_rule::AllowRule;
use crate::error::{ConfigError, NoSwiperError, Result};
use serde::{Deserialize, Serialize};

// ConfigError is now defined in error.rs - remove duplicate definition here

// Embed the common UNIX configuration (shared across all UNIX-like systems)
#[cfg(any(
    target_os = "macos",
    target_os = "linux",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "solaris",
    target_os = "illumos",
    target_os = "dragonfly"
))]
const UNIX_CONFIG_YAML: &str = include_str!("../config/unix.yaml");

// Embed the OS-specific configurations at compile time
#[cfg(target_os = "macos")]
const OS_CONFIG_YAML: &str = include_str!("../config/macos.yaml");

#[cfg(target_os = "linux")]
const OS_CONFIG_YAML: &str = include_str!("../config/linux.yaml");

#[cfg(target_os = "freebsd")]
const OS_CONFIG_YAML: &str = include_str!("../config/freebsd.yaml");

#[cfg(target_os = "netbsd")]
const OS_CONFIG_YAML: &str = include_str!("../config/netbsd.yaml");

#[cfg(target_os = "openbsd")]
const OS_CONFIG_YAML: &str = include_str!("../config/openbsd.yaml");

#[cfg(target_os = "solaris")]
const OS_CONFIG_YAML: &str = include_str!("../config/solaris.yaml");

#[cfg(target_os = "illumos")]
const OS_CONFIG_YAML: &str = include_str!("../config/illumos.yaml");

#[cfg(not(any(
    target_os = "macos",
    target_os = "linux",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "solaris",
    target_os = "illumos"
)))]
const OS_CONFIG_YAML: &str = include_str!("../config/default.yaml");

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Config {
    pub protected_files: Vec<ProtectedFile>,
    pub excluded_patterns: Vec<String>,
    #[serde(default)]
    pub global_exclusions: Vec<AllowRule>,
    #[serde(alias = "allowed_paths")] // For backward compatibility
    pub default_base_paths: Vec<String>,
    #[serde(default = "MonitoringConfig::default")]
    pub monitoring: MonitoringConfig,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ProtectedFile {
    #[serde(default)]
    pub id: Option<String>,
    pub paths: Vec<String>,
    #[serde(rename = "allow")]
    pub allow_rules: Vec<AllowRule>,
}

impl ProtectedFile {
    pub fn patterns(&self) -> Vec<String> {
        // Keep the method name for backward compatibility in the codebase
        self.paths.clone()
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct MonitoringConfig {
    pub buffer_size: usize,
    pub max_events_per_sec: usize,
}

impl Default for MonitoringConfig {
    fn default() -> Self {
        Self {
            buffer_size: 1000,
            max_events_per_sec: 100,
        }
    }
}

impl Config {
    /// Loads the default embedded configuration.
    ///
    /// This configuration is embedded at compile time and tailored to the
    /// target operating system. It includes sensible defaults for common
    /// credential files and trusted applications.
    ///
    /// # Errors
    ///
    /// Returns a [`ConfigError`] if the embedded configuration is malformed
    /// or fails validation.
    pub fn load_default() -> Result<Self> {
        // Load OS-specific config first
        let os_name = std::env::consts::OS;
        let mut config: Config = serde_yaml::from_str(OS_CONFIG_YAML).map_err(|e| {
            ConfigError::Validation(format!("Error parsing {} config: {}", os_name, e))
        })?;

        // On UNIX-like systems, merge with common UNIX configuration
        #[cfg(any(
            target_os = "macos",
            target_os = "linux",
            target_os = "freebsd",
            target_os = "netbsd",
            target_os = "openbsd",
            target_os = "solaris",
            target_os = "illumos",
            target_os = "dragonfly"
        ))]
        {
            let unix_config: Config = serde_yaml::from_str(UNIX_CONFIG_YAML).map_err(|e| {
                ConfigError::Validation(format!("Error parsing unix.yaml config: {}", e))
            })?;
            config.merge(unix_config);
        }

        config.validate_global_exclusions()?;
        Ok(config)
    }

    /// Loads configuration from a file.
    ///
    /// # Arguments
    ///
    /// * `path` - Path to the YAML configuration file
    ///
    /// # Errors
    ///
    /// Returns a [`ConfigError`] if:
    /// - The file cannot be read
    /// - The YAML is malformed
    /// - The configuration fails validation
    ///
    /// # Note
    ///
    /// Currently returns the user configuration as-is. Future versions
    /// will merge with defaults for a better user experience.
    #[allow(dead_code)] // Will be used for user configuration overrides
    pub fn from_file(path: &std::path::Path) -> Result<Self> {
        let contents = std::fs::read_to_string(path).map_err(|e| NoSwiperError::Io(e))?;
        let user_config: Config = serde_yaml::from_str(&contents)
            .map_err(|e| NoSwiperError::Config(ConfigError::InvalidYaml(e)))?;
        user_config.validate_global_exclusions()?;

        // For now, just return the user config
        // TODO: Implement proper merging with defaults
        Ok(user_config)
    }

    /// Validates that all global exclusions have either path or team_id.
    ///
    /// This is a security requirement to prevent overly broad global exclusions
    /// that could allow unauthorized access to protected files.
    fn validate_global_exclusions(&self) -> Result<()> {
        for (i, rule) in self.global_exclusions.iter().enumerate() {
            if rule.path.is_none() && rule.team_id.is_none() {
                let msg = format!(
                    "Global exclusion rule {} is missing both path and team_id. \
                     Every global exclusion must have at least one of these for security.",
                    i + 1
                );
                return Err(NoSwiperError::Config(ConfigError::Validation(msg)));
            }
        }
        Ok(())
    }

    /// Merges another config into this one.
    ///
    /// Rules are combined, with no duplicates based on ID.
    /// OS-specific rules take precedence over common UNIX rules.
    pub fn merge(&mut self, other: Config) {
        use std::collections::HashSet;

        // Merge protected files (OS-specific takes precedence)
        let mut seen_ids = HashSet::new();
        for pf in &self.protected_files {
            seen_ids.insert(pf.id.clone());
        }

        for pf in other.protected_files {
            if !seen_ids.contains(&pf.id) {
                self.protected_files.push(pf);
            }
        }

        // Merge global exclusions
        self.global_exclusions.extend(other.global_exclusions);

        // Merge excluded patterns
        let mut pattern_set: HashSet<_> = self.excluded_patterns.iter().cloned().collect();
        for pattern in other.excluded_patterns {
            if pattern_set.insert(pattern.clone()) {
                self.excluded_patterns.push(pattern);
            }
        }

        // Don't merge default_base_paths - keep OS-specific ones
    }

    /// Checks if a file path matches a glob pattern.
    ///
    /// This method supports shell-style glob patterns and automatically
    /// expands `~` to the user's home directory in both patterns and paths.
    ///
    /// # Arguments
    ///
    /// * `pattern` - The glob pattern to match against
    /// * `file_path` - The file path to test
    ///
    /// # Returns
    ///
    /// `true` if the file path matches the pattern, `false` otherwise.
    /// Invalid patterns are treated as non-matching.
    fn matches_pattern(&self, pattern: &str, file_path: &str) -> bool {
        // Expand ~ to home directory
        let expanded_pattern = shellexpand::tilde(pattern);
        let expanded_path = shellexpand::tilde(file_path);

        // Use glob matching with proper error handling
        match glob::Pattern::new(&expanded_pattern) {
            Ok(pattern) => pattern.matches(&expanded_path),
            Err(e) => {
                log::warn!("Invalid glob pattern '{}': {}", pattern, e);
                false
            }
        }
    }

    /// Check if a path is in the default basename paths
    #[allow(dead_code)] // Used by allow_rule
    pub fn is_allowed_path(&self, path: &std::path::Path) -> bool {
        self.is_allowed_path_with_debug(path, false)
    }

    /// Check if a path is in the default basename paths with optional debug logging
    pub fn is_allowed_path_with_debug(&self, path: &std::path::Path, debug: bool) -> bool {
        let path_str = path.to_string_lossy();

        if debug {
            log::debug!("Checking if path '{}' is in default_base_paths", path_str);
            log::debug!(
                "Available default_base_paths: {:?}",
                self.default_base_paths
            );
        }

        for allowed in &self.default_base_paths {
            let expanded = shellexpand::tilde(allowed);
            // Handle patterns with wildcards
            if expanded.contains('*') {
                if let Ok(pattern) = glob::Pattern::new(&expanded) {
                    if pattern.matches(&path_str) {
                        if debug {
                            log::debug!("Path '{}' matches pattern '{}'", path_str, expanded);
                        }
                        return true;
                    } else if debug {
                        log::debug!("Path '{}' does NOT match pattern '{}'", path_str, expanded);
                    }
                } else {
                    log::warn!("Invalid glob pattern in default_base_paths: '{}'", expanded);
                }
            } else {
                // Simple prefix matching for paths without wildcards
                if path_str.starts_with(expanded.as_ref()) {
                    if debug {
                        log::debug!("Path '{}' starts with prefix '{}'", path_str, expanded);
                    }
                    return true;
                } else if debug {
                    log::debug!(
                        "Path '{}' does NOT start with prefix '{}'",
                        path_str,
                        expanded
                    );
                }
            }
        }

        if debug {
            log::debug!("Path '{}' is NOT in default_base_paths", path_str);
        }
        false
    }

    /// Check if a path should be excluded from monitoring
    pub fn is_excluded(&self, path: &str) -> bool {
        for pattern in &self.excluded_patterns {
            if self.matches_pattern(pattern, path) {
                return true;
            }
        }
        false
    }
}
