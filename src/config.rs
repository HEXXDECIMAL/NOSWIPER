//! Configuration management for NoSwiper credential protection.
//!
//! This module handles loading and validating configuration from embedded YAML files
//! or user-provided configuration files. The configuration defines which files to
//! protect and which processes are allowed to access them.

use crate::allow_rule::AllowRule;
use serde::{Deserialize, Serialize};
use std::error::Error as StdError;
use std::fmt;

/// Errors that can occur during configuration loading and validation.
#[derive(Debug)]
pub enum ConfigError {
    /// Invalid YAML syntax in configuration file
    YamlParse(serde_yaml::Error),
    /// File system error reading configuration
    Io(std::io::Error),
    /// Configuration validation failed
    Validation(String),
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConfigError::YamlParse(err) => write!(f, "YAML parsing error: {}", err),
            ConfigError::Io(err) => write!(f, "I/O error: {}", err),
            ConfigError::Validation(msg) => write!(f, "Configuration validation error: {}", msg),
        }
    }
}

impl StdError for ConfigError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            ConfigError::YamlParse(err) => Some(err),
            ConfigError::Io(err) => Some(err),
            ConfigError::Validation(_) => None,
        }
    }
}

impl From<serde_yaml::Error> for ConfigError {
    fn from(err: serde_yaml::Error) -> Self {
        ConfigError::YamlParse(err)
    }
}

impl From<std::io::Error> for ConfigError {
    fn from(err: std::io::Error) -> Self {
        ConfigError::Io(err)
    }
}

// Embed the OS-specific configurations at compile time
#[cfg(target_os = "macos")]
const DEFAULT_CONFIG_YAML: &str = include_str!("../config/macos.yaml");

#[cfg(target_os = "linux")]
const DEFAULT_CONFIG_YAML: &str = include_str!("../config/linux.yaml");

#[cfg(target_os = "freebsd")]
const DEFAULT_CONFIG_YAML: &str = include_str!("../config/freebsd.yaml");

#[cfg(target_os = "netbsd")]
const DEFAULT_CONFIG_YAML: &str = include_str!("../config/netbsd.yaml");

#[cfg(target_os = "openbsd")]
const DEFAULT_CONFIG_YAML: &str = include_str!("../config/openbsd.yaml");

#[cfg(not(any(
    target_os = "macos",
    target_os = "linux",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd"
)))]
const DEFAULT_CONFIG_YAML: &str = include_str!("../config/default.yaml");

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Config {
    pub protected_files: Vec<ProtectedFile>,
    pub excluded_patterns: Vec<String>,
    #[serde(default)]
    pub global_exclusions: Vec<AllowRule>,
    #[serde(alias = "allowed_paths")] // For backward compatibility
    pub default_base_paths: Vec<String>,
    pub monitoring: MonitoringConfig,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ProtectedFile {
    #[serde(default)]
    pub id: Option<String>,
    #[serde(flatten)]
    pub patterns_config: PatternsConfig,
    #[serde(rename = "allow")]
    pub allow_rules: Vec<AllowRule>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(untagged)]
pub enum PatternsConfig {
    Single { pattern: String },
    Multiple { patterns: Vec<String> },
}

impl ProtectedFile {
    pub fn patterns(&self) -> Vec<String> {
        match &self.patterns_config {
            PatternsConfig::Single { pattern } => vec![pattern.clone()],
            PatternsConfig::Multiple { patterns } => patterns.clone(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct MonitoringConfig {
    pub buffer_size: usize,
    pub max_events_per_sec: usize,
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
    pub fn default() -> Result<Self, ConfigError> {
        let config: Config = serde_yaml::from_str(DEFAULT_CONFIG_YAML)?;
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
    pub fn from_file(path: &std::path::Path) -> Result<Self, ConfigError> {
        let contents = std::fs::read_to_string(path)?;
        let user_config: Config = serde_yaml::from_str(&contents)?;
        user_config.validate_global_exclusions()?;

        // For now, just return the user config
        // TODO: Implement proper merging with defaults
        Ok(user_config)
    }

    /// Validates that all global exclusions have either path_pattern or team_id.
    ///
    /// This is a security requirement to prevent overly broad global exclusions
    /// that could allow unauthorized access to protected files.
    fn validate_global_exclusions(&self) -> Result<(), ConfigError> {
        for (i, rule) in self.global_exclusions.iter().enumerate() {
            if rule.path_pattern.is_none() && rule.team_id.is_none() {
                let msg = format!(
                    "Global exclusion rule {} is missing both path_pattern and team_id. \
                     Every global exclusion must have at least one of these for security.",
                    i + 1
                );
                return Err(ConfigError::Validation(msg));
            }
        }
        Ok(())
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
    pub fn is_allowed_path(&self, path: &std::path::Path) -> bool {
        let path_str = path.to_string_lossy();

        for allowed in &self.default_base_paths {
            let expanded = shellexpand::tilde(allowed);
            // Handle patterns with wildcards
            if expanded.contains('*') {
                if let Ok(pattern) = glob::Pattern::new(&expanded) {
                    if pattern.matches(&path_str) {
                        return true;
                    }
                }
            } else {
                // Simple prefix matching for paths without wildcards
                if path_str.starts_with(expanded.as_ref()) {
                    return true;
                }
            }
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
