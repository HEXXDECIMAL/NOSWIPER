use crate::allow_rule::AllowRule;
use serde::{Deserialize, Serialize};

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
    /// Load the default embedded configuration
    pub fn default() -> Result<Self, serde_yaml::Error> {
        let config: Config = serde_yaml::from_str(DEFAULT_CONFIG_YAML)?;
        config.validate_global_exclusions()?;
        Ok(config)
    }

    /// Load configuration from a file, merging with defaults
    #[allow(dead_code)] // Will be used for user overrides
    pub fn from_file(path: &std::path::Path) -> Result<Self, Box<dyn std::error::Error>> {
        let contents = std::fs::read_to_string(path)?;
        let user_config: Config = serde_yaml::from_str(&contents)?;
        user_config
            .validate_global_exclusions()
            .map_err(|e| format!("Configuration validation failed: {}", e))?;

        // For now, just return the user config
        // TODO: Implement proper merging with defaults
        Ok(user_config)
    }

    /// Validate that all global exclusions have either path_pattern or team_id
    fn validate_global_exclusions(&self) -> Result<(), serde_yaml::Error> {
        for (i, rule) in self.global_exclusions.iter().enumerate() {
            if rule.path_pattern.is_none() && rule.team_id.is_none() {
                let msg = format!(
                    "Global exclusion rule {} is missing both path_pattern and team_id. \
                     Every global exclusion must have at least one of these for security.",
                    i + 1
                );
                return Err(serde::de::Error::custom(msg));
            }
        }
        Ok(())
    }

    /// Check if a file matches a pattern (with glob support)
    fn matches_pattern(&self, pattern: &str, file_path: &str) -> bool {
        // Expand ~ to home directory
        let expanded_pattern = shellexpand::tilde(pattern);
        let expanded_path = shellexpand::tilde(file_path);

        // Use glob matching
        glob::Pattern::new(&expanded_pattern)
            .map(|p| p.matches(&expanded_path))
            .unwrap_or(false)
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
