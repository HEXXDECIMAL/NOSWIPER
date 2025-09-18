use serde::{Deserialize, Serialize};

// Embed the default configuration at compile time
const DEFAULT_CONFIG_YAML: &str = include_str!("../config/default.yaml");

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Config {
    pub protected_files: Vec<ProtectedFile>,
    pub excluded_patterns: Vec<String>,
    pub allowed_paths: AllowedPaths,
    pub global_trusted_signers: Vec<String>,
    pub monitoring: MonitoringConfig,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ProtectedFile {
    pub pattern: String,
    pub allowed_programs: Vec<String>,
    #[serde(default)]
    pub allowed_signers: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AllowedPaths {
    #[serde(default)]
    pub macos: Vec<String>,
    #[serde(default)]
    pub linux: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct MonitoringConfig {
    pub watch_paths: Vec<String>,
    pub buffer_size: usize,
    pub max_events_per_sec: usize,
}

impl Config {
    /// Load the default embedded configuration
    pub fn default() -> Result<Self, serde_yaml::Error> {
        serde_yaml::from_str(DEFAULT_CONFIG_YAML)
    }

    /// Load configuration from a file, merging with defaults
    #[allow(dead_code)]  // Will be used for user overrides
    pub fn from_file(path: &std::path::Path) -> Result<Self, Box<dyn std::error::Error>> {
        let contents = std::fs::read_to_string(path)?;
        let user_config: Config = serde_yaml::from_str(&contents)?;

        // For now, just return the user config
        // TODO: Implement proper merging with defaults
        Ok(user_config)
    }

    /// Get allowed programs for a given file pattern
    #[allow(dead_code)]  // API method for future use
    pub fn get_allowed_programs(&self, file_path: &str) -> Vec<String> {
        let mut allowed = Vec::new();

        for protected in &self.protected_files {
            if self.matches_pattern(&protected.pattern, file_path) {
                allowed.extend(protected.allowed_programs.clone());
            }
        }

        allowed.sort();
        allowed.dedup();
        allowed
    }

    /// Get allowed signers for a given file pattern
    #[allow(dead_code)]  // API method for future use
    pub fn get_allowed_signers(&self, file_path: &str) -> Vec<String> {
        let mut allowed = self.global_trusted_signers.clone();

        for protected in &self.protected_files {
            if self.matches_pattern(&protected.pattern, file_path) {
                allowed.extend(protected.allowed_signers.clone());
            }
        }

        allowed.sort();
        allowed.dedup();
        allowed
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

    /// Check if a path is in the allowed executable paths
    pub fn is_allowed_path(&self, path: &std::path::Path) -> bool {
        let path_str = path.to_string_lossy();

        #[cfg(target_os = "macos")]
        let allowed_paths = &self.allowed_paths.macos;

        #[cfg(target_os = "linux")]
        let allowed_paths = &self.allowed_paths.linux;

        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
        let allowed_paths = &Vec::<String>::new();

        for allowed in allowed_paths {
            let expanded = shellexpand::tilde(allowed);
            if path_str.starts_with(expanded.as_ref()) {
                return true;
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