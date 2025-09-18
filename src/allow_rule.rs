use serde::{Deserialize, Serialize};
use std::path::Path;
use crate::config::Config;

/// A single allow rule with AND logic between conditions
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AllowRule {
    /// Process basename (e.g., "firefox", "chrome")
    #[serde(default)]
    pub base: Option<String>,

    /// Full path pattern (e.g., "/Applications/*/*.app/Contents/MacOS/*")
    #[serde(default, alias = "path")]
    pub path_pattern: Option<String>,

    /// Parent process ID (e.g., 1 for launchd)
    #[serde(default)]
    pub ppid: Option<u32>,

    /// Apple Team ID (secure, assigned by Apple)
    #[serde(default)]
    pub team_id: Option<String>,

    /// App ID / Bundle ID (can be set by developer, less secure)
    #[serde(default)]
    pub app_id: Option<String>,

    /// Command line arguments pattern
    #[serde(default)]
    pub args_pattern: Option<String>,

    /// User ID (for system processes)
    #[serde(default)]
    pub uid: Option<u32>,
}

impl AllowRule {
    /// Check if this rule matches the given process context
    #[allow(dead_code)]  // Will be used when monitor is updated
    pub fn matches(
        &self,
        process_path: &Path,
        ppid: Option<u32>,
        team_id: Option<&str>,
        app_id: Option<&str>,
        args: Option<&[String]>,
        uid: Option<u32>,
    ) -> bool {
        self.matches_with_config(process_path, ppid, team_id, app_id, args, uid, None)
    }

    /// Check if this rule matches the given process context, with config for default paths
    #[allow(dead_code)]  // Will be used when monitor is updated
    pub fn matches_with_config(
        &self,
        process_path: &Path,
        ppid: Option<u32>,
        team_id: Option<&str>,
        app_id: Option<&str>,
        args: Option<&[String]>,
        uid: Option<u32>,
        config: Option<&Config>,
    ) -> bool {
        // All specified conditions must match (AND logic)

        // Check basename
        if let Some(ref expected_basename) = self.base {
            let actual_basename = process_path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("");

            if actual_basename != expected_basename {
                log::warn!("Rule failed: basename mismatch. Expected '{}', got '{}'", expected_basename, actual_basename);
                return false;
            }
        }

        // Check path pattern
        if let Some(ref pattern) = self.path_pattern {
            let path_str = process_path.to_string_lossy();
            if !matches_pattern(pattern, &path_str) {
                log::warn!("Rule failed: path pattern '{}' doesn't match '{}'", pattern, path_str);
                return false;
            }
        } else if self.base.is_some() && self.path_pattern.is_none() {
            // If base is specified but no path_pattern, check against default paths
            if let Some(cfg) = config {
                if !cfg.is_allowed_path(process_path) {
                    log::warn!("Rule failed: basename specified but process path '{}' not in default base paths", process_path.display());
                    return false;
                }
            }
        }

        // Check ppid
        if let Some(expected_ppid) = self.ppid {
            if ppid != Some(expected_ppid) {
                log::warn!("Rule failed: ppid mismatch. Expected {}, got {:?}", expected_ppid, ppid);
                return false;
            }
        }

        // Check team_id (secure)
        if let Some(ref expected_team_id) = self.team_id {
            match team_id {
                Some(actual_team_id) => {
                    if !matches_pattern(expected_team_id, actual_team_id) {
                        log::warn!("Rule failed: team_id pattern '{}' doesn't match '{}'", expected_team_id, actual_team_id);
                        return false;
                    }
                }
                None => {
                    log::warn!("Rule failed: expected team_id '{}' but none provided", expected_team_id);
                    return false;
                }
            }
        }

        // Check app_id (less secure, can be spoofed)
        if let Some(ref expected_app_id) = self.app_id {
            match app_id {
                Some(actual_app_id) => {
                    if !matches_pattern(expected_app_id, actual_app_id) {
                        log::warn!("Rule failed: app_id pattern '{}' doesn't match '{}'", expected_app_id, actual_app_id);
                        return false;
                    }
                }
                None => {
                    log::warn!("Rule failed: expected app_id '{}' but none provided", expected_app_id);
                    return false;
                }
            }
        }

        // Check args pattern
        if let Some(ref pattern) = self.args_pattern {
            match args {
                Some(actual_args) => {
                    let args_str = actual_args.join(" ");
                    if !matches_pattern(pattern, &args_str) {
                        log::warn!("Rule failed: args pattern '{}' doesn't match '{}'", pattern, args_str);
                        return false;
                    }
                }
                None => {
                    log::warn!("Rule failed: expected args pattern '{}' but no args provided", pattern);
                    return false;
                }
            }
        }

        // Check uid
        if let Some(expected_uid) = self.uid {
            if uid != Some(expected_uid) {
                log::warn!("Rule failed: uid mismatch. Expected {}, got {:?}", expected_uid, uid);
                return false;
            }
        }

        // All specified conditions matched
        true
    }
}

/// Simple glob-like pattern matching
#[allow(dead_code)]  // Will be used when monitor is updated
fn matches_pattern(pattern: &str, text: &str) -> bool {
    // Handle wildcards
    if pattern.contains('*') {
        // Convert pattern to regex-like matching
        let parts: Vec<&str> = pattern.split('*').collect();

        if parts.is_empty() {
            return true;
        }

        let mut pos = 0;
        for (i, part) in parts.iter().enumerate() {
            if part.is_empty() {
                continue;
            }

            // First part must match at beginning
            if i == 0 && !pattern.starts_with('*') {
                if !text.starts_with(part) {
                    return false;
                }
                pos = part.len();
            }
            // Last part must match at end
            else if i == parts.len() - 1 && !pattern.ends_with('*') {
                return text.ends_with(part);
            }
            // Middle parts can match anywhere after current position
            else if let Some(idx) = text[pos..].find(part) {
                pos += idx + part.len();
            } else {
                return false;
            }
        }

        true
    } else {
        // Exact match
        pattern == text
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pattern_matching() {
        assert!(matches_pattern("*.app", "Firefox.app"));
        assert!(matches_pattern("/Applications/*/*.app/Contents/MacOS/*",
                               "/Applications/Firefox.app/Contents/MacOS/firefox"));
        assert!(matches_pattern("com.apple.*", "com.apple.security"));
        assert!(!matches_pattern("com.apple.*", "com.google.chrome"));
        assert!(matches_pattern("firefox", "firefox"));
        assert!(!matches_pattern("firefox", "chrome"));
    }

    #[test]
    fn test_rule_matching() {
        let rule = AllowRule {
            base: Some("firefox".to_string()),
            path_pattern: Some("/Applications/*/*.app/Contents/MacOS/*".to_string()),
            ppid: Some(1),
            team_id: None,
            app_id: None,
            args_pattern: None,
            uid: None,
        };

        assert!(rule.matches(
            Path::new("/Applications/Firefox.app/Contents/MacOS/firefox"),
            Some(1),
            None,
            None,
            None,
            None
        ));

        assert!(!rule.matches(
            Path::new("/Applications/Firefox.app/Contents/MacOS/firefox"),
            Some(2), // Wrong ppid
            None,
            None,
            None,
            None
        ));
    }
}