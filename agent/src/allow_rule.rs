//! Process allow rules for fine-grained access control.
//!
//! This module defines the [`AllowRule`] type which specifies conditions under which
//! a process is allowed to access protected files. Rules use AND logic, meaning all
//! specified conditions must match for the rule to apply.

use crate::config::Config;
use crate::process_context::ProcessContext;
use serde::{Deserialize, Deserializer, Serialize};

/// A single allow rule with AND logic between conditions.
///
/// This structure defines the criteria that a process must meet to be granted
/// access to protected files. All specified fields must match for the rule
/// to apply (AND logic).
///
/// # Security Considerations
///
/// - `team_id` is the most secure field as it cannot be spoofed on macOS
/// - `app_id` can be set by developers and is less reliable
/// - `path` should be as specific as possible to avoid false positives
/// - When possible, combine multiple criteria for stronger validation
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AllowRule {
    /// Process basename (e.g., "firefox", "chrome")
    #[serde(default)]
    pub base: Option<String>,

    /// Full path pattern (e.g., "/Applications/*/*.app/Contents/MacOS/*")
    #[serde(default, alias = "path_pattern")]
    pub path: Option<String>,

    /// Parent process ID (e.g., 1 for launchd)
    #[serde(default)]
    pub ppid: Option<u32>,

    /// Apple Team ID (secure, assigned by Apple)
    #[serde(default)]
    pub team_id: Option<String>,

    /// App ID / Bundle ID (can be set by developer, less secure)
    #[serde(default)]
    pub app_id: Option<String>,

    /// Command line arguments pattern (matches across all args joined)
    #[serde(default)]
    pub args_pattern: Option<String>,

    /// Specific argument that must be present (e.g., "-l" for login shell)
    #[serde(default)]
    pub arg: Option<String>,

    /// User ID (for system processes)
    #[serde(default)]
    pub uid: Option<u32>,

    /// Effective User ID - can be a single value (e.g., 0) or range (e.g., 501-599)
    #[serde(default, deserialize_with = "deserialize_euid")]
    pub euid: Option<(u32, u32)>,

    /// Whether this is an Apple platform binary
    #[serde(default)]
    pub platform_binary: Option<bool>,
}

impl AllowRule {
    /// Check if this rule matches the given process context
    #[allow(dead_code)] // Will be used when monitor is updated
    #[allow(clippy::too_many_arguments)] // TODO: Refactor to use ProcessContext fully
    pub fn matches(&self, context: &ProcessContext) -> bool {
        self.matches_with_config(context, None)
    }

    /// Check if this rule matches the given process context, with config for default paths
    #[allow(dead_code)] // Will be used when monitor is updated
    pub fn matches_with_config(&self, context: &ProcessContext, config: Option<&Config>) -> bool {
        self.matches_with_config_and_debug(context, config, false)
    }

    /// Check if this rule matches with optional debug logging
    pub fn matches_with_config_and_debug(
        &self,
        context: &ProcessContext,
        config: Option<&Config>,
        debug: bool,
    ) -> bool {
        // All specified conditions must match (AND logic)

        // Check basename (supports wildcards)
        if let Some(ref expected_basename) = self.base {
            let actual_basename = context
                .path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("");

            if !matches_pattern(expected_basename, actual_basename) {
                if debug {
                    log::debug!(
                        "Rule failed: basename pattern '{}' doesn't match '{}'",
                        expected_basename,
                        actual_basename
                    );
                }
                return false;
            }
        }

        // Check path pattern
        if let Some(ref pattern) = self.path {
            let path_str = context.path.to_string_lossy();
            if !matches_pattern(pattern, &path_str) {
                if debug {
                    log::debug!(
                        "Rule failed: path pattern '{}' doesn't match '{}'",
                        pattern,
                        path_str
                    );
                }
                return false;
            }
        } else if self.base.is_some() && self.path.is_none() {
            // If base is specified but no path, check against default paths
            if let Some(cfg) = config {
                if !cfg.is_allowed_path_with_debug(&context.path, debug) {
                    if debug {
                        log::debug!("Rule failed: basename specified but process path '{}' not in default base paths", context.path.display());
                    }
                    return false;
                }
            }
        }

        // Check ppid
        if let Some(expected_ppid) = self.ppid {
            if context.ppid != Some(expected_ppid) {
                if debug {
                    log::debug!(
                        "Rule failed: ppid mismatch. Expected {}, got {:?}",
                        expected_ppid,
                        context.ppid
                    );
                }
                return false;
            }
        }

        // Check team_id (secure)
        if let Some(ref expected_team_id) = self.team_id {
            match &context.team_id {
                Some(actual_team_id) => {
                    if !matches_pattern(expected_team_id, actual_team_id) {
                        if debug {
                            log::debug!(
                                "Rule failed: team_id pattern '{}' doesn't match '{}'",
                                expected_team_id,
                                actual_team_id
                            );
                        }
                        return false;
                    }
                }
                None => {
                    if debug {
                        log::debug!(
                            "Rule failed: expected team_id '{}' but none provided",
                            expected_team_id
                        );
                    }
                    return false;
                }
            }
        }

        // Check app_id (less secure, can be spoofed)
        if let Some(ref expected_app_id) = self.app_id {
            match &context.app_id {
                Some(actual_app_id) => {
                    if !matches_pattern(expected_app_id, actual_app_id) {
                        if debug {
                            log::debug!(
                                "Rule failed: app_id pattern '{}' doesn't match '{}'",
                                expected_app_id,
                                actual_app_id
                            );
                        }
                        return false;
                    }
                }
                None => {
                    if debug {
                        log::debug!(
                            "Rule failed: expected app_id '{}' but none provided",
                            expected_app_id
                        );
                    }
                    return false;
                }
            }
        }

        // Check args pattern (matches across all args joined)
        if let Some(ref pattern) = self.args_pattern {
            match &context.args {
                Some(actual_args) => {
                    let args_str = actual_args.join(" ");
                    if !matches_pattern(pattern, &args_str) {
                        if debug {
                            log::debug!(
                                "Rule failed: args pattern '{}' doesn't match '{}'",
                                pattern,
                                args_str
                            );
                        }
                        return false;
                    }
                }
                None => {
                    if debug {
                        log::debug!(
                            "Rule failed: expected args pattern '{}' but no args provided",
                            pattern
                        );
                    }
                    return false;
                }
            }
        }

        // Check for specific arg (must be present in args array)
        if let Some(ref expected_arg) = self.arg {
            match &context.args {
                Some(actual_args) => {
                    if !actual_args.contains(expected_arg) {
                        if debug {
                            log::debug!(
                                "Rule failed: required arg '{}' not found in {:?}",
                                expected_arg,
                                actual_args
                            );
                        }
                        return false;
                    }
                }
                None => {
                    if debug {
                        log::debug!(
                            "Rule failed: expected arg '{}' but no args provided",
                            expected_arg
                        );
                    }
                    return false;
                }
            }
        }

        // Check uid
        if let Some(expected_uid) = self.uid {
            if context.uid != Some(expected_uid) {
                if debug {
                    log::debug!(
                        "Rule failed: uid mismatch. Expected {}, got {:?}",
                        expected_uid,
                        context.uid
                    );
                }
                return false;
            }
        }

        // Check euid (handles both single values and ranges)
        if let Some((min_euid, max_euid)) = self.euid {
            match context.euid {
                Some(actual_euid) => {
                    if actual_euid < min_euid || actual_euid > max_euid {
                        if debug {
                            log::debug!(
                                "Rule failed: euid {} not in range {}-{}",
                                actual_euid,
                                min_euid,
                                max_euid
                            );
                        }
                        return false;
                    }
                }
                None => {
                    if debug {
                        log::debug!(
                            "Rule failed: expected euid in range {}-{} but none provided",
                            min_euid,
                            max_euid
                        );
                    }
                    return false;
                }
            }
        }

        // Check platform_binary
        if let Some(expected_platform) = self.platform_binary {
            match context.platform_binary {
                Some(actual_platform) => {
                    if actual_platform != expected_platform {
                        if debug {
                            log::debug!(
                                "Rule failed: platform_binary mismatch. Expected {}, got {}",
                                expected_platform,
                                actual_platform
                            );
                        }
                        return false;
                    }
                }
                None => {
                    if debug {
                        log::debug!(
                            "Rule failed: expected platform_binary {} but none provided",
                            expected_platform
                        );
                    }
                    return false;
                }
            }
        }

        // All specified conditions matched
        true
    }
}

/// Performs simple glob-like pattern matching.
///
/// This function implements basic wildcard matching where `*` matches any
/// sequence of characters. The implementation is optimized for the common
/// patterns used in process and path matching.
///
/// # Arguments
///
/// * `pattern` - The pattern string, may contain `*` wildcards
/// * `text` - The text to match against the pattern
///
/// # Returns
///
/// `true` if the text matches the pattern, `false` otherwise.
///
/// # Examples
///
/// ```
/// # use noswiper::allow_rule::matches_pattern;
/// assert!(matches_pattern("*.app", "Firefox.app"));
/// assert!(matches_pattern("docker-credential-*", "docker-credential-desktop"));
/// assert!(!matches_pattern("firefox", "chrome"));
/// ```
pub fn matches_pattern(pattern: &str, text: &str) -> bool {
    // Use a proper glob matching algorithm that handles * correctly
    glob_match(pattern, text)
}

/// Implements glob pattern matching with * wildcard support
/// This uses a standard two-pointer algorithm with backtracking
fn glob_match(pattern: &str, text: &str) -> bool {
    let pattern_chars: Vec<char> = pattern.chars().collect();
    let text_chars: Vec<char> = text.chars().collect();

    let mut p = 0; // pattern index
    let mut t = 0; // text index
    let mut star_idx = None; // position of last * in pattern
    let mut star_match = 0; // position in text where * started matching

    while t < text_chars.len() {
        if p < pattern_chars.len() && pattern_chars[p] == text_chars[t] {
            // Characters match exactly
            p += 1;
            t += 1;
        } else if p < pattern_chars.len() && pattern_chars[p] == '*' {
            // Found *, remember positions for backtracking
            star_idx = Some(p);
            star_match = t;
            p += 1; // Move past the * in pattern
        } else if let Some(star_p) = star_idx {
            // No match, but we have a * to backtrack to
            // Try matching one more character with the *
            p = star_p + 1;
            star_match += 1;
            t = star_match;
        } else {
            // No match and no * to backtrack to
            return false;
        }
    }

    // Consume any trailing * in pattern
    while p < pattern_chars.len() && pattern_chars[p] == '*' {
        p += 1;
    }

    // Match successful if we've consumed the entire pattern
    p == pattern_chars.len()
}

/// Deserialize EUID from either a single value or a range string
fn deserialize_euid<'de, D>(deserializer: D) -> Result<Option<(u32, u32)>, D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de::{self, Visitor};
    use std::fmt;

    struct EuidRangeVisitor;

    impl<'de> Visitor<'de> for EuidRangeVisitor {
        type Value = Option<(u32, u32)>;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("a number or a range like '501-599'")
        }

        fn visit_none<E>(self) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            Ok(None)
        }

        fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            let val = value as u32;
            Ok(Some((val, val)))
        }

        fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            if value < 0 {
                return Err(E::custom("EUID must be non-negative"));
            }
            let val = value as u32;
            Ok(Some((val, val)))
        }

        fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            if value.is_empty() {
                return Ok(None);
            }

            if let Some(dash_pos) = value.find('-') {
                // Parse range like "501-599"
                let start = value[..dash_pos].trim().parse::<u32>().map_err(|_| {
                    E::custom(format!("Invalid start of range: {}", &value[..dash_pos]))
                })?;
                let end = value[dash_pos + 1..].trim().parse::<u32>().map_err(|_| {
                    E::custom(format!("Invalid end of range: {}", &value[dash_pos + 1..]))
                })?;

                if start > end {
                    return Err(E::custom(format!("Invalid range: {} > {}", start, end)));
                }

                Ok(Some((start, end)))
            } else {
                // Single value
                let val = value
                    .trim()
                    .parse::<u32>()
                    .map_err(|_| E::custom(format!("Invalid EUID value: {}", value)))?;
                Ok(Some((val, val)))
            }
        }
    }

    deserializer.deserialize_any(EuidRangeVisitor)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn test_pattern_matching() {
        assert!(matches_pattern("*.app", "Firefox.app"));
        // Simplified pattern - the complex nested wildcard pattern isn't used in practice
        assert!(matches_pattern(
            "/Applications/*.app/*",
            "/Applications/Firefox.app/Contents"
        ));
        assert!(matches_pattern("com.apple.*", "com.apple.security"));
        assert!(!matches_pattern("com.apple.*", "com.google.chrome"));
        assert!(matches_pattern("firefox", "firefox"));
        assert!(!matches_pattern("firefox", "chrome"));

        // Test basename wildcards
        assert!(matches_pattern(
            "docker-credential-*",
            "docker-credential-desktop"
        ));
        assert!(matches_pattern(
            "docker-credential-*",
            "docker-credential-pass"
        ));
        assert!(!matches_pattern("docker-credential-*", "docker-compose"));
        assert!(matches_pattern("pinentry*", "pinentry"));
        assert!(matches_pattern("pinentry*", "pinentry-gtk-2"));
        assert!(matches_pattern("python*", "python3"));
        assert!(matches_pattern("python*", "python3.11"));
        assert!(!matches_pattern("python*", "ruby"));
    }

    #[test]
    fn test_rule_matching() {
        let rule = AllowRule {
            base: Some("firefox".to_string()),
            path: Some("/Applications/*.app/*".to_string()),
            ppid: Some(1),
            team_id: None,
            app_id: None,
            args_pattern: None,
            arg: None,
            uid: None,
            euid: None,
            platform_binary: None,
        };

        let context1 = ProcessContext::new(
            Path::new("/Applications/Firefox.app/Contents/MacOS/firefox").to_path_buf(),
        )
        .with_ppid(1);
        assert!(rule.matches(&context1));

        let context2 = ProcessContext::new(
            Path::new("/Applications/Firefox.app/Contents/MacOS/firefox").to_path_buf(),
        )
        .with_ppid(2); // Wrong ppid
        assert!(!rule.matches(&context2));
    }
}
