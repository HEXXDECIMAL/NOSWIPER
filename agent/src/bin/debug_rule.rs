//! Debug tool for analyzing NoSwiper rule matches and failures.
//!
//! This tool helps diagnose why certain processes are blocked or allowed
//! by parsing detection log lines and evaluating them against the current
//! configuration.

use anyhow::{Context, Result};
use noswiper::allow_rule::AllowRule;
use noswiper::config::Config;
use noswiper::process_context::ProcessContext;
use std::env;
use std::fmt;
use std::path::{Path, PathBuf};
use std::str::FromStr;

fn main() -> Result<()> {
    env_logger::init();

    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: {} \"<detection log line>\"", args[0]);
        eprintln!("\nExample:");
        eprintln!("  {} \"DETECTED[keychain]: /Users/t/Library/Keychains/login.keychain-db open: /Applications/Spotify.app/Contents/MacOS/Spotify --autostart [2FNC3A47ZF:1408@501]→/sbin/launchd\"", args[0]);
        std::process::exit(1);
    }

    let log_line = &args[1];
    let detection = DetectionLog::from_str(log_line)?;

    println!("Parsed Detection:");
    println!("{}", detection);

    // Load config
    let config = Config::load_default().context("Failed to load default configuration")?;

    // Find matching protected file rule
    let mut found_rule = false;

    for protected_file in &config.protected_files {
        let rule_id = protected_file.id.as_deref().unwrap_or("unnamed");

        // Check if this rule's paths match the accessed file
        for path_pattern in &protected_file.paths {
            let expanded = shellexpand::tilde(path_pattern);

            if path_matches(&detection.file_path, &expanded) {
                println!("Rule Configuration: {}", rule_id);
                println!("  Protected Path Pattern: {}", path_pattern);
                println!("    ✓ MATCHES: {}", detection.file_path.display());
                found_rule = true;

                // Create process context for matching
                let process_context = detection.to_process_context();

                // Check allow rules
                println!("\n  Allow Rules for this protected file:");
                let allowed =
                    evaluate_allow_rules(&protected_file.allow_rules, &process_context, &config);

                if !allowed {
                    suggest_fixes(&detection, rule_id);
                } else {
                    println!("\n✅ Access would be ALLOWED");
                }

                break;
            }
        }
    }

    if !found_rule {
        println!(
            "⚠️  No protected file rule found for: {}",
            detection.file_path.display()
        );
        println!("   This file may not be in the protected files list.");
    }

    Ok(())
}

/// Represents a parsed detection log entry
#[derive(Debug, Clone)]
struct DetectionLog {
    rule_name: String,
    file_path: PathBuf,
    process_path: PathBuf,
    args: Vec<String>,
    team_id: Option<String>,
    pid: u32,
    uid: u32,
}

impl DetectionLog {
    /// Convert to ProcessContext for rule evaluation
    fn to_process_context(&self) -> ProcessContext {
        ProcessContext {
            path: self.process_path.clone(),
            args: if self.args.is_empty() {
                None
            } else {
                Some(self.args.clone())
            },
            pid: Some(self.pid),
            ppid: Some(1), // Default to launchd, would need to parse from log if available
            uid: Some(self.uid),
            euid: Some(self.uid),
            team_id: self.team_id.clone(),
            app_id: None, // Would need to get this from somewhere
            platform_binary: self.team_id.as_deref().map(|t| t.starts_with('*')),
        }
    }
}

impl fmt::Display for DetectionLog {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "  Rule: {}", self.rule_name)?;
        writeln!(f, "  File: {}", self.file_path.display())?;
        writeln!(f, "  Process: {}", self.process_path.display())?;
        writeln!(f, "  Arguments: {}", self.args.join(" "))?;

        if let Some(ref team_id) = self.team_id {
            let display_id = if let Some(stripped) = team_id.strip_prefix('*') {
                format!("{} (platform binary)", stripped)
            } else {
                team_id.clone()
            };
            writeln!(f, "  Team ID: {}", display_id)?;
        } else {
            writeln!(f, "  Team ID: (unsigned)")?;
        }

        writeln!(f, "  PID: {}", self.pid)?;
        write!(f, "  UID: {}", self.uid)
    }
}

impl FromStr for DetectionLog {
    type Err = anyhow::Error;

    fn from_str(line: &str) -> Result<Self> {
        // Example: DETECTED[keychain]: /Users/t/Library/Keychains/login.keychain-db open: /Applications/Spotify.app/Contents/MacOS/Spotify --autostart [2FNC3A47ZF:1408@501]→/sbin/launchd

        // Extract rule name
        let rule_start = line
            .find("DETECTED[")
            .context("Invalid log format: missing 'DETECTED['")?;
        let rule_end = line[rule_start..]
            .find(']')
            .context("Invalid log format: missing ']'")?;
        let rule_name = line[rule_start + 9..rule_start + rule_end].to_string();

        // Find the colon after the rule
        let content_start = rule_start + rule_end + 3; // Skip "]: "
        let content = &line[content_start..];

        // Split by " open: " to get file path and the rest
        let parts: Vec<&str> = content.splitn(2, " open: ").collect();
        if parts.len() != 2 {
            anyhow::bail!("Invalid log format: missing ' open: '");
        }

        let file_path = PathBuf::from(parts[0]);
        let process_part = parts[1];

        // Extract team_id and pid/uid info from brackets
        let bracket_start = process_part
            .find('[')
            .context("Invalid log format: missing '['")?;
        let bracket_end = process_part
            .find(']')
            .context("Invalid log format: missing ']'")?;

        let process_and_args = process_part[..bracket_start].trim();
        let bracket_content = &process_part[bracket_start + 1..bracket_end];

        // Parse team_id:pid@uid or just pid@uid
        // Handle platform binary prefix (*)
        let (team_id, pid_uid_part) = if bracket_content.contains(':') {
            let parts: Vec<&str> = bracket_content.splitn(2, ':').collect();
            let tid = parts[0].to_string();
            // Don't filter asterisk - keep it to identify platform binaries
            (
                if tid == "NOSIG" || tid.is_empty() {
                    None
                } else {
                    Some(tid)
                },
                parts[1],
            )
        } else {
            (None, bracket_content)
        };

        // Parse pid@uid
        let pid_uid: Vec<&str> = pid_uid_part.split('@').collect();
        let pid = pid_uid[0].parse::<u32>().context("Failed to parse PID")?;
        let uid = pid_uid
            .get(1)
            .and_then(|s| s.parse::<u32>().ok())
            .unwrap_or(501);

        // Split process path and arguments
        let (process_path, args) = split_command_line(process_and_args);

        Ok(DetectionLog {
            rule_name,
            file_path,
            process_path,
            args,
            team_id,
            pid,
            uid,
        })
    }
}

/// Split a command line into path and arguments
fn split_command_line(cmd: &str) -> (PathBuf, Vec<String>) {
    let parts: Vec<&str> = cmd.splitn(2, ' ').collect();
    let process_path = PathBuf::from(parts[0]);
    let args = parts
        .get(1)
        .map(|s| s.split_whitespace().map(String::from).collect())
        .unwrap_or_default();

    (process_path, args)
}

/// Check if a file path matches a pattern (supports glob patterns)
fn path_matches(file_path: &Path, pattern: &str) -> bool {
    file_path.starts_with(pattern)
        || glob::Pattern::new(pattern)
            .ok()
            .is_some_and(|p| p.matches(file_path.to_string_lossy().as_ref()))
}

/// Evaluate allow rules and return whether access would be allowed
fn evaluate_allow_rules(
    allow_rules: &[AllowRule],
    process_context: &ProcessContext,
    config: &Config,
) -> bool {
    for (idx, allow_rule) in allow_rules.iter().enumerate() {
        println!("    Rule #{}: {}", idx + 1, format_rule(allow_rule));

        if allow_rule.matches_with_config_and_debug(process_context, Some(config), true) {
            println!("      ✓ MATCHES - Access would be ALLOWED");
            return true;
        }
    }

    println!("\n❌ NO ALLOW RULES MATCHED - Access would be BLOCKED");
    false
}

/// Suggest potential fixes for blocked access
fn suggest_fixes(detection: &DetectionLog, rule_id: &str) {
    println!(
        "\nPotential fixes - add one of these to the '{}' rule:",
        rule_id
    );

    if let Some(ref team_id) = detection.team_id {
        // Strip platform binary prefix for the suggestion
        let clean_id = if let Some(stripped) = team_id.strip_prefix('*') {
            stripped
        } else {
            team_id.as_str()
        };

        println!("\n  1. Add team_id (most secure):");
        println!("     allow:");
        println!("       - team_id: \"{}\"", clean_id);
    }

    println!("\n  2. Add path:");
    println!("     allow:");
    println!("       - path: \"{}\"", detection.process_path.display());

    if let Some(process_name) = detection.process_path.file_name() {
        println!("\n  3. Add basename:");
        println!("     allow:");
        println!("       - base: \"{}\"", process_name.to_string_lossy());
    }

    println!("\n  4. Add path pattern:");
    println!("     allow:");
    println!("       - path: \"/Applications/*/Contents/MacOS/*\"");

    if detection
        .team_id
        .as_ref()
        .is_some_and(|t| t.starts_with('*'))
    {
        println!("\n  5. Add platform_binary flag (for Apple system binaries):");
        println!("     allow:");
        println!("       - platform_binary: true");
    }
}

/// Format an allow rule for display
fn format_rule(rule: &AllowRule) -> String {
    let mut parts = Vec::new();

    if let Some(ref team_id) = rule.team_id {
        parts.push(format!("team_id={}", team_id));
    }
    if let Some(ref base) = rule.base {
        parts.push(format!("base={}", base));
    }
    if let Some(ref path) = rule.path {
        parts.push(format!("path={}", path));
    }
    if let Some(ref app_id) = rule.app_id {
        parts.push(format!("app_id={}", app_id));
    }
    if let Some(ppid) = rule.ppid {
        parts.push(format!("ppid={}", ppid));
    }
    if let Some(uid) = rule.uid {
        parts.push(format!("uid={}", uid));
    }
    if let Some(platform) = rule.platform_binary {
        parts.push(format!("platform_binary={}", platform));
    }

    if parts.is_empty() {
        "empty rule".to_string()
    } else {
        format!("\"{}\"", parts.join(", "))
    }
}
