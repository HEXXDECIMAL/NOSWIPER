use anyhow::Result;
use noswiper::allow_rule::AllowRule;
use noswiper::config::Config;
use noswiper::process_context::ProcessContext;
use std::env;
use std::path::{Path, PathBuf};

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

    // Parse the log line
    let parts = parse_log_line(log_line)?;

    println!("Parsed Detection:");
    println!("  Rule: {}", parts.rule_name);
    println!("  File: {}", parts.file_path);
    println!("  Process: {}", parts.process_path);
    println!("  Arguments: {}", parts.args);
    println!("  Team ID: {}", parts.team_id);
    println!("  PID: {}", parts.pid);
    println!("  UID: {}", parts.uid);
    println!();

    // Load config
    let config = Config::default()?;

    // Find matching protected file rule
    let mut found_rule = false;
    for protected_file in &config.protected_files {
        let unnamed = "unnamed".to_string();
        let rule_id = protected_file.id.as_ref().unwrap_or(&unnamed);

        // Check if this rule's paths match the accessed file
        for path_pattern in &protected_file.paths {
            let expanded = shellexpand::tilde(path_pattern).to_string();
            if Path::new(&parts.file_path).starts_with(&expanded)
                || glob::Pattern::new(&expanded)
                    .ok()
                    .map_or(false, |p| p.matches(&parts.file_path))
            {
                println!("Rule Configuration: {}", rule_id);
                println!("  Protected Path Pattern: {}", path_pattern);
                println!("    ✓ MATCHES: {}", parts.file_path);
                found_rule = true;

                // Create process context for matching
                let process_context = ProcessContext {
                    path: PathBuf::from(&parts.process_path),
                    args: if parts.args.is_empty() {
                        None
                    } else {
                        Some(parts.args.split_whitespace().map(String::from).collect())
                    },
                    pid: Some(parts.pid),
                    ppid: Some(1), // Default to launchd, would need to parse from log if available
                    uid: Some(parts.uid),
                    euid: Some(parts.uid),
                    team_id: if parts.team_id.is_empty() {
                        None
                    } else {
                        Some(parts.team_id.clone())
                    },
                    app_id: None, // Would need to get this from somewhere
                    platform_binary: None,
                };

                // Check allow rules
                println!("\n  Allow Rules for this protected file:");
                let mut allowed = false;
                for (idx, allow_rule) in protected_file.allow_rules.iter().enumerate() {
                    println!("    Rule #{}: {:?}", idx + 1, format_rule(allow_rule));

                    if allow_rule.matches_with_config_and_debug(
                        &process_context,
                        Some(&config),
                        true,
                    ) {
                        println!("      ✓ MATCHES - Access would be ALLOWED");
                        allowed = true;
                        break;
                    }
                }

                if !allowed {
                    println!("\n❌ NO ALLOW RULES MATCHED - Access would be BLOCKED");

                    // Suggest potential fixes
                    println!(
                        "\nPotential fixes - add one of these to the '{}' rule:",
                        rule_id
                    );

                    if !parts.team_id.is_empty() {
                        println!("\n  1. Add team_id (most secure):");
                        println!("     allow:");
                        println!("       - team_id: \"{}\"", parts.team_id);
                    }

                    println!("\n  2. Add path:");
                    println!("     allow:");
                    println!("       - path: \"{}\"", parts.process_path);

                    let process_name = Path::new(&parts.process_path)
                        .file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or("");

                    println!("\n  3. Add basename:");
                    println!("     allow:");
                    println!("       - base: \"{}\"", process_name);

                    println!("\n  4. Add path pattern:");
                    println!("     allow:");
                    println!("       - path: \"/Applications/*/Contents/MacOS/*\"");
                } else {
                    println!("\n✅ Access would be ALLOWED");
                }

                break;
            }
        }
    }

    if !found_rule {
        println!("⚠️  No protected file rule found for: {}", parts.file_path);
        println!("   This file may not be in the protected files list.");
    }

    Ok(())
}

struct LogParts {
    rule_name: String,
    file_path: String,
    process_path: String,
    args: String,
    team_id: String,
    pid: u32,
    uid: u32,
}

fn parse_log_line(line: &str) -> Result<LogParts> {
    // Example: DETECTED[keychain]: /Users/t/Library/Keychains/login.keychain-db open: /Applications/Spotify.app/Contents/MacOS/Spotify --autostart [2FNC3A47ZF:1408@501]→/sbin/launchd

    // Extract rule name
    let rule_start = line
        .find("DETECTED[")
        .ok_or_else(|| anyhow::anyhow!("Invalid log format: missing 'DETECTED['"))?;
    let rule_end = line[rule_start..]
        .find(']')
        .ok_or_else(|| anyhow::anyhow!("Invalid log format: missing ']'"))?;
    let rule_name = line[rule_start + 9..rule_start + rule_end].to_string();

    // Find the colon after the rule
    let content_start = rule_start + rule_end + 3; // Skip "]: "
    let content = &line[content_start..];

    // Split by " open: " to get file path and the rest
    let parts: Vec<&str> = content.splitn(2, " open: ").collect();
    if parts.len() != 2 {
        return Err(anyhow::anyhow!("Invalid log format: missing ' open: '"));
    }

    let file_path = parts[0].to_string();
    let process_part = parts[1];

    // Extract team_id and pid/uid info from brackets
    let bracket_start = process_part
        .find('[')
        .ok_or_else(|| anyhow::anyhow!("Invalid log format: missing '['"))?;
    let bracket_end = process_part
        .find(']')
        .ok_or_else(|| anyhow::anyhow!("Invalid log format: missing ']'"))?;

    let process_and_args = process_part[..bracket_start].trim().to_string();
    let bracket_content = &process_part[bracket_start + 1..bracket_end];

    // Parse team_id:pid@uid or just pid@uid
    let (team_id, pid_uid_part) = if bracket_content.contains(':') {
        let parts: Vec<&str> = bracket_content.splitn(2, ':').collect();
        (parts[0].to_string(), parts[1])
    } else {
        (String::new(), bracket_content)
    };

    let pid_uid: Vec<&str> = pid_uid_part.split('@').collect();
    let pid = pid_uid[0].parse::<u32>().unwrap_or(0);
    let uid = if pid_uid.len() == 2 {
        pid_uid[1].parse::<u32>().unwrap_or(501)
    } else {
        501
    };

    // Split process path and arguments
    let process_parts: Vec<&str> = process_and_args.splitn(2, ' ').collect();
    let process_path = process_parts[0].to_string();
    let args = if process_parts.len() > 1 {
        process_parts[1].to_string()
    } else {
        String::new()
    };

    Ok(LogParts {
        rule_name,
        file_path,
        process_path,
        args,
        team_id,
        pid,
        uid,
    })
}

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

    if parts.is_empty() {
        "empty rule".to_string()
    } else {
        parts.join(", ")
    }
}
