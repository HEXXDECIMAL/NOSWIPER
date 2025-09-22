use clap::Parser;
use noswiper_agent::config::Config;
use noswiper_agent::process_context::ProcessContext;
use regex::Regex;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "debug-rule")]
#[command(about = "Debug why a process was blocked or allowed to access a protected file")]
struct Args {
    /// Log message to parse (e.g., "OK[keychain]: /path/to/file open: process [TeamID:PID@EUID]→parent")
    /// Or individual parameters can be specified
    log_message: Option<String>,

    /// The protected file path that was accessed (if not using log message)
    #[arg(short = 'f', long)]
    file: Option<String>,

    /// The process executable path (if not using log message)
    #[arg(short = 'p', long)]
    process: Option<String>,

    /// The process team ID (macOS) (if not using log message)
    #[arg(short = 't', long)]
    team_id: Option<String>,

    /// The process app ID (macOS) (if not using log message)
    #[arg(short = 'a', long)]
    app_id: Option<String>,

    /// The effective user ID (if not using log message)
    #[arg(short = 'e', long)]
    euid: Option<u32>,

    /// The user ID (if not using log message)
    #[arg(short = 'u', long)]
    uid: Option<u32>,

    /// The parent process ID (if not using log message)
    #[arg(long)]
    ppid: Option<u32>,

    /// Process arguments (if not using log message)
    #[arg(long)]
    args: Vec<String>,

    /// Is this a platform binary? (if not using log message)
    #[arg(long)]
    platform_binary: Option<bool>,

    /// Config file to use (defaults to built-in)
    #[arg(short = 'c', long)]
    config: Option<PathBuf>,
}

struct ParsedLogEntry {
    status: String,  // "OK" or "DETECTED"
    rule_id: String, // e.g., "keychain"
    file_path: String,
    operation: String, // "open" or "exec"
    process_path: String,
    team_id: Option<String>,
    pid: Option<u32>,
    euid: Option<u32>,
    parent: Option<String>,
    ppid: Option<u32>,
}

fn parse_log_message(message: &str) -> Option<ParsedLogEntry> {
    // Parse messages like:
    // "OK[keychain]: /Users/t/Library/Keychains/login.keychain-db open: security [Apple:9730@501]→clau"
    // "DETECTED[keychain]: /Users/t/Library/Keychains/login.keychain-db open: /Applications/Spotify.app/Contents/MacOS/Spotify --autostart [2FNC3A47ZF:1408@501]→/sbin/launchd"

    let re = Regex::new(r"^(OK|DETECTED)\[([^\]]+)\]:\s+([^\s]+)\s+(open|exec):\s+(.+?)(?:\s+--[^\[]+)?\s*\[([^\]]+)\](?:→(.+))?$").ok()?;

    let caps = re.captures(message)?;

    let status = caps.get(1)?.as_str().to_string();
    let rule_id = caps.get(2)?.as_str().to_string();
    let file_path = caps.get(3)?.as_str().to_string();
    let operation = caps.get(4)?.as_str().to_string();
    let process_path = caps.get(5)?.as_str().trim().to_string();
    let process_info = caps.get(6)?.as_str();
    let parent = caps.get(7).map(|m| m.as_str().to_string());

    // Parse process info like "2FNC3A47ZF:1408@501" or "Apple:9730@501"
    let info_re = Regex::new(r"^([^:]+):(\d+)@(\d+)$").ok()?;
    let info_caps = info_re.captures(process_info)?;

    let team_id = Some(info_caps.get(1)?.as_str().to_string());
    let pid = info_caps.get(2)?.as_str().parse().ok();
    let euid = info_caps.get(3)?.as_str().parse().ok();

    // Try to determine ppid
    let ppid = if let Some(ref parent_str) = parent {
        if parent_str == "/sbin/launchd" || parent_str == "launchd" {
            Some(1)
        } else {
            None
        }
    } else {
        None
    };

    Some(ParsedLogEntry {
        status,
        rule_id,
        file_path,
        operation,
        process_path,
        team_id,
        pid,
        euid,
        parent,
        ppid,
    })
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logger
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("debug")).init();

    let args = Args::parse();

    // Load configuration
    let config = if let Some(config_path) = args.config {
        Config::from_file(&config_path)?
    } else {
        Config::load()?
    };

    // Parse log message or use individual arguments
    let (file_path, context, rule_id, status) = if let Some(log_msg) = args.log_message {
        if let Some(parsed) = parse_log_message(&log_msg) {
            println!("=== Parsed Log Entry ===");
            println!("Status: {}", parsed.status);
            println!("Rule ID: {}", parsed.rule_id);
            println!("File: {}", parsed.file_path);
            println!("Operation: {}", parsed.operation);
            println!("Process: {}", parsed.process_path);
            println!("Team ID: {:?}", parsed.team_id);
            println!("PID: {:?}", parsed.pid);
            println!("EUID: {:?}", parsed.euid);
            println!("Parent: {:?}", parsed.parent);
            println!("PPID: {:?}", parsed.ppid);
            println!();

            let context = ProcessContext {
                path: PathBuf::from(&parsed.process_path),
                pid: parsed.pid,
                ppid: parsed.ppid,
                uid: None, // Not in log format
                euid: parsed.euid,
                args: None, // Could parse from process_path if needed
                team_id: parsed.team_id,
                app_id: None, // Not in log format
                platform_binary: if parsed.team_id == Some("Apple".to_string()) {
                    Some(true)
                } else {
                    None
                },
            };

            (
                parsed.file_path,
                context,
                Some(parsed.rule_id),
                Some(parsed.status),
            )
        } else {
            eprintln!("Failed to parse log message. Please check the format.");
            std::process::exit(1);
        }
    } else if let (Some(file), Some(process)) = (args.file, args.process) {
        let context = ProcessContext {
            path: PathBuf::from(&process),
            pid: Some(1234), // Dummy PID for testing
            ppid: args.ppid,
            uid: args.uid,
            euid: args.euid,
            args: if args.args.is_empty() {
                None
            } else {
                Some(args.args)
            },
            team_id: args.team_id,
            app_id: args.app_id,
            platform_binary: args.platform_binary,
        };
        (file, context, None, None)
    } else {
        eprintln!("Please provide either a log message or both --file and --process");
        std::process::exit(1);
    };

    println!("=== Debug Rule Matching ===\n");
    println!("File: {}", file_path);
    println!("Process: {}", context.path.display());
    println!("Context: {:#?}\n", context);

    if let Some(ref expected_status) = status {
        println!("Expected result: {}\n", expected_status);
    }

    // Find which protected file rule matches
    let mut rule_matched = false;
    for protected_file in &config.protected_files {
        // If we have a rule_id from the log, check if it matches
        if let Some(ref log_rule_id) = rule_id {
            if protected_file.id.as_deref() != Some(log_rule_id) {
                continue;
            }
        }

        for pattern in &protected_file.paths {
            let expanded = shellexpand::tilde(pattern);
            if let Ok(glob_pattern) = glob::Pattern::new(&expanded) {
                let file_expanded = shellexpand::tilde(&file_path);
                if glob_pattern.matches(&file_expanded) {
                    println!(
                        "✓ File matches protected rule: {} ({})",
                        protected_file.id.as_deref().unwrap_or("unnamed"),
                        pattern
                    );
                    rule_matched = true;

                    println!(
                        "\n  Checking {} allow rules:",
                        protected_file.allow_rules.len()
                    );

                    let mut any_rule_matched = false;
                    for (i, rule) in protected_file.allow_rules.iter().enumerate() {
                        println!("\n  Rule #{} - {:?}", i + 1, rule);

                        if rule.matches_with_config_and_debug(&context, Some(&config), true) {
                            println!("  ✅ RULE MATCHES - Access would be ALLOWED");
                            any_rule_matched = true;

                            if let Some(ref expected) = status {
                                if expected == "OK" {
                                    println!("  ✅ This matches the expected OK status!");
                                } else {
                                    println!(
                                        "  ❌ ERROR: Rule matched but log shows DETECTED status!"
                                    );
                                }
                            }
                            break;
                        } else {
                            println!("  ❌ Rule does not match");
                        }
                    }

                    if !any_rule_matched {
                        println!("\n  ⚠️  NO ALLOW RULES MATCHED - Access would be BLOCKED");

                        if let Some(ref expected) = status {
                            if expected == "DETECTED" {
                                println!("  ✅ This matches the expected DETECTED status!");
                            } else {
                                println!("  ❌ ERROR: No rules matched but log shows OK status!");
                            }
                        }
                    }
                }
            }
        }
    }

    if !rule_matched {
        println!(
            "ℹ️  File '{}' does not match any protected file patterns",
            file_path
        );
    }

    // Also check global exclusions
    println!("\n=== Checking Global Exclusions ===");
    let mut globally_excluded = false;
    for (i, exclusion) in config.global_exclusions.iter().enumerate() {
        println!("\nGlobal Exclusion #{}: {:?}", i + 1, exclusion);
        if exclusion.matches_with_config_and_debug(&context, Some(&config), true) {
            println!("✅ MATCHES - Process would be globally excluded from monitoring");
            globally_excluded = true;
            break;
        }
    }

    if globally_excluded && status == Some("DETECTED".to_string()) {
        println!("\n❌ ERROR: Process is globally excluded but was DETECTED!");
    }

    Ok(())
}
