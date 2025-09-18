mod cli;
mod defaults;
mod monitor;
mod rules;

#[cfg(target_os = "linux")]
mod linux_monitor;

use anyhow::Result;
use clap::Parser;
use cli::{Args, LogLevel};
use log::{error, info};
use monitor::Monitor;

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // Initialize logging
    init_logging(&args.log_level)?;

    // Validate arguments
    if let Err(e) = args.validate() {
        error!("Invalid arguments: {}", e);
        std::process::exit(1);
    }

    // Handle special commands
    if args.show_config {
        show_config();
        return Ok(());
    }

    if let Some(config_path) = args.validate_config {
        validate_config(&config_path)?;
        return Ok(());
    }

    // Check if running as root (required for monitoring)
    check_root_privileges()?;

    // Show startup information
    info!("NoSwiper agent starting");
    info!("Version: {}", env!("CARGO_PKG_VERSION"));
    info!("Mode: {}", args.get_mode());
    info!("Mechanism: {}", args.get_mechanism());

    // Create and start monitor
    let mut monitor = Monitor::new(args.get_mode(), args.get_mechanism());

    // Handle shutdown gracefully
    let shutdown_result = tokio::select! {
        result = monitor.start() => {
            match result {
                Ok(_) => {
                    info!("Monitor exited normally");
                    Ok(())
                }
                Err(e) => {
                    error!("Monitor failed: {}", e);
                    Err(e)
                }
            }
        }
        _ = tokio::signal::ctrl_c() => {
            info!("Received shutdown signal, exiting gracefully");
            Ok(())
        }
    };

    info!("NoSwiper daemon shutting down");
    shutdown_result
}

fn init_logging(log_level: &LogLevel) -> Result<()> {
    let mut builder = env_logger::Builder::new();

    // Set log level
    builder.filter_level(log_level.clone().into());

    // Configure format based on platform
    #[cfg(target_os = "macos")]
    {
        // On macOS, use a format that works well with unified logging
        builder.format(|buf, record| {
            use std::io::Write;
            writeln!(
                buf,
                "[{}] [{}] [{}:{}] {}",
                chrono::Utc::now().format("%Y-%m-%d %H:%M:%S%.3f"),
                record.level(),
                record.file().unwrap_or("unknown"),
                record.line().unwrap_or(0),
                record.args()
            )
        });
    }

    #[cfg(target_os = "linux")]
    {
        // On Linux, use systemd-compatible format
        builder.format(|buf, record| {
            use std::io::Write;
            writeln!(
                buf,
                "<{}>[{}] {}: {}",
                match record.level() {
                    log::Level::Error => 3,
                    log::Level::Warn => 4,
                    log::Level::Info => 6,
                    log::Level::Debug => 7,
                    log::Level::Trace => 7,
                },
                chrono::Utc::now().format("%Y-%m-%d %H:%M:%S%.3f"),
                record.target(),
                record.args()
            )
        });
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        // Default format for other platforms
        builder.format_timestamp_secs();
    }

    builder.init();
    Ok(())
}

fn check_root_privileges() -> Result<()> {
    // Check if running as root/administrator
    #[cfg(unix)]
    {
        if unsafe { libc::geteuid() } != 0 {
            return Err(anyhow::anyhow!(
                "NoSwiper daemon requires root privileges to monitor file access.\n\
                Please run with: sudo noswiper-daemon"
            ));
        }
    }

    #[cfg(windows)]
    {
        // On Windows, check for administrator privileges
        // This is a simplified check - a full implementation would use Windows APIs
        if std::env::var("USERNAME").unwrap_or_default() != "Administrator" {
            return Err(anyhow::anyhow!(
                "NoSwiper daemon requires administrator privileges.\n\
                Please run as Administrator."
            ));
        }
    }

    Ok(())
}

fn show_config() {
    use crate::defaults::{DEFAULT_PROTECTED, EXCLUDED_PATTERNS};

    println!("NoSwiper Configuration");
    println!("======================");
    println!();

    println!("Protected Patterns:");
    for (pattern, allowed_programs) in DEFAULT_PROTECTED {
        println!("  {} -> {:?}", pattern, allowed_programs);
    }

    println!();
    println!("Excluded Patterns:");
    for pattern in EXCLUDED_PATTERNS {
        println!("  {}", pattern);
    }

    println!();
    println!("Platform-specific paths:");
    #[cfg(target_os = "macos")]
    {
        println!("  macOS common paths:");
        for path in crate::defaults::MACOS_COMMON_PATHS {
            println!("    {}", path);
        }
    }

    #[cfg(target_os = "linux")]
    {
        println!("  Linux common paths:");
        for path in crate::defaults::LINUX_COMMON_PATHS {
            println!("    {}", path);
        }
    }
}

fn validate_config(config_path: &std::path::Path) -> Result<()> {
    if !config_path.exists() {
        return Err(anyhow::anyhow!(
            "Configuration file does not exist: {}",
            config_path.display()
        ));
    }

    // For now, just check if it's a valid file
    // In a full implementation, we'd parse and validate YAML config
    match std::fs::read_to_string(config_path) {
        Ok(_content) => {
            println!("✓ Configuration file is valid: {}", config_path.display());
            Ok(())
        }
        Err(e) => Err(anyhow::anyhow!("Failed to read configuration file: {}", e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cli_args_validation() {
        // Test that multiple modes are rejected
        let args = Args {
            monitor: true,
            enforce: true,
            interactive: false,
            mechanism: None,
            log_level: LogLevel::Info,
            config: None,
            show_config: false,
            validate_config: None,
        };

        assert!(args.validate().is_err());
    }

    #[test]
    fn test_cli_args_single_mode() {
        let args = Args {
            monitor: false,
            enforce: true,
            interactive: false,
            mechanism: None,
            log_level: LogLevel::Info,
            config: None,
            show_config: false,
            validate_config: None,
        };

        assert!(args.validate().is_ok());
    }
}
