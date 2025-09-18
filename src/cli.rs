use clap::{Parser, ValueEnum};

#[derive(Parser)]
#[command(name = "noswiper-agent")]
#[command(about = "Simple Rust-based credential protection agent")]
#[command(version)]
pub struct Args {
    /// Run in monitor-only mode (log access attempts but don't block)
    #[arg(long)]
    pub monitor: bool,

    /// Run in interactive mode (prompt user via CLI for decisions)
    #[arg(long)]
    pub interactive: bool,

    /// Monitoring mechanism to use
    #[arg(long, value_enum)]
    pub mechanism: Option<Mechanism>,

    /// Log level
    #[arg(long, value_enum, default_value = "info")]
    pub log_level: LogLevel,

    /// Configuration file path (optional)
    #[arg(long)]
    pub config: Option<std::path::PathBuf>,

    /// Show current configuration and exit
    #[arg(long)]
    pub show_config: bool,

    /// Validate configuration file and exit
    #[arg(long)]
    pub validate_config: Option<std::path::PathBuf>,
}

#[derive(Clone, ValueEnum)]
pub enum Mechanism {
    /// Automatically select the best available mechanism
    Auto,

    #[cfg(target_os = "macos")]
    /// Use eslogger command (easier, no entitlements required)
    Eslogger,

    #[cfg(target_os = "macos")]
    /// Use Endpoint Security Framework (faster, requires entitlements)
    Esf,

    #[cfg(target_os = "linux")]
    /// Use fanotify (simpler, works on older kernels)
    Fanotify,

    #[cfg(target_os = "linux")]
    /// Use eBPF (more powerful, requires newer kernel)
    Ebpf,
}

#[derive(Clone, ValueEnum)]
pub enum LogLevel {
    Debug,
    Info,
    Warn,
    Error,
}

#[derive(Debug, Clone, Copy)]
pub enum Mode {
    Monitor,     // Just log access attempts
    Enforce,     // Block unauthorized access silently
    Interactive, // Block and prompt user via CLI
}

impl Args {
    pub fn get_mode(&self) -> Mode {
        if self.interactive {
            Mode::Interactive
        } else if self.monitor {
            Mode::Monitor
        } else {
            // Default to enforce mode
            Mode::Enforce
        }
    }

    pub fn get_mechanism(&self) -> Mechanism {
        self.mechanism.clone().unwrap_or(Mechanism::Auto)
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        // Only one mode can be active
        let mode_count = [self.monitor, self.interactive]
            .iter()
            .filter(|&&x| x)
            .count();

        if mode_count > 1 {
            return Err(anyhow::anyhow!(
                "Only one mode can be specified: --monitor or --interactive"
            ));
        }

        // Validate mechanism is available on this platform
        // Note: Platform-specific validation is done at runtime

        Ok(())
    }
}

impl std::fmt::Display for Mode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Mode::Monitor => write!(f, "monitor"),
            Mode::Enforce => write!(f, "enforce"),
            Mode::Interactive => write!(f, "interactive"),
        }
    }
}

impl std::fmt::Display for Mechanism {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Mechanism::Auto => write!(f, "auto"),
            #[cfg(target_os = "macos")]
            Mechanism::Eslogger => write!(f, "eslogger"),
            #[cfg(target_os = "macos")]
            Mechanism::Esf => write!(f, "esf"),
            #[cfg(target_os = "linux")]
            Mechanism::Fanotify => write!(f, "fanotify"),
            #[cfg(target_os = "linux")]
            Mechanism::Ebpf => write!(f, "ebpf"),
        }
    }
}

impl From<LogLevel> for log::LevelFilter {
    fn from(level: LogLevel) -> Self {
        match level {
            LogLevel::Debug => log::LevelFilter::Debug,
            LogLevel::Info => log::LevelFilter::Info,
            LogLevel::Warn => log::LevelFilter::Warn,
            LogLevel::Error => log::LevelFilter::Error,
        }
    }
}
