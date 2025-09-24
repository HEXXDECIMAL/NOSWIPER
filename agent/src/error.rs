//! Error types for NoSwiper credential protection.
//!
//! This module provides comprehensive error handling for all NoSwiper operations,
//! with detailed error messages and proper error context propagation.

use std::fmt;

/// Main error type for NoSwiper operations.
#[derive(Debug)]
pub enum NoSwiperError {
    /// Configuration-related errors
    Config(ConfigError),
    /// Process monitoring errors
    Monitor(MonitorError),
    /// I/O errors
    Io(std::io::Error),
    /// Permission or privilege errors
    Permission(PermissionError),
}

/// Configuration-related errors.
#[derive(Debug)]
pub enum ConfigError {
    /// Invalid YAML syntax in configuration file
    InvalidYaml(serde_yaml::Error),
    /// Configuration file not found
    FileNotFound(std::path::PathBuf),
    /// Configuration validation failed
    Validation(String),
}

/// Process monitoring errors.
#[derive(Debug)]
pub enum MonitorError {
    /// Failed to start monitoring process
    StartupFailed(String),
}

/// Permission or privilege errors.
#[derive(Debug)]
pub enum PermissionError {
    /// Not running as root when required
    NotRoot,
}

impl fmt::Display for NoSwiperError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NoSwiperError::Config(err) => write!(f, "Configuration error: {}", err),
            NoSwiperError::Monitor(err) => write!(f, "Monitor error: {}", err),
            NoSwiperError::Io(err) => write!(f, "I/O error: {}", err),
            NoSwiperError::Permission(err) => write!(f, "Permission error: {}", err),
        }
    }
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConfigError::InvalidYaml(err) => write!(f, "Invalid YAML: {}", err),
            ConfigError::FileNotFound(path) => {
                write!(f, "Configuration file not found: {}", path.display())
            }
            ConfigError::Validation(msg) => write!(f, "Validation failed: {}", msg),
        }
    }
}

impl fmt::Display for MonitorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MonitorError::StartupFailed(msg) => write!(f, "Monitor startup failed: {}", msg),
        }
    }
}

impl fmt::Display for PermissionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PermissionError::NotRoot => {
                write!(
                    f,
                    "NoSwiper daemon requires root privileges to monitor file access"
                )
            }
        }
    }
}

impl std::error::Error for NoSwiperError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            NoSwiperError::Config(err) => Some(err),
            NoSwiperError::Monitor(err) => Some(err),
            NoSwiperError::Io(err) => Some(err),
            NoSwiperError::Permission(err) => Some(err),
        }
    }
}

impl std::error::Error for ConfigError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ConfigError::InvalidYaml(err) => Some(err),
            _ => None,
        }
    }
}

impl std::error::Error for MonitorError {}
impl std::error::Error for PermissionError {}

// Conversion implementations for easier error propagation
impl From<std::io::Error> for NoSwiperError {
    fn from(err: std::io::Error) -> Self {
        NoSwiperError::Io(err)
    }
}

impl From<serde_yaml::Error> for NoSwiperError {
    fn from(err: serde_yaml::Error) -> Self {
        NoSwiperError::Config(ConfigError::InvalidYaml(err))
    }
}

impl From<ConfigError> for NoSwiperError {
    fn from(err: ConfigError) -> Self {
        NoSwiperError::Config(err)
    }
}

impl From<MonitorError> for NoSwiperError {
    fn from(err: MonitorError) -> Self {
        NoSwiperError::Monitor(err)
    }
}

impl From<PermissionError> for NoSwiperError {
    fn from(err: PermissionError) -> Self {
        NoSwiperError::Permission(err)
    }
}

// Conversion from anyhow::Error for compatibility
impl From<anyhow::Error> for NoSwiperError {
    fn from(err: anyhow::Error) -> Self {
        NoSwiperError::Monitor(MonitorError::StartupFailed(err.to_string()))
    }
}

/// Convenience type alias for Results using NoSwiperError
pub type Result<T> = std::result::Result<T, NoSwiperError>;

/// Helper macros for creating specific error types
#[macro_export]
macro_rules! config_error {
    ($msg:expr) => {
        crate::error::NoSwiperError::Config(crate::error::ConfigError::Validation($msg.to_string()))
    };
}

#[macro_export]
macro_rules! monitor_error {
    ($msg:expr) => {
        crate::error::NoSwiperError::Monitor(crate::error::MonitorError::StartupFailed(
            $msg.to_string(),
        ))
    };
}

#[macro_export]
macro_rules! permission_error {
    ($msg:expr) => {
        crate::error::NoSwiperError::Permission(
            crate::error::PermissionError::InsufficientPrivileges($msg.to_string()),
        )
    };
}
