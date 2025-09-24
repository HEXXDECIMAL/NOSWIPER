//! NoSwiper library - credential protection daemon
//!
//! This crate provides the core functionality for monitoring and protecting
//! sensitive credential files from unauthorized access.

#![allow(clippy::multiple_crate_versions)] // Dependencies have version conflicts
#![allow(clippy::cargo_common_metadata)] // Not publishing to crates.io yet

pub mod allow_rule;
pub mod config;
pub mod error;
pub mod process_context;
pub mod rules;
pub mod types;

/// Matcher module provides types for process matching in debug tools
pub mod matcher {
    /// Information about a process for rule matching
    #[derive(Debug, Clone)]
    pub struct ProcessInfo {
        pub path: String,
        pub signature: Option<String>,
        pub pid: u32,
        pub uid: u32,
        pub name: String,
    }

    /// Placeholder for rule matching functionality
    #[derive(Debug, Clone)]
    pub struct RuleMatcher;
}
