pub mod allow_rule;
pub mod config;
pub mod process_context;
pub mod rules;

pub mod matcher {
    use crate::allow_rule::AllowRule;
    use crate::process_context::ProcessContext;

    pub struct ProcessInfo {
        pub path: String,
        pub signature: Option<String>,
        pub pid: u32,
        pub uid: u32,
        pub name: String,
    }

    pub struct RuleMatcher;
}
