//! Violation dialog window for displaying security violations and allowing user actions

use crate::ipc_client::{EventType, IpcClient, ProcessTreeEntry};
use eframe::egui;
use std::sync::Arc;

/// Actions the user can take on a violation
#[derive(Debug, Clone, PartialEq)]
pub enum ViolationAction {
    AllowOnce,
    Kill,
    AllowPermanently,
    Dismiss,
}

/// Violation dialog window
pub struct ViolationDialog {
    event_id: String,
    rule_name: String,
    file_path: String,
    process_path: String,
    process_pid: u32,
    process_cmdline: Option<String>,
    process_tree: Option<Vec<ProcessTreeEntry>>,
    team_id: Option<String>,
    action: Option<ViolationAction>,
    client: Arc<IpcClient>,
}

impl ViolationDialog {
    /// Create a new violation dialog from an event
    pub fn new(event_id: String, event: &EventType, client: Arc<IpcClient>) -> Option<Self> {
        match event {
            EventType::AccessDenied {
                rule_name,
                file_path,
                process_path,
                process_pid,
                process_cmdline,
                process_tree,
                team_id,
                ..
            } => Some(Self {
                event_id,
                rule_name: rule_name.clone(),
                file_path: file_path.clone(),
                process_path: process_path.clone(),
                process_pid: *process_pid,
                process_cmdline: process_cmdline.clone(),
                process_tree: process_tree.clone(),
                team_id: team_id.clone(),
                action: None,
                client,
            }),
            _ => None,
        }
    }

    /// Show the dialog and handle user interaction
    pub fn show(self) {
        let options = eframe::NativeOptions {
            viewport: egui::ViewportBuilder::default()
                .with_title("NoSwiper Security Violation")
                .with_inner_size([600.0, 400.0])
                .with_resizable(false)
                .with_always_on_top(),
            ..Default::default()
        };

        let _ = eframe::run_native(
            "NoSwiper Violation",
            options,
            Box::new(|_cc| Ok(Box::new(self))),
        );
    }

    /// Format the process tree for display
    fn format_process_tree(&self) -> String {
        if let Some(ref tree) = self.process_tree {
            let mut result = String::new();
            for (i, entry) in tree.iter().enumerate() {
                let indent = "  ".repeat(i);
                let arrow = if i == 0 { "▶" } else { "└─" };
                result.push_str(&format!(
                    "{}{} {} (PID: {})",
                    indent, arrow, entry.name, entry.pid
                ));
                if let Some(ref cmd) = entry.cmdline {
                    if cmd.len() < 100 {
                        result.push_str(&format!("\n{}   {}", indent, cmd));
                    }
                }
                result.push('\n');
            }
            result
        } else {
            format!(
                "▶ {} (PID: {})",
                self.process_path
                    .split('/')
                    .last()
                    .unwrap_or(&self.process_path),
                self.process_pid
            )
        }
    }
}

impl eframe::App for ViolationDialog {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::CentralPanel::default().show(ctx, |ui| {
            // Title
            ui.heading("🚨 Security Violation Detected");
            ui.separator();
            ui.add_space(10.0);

            // Violation details
            ui.horizontal(|ui| {
                ui.label("Process:");
                ui.strong(&self.process_path);
                ui.label(format!("(PID: {})", self.process_pid));
            });

            ui.horizontal(|ui| {
                ui.label("Attempted to access:");
                ui.strong(&self.file_path);
            });

            ui.horizontal(|ui| {
                ui.label("Rule violated:");
                ui.strong(&self.rule_name);
            });

            if let Some(ref team_id) = self.team_id {
                ui.horizontal(|ui| {
                    ui.label("Team ID:");
                    ui.strong(team_id);
                });
            }

            ui.add_space(10.0);
            ui.separator();
            ui.add_space(10.0);

            // Process tree
            ui.label("Process Hierarchy:");
            egui::ScrollArea::vertical()
                .max_height(150.0)
                .show(ui, |ui| {
                    ui.add(
                        egui::TextEdit::multiline(&mut self.format_process_tree().as_str())
                            .font(egui::TextStyle::Monospace)
                            .desired_rows(6)
                            .interactive(false),
                    );
                });

            ui.add_space(10.0);

            // Command line if available
            if let Some(ref cmdline) = self.process_cmdline {
                ui.label("Command line:");
                ui.add(
                    egui::TextEdit::singleline(&mut cmdline.as_str())
                        .font(egui::TextStyle::Monospace)
                        .interactive(false),
                );
                ui.add_space(10.0);
            }

            ui.separator();
            ui.add_space(10.0);

            // Action buttons
            ui.horizontal(|ui| {
                ui.add_space(50.0);

                if ui.button("✅ Allow Once").clicked() {
                    self.action = Some(ViolationAction::AllowOnce);
                }

                if ui.button("❌ Kill Process").clicked() {
                    self.action = Some(ViolationAction::Kill);
                }

                if ui.button("✓ Allow Permanently").clicked() {
                    self.action = Some(ViolationAction::AllowPermanently);
                }

                if ui.button("Dismiss").clicked() {
                    self.action = Some(ViolationAction::Dismiss);
                }
            });

            // Handle action if one was selected
            if let Some(ref action) = self.action {
                match action {
                    ViolationAction::AllowOnce => {
                        log::info!("User chose to allow process {} once", self.process_pid);
                        if let Err(e) = self.client.continue_process(&self.event_id) {
                            log::error!("Failed to continue process: {}", e);
                        }
                    }
                    ViolationAction::Kill => {
                        log::info!("User chose to kill process {}", self.process_pid);
                        if let Err(e) = self.client.kill_process(&self.event_id) {
                            log::error!("Failed to kill process: {}", e);
                        }
                    }
                    ViolationAction::AllowPermanently => {
                        log::info!(
                            "User chose to permanently allow {} -> {}",
                            self.process_path,
                            self.file_path
                        );
                        if let Err(e) = self.client.add_to_whitelist(&self.event_id) {
                            log::error!("Failed to add to whitelist: {}", e);
                        }
                    }
                    ViolationAction::Dismiss => {
                        log::info!("User dismissed violation dialog");
                    }
                }
                ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            }
        });
    }
}
