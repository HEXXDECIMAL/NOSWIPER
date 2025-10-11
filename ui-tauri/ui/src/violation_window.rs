use egui::{Align2, Context, Id, Vec2};

use crate::ipc_client::Violation;
use crate::ViolationAction;

pub struct ViolationWindow {
    violation: Violation,
    is_open: bool,
    id: Id,
}

impl ViolationWindow {
    pub fn new(violation: Violation) -> Self {
        Self {
            violation,
            is_open: true,
            id: Id::new("violation_popup"),
        }
    }

    pub fn is_open(&self) -> bool {
        self.is_open
    }

    pub fn show(&mut self, ctx: &Context) -> Option<(Violation, ViolationAction)> {
        let mut result = None;

        egui::Window::new("Security Violation Detected")
            .id(self.id)
            .resizable(false)
            .collapsible(false)
            .anchor(Align2::CENTER_CENTER, Vec2::ZERO)
            .fixed_size(Vec2::new(450.0, 320.0))
            .open(&mut self.is_open)
            .show(ctx, |ui| {
                // Warning header
                ui.vertical_centered(|ui| {
                    ui.heading("⚠️ Credential Access Blocked");
                });

                ui.separator();

                // Violation details
                ui.group(|ui| {
                    ui.vertical(|ui| {
                        ui.strong("Process Information:");
                        ui.add_space(4.0);

                        ui.horizontal(|ui| {
                            ui.label("Name:");
                            ui.monospace(&self.violation.process_name);
                        });

                        ui.horizontal(|ui| {
                            ui.label("PID:");
                            ui.monospace(self.violation.pid.to_string());
                        });

                        ui.horizontal(|ui| {
                            ui.label("Path:");
                            ui.label(shorten_path(&self.violation.process_path, 45));
                        });
                    });
                });

                ui.add_space(8.0);

                ui.group(|ui| {
                    ui.vertical(|ui| {
                        ui.strong("Attempted to access:");
                        ui.add_space(4.0);
                        ui.label(shorten_path(&self.violation.file_path, 50));
                    });
                });

                ui.add_space(8.0);

                // Explanation
                ui.label("This application tried to access sensitive credentials.");
                ui.label("The process has been temporarily suspended.");

                ui.add_space(12.0);

                // Action buttons
                ui.vertical_centered(|ui| {
                    ui.horizontal(|ui| {
                        ui.spacing_mut().button_padding = Vec2::new(10.0, 5.0);

                        // Allow Once button
                        if ui.button("Allow Once").clicked() {
                            result = Some((self.violation.clone(), ViolationAction::Allow));
                            self.is_open = false;
                        }

                        // Kill Process button (red)
                        ui.visuals_mut().override_text_color = Some(egui::Color32::from_rgb(200, 50, 50));
                        if ui.button("Kill Process").clicked() {
                            result = Some((self.violation.clone(), ViolationAction::Kill));
                            self.is_open = false;
                        }
                        ui.visuals_mut().override_text_color = None;

                        // Whitelist button (green)
                        ui.visuals_mut().override_text_color = Some(egui::Color32::from_rgb(50, 150, 50));
                        if ui.button("Always Allow").clicked() {
                            result = Some((self.violation.clone(), ViolationAction::Whitelist));
                            self.is_open = false;
                        }
                        ui.visuals_mut().override_text_color = None;
                    });

                    ui.add_space(8.0);

                    // Help text
                    ui.small("• Allow Once: Resume this process for this access only");
                    ui.small("• Kill Process: Terminate the application immediately");
                    ui.small("• Always Allow: Add to whitelist and allow all future access");
                });
            });

        result
    }
}

fn shorten_path(path: &str, max_len: usize) -> String {
    if path.len() <= max_len {
        return path.to_string();
    }

    let parts: Vec<&str> = path.split('/').collect();
    if parts.len() <= 3 {
        return format!("...{}", &path[path.len() - max_len + 3..]);
    }

    // Try to keep first and last parts
    let start = parts[0..2].join("/");
    let end = parts[parts.len() - 2..].join("/");
    let middle = "...";

    let result = format!("{}/{}.../{}", start, middle, end);
    if result.len() > max_len {
        format!("...{}", &path[path.len() - max_len + 3..])
    } else {
        result
    }
}