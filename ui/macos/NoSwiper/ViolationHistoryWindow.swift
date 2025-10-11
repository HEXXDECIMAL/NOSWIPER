//
//  ViolationHistoryWindow.swift
//  NoSwiper
//
//  Window for viewing violation history.
//

import SwiftUI
import AppKit

class ViolationHistoryWindowController: NSWindowController {
    convenience init(events: [ViolationEvent]) {
        let window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 800, height: 500),
            styleMask: [.titled, .closable, .resizable],
            backing: .buffered,
            defer: false
        )
        window.title = "Recent Violations"
        window.center()

        let view = ViolationHistoryView(events: events)
        window.contentView = NSHostingView(rootView: view)

        self.init(window: window)
    }
}

struct ViolationHistoryView: View {
    let events: [ViolationEvent]
    @Environment(\.dismiss) var dismiss

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            // Header
            HStack {
                if #available(macOS 11.0, *) {
                    Image(systemName: "clock.arrow.circlepath")
                        .font(.system(size: 24))
                        .foregroundColor(.blue)
                }
                VStack(alignment: .leading, spacing: 4) {
                    Text("Recent Violations")
                        .font(.headline)
                    Text("\(events.count) credential access attempts")
                        .font(.caption)
                        .foregroundColor(.secondary)
                }
                Spacer()
            }
            .padding(.bottom, 8)

            Divider()

            // Content
            if events.isEmpty {
                VStack(spacing: 12) {
                    if #available(macOS 11.0, *) {
                        Image(systemName: "checkmark.shield")
                            .font(.system(size: 48))
                            .foregroundColor(.green)
                    }
                    Text("No Violations")
                        .font(.title3)
                    Text("All credential access has been authorized")
                        .font(.caption)
                        .foregroundColor(.secondary)
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                ScrollView {
                    VStack(alignment: .leading, spacing: 12) {
                        ForEach(events, id: \.id) { event in
                            ViolationRow(event: event)
                        }
                    }
                    .padding()
                }
                .background(Color(NSColor.textBackgroundColor))
                .cornerRadius(8)
            }

            Divider()

            // Footer
            HStack {
                Text("Showing most recent \(events.count) violations")
                    .font(.caption)
                    .foregroundColor(.secondary)

                Spacer()

                Button("Close") {
                    NSApp.keyWindow?.close()
                }
                .keyboardShortcut(.cancelAction)
            }
        }
        .padding(20)
        .frame(minWidth: 700, minHeight: 400)
    }
}

struct ViolationRow: View {
    let event: ViolationEvent

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                // Icon based on action
                if #available(macOS 11.0, *) {
                    Image(systemName: iconName)
                        .foregroundColor(iconColor)
                }

                VStack(alignment: .leading, spacing: 2) {
                    HStack {
                        Text(processName)
                            .font(.system(.body, design: .monospaced))
                            .fontWeight(.medium)
                        Spacer()
                        Text(formattedTime)
                            .font(.caption)
                            .foregroundColor(.secondary)
                    }

                    Text(event.filePath)
                        .font(.caption)
                        .foregroundColor(.secondary)
                        .lineLimit(1)
                }
            }

            if let action = event.action {
                HStack {
                    Text(action.uppercased())
                        .font(.caption2)
                        .padding(.horizontal, 6)
                        .padding(.vertical, 2)
                        .background(actionColor.opacity(0.2))
                        .foregroundColor(actionColor)
                        .cornerRadius(4)

                    if let ruleName = event.ruleName {
                        Text("Rule: \(ruleName)")
                            .font(.caption2)
                            .foregroundColor(.secondary)
                    }
                }
            }
        }
        .padding()
        .background(Color(NSColor.controlBackgroundColor))
        .cornerRadius(8)
    }

    private var processName: String {
        URL(fileURLWithPath: event.processPath).lastPathComponent
    }

    private var formattedTime: String {
        // Parse ISO 8601 timestamp
        let formatter = ISO8601DateFormatter()
        if let date = formatter.date(from: event.timestamp) {
            let displayFormatter = DateFormatter()
            displayFormatter.dateStyle = .short
            displayFormatter.timeStyle = .medium
            return displayFormatter.string(from: date)
        }
        return event.timestamp
    }

    private var iconName: String {
        switch event.action {
        case "blocked":
            return "xmark.shield"
        case "allowed":
            return "checkmark.shield"
        default:
            return "exclamationmark.triangle"
        }
    }

    private var iconColor: Color {
        switch event.action {
        case "blocked":
            return .red
        case "allowed":
            return .green
        default:
            return .orange
        }
    }

    private var actionColor: Color {
        switch event.action {
        case "blocked":
            return .red
        case "allowed":
            return .green
        default:
            return .orange
        }
    }
}
