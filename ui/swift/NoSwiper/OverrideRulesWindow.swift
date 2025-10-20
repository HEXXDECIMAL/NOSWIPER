//
//  OverrideRulesWindow.swift
//  NoSwiper
//
//  Window for viewing override rules.
//

import SwiftUI
import AppKit

class OverrideRulesWindowController: NSWindowController {
    convenience init(content: String) {
        let window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 600, height: 400),
            styleMask: [.titled, .closable, .resizable],
            backing: .buffered,
            defer: false
        )
        window.title = "Override Rules"
        window.center()

        let view = OverrideRulesView(content: content)
        window.contentView = NSHostingView(rootView: view)

        self.init(window: window)
    }
}

struct OverrideRulesView: View {
    let content: String
    @Environment(\.dismiss) var dismiss

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            // Header
            HStack {
                if #available(macOS 11.0, *) {
                    Image(systemName: "list.bullet.rectangle")
                        .font(.system(size: 24))
                        .foregroundColor(.blue)
                }
                VStack(alignment: .leading, spacing: 4) {
                    Text("Override Rules")
                        .font(.headline)
                    Text("Permanently allowed credential access")
                        .font(.caption)
                        .foregroundColor(.secondary)
                }
                Spacer()
            }
            .padding(.bottom, 8)

            Divider()

            // Content
            if content.isEmpty {
                VStack(spacing: 12) {
                    if #available(macOS 11.0, *) {
                        Image(systemName: "checkmark.shield")
                            .font(.system(size: 48))
                            .foregroundColor(.green)
                    }
                    Text("No Override Rules")
                        .font(.title3)
                    Text("All credential access is being protected")
                        .font(.caption)
                        .foregroundColor(.secondary)
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                ScrollView {
                    Text(content)
                        .font(.system(.body, design: .monospaced))
                        .textSelection(.enabled)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding()
                }
                .background(Color(NSColor.textBackgroundColor))
                .cornerRadius(8)
            }

            Divider()

            // Footer
            HStack {
                Text("Override rules are stored in the daemon configuration")
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
        .frame(minWidth: 500, minHeight: 300)
    }
}
