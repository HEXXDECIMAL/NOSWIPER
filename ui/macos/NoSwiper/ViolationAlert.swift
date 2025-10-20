//
//  ViolationAlert.swift
//  NoSwiper
//
//  Native macOS alert for credential access violations.
//

import SwiftUI
import AppKit
import UserNotifications

struct ViolationAlert {
    static func show(event: ViolationEvent, ipcClient: IPCClient) {
        // Extract process name from path
        let processName = URL(fileURLWithPath: event.processPath).lastPathComponent

        // Debug logging
        print("ViolationAlert: event.id = \(event.id)")
        print("ViolationAlert: event.teamId = \(String(describing: event.teamId))")

        // Create alert window
        let alert = NSAlert()
        alert.alertStyle = .critical
        alert.messageText = "Credential Access Blocked"
        alert.informativeText = buildInformativeText(event: event, processName: processName)

        // Add buttons in reverse order (rightmost button is added first)
        // Apple HIG: [Cancel/Destructive] ... [Default/Recommended]
        alert.addButton(withTitle: "Allow Once")        // Rightmost (default action)
        alert.addButton(withTitle: "Always Allow")      // Middle
        alert.addButton(withTitle: "Kill Process")      // Leftmost (destructive)

        // Show process hierarchy as accessory view if available
        if let processTree = event.processTree, !processTree.isEmpty {
            let accessoryView = createProcessTreeView(tree: processTree, currentPid: event.processPid)
            alert.accessoryView = accessoryView
        }

        // Present alert and handle response
        DispatchQueue.main.async {
            NSApp.activate(ignoringOtherApps: true)

            let response = alert.runModal()

            switch response {
            case .alertFirstButtonReturn: // Allow Once (rightmost - default)
                print("User chose: Allow Once for event \(event.id)")
                if !ipcClient.allowOnce(eventId: event.id) {
                    print("ERROR: Failed to send allow_once to daemon")
                    showError(message: "Failed to allow process. The daemon may not be running.")
                }

            case .alertSecondButtonReturn: // Always Allow (middle)
                print("User chose: Always Allow for event \(event.id)")
                if !ipcClient.allowPermanently(eventId: event.id) {
                    print("ERROR: Failed to send allow_permanently to daemon")
                    showError(message: "Failed to allow process permanently. The daemon may not be running.")
                }

            case .alertThirdButtonReturn: // Kill Process (leftmost - destructive)
                print("User chose: Kill Process for event \(event.id)")
                if ipcClient.killProcess(eventId: event.id) {
                    showNotification(title: "Process Terminated", body: "\(processName) has been terminated.")
                } else {
                    print("ERROR: Failed to send kill to daemon")
                    showError(message: "Failed to kill process. The daemon may not be running.")
                }

            default:
                break
            }
        }
    }

    private static func buildInformativeText(event: ViolationEvent, processName: String) -> String {
        var text = ""

        // Process info
        text += "Process: \(processName) (PID: \(event.processPid))\n"
        text += "Path: \(event.processPath)\n\n"

        // Attempted access
        text += "Attempted to access:\n\(event.filePath)\n\n"

        // Team ID if available
        if let teamId = event.teamId, !teamId.isEmpty {
            text += "Developer: \(teamId)\n"
        } else {
            text += "⚠️ Unsigned or unknown developer\n"
        }

        // Rule that triggered
        if let ruleName = event.ruleName {
            text += "Rule: \(ruleName)"
        }

        return text
    }

    private static func createProcessTreeView(tree: [ProcessTreeEntry], currentPid: UInt32) -> NSView {
        let scrollView = NSScrollView(frame: NSRect(x: 0, y: 0, width: 500, height: 120))
        scrollView.hasVerticalScroller = true
        scrollView.hasHorizontalScroller = false
        scrollView.autoresizingMask = [.width, .height]
        scrollView.borderType = .bezelBorder

        let textView = NSTextView(frame: scrollView.bounds)
        textView.isEditable = false
        textView.isSelectable = true
        textView.font = NSFont.monospacedSystemFont(ofSize: 10, weight: .regular)
        textView.autoresizingMask = [.width]

        // Use attributed string for colored signing information
        let attributedText = NSMutableAttributedString()
        let baseAttributes: [NSAttributedString.Key: Any] = [
            .font: NSFont.monospacedSystemFont(ofSize: 10, weight: .regular),
            .foregroundColor: NSColor.textColor
        ]

        attributedText.append(NSAttributedString(string: "Process Hierarchy:\n", attributes: baseAttributes))

        // Find current process entry
        if let current = tree.first(where: { $0.pid == currentPid }) {
            appendProcessEntry(to: attributedText, entry: current, indent: "", marker: "├─", baseAttributes: baseAttributes)
        }

        // Find ancestors
        var currentPid = currentPid
        var depth = 1
        while let parent = tree.first(where: { $0.pid == currentPid })?.ppid {
            if let parentEntry = tree.first(where: { $0.pid == parent }) {
                let indent = String(repeating: "│  ", count: depth)
                appendProcessEntry(to: attributedText, entry: parentEntry, indent: indent, marker: "└─", baseAttributes: baseAttributes)
                currentPid = parent
                depth += 1
            } else {
                break
            }

            if depth > 10 { break } // Prevent infinite loops
        }

        textView.textStorage?.setAttributedString(attributedText)
        scrollView.documentView = textView

        return scrollView
    }

    private static func appendProcessEntry(to attributedText: NSMutableAttributedString, entry: ProcessTreeEntry, indent: String, marker: String, baseAttributes: [NSAttributedString.Key: Any]) {
        // Process name and PID
        attributedText.append(NSAttributedString(string: "\(indent)\(marker) \(entry.name) (PID: \(entry.pid))", attributes: baseAttributes))

        // Add signing information with color coding (like Tauri UI)
        if let teamId = entry.teamId, !teamId.isEmpty {
            let signingAttributes: [NSAttributedString.Key: Any] = [
                .font: NSFont.monospacedSystemFont(ofSize: 10, weight: .medium),
                .foregroundColor: NSColor.systemBlue
            ]
            attributedText.append(NSAttributedString(string: " [\(teamId)]", attributes: signingAttributes))
        } else if let signingId = entry.signingId, !signingId.isEmpty {
            let signingAttributes: [NSAttributedString.Key: Any] = [
                .font: NSFont.monospacedSystemFont(ofSize: 10, weight: .medium),
                .foregroundColor: NSColor.systemPurple
            ]
            attributedText.append(NSAttributedString(string: " [\(signingId)]", attributes: signingAttributes))
        }

        attributedText.append(NSAttributedString(string: "\n", attributes: baseAttributes))

        // Path
        attributedText.append(NSAttributedString(string: "\(indent)   \(entry.path)\n", attributes: baseAttributes))

        // Command line if available
        if let cmdline = entry.cmdline, !cmdline.isEmpty {
            let truncated = cmdline.count > 80 ? String(cmdline.prefix(80)) + "..." : cmdline
            attributedText.append(NSAttributedString(string: "\(indent)   \(truncated)\n", attributes: baseAttributes))
        }
    }

    private static func currentProcessName(from tree: [ProcessTreeEntry], pid: UInt32) -> String {
        tree.first(where: { $0.pid == pid })?.name ?? "unknown"
    }

    private static func showError(message: String) {
        let alert = NSAlert()
        alert.messageText = "NoSwiper Error"
        alert.informativeText = message
        alert.alertStyle = .warning
        alert.addButton(withTitle: "OK")
        alert.runModal()
    }

    private static func showNotification(title: String, body: String) {
        if #available(macOS 10.14, *) {
            let center = UNUserNotificationCenter.current()

            // Request permission (will only prompt once)
            center.requestAuthorization(options: [.alert, .sound]) { granted, _ in
                guard granted else { return }

                let content = UNMutableNotificationContent()
                content.title = title
                content.body = body
                content.sound = .default

                let request = UNNotificationRequest(
                    identifier: UUID().uuidString,
                    content: content,
                    trigger: nil
                )

                center.add(request)
            }
        }
    }
}

// MARK: - SwiftUI Preview Support
struct ViolationAlertView: View {
    let event: ViolationEvent
    let onAction: (String) -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            // Header
            HStack(spacing: 12) {
                if #available(macOS 11.0, *) {
                    Image(systemName: "exclamationmark.shield.fill")
                        .font(.system(size: 48))
                        .foregroundColor(.red)
                } else {
                    Text("⚠️")
                        .font(.system(size: 48))
                }

                VStack(alignment: .leading, spacing: 4) {
                    Text("Credential Access Blocked")
                        .font(.headline)
                        .bold()

                    Text(processName)
                        .font(.subheadline)
                        .foregroundColor(.secondary)
                }
            }

            Divider()

            // Details
            VStack(alignment: .leading, spacing: 8) {
                DetailRow(label: "Process", value: "\(processName) (PID: \(event.processPid))")
                DetailRow(label: "Path", value: event.processPath)
                DetailRow(label: "Attempting to access", value: event.filePath)

                if let teamId = event.teamId, !teamId.isEmpty {
                    DetailRow(label: "Developer", value: teamId)
                } else {
                    HStack {
                        Text("Developer:")
                            .foregroundColor(.secondary)
                        Text("⚠️ Unsigned or unknown")
                            .foregroundColor(.orange)
                    }
                }
            }

            // Process tree if available
            if let tree = event.processTree, !tree.isEmpty {
                Divider()
                ProcessTreeView(tree: tree, currentPid: event.processPid)
            }

            Divider()

            // Action buttons
            HStack(spacing: 12) {
                Spacer()

                Button("Kill Process") {
                    onAction("kill")
                }
                .keyboardShortcut(.cancelAction)

                Button("Allow Once") {
                    onAction("allow_once")
                }
                .keyboardShortcut(.defaultAction)

                Button("Always Allow") {
                    onAction("allow_permanently")
                }
            }
        }
        .padding(20)
        .frame(width: 500)
    }

    private var processName: String {
        URL(fileURLWithPath: event.processPath).lastPathComponent
    }
}

struct DetailRow: View {
    let label: String
    let value: String

    var body: some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(label)
                .font(.caption)
                .foregroundColor(.secondary)
            Text(value)
                .font(.body)
                .textSelection(.enabled)
        }
    }
}

struct ProcessTreeView: View {
    let tree: [ProcessTreeEntry]
    let currentPid: UInt32

    var body: some View {
        VStack(alignment: .leading, spacing: 2) {
            Text("Process Hierarchy")
                .font(.caption)
                .foregroundColor(.secondary)

            ScrollView {
                VStack(alignment: .leading, spacing: 2) {
                    ForEach(hierarchyEntries, id: \.pid) { entry in
                        HStack(spacing: 4) {
                            Text(String(repeating: "  ", count: entry.depth))
                            Text(entry.depth == 0 ? "├─" : "└─")
                                .foregroundColor(.secondary)
                            Text("\(entry.name) (\(entry.pid))")
                                .font(.system(.body, design: .monospaced))
                        }
                    }
                }
            }
            .frame(height: 100)
        }
    }

    private var hierarchyEntries: [(pid: UInt32, name: String, depth: Int)] {
        var result: [(pid: UInt32, name: String, depth: Int)] = []

        // Start with current process
        if let current = tree.first(where: { $0.pid == currentPid }) {
            result.append((pid: current.pid, name: current.name, depth: 0))

            // Find ancestors
            var currentPid = currentPid
            var depth = 1

            while let parent = tree.first(where: { $0.pid == currentPid })?.ppid {
                if let parentEntry = tree.first(where: { $0.pid == parent }) {
                    result.append((pid: parentEntry.pid, name: parentEntry.name, depth: depth))
                    currentPid = parent
                    depth += 1
                } else {
                    break
                }

                if depth > 10 { break } // Prevent infinite loops
            }
        }

        return result
    }
}
