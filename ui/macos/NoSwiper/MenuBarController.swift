//
//  MenuBarController.swift
//  NoSwiper
//
//  Menu bar controller for system tray icon and menu.
//

import AppKit
import SwiftUI

class MenuBarController: NSObject, NSMenuDelegate {
    private var statusItem: NSStatusItem?
    private let ipcClient: IPCClient
    private var statusUpdateTimer: Timer?

    init(ipcClient: IPCClient) {
        self.ipcClient = ipcClient
        super.init()
        setupMenuBar()
        startStatusUpdates()
    }

    private func setupMenuBar() {
        statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)

        if let button = statusItem?.button {
            // Use SF Symbol for native macOS look
            if #available(macOS 11.0, *) {
                button.image = NSImage(systemSymbolName: "shield.lefthalf.filled", accessibilityDescription: "NoSwiper")
            } else {
                button.title = "🛡"
            }
        }

        // Create menu and set delegate
        let menu = NSMenu()
        menu.delegate = self
        statusItem?.menu = menu
    }

    // NSMenuDelegate method - called just before menu is shown
    func menuNeedsUpdate(_ menu: NSMenu) {
        menu.removeAllItems()
        buildMenu(menu)
    }

    private func buildMenu(_ menu: NSMenu) {
        // Status section
        let status = ipcClient.getStatus()
        let statusTitle = status?.running == true ? "NoSwiper Active" : "Agent Not Running"
        let statusIcon = status?.running == true ? "✓" : "⚠️"

        let statusMenuItem = NSMenuItem(title: "\(statusIcon) \(statusTitle)", action: nil, keyEquivalent: "")
        statusMenuItem.isEnabled = false
        menu.addItem(statusMenuItem)

        menu.addItem(NSMenuItem.separator())

        // Mode toggle
        if let currentStatus = status {
            let modeItem = NSMenuItem(
                title: "Enforce Access Restrictions",
                action: #selector(toggleMode),
                keyEquivalent: ""
            )
            modeItem.target = self
            modeItem.state = currentStatus.mode == .enforce ? .on : .off
            menu.addItem(modeItem)

            menu.addItem(NSMenuItem.separator())
        }

        // View Recent Violations (now enabled!)
        let violationsItem = NSMenuItem(title: "Recent Violations…", action: #selector(showViolations), keyEquivalent: "")
        violationsItem.target = self
        violationsItem.isEnabled = true
        menu.addItem(violationsItem)

        // View Override Rules
        let overridesItem = NSMenuItem(title: "View Override Rules…", action: #selector(showOverrides), keyEquivalent: "")
        overridesItem.target = self
        menu.addItem(overridesItem)

        menu.addItem(NSMenuItem.separator())

        // Open preferences (future)
        let prefsItem = NSMenuItem(title: "Preferences…", action: nil, keyEquivalent: ",")
        prefsItem.isEnabled = false // TODO: Implement preferences
        menu.addItem(prefsItem)

        menu.addItem(NSMenuItem.separator())

        // Quit
        let quitItem = NSMenuItem(title: "Quit NoSwiper", action: #selector(quit), keyEquivalent: "q")
        quitItem.target = self
        menu.addItem(quitItem)
    }

    @objc private func toggleMode() {
        guard let status = ipcClient.getStatus() else { return }

        let newMode: DaemonMode = status.mode == .enforce ? .monitor : .enforce

        if !ipcClient.setMode(newMode) {
            showError(message: "Failed to change mode. Is the daemon running?")
        }
        // Menu will update automatically next time it's opened via menuNeedsUpdate
    }

    @objc private func showViolations() {
        guard let events = ipcClient.getViolations(limit: 100) else {
            showError(message: "Failed to fetch violations. Is the daemon running?")
            return
        }

        let windowController = ViolationHistoryWindowController(events: events)
        windowController.showWindow(nil)
    }

    @objc private func showOverrides() {
        guard let content = ipcClient.getOverrides() else {
            showError(message: "Failed to fetch override rules. Is the daemon running?")
            return
        }

        let windowController = OverrideRulesWindowController(content: content)
        windowController.showWindow(nil)
    }

    @objc private func quit() {
        NSApplication.shared.terminate(nil)
    }

    private func startStatusUpdates() {
        statusUpdateTimer = Timer.scheduledTimer(withTimeInterval: 30.0, repeats: true) { [weak self] _ in
            self?.updateMenuBarIcon()
        }
        statusUpdateTimer?.fire() // Update immediately
    }

    private func updateMenuBarIcon() {
        guard let button = statusItem?.button else { return }

        let status = ipcClient.getStatus()

        if #available(macOS 11.0, *) {
            if status?.running == true {
                button.image = NSImage(systemSymbolName: "shield.lefthalf.filled", accessibilityDescription: "NoSwiper Active")
            } else {
                button.image = NSImage(systemSymbolName: "exclamationmark.triangle", accessibilityDescription: "NoSwiper Not Running")
            }
        } else {
            button.title = status?.running == true ? "🛡" : "⚠️"
        }
    }

    private func showError(message: String) {
        let alert = NSAlert()
        alert.messageText = "NoSwiper Error"
        alert.informativeText = message
        alert.alertStyle = .warning
        alert.addButton(withTitle: "OK")
        alert.runModal()
    }

    deinit {
        statusUpdateTimer?.invalidate()
    }
}
