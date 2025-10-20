//
//  NoSwiperApp.swift
//  NoSwiper
//
//  Native macOS UI for NoSwiper credential protection.
//

import SwiftUI
import AppKit

@main
struct NoSwiperApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) var appDelegate

    var body: some Scene {
        Settings {
            EmptyView()
        }
    }
}

class AppDelegate: NSObject, NSApplicationDelegate {
    var menuBarController: MenuBarController?
    var ipcClient: IPCClient?

    func applicationDidFinishLaunching(_ notification: Notification) {
        // Hide dock icon - we're a menu bar app
        NSApp.setActivationPolicy(.accessory)

        // Initialize IPC client
        ipcClient = IPCClient()

        // Set up menu bar
        menuBarController = MenuBarController(ipcClient: ipcClient!)

        // Start monitoring for violations
        ipcClient?.startMonitoring { [weak self] event in
            DispatchQueue.main.async {
                self?.handleViolation(event: event)
            }
        }
    }

    func handleViolation(event: ViolationEvent) {
        ViolationAlert.show(event: event, ipcClient: ipcClient!)
    }
}
