// MARK: - App/VaultUIApplication.swift

import SwiftUI
import VaultAppUI

@main
struct VaultUIApplication: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) var appDelegate

    var body: some Scene {
        Window("Vault UI", id: "main") {
            VaultAppView()
        }
        .windowStyle(.hiddenTitleBar)
        .commands {
            CommandGroup(replacing: .newItem, addition: {})
        }
    }
}

class AppDelegate: NSObject, NSApplicationDelegate {
    func applicationDidFinishLaunching(_ notification: Notification) {
        // App finished launching
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        // Keep the app running in the dock even if the main window is closed,
        // like a typical password manager
        return false
    }
}
