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

@MainActor
class AppDelegate: NSObject, NSApplicationDelegate {
    private var pickerWindow: NSWindow?

    func applicationDidFinishLaunching(_ notification: Notification) {
        // App finished launching
        
        // Terminate any other running instances of this app
        if let bundleIdentifier = Bundle.main.bundleIdentifier {
            let runningApps = NSRunningApplication.runningApplications(withBundleIdentifier: bundleIdentifier)
            let currentPid = ProcessInfo.processInfo.processIdentifier
            for app in runningApps {
                if app.processIdentifier != currentPid {
                    app.forceTerminate()
                }
            }
        }
        
        // Listen for IPC from Safari Extension
        DistributedNotificationCenter.default().addObserver(
            self,
            selector: #selector(showNativePicker),
            name: NSNotification.Name("de.tobisk.apps.vaultui.ShowPicker"),
            object: nil
        )
    }

    @objc private func showNativePicker() {
        let sharedDefaults = UserDefaults(suiteName: "group.de.tobisk.apps.vaultui")
        guard let req = sharedDefaults?.dictionary(forKey: "VaultUIPickerRequest"),
              let requestId = req["id"] as? String,
              let urlString = req["url"] as? String else {
            return
        }
        
        // Ensure we are on main thread
        DispatchQueue.main.async {
            self.presentPickerWindow(url: urlString, requestId: requestId)
        }
    }
    
    private func presentPickerWindow(url: String, requestId: String) {
        // Close existing if any
        pickerWindow?.close()
        
        let pickerView = NativePickerView(url: url, requestId: requestId) { [weak self] in
            self?.pickerWindow?.close()
            self?.pickerWindow = nil
        }
        
        let hostingController = NSHostingController(rootView: pickerView)
        let window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 300, height: 400),
            styleMask: [.titled, .closable, .fullSizeContentView],
            backing: .buffered,
            defer: false
        )
        
        window.center()
        window.isOpaque = false
        window.backgroundColor = .clear
        window.isMovableByWindowBackground = true
        window.level = .floating
        window.contentViewController = hostingController
        window.titlebarAppearsTransparent = true
        window.titleVisibility = .hidden
        
        window.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
        
        self.pickerWindow = window
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        // Keep the app running in the dock even if the main window is closed,
        // like a typical password manager
        return false
    }

    func application(_ application: NSApplication, continue userActivity: NSUserActivity, restorationHandler: @escaping ([NSUserActivityRestoring]) -> Void) -> Bool {
        print("VaultUI AppDelegate received userActivity with type: \(userActivity.activityType)")
        if userActivity.activityType == "com.apple.authenticationservices.credential-exchange" || 
           userActivity.activityType == "ASCredentialExchangeActivity" ||
           userActivity.activityType.contains("CredentialExchange") {
            NSApp.activate(ignoringOtherApps: true)
            
            // Re-open main window if it was closed
            if let window = NSApplication.shared.windows.first(where: { $0.title == "Vault UI" }) {
                window.makeKeyAndOrderFront(nil)
            } else {
                // SwiftUI 14+ way to open a specific Window by id if closed isn't cleanly available in AppDelegate
                // so we rely on the system to re-create the Window on activation or broadcast a notification.
                // Since `Window` in SwiftUI is singleton-like, we just broadcast the notification.
            }

            NotificationCenter.default.post(
                name: NSNotification.Name("VaultUIHandleCredentialExchange"),
                object: nil,
                userInfo: userActivity.userInfo
            )
            return true
        }
        return false
    }
}
