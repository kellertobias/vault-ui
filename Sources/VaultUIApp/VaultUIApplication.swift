import VaultServices
import os.log
// MARK: - App/VaultUIApplication.swift

import SwiftUI
import VaultAppUI
import VaultModels
import VaultSSH
@preconcurrency import UserNotifications

@main
struct VaultUIApplication: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) var appDelegate
    @StateObject private var runtime = VaultAppRuntime()

    var body: some Scene {
        Window("Vault UI", id: "main") {
            VaultAppView(runtime: runtime)
                .onAppear {
                    runtime.start()
                }
        }
        .windowStyle(.hiddenTitleBar)
        .commands {
            CommandGroup(replacing: .newItem, addition: {})
        }
    }
}

@MainActor
class AppDelegate: NSObject, NSApplicationDelegate, UNUserNotificationCenterDelegate {
    private let closeToMenuBarOnQuitKey = "closeToMenuBarOnQuit"
    private var statusItem: NSStatusItem?
    private var shouldTerminate = false
    private var isHiddenInMenuBar = false


    func applicationDidFinishLaunching(_ notification: Notification) {
        // App finished launching
        UNUserNotificationCenter.current().delegate = self
        runFirstLaunchPostInstallCleanup()
        
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
        
        // Setup complete
    }

    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        guard !shouldTerminate,
              defaultedBool(forKey: closeToMenuBarOnQuitKey, defaultValue: false) else {
            return .terminateNow
        }

        hideToMenuBar()
        return .terminateCancel
    }

    nonisolated func userNotificationCenter(
        _ center: UNUserNotificationCenter,
        willPresent notification: UNNotification,
        withCompletionHandler completionHandler: @escaping (UNNotificationPresentationOptions) -> Void
    ) {
        completionHandler([.banner, .list])
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
            showFromMenuBar()
            
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

    @objc private func showFromMenuBar() {
        guard isHiddenInMenuBar else {
            NSApp.activate(ignoringOtherApps: true)
            return
        }

        isHiddenInMenuBar = false
        NSApp.setActivationPolicy(.regular)
        removeStatusItem()
        NSApp.activate(ignoringOtherApps: true)

        for window in NSApplication.shared.windows {
            window.makeKeyAndOrderFront(nil)
        }
    }

    @objc private func quitFromMenuBar() {
        shouldTerminate = true
        NSApp.terminate(nil)
    }

    private func hideToMenuBar() {
        isHiddenInMenuBar = true
        installStatusItemIfNeeded()

        for window in NSApplication.shared.windows {
            window.orderOut(nil)
        }

        NSApp.setActivationPolicy(.accessory)
    }

    private func installStatusItemIfNeeded() {
        guard statusItem == nil else { return }

        let item = NSStatusBar.system.statusItem(withLength: NSStatusItem.squareLength)
        item.button?.image = NSImage(systemSymbolName: "lock.shield", accessibilityDescription: "Vault UI")
        item.button?.image?.isTemplate = true
        item.button?.toolTip = "Vault UI"

        let menu = NSMenu()
        menu.addItem(NSMenuItem(title: "Show Vault UI", action: #selector(showFromMenuBar), keyEquivalent: ""))
        menu.addItem(.separator())
        menu.addItem(NSMenuItem(title: "Quit Vault UI", action: #selector(quitFromMenuBar), keyEquivalent: "q"))
        menu.items.forEach { $0.target = self }
        item.menu = menu

        statusItem = item
    }

    private func removeStatusItem() {
        guard let statusItem else { return }

        NSStatusBar.system.removeStatusItem(statusItem)
        self.statusItem = nil
    }

    private func defaultedBool(forKey key: String, defaultValue: Bool) -> Bool {
        UserDefaults.standard.object(forKey: key) == nil
            ? defaultValue
            : UserDefaults.standard.bool(forKey: key)
    }

    private func runFirstLaunchPostInstallCleanup() {
        let cleanupKey = "postInstallCleanupVersion"
        let version = Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "unknown"
        let build = Bundle.main.object(forInfoDictionaryKey: "CFBundleVersion") as? String ?? "unknown"
        let currentInstall = "\(version)-\(build)"

        guard UserDefaults.standard.string(forKey: cleanupKey) != currentInstall else { return }

        cleanupStaleExtensionRegistrations()
        stopLegacyCLIHelperIfNeeded()
        refreshExistingSSHLaunchAgentIfNeeded()

        UserDefaults.standard.set(currentInstall, forKey: cleanupKey)
    }

    private func cleanupStaleExtensionRegistrations() {
        let currentAppPath = Bundle.main.bundleURL.resolvingSymlinksInPath().path
        let currentPluginPrefix = "\(currentAppPath)/Contents/PlugIns/"
        let extensionIdentifiers = [
            AppIdentifiers.safariExtensionBundleIdentifier,
            AppIdentifiers.autoFillExtensionBundleIdentifier
        ]

        for identifier in extensionIdentifiers {
            for path in registeredExtensionPaths(for: identifier) {
                guard !path.hasPrefix(currentPluginPrefix) else { continue }
                unregisterExtension(at: path)
            }
        }
    }

    private func registeredExtensionPaths(for identifier: String) -> [String] {
        let output = runProcess(
            executablePath: "/usr/bin/pluginkit",
            arguments: ["-m", "-A", "-D", "-vvv", "-i", identifier]
        )

        return output
            .split(separator: "\n")
            .compactMap { line -> String? in
                let trimmed = line.trimmingCharacters(in: .whitespacesAndNewlines)
                guard trimmed.hasPrefix("Path = ") else { return nil }
                return String(trimmed.dropFirst("Path = ".count))
            }
    }

    private func unregisterExtension(at path: String) {
        _ = runProcess(
            executablePath: "/usr/bin/pluginkit",
            arguments: ["-r", path]
        )
    }

    private func runProcess(executablePath: String, arguments: [String]) -> String {
        let process = Process()
        let outputPipe = Pipe()
        process.executableURL = URL(fileURLWithPath: executablePath)
        process.arguments = arguments
        process.standardOutput = outputPipe
        process.standardError = nil

        do {
            try process.run()
            process.waitUntilExit()
        } catch {
            return ""
        }

        let data = outputPipe.fileHandleForReading.readDataToEndOfFile()
        return String(data: data, encoding: .utf8) ?? ""
    }

    private func stopLegacyCLIHelperIfNeeded() {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/pkill")
        process.arguments = ["-f", "[/]vaultui agent start"]
        try? process.run()
        process.waitUntilExit()
    }

    private func refreshExistingSSHLaunchAgentIfNeeded() {
        let fileManager = FileManager.default
        let plistPath = SSHAgentServer.launchAgentPlistPath

        let shouldRefresh = fileManager.fileExists(atPath: plistPath)
            || UserDefaults.standard.bool(forKey: "sshAgentEnabled")

        guard shouldRefresh else { return }
        guard let cliPath = preferredCLIPath() else { return }

        try? SSHAgentServer.installLaunchAgent(cliPath: cliPath)
    }

    private func preferredCLIPath() -> String? {
        let helperCLI = Bundle.main.bundlePath
            + "/Contents/Helpers/VaultUIAgent.app/Contents/MacOS/vaultui"
        let bundleCLI = Bundle.main.bundlePath + "/Contents/MacOS/vaultui"
        let siblingCLI = Bundle.main.executablePath
            .map { ($0 as NSString).deletingLastPathComponent + "/vaultui" }
            ?? ""
        let candidates = [
            helperCLI,
            bundleCLI,
            siblingCLI,
            "/usr/local/bin/vaultui",
            "/opt/homebrew/bin/vaultui"
        ]

        return candidates.first { FileManager.default.isExecutableFile(atPath: $0) }
    }
}
