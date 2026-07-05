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
class AppDelegate: NSObject, NSApplicationDelegate, UNUserNotificationCenterDelegate, NSMenuDelegate {
    private let closeToMenuBarOnQuitKey = "closeToMenuBarOnQuit"
    private let sshLaunchAgentRefreshVersionKey = "sshLaunchAgentRefreshVersion"
    private var statusItem: NSStatusItem?
    private var shouldTerminate = false
    private var isHiddenInMenuBar = false
    private let sshAuthenticationBypassDurations = [10, 15, 30, 60, 120, 240, 480, 720]
    private let relativeDateFormatter: RelativeDateTimeFormatter = {
        let formatter = RelativeDateTimeFormatter()
        formatter.unitsStyle = .short
        return formatter
    }()
    private let absoluteDateFormatter: DateFormatter = {
        let formatter = DateFormatter()
        formatter.dateStyle = .short
        formatter.timeStyle = .short
        return formatter
    }()
    private enum SSHUnlockMenuStatus {
        case checking
        case unavailable
        case locked
        case unlocked(until: Date)
    }
    private var sshUnlockStatusMenuItems: [String: NSMenuItem] = [:]
    private var sshUnlockMenuStatuses: [String: SSHUnlockMenuStatus] = [:]
    private var sshUnlockStatusTimer: Timer?


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
        installStatusItemIfNeeded()
        refreshExistingSSHLaunchAgentIfNeeded()
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
        NSApp.activate(ignoringOtherApps: true)

        for window in NSApplication.shared.windows {
            window.makeKeyAndOrderFront(nil)
        }
    }

    @objc private func quitFromMenuBar() {
        shouldTerminate = true
        NSApp.terminate(nil)
    }

    @objc private func hideFromMenuBarItem() {
        hideToMenuBar()
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
        menu.delegate = self
        rebuildStatusMenu(menu)
        item.menu = menu

        statusItem = item
    }

    func menuNeedsUpdate(_ menu: NSMenu) {
        rebuildStatusMenu(menu)
    }

    func menuDidClose(_ menu: NSMenu) {
        sshUnlockStatusTimer?.invalidate()
        sshUnlockStatusTimer = nil
        sshUnlockStatusMenuItems.removeAll()
        sshUnlockMenuStatuses.removeAll()
    }

    private func rebuildStatusMenu(_ menu: NSMenu) {
        menu.removeAllItems()
        sshUnlockStatusMenuItems.removeAll()
        sshUnlockMenuStatuses.removeAll()

        let appItem = NSMenuItem(
            title: isHiddenInMenuBar ? "Show Vault UI" : "Hide Vault UI",
            action: isHiddenInMenuBar ? #selector(showFromMenuBar) : #selector(hideFromMenuBarItem),
            keyEquivalent: ""
        )
        appItem.target = self
        menu.addItem(appItem)

        menu.addItem(.separator())
        menu.addItem(sshKeysMenuItem())

        menu.addItem(.separator())
        let quitItem = NSMenuItem(title: "Quit Vault UI", action: #selector(quitFromMenuBar), keyEquivalent: "q")
        quitItem.target = self
        menu.addItem(quitItem)
    }

    private func sshKeysMenuItem() -> NSMenuItem {
        let rootItem = NSMenuItem(title: "SSH Keys", action: nil, keyEquivalent: "")
        let submenu = NSMenu()

        guard UserDefaults.standard.bool(forKey: SSHAgentKeyAccessStore.menuBarKeysEnabledKey) else {
            let disabledItem = NSMenuItem(
                title: "Disabled for security",
                action: nil,
                keyEquivalent: ""
            )
            disabledItem.isEnabled = false
            submenu.addItem(disabledItem)

            let infoItem = NSMenuItem(
                title: "This menu can show active SSH keys and per-key agent access controls. Enable it in Settings > SSH Agent.",
                action: nil,
                keyEquivalent: ""
            )
            infoItem.isEnabled = false
            submenu.addItem(infoItem)

            rootItem.submenu = submenu
            return rootItem
        }

        let identities = SharedCredentialStore.shared.fetchSSHIdentities()

        guard !identities.isEmpty else {
            let emptyItem = NSMenuItem(title: "No SSH keys", action: nil, keyEquivalent: "")
            emptyItem.isEnabled = false
            submenu.addItem(emptyItem)
            rootItem.submenu = submenu
            return rootItem
        }

        for identity in identities.sorted(by: { $0.comment.localizedCaseInsensitiveCompare($1.comment) == .orderedAscending }) {
            let item = NSMenuItem(title: identity.comment, action: nil, keyEquivalent: "")
            item.submenu = sshKeySubmenu(for: identity)
            submenu.addItem(item)
        }

        rootItem.submenu = submenu
        return rootItem
    }

    private func sshKeySubmenu(for identity: SSHIdentity) -> NSMenu {
        let menu = NSMenu()
        let access = SSHAgentKeyAccessStore.access(for: identity.cipherId)

        let visibleItem = NSMenuItem(title: "Visible for agent", action: #selector(setSSHKeyVisible(_:)), keyEquivalent: "")
        visibleItem.target = self
        visibleItem.representedObject = identity.cipherId
        visibleItem.state = access.isVisible ? .on : .off
        menu.addItem(visibleItem)

        let hiddenItem = NSMenuItem(title: "Not visible for agent", action: #selector(setSSHKeyHidden(_:)), keyEquivalent: "")
        hiddenItem.target = self
        hiddenItem.representedObject = identity.cipherId
        hiddenItem.state = access.isVisible ? .off : .on
        menu.addItem(hiddenItem)

        let timedItem = NSMenuItem(title: "Skip fingerprint for", action: nil, keyEquivalent: "")
        let timedMenu = NSMenu()
        for minutes in sshAuthenticationBypassDurations {
            let item = NSMenuItem(title: durationTitle(minutes: minutes), action: #selector(authorizeSSHKeyWithoutFingerprint(_:)), keyEquivalent: "")
            item.target = self
            item.representedObject = "\(identity.cipherId)|\(minutes)|\(identity.comment)"
            if let until = access.authenticationBypassUntil,
               abs(until.timeIntervalSinceNow - TimeInterval(minutes * 60)) < 60 {
                item.state = .on
            }
            timedMenu.addItem(item)
        }
        timedItem.submenu = timedMenu
        menu.addItem(timedItem)

        menu.addItem(.separator())
        let unlockStatusItem = NSMenuItem(title: "Unlock status: Checking...", action: nil, keyEquivalent: "")
        unlockStatusItem.isEnabled = false
        menu.addItem(unlockStatusItem)
        registerUnlockStatusItem(unlockStatusItem, cipherId: identity.cipherId)

        let lastUsedTitle: String
        if let lastUsedAt = access.lastUsedAt {
            lastUsedTitle = "Last used \(relativeDateFormatter.localizedString(for: lastUsedAt, relativeTo: Date()))"
        } else {
            lastUsedTitle = "Last used never"
        }
        let lastUsedItem = NSMenuItem(title: lastUsedTitle, action: nil, keyEquivalent: "")
        lastUsedItem.isEnabled = false
        menu.addItem(lastUsedItem)

        let recentItem = NSMenuItem(title: "Last 10 uses", action: nil, keyEquivalent: "")
        let recentMenu = NSMenu()
        if access.recentUses.isEmpty {
            let emptyItem = NSMenuItem(title: "No recorded uses", action: nil, keyEquivalent: "")
            emptyItem.isEnabled = false
            recentMenu.addItem(emptyItem)
        } else {
            for use in access.recentUses {
                let title = usageTitle(for: use)
                let item = NSMenuItem(title: title, action: nil, keyEquivalent: "")
                item.isEnabled = false
                recentMenu.addItem(item)
            }
        }
        recentItem.submenu = recentMenu
        menu.addItem(recentItem)

        return menu
    }

    @objc private func setSSHKeyVisible(_ sender: NSMenuItem) {
        guard let cipherId = sender.representedObject as? String else { return }
        SSHAgentKeyAccessStore.setVisible(true, cipherId: cipherId)
    }

    @objc private func setSSHKeyHidden(_ sender: NSMenuItem) {
        guard let cipherId = sender.representedObject as? String else { return }
        SSHAgentKeyAccessStore.setVisible(false, cipherId: cipherId)
    }

    @objc private func authorizeSSHKeyWithoutFingerprint(_ sender: NSMenuItem) {
        guard let payload = sender.representedObject as? String else { return }
        let parts = payload.split(separator: "|", maxSplits: 2).map(String.init)
        guard parts.count == 3, let minutes = Int(parts[1]) else { return }
        Task {
            let ok = await SSHAgentControlClient.authorizeKey(
                cipherId: parts[0],
                comment: parts[2],
                minutes: minutes
            )
            if !ok {
                NSSound.beep()
                return
            }

            await MainActor.run {
                let until = Date().addingTimeInterval(TimeInterval(min(max(1, minutes), 12 * 60) * 60))
                sshUnlockMenuStatuses[parts[0]] = .unlocked(until: until)
                updateUnlockStatusMenuItem(for: parts[0])
            }
        }
    }

    private func registerUnlockStatusItem(_ item: NSMenuItem, cipherId: String) {
        sshUnlockStatusMenuItems[cipherId] = item
        sshUnlockMenuStatuses[cipherId] = .checking
        updateUnlockStatusMenuItem(for: cipherId)
        startUnlockStatusTimerIfNeeded()

        Task {
            let status = await SSHAgentControlClient.keyStatus(cipherId: cipherId)
            await MainActor.run {
                guard sshUnlockStatusMenuItems[cipherId] === item else { return }
                if let expiresAt = status?.expiresAt {
                    sshUnlockMenuStatuses[cipherId] = .unlocked(until: expiresAt)
                } else if status != nil {
                    sshUnlockMenuStatuses[cipherId] = .locked
                } else {
                    sshUnlockMenuStatuses[cipherId] = .unavailable
                }
                updateUnlockStatusMenuItem(for: cipherId)
            }
        }
    }

    private func startUnlockStatusTimerIfNeeded() {
        guard sshUnlockStatusTimer == nil else { return }
        sshUnlockStatusTimer = Timer.scheduledTimer(withTimeInterval: 1, repeats: true) { [weak self] _ in
            Task { @MainActor in
                self?.refreshUnlockStatusMenuItems()
            }
        }
    }

    private func refreshUnlockStatusMenuItems() {
        guard !sshUnlockStatusMenuItems.isEmpty else {
            sshUnlockStatusTimer?.invalidate()
            sshUnlockStatusTimer = nil
            return
        }

        for cipherId in sshUnlockStatusMenuItems.keys {
            updateUnlockStatusMenuItem(for: cipherId)
        }
    }

    private func updateUnlockStatusMenuItem(for cipherId: String) {
        guard let item = sshUnlockStatusMenuItems[cipherId],
              let status = sshUnlockMenuStatuses[cipherId] else {
            return
        }

        switch status {
        case .checking:
            item.title = "Unlock status: Checking..."
            item.toolTip = nil
        case .unavailable:
            item.title = "Unlock status unavailable"
            item.toolTip = "The running SSH agent did not return cache status."
        case .locked:
            item.title = "Locked - fingerprint required"
            item.toolTip = nil
        case .unlocked(let until):
            let remaining = until.timeIntervalSinceNow
            if remaining <= 0 {
                sshUnlockMenuStatuses[cipherId] = .locked
                item.title = "Locked - fingerprint required"
                item.toolTip = nil
                return
            }
            item.title = "Unlocked for \(remainingUnlockTimeTitle(seconds: Int(ceil(remaining))))"
            item.toolTip = "Locks at \(absoluteDateFormatter.string(from: until))"
        }
    }

    private func remainingUnlockTimeTitle(seconds: Int) -> String {
        let seconds = max(0, seconds)
        if seconds < 60 {
            return "\(seconds)s"
        }
        if seconds < 3_600 {
            return "\(seconds / 60)m \(seconds % 60)s"
        }
        let hours = seconds / 3_600
        let minutes = (seconds % 3_600) / 60
        return "\(hours)h \(minutes)m"
    }

    private func durationTitle(minutes: Int) -> String {
        switch minutes {
        case 60:
            return "1 hour"
        case let value where value % 60 == 0:
            return "\(value / 60) hours"
        default:
            return "\(minutes) minutes"
        }
    }

    private func usageTitle(for use: SSHAgentKeyUse) -> String {
        let date = absoluteDateFormatter.string(from: use.usedAt)
        guard let peer = use.peer, !peer.isEmpty else { return date }
        return "\(date) - \(peer)"
    }

    private func defaultedBool(forKey key: String, defaultValue: Bool) -> Bool {
        UserDefaults.standard.object(forKey: key) == nil
            ? defaultValue
            : UserDefaults.standard.bool(forKey: key)
    }

    private func runFirstLaunchPostInstallCleanup() {
        let cleanupKey = "postInstallCleanupVersion"
        let currentInstall = currentInstallIdentifier()

        guard UserDefaults.standard.string(forKey: cleanupKey) != currentInstall else { return }

        cleanupStaleExtensionRegistrations()
        stopLegacyCLIHelperIfNeeded()

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
        let currentInstall = currentInstallIdentifier()
        let refreshVersionKey = sshLaunchAgentRefreshVersionKey

        Task.detached(priority: .utility) {
            guard await Self.shouldRefreshSSHLaunchAgent(
                plistPath: plistPath,
                cliPath: cliPath,
                currentInstall: currentInstall,
                refreshVersionKey: refreshVersionKey
            ) else {
                return
            }

            do {
                try SSHAgentServer.installLaunchAgent(cliPath: cliPath)
                UserDefaults.standard.set(currentInstall, forKey: refreshVersionKey)
            } catch {
                NSLog("Vault UI failed to refresh SSH LaunchAgent: \(error.localizedDescription)")
            }
        }
    }

    private nonisolated static func shouldRefreshSSHLaunchAgent(
        plistPath: String,
        cliPath: String,
        currentInstall: String,
        refreshVersionKey: String
    ) async -> Bool {
        guard FileManager.default.fileExists(atPath: plistPath) else { return true }

        if launchAgentProgramPath(plistPath: plistPath) != cliPath {
            return true
        }

        if UserDefaults.standard.string(forKey: refreshVersionKey) != currentInstall {
            return true
        }

        // A successful status query proves the running agent understands the
        // current internal control protocol. The bogus ID never resolves to a
        // real key and cannot trigger authentication or key material access.
        return await SSHAgentControlClient.keyStatus(cipherId: "__vaultui_startup_probe__") == nil
    }

    private nonisolated static func launchAgentProgramPath(plistPath: String) -> String? {
        guard let data = try? Data(contentsOf: URL(fileURLWithPath: plistPath)),
              let plist = try? PropertyListSerialization.propertyList(from: data, format: nil),
              let dictionary = plist as? [String: Any],
              let arguments = dictionary["ProgramArguments"] as? [String],
              let firstArgument = arguments.first else {
            return nil
        }

        return URL(fileURLWithPath: firstArgument).resolvingSymlinksInPath().path
    }

    private func currentInstallIdentifier() -> String {
        let version = Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "unknown"
        let build = Bundle.main.object(forInfoDictionaryKey: "CFBundleVersion") as? String ?? "unknown"
        return "\(version)-\(build)"
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
