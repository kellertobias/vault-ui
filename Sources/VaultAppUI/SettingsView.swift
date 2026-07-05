// MARK: - VaultAppUI/SettingsView.swift
// Application settings and preferences

import SwiftUI
import SafariServices
import VaultModels
import VaultServices
import VaultSSH

/// Application settings view.
public struct SettingsView: View {
    @EnvironmentObject var session: SessionManager
    // General
    @AppStorage("lockTimeout") private var lockTimeout = 15
    @AppStorage("clearClipboard") private var clearClipboard = true
    @AppStorage("clipboardTimeout") private var clipboardTimeout = 30
    @AppStorage("syncInterval") private var syncInterval = 5
    @AppStorage("backgroundSyncStatusNotifications") private var backgroundSyncStatusNotifications = true
    @AppStorage("closeToMenuBarOnQuit") private var closeToMenuBarOnQuit = false

    // AutoFill
    @AppStorage(SharedCredentialStore.systemCredentialIdentitySyncEnabledKey)
    private var systemIdentitySyncEnabled = true

    // Security
    @AppStorage("useTouchID") private var useTouchID = true
    @AppStorage("lockOnSleep") private var lockOnSleep = true
    @AppStorage("lockOnScreenSaver") private var lockOnScreenSaver = true

    // SSH Agent
    @AppStorage("sshAgentEnabled") private var sshAgentEnabled = false
    @AppStorage(SSHAgentKeyAccessStore.menuBarKeysEnabledKey) private var showSSHKeysInMenuBar = false
    @AppStorage("sshAgentUnlockTimeout") private var sshAgentUnlockTimeout = 15
    // Agent re-authentication policy: "everyTime" | "fixed" | "sliding".
    @AppStorage("agentReauthMode") private var agentReauthMode = "sliding"
    @State private var showLogoutConfirmation = false
    @State private var iconCacheCleared = false
    @State private var thirdPartyLicenses = "Loading licenses..."
    @State private var launchAgentInstallStatus: String?

    @Environment(\.dismiss) private var dismiss
    public init() {}

    public var body: some View {
        VStack(spacing: 0) {
            HStack {
                Spacer()
                Button("Done") {
                    dismiss()
                }
                .keyboardShortcut(.defaultAction)
                .padding()
            }

            TabView {
                generalTab
                    .tabItem { Label("General", systemImage: "gearshape.fill") }

                securityTab
                    .tabItem { Label("Security", systemImage: "lock.shield.fill") }

                accountsTab
                    .tabItem { Label("Accounts", systemImage: "person.2.fill") }

                sshTab
                    .tabItem { Label("SSH Agent", systemImage: "terminal.fill") }

                licensesTab
                    .tabItem { Label("Licenses", systemImage: "doc.text.fill") }

                aboutTab
                    .tabItem { Label("About", systemImage: "info.circle.fill") }
            }
        }
        .frame(width: 500, height: 440)
        .task {
            await session.syncSecretAgentState()
            await session.syncSSHAgentState()
        }
    }

    // MARK: - General Tab

    private var generalTab: some View {
        Form {
            Section("Vault") {
                Picker("Lock timeout", selection: $lockTimeout) {
                    Text("1 minute").tag(1)
                    Text("5 minutes").tag(5)
                    Text("15 minutes").tag(15)
                    Text("30 minutes").tag(30)
                    Text("1 hour").tag(60)
                    Text("Never").tag(0)
                }

                Picker("Sync interval", selection: $syncInterval) {
                    Text("1 minute").tag(1)
                    Text("5 minutes").tag(5)
                    Text("15 minutes").tag(15)
                    Text("30 minutes").tag(30)
                    Text("Manual only").tag(0)
                }

                Toggle("Notify after background sync", isOn: $backgroundSyncStatusNotifications)
            }

            Section("App") {
                Toggle("Close to menu bar on Command-Q", isOn: $closeToMenuBarOnQuit)

                Text("When enabled, Command-Q hides Vault UI from the Dock and app switcher while keeping it available from the menu bar.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }

            Section("Clipboard") {
                Toggle("Clear clipboard after copy", isOn: $clearClipboard)

                if clearClipboard {
                    Picker("Clear after", selection: $clipboardTimeout) {
                        Text("10 seconds").tag(10)
                        Text("20 seconds").tag(20)
                        Text("30 seconds").tag(30)
                        Text("60 seconds").tag(60)
                    }
                }
            }
            Section("AutoFill") {
                Button("Open System AutoFill Settings") {
                    if let url = URL(string: "x-apple.systempreferences:com.apple.Passwords-Settings.extension") {
                        NSWorkspace.shared.open(url)
                    }
                }
                Text("Enable Vault UI as a Credential Provider to AutoFill passwords in Safari and other apps.")
                    .font(.caption)
                    .foregroundStyle(.secondary)

                Toggle("Suggest credentials in system AutoFill", isOn: $systemIdentitySyncEnabled)
                    .onChange(of: systemIdentitySyncEnabled) { _ in
                        Task { await session.syncSystemCredentialIdentityState() }
                    }
                Text("Shows matching passwords and passkeys directly in the AutoFill suggestions instead of only behind the Vault UI picker. Only names, usernames and domains are registered with the system; secrets stay encrypted and require Touch ID.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            
            Section("Safari Extension") {
                Button("Open Safari Preferences") {
                    SFSafariApplication.showPreferencesForExtension(withIdentifier: AppIdentifiers.safariExtensionBundleIdentifier) { error in
                        if let error = error {
                            print("Error opening Safari preferences: \(error)")
                        }
                    }
                }
                Text("Enable the Vault UI Safari Extension for exact subdomain matching and faster AutoFill.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
        .formStyle(.grouped)
        .padding()
    }

    // MARK: - Security Tab

    private var securityTab: some View {
        Form {
            Section("Biometric") {
                Toggle("Use Touch ID to unlock", isOn: $useTouchID)
            }

            Section("Auto-Lock") {
                Toggle("Lock on sleep", isOn: $lockOnSleep)
                Toggle("Lock on screen saver", isOn: $lockOnScreenSaver)
            }

            Section("Cache") {
                Button("Clear Icon Cache") {
                    IconCache.shared.clearAll()
                    iconCacheCleared = true
                    DispatchQueue.main.asyncAfter(deadline: .now() + 2) {
                        iconCacheCleared = false
                    }
                }
                if iconCacheCleared {
                    Text("Icon cache cleared ✓")
                        .font(.caption)
                        .foregroundStyle(.green)
                }
            }

            Section("Danger Zone") {
                Button("Log Out", role: .destructive) {
                    showLogoutConfirmation = true
                }
                .foregroundStyle(.red)

                Text("Removes all local data, credentials, and device registration. You will need to log in again.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
        .formStyle(.grouped)
        .padding()
        .alert("Log Out?", isPresented: $showLogoutConfirmation) {
            Button("Cancel", role: .cancel) {}
            Button("Log Out", role: .destructive) {
                dismiss()
                session.logout()
            }
        } message: {
            Text("This will delete all local vault data, saved credentials, and device registration. Your server data will not be affected. You will need to log in again and re-verify your device.")
        }
    }

    // MARK: - Accounts Tab

    @State private var aliasEdits: [String: String] = [:]
    @State private var shortNameEdits: [String: String] = [:]
    @State private var metadataCommitTask: Task<Void, Never>?
    @State private var accountPendingLogOut: Account?
    @State private var accountPendingRemoval: Account?

    private var accountsTab: some View {
        Form {
            ForEach(session.accounts) { account in
                Section {
                    HStack(spacing: 10) {
                        AccountAvatarView(email: account.email, colorIndex: account.avatarColorIndex, size: 36)
                        VStack(alignment: .leading, spacing: 2) {
                            Text(account.email)
                                .font(.headline)
                            Text(account.serverURL.host ?? account.serverURL.absoluteString)
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                        Spacer()
                        if account.id == session.activeAccount?.id {
                            Text("Active")
                                .font(.caption2.bold())
                                .padding(.horizontal, 8)
                                .padding(.vertical, 3)
                                .background(Capsule().fill(Color.green.opacity(0.2)))
                                .foregroundStyle(.green)
                        }
                    }

                    TextField("Alias", text: metadataBinding(for: account, edits: $aliasEdits, stored: account.alias))
                    TextField("Short Name", text: metadataBinding(for: account, edits: $shortNameEdits, stored: account.shortName))

                    Text("Shown in AutoFill as: [\(previewLabel(for: account))]")
                        .font(.caption)
                        .foregroundStyle(.secondary)

                    HStack {
                        Button("Log Out") {
                            accountPendingLogOut = account
                        }
                        Spacer()
                        Button("Remove from this Device", role: .destructive) {
                            accountPendingRemoval = account
                        }
                        .foregroundStyle(.red)
                    }
                }
            }
        }
        .formStyle(.grouped)
        .padding()
        .alert(item: $accountPendingLogOut) { account in
            Alert(
                title: Text("Log Out of \(account.email)?"),
                message: Text("Removes the session, Touch ID keys, and AutoFill data for this account. The locally cached vault data is kept, so signing back in does not require a full resync."),
                primaryButton: .destructive(Text("Log Out")) {
                    let wasActive = account.id == session.activeAccount?.id
                    session.logOutAccount(account.id)
                    if wasActive { dismiss() }
                },
                secondaryButton: .cancel()
            )
        }
        .alert(item: $accountPendingRemoval) { account in
            Alert(
                title: Text("Remove \(account.email) from this Device?"),
                message: Text("This will delete all local vault data, saved credentials, and device registration for this account. Your server data will not be affected."),
                primaryButton: .destructive(Text("Remove")) {
                    let wasActive = account.id == session.activeAccount?.id
                    session.removeAccount(account.id)
                    if wasActive { dismiss() }
                },
                secondaryButton: .cancel()
            )
        }
    }

    /// Binding into the per-account edit buffer, falling back to the stored
    /// value; commits (debounced) so QuickType labels follow along.
    private func metadataBinding(for account: Account, edits: Binding<[String: String]>, stored: String?) -> Binding<String> {
        Binding(
            get: { edits.wrappedValue[account.id] ?? stored ?? "" },
            set: { newValue in
                edits.wrappedValue[account.id] = newValue
                scheduleMetadataCommit(for: account)
            }
        )
    }

    /// Debounce the SwiftData + shared-store write so typing doesn't re-register
    /// system credential identities on every keystroke.
    private func scheduleMetadataCommit(for account: Account) {
        metadataCommitTask?.cancel()
        let accountId = account.id
        metadataCommitTask = Task { @MainActor in
            try? await Task.sleep(nanoseconds: 800_000_000)
            guard !Task.isCancelled else { return }
            session.updateAccountMetadata(
                accountId: accountId,
                alias: aliasEdits[accountId] ?? account.alias,
                shortName: shortNameEdits[accountId] ?? account.shortName
            )
        }
    }

    /// Live AutoFill label preview, using the in-progress edits for all accounts.
    private func previewLabel(for account: Account) -> String {
        let sources = session.accounts.map { acc in
            AccountLabelSource(
                accountId: acc.id,
                shortName: shortNameEdits[acc.id] ?? acc.shortName,
                alias: aliasEdits[acc.id] ?? acc.alias,
                serverHost: acc.serverURL.host,
                email: acc.email
            )
        }
        return AccountLabelResolver.resolveLabels(for: sources)[account.id] ?? account.email
    }

    // MARK: - SSH Tab

    @State private var cliInstallStatus: String?

    private var sshTab: some View {
        Form {
            Section("SSH Agent") {
                Toggle("Enable SSH Agent", isOn: $sshAgentEnabled)
                    .onChange(of: sshAgentEnabled) { _ in
                        Task { await session.syncSSHAgentState() }
                    }

                Toggle("Show SSH keys in menu bar", isOn: $showSSHKeysInMenuBar)

                HStack {
                    Text("Status")
                    Spacer()
                    if session.isSSHAgentRunning {
                        Label("Running", systemImage: "checkmark.circle.fill")
                            .foregroundStyle(.green)
                    } else {
                        Label("Stopped", systemImage: "xmark.circle.fill")
                            .foregroundStyle(.red)
                    }
                }

                HStack {
                    Text("Socket")
                    Spacer()
                    Text(SSHAgentServer.defaultSocketPath)
                        .font(.caption.monospaced())
                        .foregroundStyle(.secondary)
                        .textSelection(.enabled)
                }
                
                if sshAgentEnabled {
                    Picker("Re-authentication", selection: $agentReauthMode) {
                        Text("Ask every time").tag("everyTime")
                        Text("Ask again after a fixed time").tag("fixed")
                        Text("Sliding window (resets on use)").tag("sliding")
                    }

                    if agentReauthMode == "fixed" {
                        Picker("Ask again after", selection: $sshAgentUnlockTimeout) {
                            Text("5 minutes").tag(5)
                            Text("10 minutes").tag(10)
                            Text("15 minutes").tag(15)
                            Text("20 minutes").tag(20)
                            Text("30 minutes").tag(30)
                        }
                    } else if agentReauthMode == "sliding" {
                        Picker("Sliding window", selection: $sshAgentUnlockTimeout) {
                            Text("10 minutes").tag(10)
                            Text("15 minutes").tag(15)
                            Text("20 minutes").tag(20)
                            Text("30 minutes").tag(30)
                        }
                    }

                    Text({
                        switch agentReauthMode {
                        case "everyTime":
                            return "Touch ID is required for every secret and SSH key request. Most secure, most prompts."
                        case "fixed":
                            return "After you authorize, access stays unlocked for the chosen time, then Touch ID is required again — even with continued use."
                        default:
                            return "Each use extends the unlock window; it expires only after the chosen period of inactivity."
                        }
                    }())
                    .font(.caption)
                    .foregroundStyle(.secondary)
                }
            }

            Section("Setup") {
                VStack(alignment: .leading, spacing: 8) {
                    Text("Add to your shell profile:")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                    Text("export SSH_AUTH_SOCK=\"\(SSHAgentServer.defaultSocketPath)\"")
                        .font(.system(.caption, design: .monospaced))
                        .textSelection(.enabled)
                        .padding(8)
                        .background(RoundedRectangle(cornerRadius: 6).fill(.background))
                }

                Button("Install LaunchAgent") {
                    installSSHLaunchAgent()
                }

                if let status = launchAgentInstallStatus {
                    Text(status)
                        .font(.caption)
                        .foregroundStyle(status.contains("✓") ? .green : .red)
                }
            }

            Section("CLI Tool") {
                HStack {
                    Text("Secret Agent")
                    Spacer()
                    if session.isSecretAgentRunning {
                        Label("Running", systemImage: "checkmark.circle.fill")
                            .foregroundStyle(.green)
                    } else {
                        Label("Stopped", systemImage: "xmark.circle.fill")
                            .foregroundStyle(.red)
                    }
                }

                HStack {
                    Text("Socket")
                    Spacer()
                    Text(SecretAgentServer.defaultSocketPath)
                        .font(.caption.monospaced())
                        .foregroundStyle(.secondary)
                        .textSelection(.enabled)
                }

                Button("Install CLI to /usr/local/bin") {
                    installCLI()
                }

                if let status = cliInstallStatus {
                    Text(status)
                        .font(.caption)
                        .foregroundStyle(status.contains("✓") ? .green : .red)
                }

                VStack(alignment: .leading, spacing: 4) {
                    Text("Usage:")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                    Text("vaultui get <slug>")
                        .font(.system(.caption, design: .monospaced))
                        .textSelection(.enabled)
                }
            }
        }
        .formStyle(.grouped)
        .padding()
    }

    private func installCLI() {
        let dest = "/usr/local/bin/vaultui"

        // Find the CLI binary — check app bundle first, then sibling executable
        let cliPath = bundledCLIPath()

        guard FileManager.default.fileExists(atPath: cliPath) else {
            cliInstallStatus = "CLI binary not found in app bundle"
            return
        }

        // Try direct symlink first (works if /usr/local/bin is writable)
        do {
            if FileManager.default.fileExists(atPath: dest) {
                try FileManager.default.removeItem(atPath: dest)
            }
            try FileManager.default.createSymbolicLink(atPath: dest, withDestinationPath: cliPath)
            cliInstallStatus = "Installed ✓"
            return
        } catch {
            // Needs elevated permissions — fall through
        }

        // Copy the sudo command to clipboard and open Terminal for the user
        let command = "sudo ln -sf '\(cliPath)' '\(dest)'"
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(command, forType: .string)

        // Open Terminal.app
        NSWorkspace.shared.open(URL(fileURLWithPath: "/System/Applications/Utilities/Terminal.app"))

        cliInstallStatus = "Paste the command in Terminal (⌘V)"

        // Poll in the background for the symlink to appear
        DispatchQueue.global(qos: .userInitiated).async {
            for _ in 0..<60 {
                Thread.sleep(forTimeInterval: 1.0)
                if FileManager.default.fileExists(atPath: dest) {
                    DispatchQueue.main.async {
                        cliInstallStatus = "Installed ✓"
                    }
                    return
                }
            }
        }
    }

    private func installSSHLaunchAgent() {
        guard let cliPath = preferredCLIPath() else {
            launchAgentInstallStatus = "CLI binary not found"
            return
        }

        do {
            try SSHAgentServer.installLaunchAgent(cliPath: cliPath)
            launchAgentInstallStatus = "LaunchAgent installed ✓"
        } catch {
            launchAgentInstallStatus = "LaunchAgent failed: \(error.localizedDescription)"
        }
    }

    private func preferredCLIPath() -> String? {
        let candidates = [
            bundledCLIPath(),
            "/usr/local/bin/vaultui",
            "/opt/homebrew/bin/vaultui"
        ]

        return candidates.first { FileManager.default.isExecutableFile(atPath: $0) }
    }

    private func bundledCLIPath() -> String {
        let bundleCLI = Bundle.main.bundlePath + "/Contents/MacOS/vaultui"
        let siblingCLI = Bundle.main.executablePath
            .map { ($0 as NSString).deletingLastPathComponent + "/vaultui" }
            ?? ""

        return FileManager.default.fileExists(atPath: bundleCLI) ? bundleCLI : siblingCLI
    }

    // MARK: - About Tab

    private var licensesTab: some View {
        ScrollView {
            Text(thirdPartyLicenses)
                .font(.system(.caption, design: .monospaced))
                .foregroundStyle(.primary)
                .textSelection(.enabled)
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding()
        }
        .background(Color(nsColor: .textBackgroundColor))
        .task {
            thirdPartyLicenses = loadThirdPartyLicenses()
        }
    }

    private func loadThirdPartyLicenses() -> String {
        guard let url = Bundle.module.url(forResource: "THIRD_PARTY_LICENSES", withExtension: "md") else {
            return "Third-party license file was not bundled with the application."
        }

        return (try? String(contentsOf: url, encoding: .utf8))
            ?? "Unable to read third-party license file."
    }

    private var aboutTab: some View {
        VStack(spacing: 16) {
            HStack(spacing: 12) {
                Image(nsImage: NSApplication.shared.applicationIconImage)
                    .resizable()
                    .scaledToFit()
                    .frame(width: 64, height: 64)

                Text("Vault UI")
                    .font(.system(size: 36, weight: .bold))
            }

            Text("v1.5.27")
                .font(.caption)
                .foregroundStyle(.secondary)

            Text("Native macOS Bitwarden/Vaultwarden Client")
                .font(.body)
                .foregroundStyle(.secondary)

            Divider()
                .frame(width: 200)

            VStack(spacing: 4) {
                Text("Built with Swift, SwiftUI, and CryptoKit")
                    .font(.caption)
                    .foregroundStyle(.tertiary)
                Text("No Electron. No compromises.")
                    .font(.caption)
                    .foregroundStyle(.tertiary)
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}
