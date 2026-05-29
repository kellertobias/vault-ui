// MARK: - VaultAppUI/SettingsView.swift
// Application settings and preferences

import SwiftUI
import SafariServices
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

    // Security
    @AppStorage("useTouchID") private var useTouchID = true
    @AppStorage("lockOnSleep") private var lockOnSleep = true
    @AppStorage("lockOnScreenSaver") private var lockOnScreenSaver = true

    // SSH Agent
    @AppStorage("sshAgentEnabled") private var sshAgentEnabled = false
    @AppStorage("sshAgentUnlockTimeout") private var sshAgentUnlockTimeout = 15
    @State private var showLogoutConfirmation = false
    @State private var iconCacheCleared = false
    @State private var thirdPartyLicenses = "Loading licenses..."

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

                sshTab
                    .tabItem { Label("SSH Agent", systemImage: "terminal.fill") }

                licensesTab
                    .tabItem { Label("Licenses", systemImage: "doc.text.fill") }

                aboutTab
                    .tabItem { Label("About", systemImage: "info.circle.fill") }
            }
        }
        .frame(width: 500, height: 440)
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
            }
            
            Section("Safari Extension") {
                Button("Open Safari Preferences") {
                    SFSafariApplication.showPreferencesForExtension(withIdentifier: "de.tobisk.apps.vaultui.SafariExtension") { error in
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

    // MARK: - SSH Tab

    @State private var cliInstallStatus: String?

    private var sshTab: some View {
        Form {
            Section("SSH Agent") {
                Toggle("Enable SSH Agent", isOn: $sshAgentEnabled)
                    .onChange(of: sshAgentEnabled) { _ in
                        Task { await session.syncSSHAgentState() }
                    }

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
                    Picker("Biometric Unlock Timeout", selection: $sshAgentUnlockTimeout) {
                        Text("1 minute").tag(1)
                        Text("5 minutes").tag(5)
                        Text("15 minutes").tag(15)
                        Text("30 minutes").tag(30)
                        Text("1 hour").tag(60)
                    }
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
                    try? SSHAgentServer.installLaunchAgent(
                        cliPath: "/usr/local/bin/vaultui"
                    )
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
                    Text("vaultui secret get <slug>")
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
        let bundleCLI = Bundle.main.bundlePath + "/Contents/MacOS/vaultui"
        let siblingCLI = (Bundle.main.executablePath.map { ($0 as NSString).deletingLastPathComponent + "/vaultui" }) ?? ""
        let cliPath = FileManager.default.fileExists(atPath: bundleCLI) ? bundleCLI : siblingCLI

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

            Text("v0.1.0")
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
