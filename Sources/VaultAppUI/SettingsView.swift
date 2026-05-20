// MARK: - VaultAppUI/SettingsView.swift
// Application settings and preferences

import SwiftUI
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
    @State private var agentRunning = false
    @State private var showPurgeConfirmation = false
    @State private var iconCacheCleared = false

    public init() {}

    public var body: some View {
        TabView {
            generalTab
                .tabItem { Label("General", systemImage: "gearshape.fill") }

            securityTab
                .tabItem { Label("Security", systemImage: "lock.shield.fill") }

            sshTab
                .tabItem { Label("SSH Agent", systemImage: "terminal.fill") }

            aboutTab
                .tabItem { Label("About", systemImage: "info.circle.fill") }
        }
        .frame(width: 500, height: 400)
        .onAppear { checkAgentStatus() }
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
                Button("Purge Local Vault Data", role: .destructive) {
                    showPurgeConfirmation = true
                }
                .foregroundStyle(.red)
            }
        }
        .formStyle(.grouped)
        .padding()
        .alert("Purge Local Vault Data?", isPresented: $showPurgeConfirmation) {
            Button("Cancel", role: .cancel) {}
            Button("Purge", role: .destructive) {
                purgeLocalData()
            }
        } message: {
            Text("This will delete all locally cached vault data. You will need to sync again to restore your items. Your server data will not be affected.")
        }
    }

    private func purgeLocalData() {
        guard let engine = try? session.getSyncEngine() else {
            // If no sync engine, just lock
            session.lock()
            return
        }

        // Delete all local ciphers, folders, sends
        if let ciphers = try? engine.fetchCiphers(includeDeleted: true) {
            for cipher in ciphers {
                if let c = try? cipher.toCipher() {
                    try? engine.saveCipherLocally(c, operation: .delete)
                }
            }
        }

        session.lock()
    }

    // MARK: - SSH Tab

    private var sshTab: some View {
        Form {
            Section("SSH Agent") {
                Toggle("Enable SSH Agent", isOn: $sshAgentEnabled)

                HStack {
                    Text("Status")
                    Spacer()
                    if agentRunning {
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
        }
        .formStyle(.grouped)
        .padding()
    }

    // MARK: - About Tab

    private var aboutTab: some View {
        VStack(spacing: 16) {
            Image(systemName: "shield.lefthalf.filled")
                .font(.system(size: 64))
                .foregroundStyle(.blue)

            Text("Vault UI")
                .font(.title.bold())

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

    private func checkAgentStatus() {
        agentRunning = FileManager.default.fileExists(
            atPath: SSHAgentServer.defaultSocketPath
        )
    }
}
