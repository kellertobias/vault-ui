// MARK: - VaultAppUI/ImportView.swift
// Import vault data from external sources

import SwiftUI
import VaultModels
import VaultCrypto
import VaultServices
import UniformTypeIdentifiers
import AuthenticationServices

/// Import wizard for vault data.
struct ImportView: View {
    @EnvironmentObject var session: SessionManager
    @Environment(\.dismiss) private var dismiss

    @State private var importSource: ImportSource = .bitwardenJSON
    @State private var selectedFileURL: URL?
    var importToken: UUID?

    public init(importToken: UUID? = nil) {
        self.importToken = importToken
        if importToken != nil {
            self._importSource = State(initialValue: .appleCredentialExchange)
        }
    }
    @State private var isImporting = false
    @State private var result: ImportResult?
    @State private var errorMessage: String?

    enum ImportSource: String, CaseIterable {
        case bitwardenJSON = "Bitwarden JSON"
        case macOSPasswords = "macOS Passwords CSV"
        case sshKey = "SSH Key"
        case appleCredentialExchange = "Apple Direct Import"
    }

    var body: some View {
        VStack(spacing: 0) {
            // Header
            HStack {
                Text("Import Data")
                    .font(.title2.bold())
                Spacer()
            }
            .padding(20)

            // Source picker
            Picker("Source", selection: $importSource) {
                ForEach(ImportSource.allCases, id: \.self) { source in
                    Text(source.rawValue).tag(source)
                }
            }
            .pickerStyle(.segmented)
            .padding(.horizontal, 20)

            Divider()
                .padding(.top, 16)

            // Content
            ScrollView {
                VStack(alignment: .leading, spacing: 16) {
                    // Instructions
                    instructionsForSource

                    // File selection
                    if importSource != .appleCredentialExchange {
                        GroupBox {
                            VStack(spacing: 16) {
                                if let url = selectedFileURL {
                                    HStack {
                                        Image(systemName: "doc.fill")
                                            .foregroundStyle(.blue)
                                        Text(url.lastPathComponent)
                                            .font(.body)
                                        Spacer()
                                        Button("Change") { selectFile() }
                                    }
                                } else {
                                    VStack(spacing: 12) {
                                        Image(systemName: "arrow.down.doc.fill")
                                            .font(.system(size: 32))
                                            .foregroundStyle(.secondary)
                                        Text("Select a file to import")
                                            .font(.body)
                                            .foregroundStyle(.secondary)
                                        Button("Choose File…") { selectFile() }
                                            .buttonStyle(.borderedProminent)
                                    }
                                    .frame(maxWidth: .infinity)
                                    .padding(24)
                                }
                            }
                            .padding(8)
                        }
                    }

                    // Results
                    if let result = result {
                        GroupBox("Results") {
                            VStack(alignment: .leading, spacing: 8) {
                                Label(
                                    "\(result.totalImported) items imported",
                                    systemImage: "checkmark.circle.fill"
                                )
                                .foregroundStyle(.green)
                                .font(.headline)

                                if !result.ciphers.isEmpty {
                                    Text("\(result.ciphers.count) vault items")
                                        .font(.caption)
                                        .foregroundStyle(.secondary)
                                }
                                if !result.folders.isEmpty {
                                    Text("\(result.folders.count) folders")
                                        .font(.caption)
                                        .foregroundStyle(.secondary)
                                }
                                ForEach(result.warnings, id: \.self) { warning in
                                    Label(warning, systemImage: "exclamationmark.triangle.fill")
                                        .font(.caption)
                                        .foregroundStyle(.orange)
                                }
                            }
                            .padding(8)
                        }
                    }

                    if let error = errorMessage {
                        GroupBox {
                            Label(error, systemImage: "xmark.circle.fill")
                                .foregroundStyle(.red)
                                .padding(8)
                        }
                    }
                }
                .padding(20)
            }

            Divider()

            // Actions
            HStack {
                Button("Cancel") { dismiss() }
                    .keyboardShortcut(.cancelAction)
                Spacer()
                if result != nil {
                    Button("Done") { dismiss() }
                        .buttonStyle(.borderedProminent)
                } else {
                    Button {
                        Task { await performImport() }
                    } label: {
                        if isImporting {
                            ProgressView()
                                .controlSize(.small)
                        } else {
                            Text("Import")
                        }
                    }
                    .buttonStyle(.borderedProminent)
                    .disabled((importSource != .appleCredentialExchange && selectedFileURL == nil) || isImporting)
                }
            }
            .padding(20)
        }
        .frame(minWidth: 500, minHeight: 500)
    }

    @ViewBuilder
    private var instructionsForSource: some View {
        switch importSource {
        case .bitwardenJSON:
            VStack(alignment: .leading, spacing: 4) {
                Text("Import from Bitwarden/Vaultwarden")
                    .font(.headline)
                Text("Export your vault as **unencrypted JSON** from Bitwarden settings, then select the file below.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        case .macOSPasswords:
            VStack(alignment: .leading, spacing: 4) {
                Text("Import from macOS Passwords")
                    .font(.headline)
                Text("Open **Passwords** app → File → Export Passwords → save as CSV. Then select the file below.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        case .sshKey:
            VStack(alignment: .leading, spacing: 4) {
                Text("Import SSH Key")
                    .font(.headline)
                Text("Select a private key file (e.g., `~/.ssh/id_ed25519`). The public key will be loaded automatically if available.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        case .appleCredentialExchange:
            VStack(alignment: .leading, spacing: 4) {
                Text("Apple Direct Import")
                    .font(.headline)
                Text("Import securely and directly from Apple Passwords.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
    }

    private func selectFile() {
        let panel = NSOpenPanel()
        panel.canChooseDirectories = false
        panel.allowsMultipleSelection = false

        switch importSource {
        case .bitwardenJSON:
            panel.allowedContentTypes = [UTType.json]
        case .macOSPasswords:
            panel.allowedContentTypes = [UTType.commaSeparatedText]
        case .sshKey:
            panel.allowedContentTypes = [UTType.data]
            panel.directoryURL = FileManager.default.homeDirectoryForCurrentUser
                .appendingPathComponent(".ssh")
        case .appleCredentialExchange:
            return
        }

        panel.begin { response in
            if response == .OK {
                selectedFileURL = panel.url
                result = nil
                errorMessage = nil
            }
        }
    }

    private func performImport() async {
        if importSource != .appleCredentialExchange {
            guard selectedFileURL != nil else { return }
        }

        isImporting = true
        errorMessage = nil
        result = nil
        defer { isImporting = false }

        do {
            guard let key = try? session.getVaultKey() else {
                errorMessage = "Vault is locked"
                return
            }

            if importSource == .appleCredentialExchange {
                if #available(macOS 26.0, *) {
                    guard let token = importToken else {
                        errorMessage = "No active Apple Passwords import session."
                        return
                    }
                    let manager = ASCredentialImportManager()
                    let exportedData = try await manager.importCredentials(token: token)
                    result = try ImportService.importAppleCredentialExchange(exportedData: exportedData, encryptionKey: key)
                } else {
                    errorMessage = "Apple Direct Import requires macOS 15.0 or later."
                }
            } else {
                guard let url = selectedFileURL else { return }
                let data = try Data(contentsOf: url)
                
                switch importSource {
                case .bitwardenJSON:
                    result = try ImportService.importBitwardenJSON(data: data, encryptionKey: key)
                case .macOSPasswords:
                    result = try ImportService.importMacOSPasswordsCSV(data: data, encryptionKey: key)
                case .sshKey:
                    let pubURL = url.appendingPathExtension("pub")
                    let pubData = try? Data(contentsOf: pubURL)
                    let cipher = try ImportService.importSSHKey(
                        privateKeyData: data,
                        publicKeyData: pubData,
                        name: url.deletingPathExtension().lastPathComponent,
                        encryptionKey: key
                    )
                    result = ImportResult(ciphers: [cipher], folders: [], totalImported: 1, warnings: [])
                case .appleCredentialExchange:
                    break
                }
            }
            
            // Persist the imported data
            if let r = result {
                let engine = try session.getSyncEngine()
                for folder in r.folders {
                    try engine.saveFolderLocally(folder, operation: .create)
                }
                for cipher in r.ciphers {
                    try engine.saveCipherLocally(cipher, operation: .create)
                }
                // Trigger background sync to push to server
                Task { try? await engine.fullSync() }
            }
        } catch {
            errorMessage = error.localizedDescription
        }
    }
}
