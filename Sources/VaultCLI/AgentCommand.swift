// MARK: - VaultCLI/AgentCommand.swift
// Long-running local agent process for SSH and CLI secret access.

import ArgumentParser
import Foundation
import LocalAuthentication
import SwiftData
import VaultCrypto
import VaultModels
import VaultServices
import VaultSSH
import VaultSync

struct AgentCommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "agent",
        abstract: "Run Vault UI background agents",
        subcommands: [
            StartAgentCommand.self,
            InstallLaunchAgentCommand.self,
        ]
    )
}

struct InstallLaunchAgentCommand: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "install-launch-agent",
        abstract: "Install and start the SSH LaunchAgent"
    )

    @Option(help: "CLI executable path for the LaunchAgent.")
    var cliPath: String?

    func run() throws {
        let selectedPath = cliPath ?? CommandLine.arguments.first ?? "/usr/local/bin/vaultui"
        let resolvedPath = URL(fileURLWithPath: selectedPath).resolvingSymlinksInPath().path
        try SSHAgentServer.installLaunchAgent(cliPath: preferredAgentPath(for: resolvedPath))
        print("LaunchAgent installed")
    }

    private func preferredAgentPath(for cliPath: String) -> String {
        let cliURL = URL(fileURLWithPath: cliPath).resolvingSymlinksInPath()
        var currentURL = cliURL.deletingLastPathComponent()

        while currentURL.path != "/" {
            if currentURL.pathExtension == "app" {
                let helperPath = currentURL
                    .appendingPathComponent("Contents", isDirectory: true)
                    .appendingPathComponent("Helpers", isDirectory: true)
                    .appendingPathComponent("VaultUIAgent.app", isDirectory: true)
                    .appendingPathComponent("Contents", isDirectory: true)
                    .appendingPathComponent("MacOS", isDirectory: true)
                    .appendingPathComponent("vaultui", isDirectory: false)
                    .path

                if FileManager.default.isExecutableFile(atPath: helperPath) {
                    return helperPath
                }
                break
            }

            currentURL.deleteLastPathComponent()
        }

        return cliPath
    }
}

struct StartAgentCommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "start",
        abstract: "Start the SSH and secret agent sockets"
    )

    @Flag(help: "Only start the SSH agent socket; the GUI app owns the secret agent socket.")
    var sshOnly = false

    func run() async throws {
        let runtime = try await MainActor.run {
            try LocalAgentRuntime()
        }

        let sshHandler = SSHAgentHandler { cipherId, reason in
            await runtime.privateKeyData(for: cipherId, reason: reason)
        }
        let initialIdentities = runtime.cachedSSHIdentities()
        sshHandler.setIdentities(initialIdentities)

        let sshServer = SSHAgentServer(handler: sshHandler)
        try await sshServer.start()

        let secretHandler: SecretAgentHandler? = sshOnly ? nil : SecretAgentHandler { reason in
            await runtime.decryptedCiphers(reason: reason)
        }

        let maintenanceTask = startAgentMaintenance(
            runtime: runtime,
            sshHandler: sshHandler,
            secretHandler: secretHandler,
            initialIdentities: initialIdentities
        )
        defer { maintenanceTask.cancel() }

        print("SSH Agent:    running (\(sshServer.agentSocketPath))")

        if sshOnly {
            try await sshServer.waitUntilClosed()
            return
        }

        guard let secretHandler else { return }
        let secretServer = SecretAgentServer(handler: secretHandler)
        try await secretServer.start()

        print("Secret Agent: running (\(secretServer.agentSocketPath))")

        try await withThrowingTaskGroup(of: Void.self) { group in
            group.addTask {
                try await sshServer.waitUntilClosed()
            }
            group.addTask {
                try await secretServer.waitUntilClosed()
            }
            try await group.waitForAll()
        }
    }

    private func startAgentMaintenance(
        runtime: LocalAgentRuntime,
        sshHandler: SSHAgentHandler,
        secretHandler: SecretAgentHandler?,
        initialIdentities: [SSHIdentity]
    ) -> Task<Void, Never> {
        Task {
            var currentIdentities = initialIdentities
            var lockGeneration = SharedCredentialStore.shared.fetchVaultLockGeneration()
            while !Task.isCancelled {
                try? await Task.sleep(for: .seconds(2))
                guard !Task.isCancelled else { break }

                // The GUI bumps the lock marker when the vault locks; drop all
                // cached key material so it does not outlive the vault session.
                let generation = SharedCredentialStore.shared.fetchVaultLockGeneration()
                if generation != lockGeneration {
                    lockGeneration = generation
                    sshHandler.clearCachedPrivateKeys()
                    secretHandler?.clearCache()
                }

                let identities = runtime.cachedSSHIdentities()
                guard identities != currentIdentities else { continue }

                sshHandler.setIdentities(identities)
                currentIdentities = identities
            }
        }
    }
}

@MainActor
private final class LocalAgentRuntime {
    private let modelContainer: ModelContainer
    private let biometricKeyStorage = BiometricKeyStorage()

    init() throws {
        self.modelContainer = try VaultDataStore.createModelContainer()
    }

    nonisolated func cachedSSHIdentities() -> [SSHIdentity] {
        SharedCredentialStore.shared.fetchSSHIdentities()
    }

    func privateKeyData(for cipherId: String, reason: String? = nil) async -> Data? {
        guard let account = activeAccount(),
              let cipher = fetchCipher(id: cipherId, accountId: account.id),
              let sshKey = cipher.sshKey,
              let privateKeyEnc = sshKey.privateKey,
              var vaultKey = await retrieveVaultKey(accountId: account.id, reason: reason) else {
            return nil
        }

        defer {
            vaultKey.zeroize()
        }

        let itemKey = itemKey(for: cipher, vaultKey: vaultKey)
        guard let privateKeyString = try? CipherEncryption.decryptString(privateKeyEnc, key: itemKey) else {
            return nil
        }
        return privateKeyString.data(using: .utf8)
    }

    func decryptedCiphers(reason: String? = nil) async -> [(cipher: Cipher, key: SymmetricCryptoKey)]? {
        guard let account = activeAccount(),
              var vaultKey = await retrieveVaultKey(accountId: account.id, reason: reason) else {
            return nil
        }

        defer {
            vaultKey.zeroize()
        }

        let ciphers = fetchCiphers(accountId: account.id)
        return ciphers.map { cipher in
            (cipher: cipher, key: itemKey(for: cipher, vaultKey: vaultKey))
        }
    }

    private func activeAccount() -> Account? {
        let context = modelContainer.mainContext
        let descriptor = FetchDescriptor<PersistedAccount>()
        guard let accounts = try? context.fetch(descriptor) else { return nil }
        return accounts.first(where: { $0.isActive })?.toAccount() ?? accounts.first?.toAccount()
    }

    private func fetchCipher(id: String, accountId: String) -> Cipher? {
        let context = modelContainer.mainContext
        let descriptor = FetchDescriptor<PersistedCipher>(
            predicate: #Predicate { $0.id == id && $0.accountId == accountId && $0.deletedDate == nil }
        )
        return (try? context.fetch(descriptor).first).flatMap { try? $0.toCipher() }
    }

    private func fetchCiphers(accountId: String) -> [Cipher] {
        let context = modelContainer.mainContext
        let descriptor = FetchDescriptor<PersistedCipher>(
            predicate: #Predicate { $0.accountId == accountId && $0.deletedDate == nil }
        )
        guard let persisted = try? context.fetch(descriptor) else { return [] }
        return persisted.compactMap { try? $0.toCipher() }
    }

    private func retrieveVaultKey(accountId: String, reason: String? = nil) async -> SymmetricCryptoKey? {
        guard biometricKeyStorage.hasStoredKeys(for: accountId) else {
            return nil
        }

        do {
            let context = LAContext()
            let success = try await context.evaluatePolicy(
                .deviceOwnerAuthenticationWithBiometrics,
                localizedReason: reason?.isEmpty == false ? reason! : "Unlock Vault UI Agent"
            )
            guard success else { return nil }

            return try biometricKeyStorage.retrieveKeys(for: accountId, context: context).vaultKey
        } catch {
            return nil
        }
    }

    private func itemKey(for cipher: Cipher, vaultKey: SymmetricCryptoKey) -> SymmetricCryptoKey {
        if let keyEnc = cipher.key,
           let keyData = try? CipherEncryption.decryptData(keyEnc, key: vaultKey),
           let itemKey = try? SymmetricCryptoKey(keyData: keyData) {
            return itemKey
        }
        return vaultKey
    }
}
