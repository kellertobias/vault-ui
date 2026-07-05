// MARK: - VaultServices/AgentCoordinator.swift
// Owns the SSH agent and secret agent socket servers and their request handling.

import Foundation
import SwiftData
import LocalAuthentication
import OSLog
import VaultModels
import VaultCrypto
import VaultSync
import VaultSSH

private let logger = Logger(subsystem: "com.vaultui", category: "AgentCoordinator")

/// The slice of session state the agent subsystem needs at request time.
///
/// `SessionManager` conforms and remains the owner of the vault key, the active
/// account, the model container, and the `@Published` running flags (so the UI
/// keeps observing `session.isSSHAgentRunning` / `isSecretAgentRunning`). The
/// coordinator reads through this protocol so it never has to reach into session
/// internals or duplicate that state.
@MainActor
protocol AgentHost: AnyObject {
    var agentVaultKey: SymmetricCryptoKey? { get }
    var agentAccountId: String? { get }
    var agentModelContainer: ModelContainer? { get }
    var agentVaultUnlocked: Bool { get }
    var isSSHAgentRunning: Bool { get set }
    var isSecretAgentRunning: Bool { get set }
}

/// Manages the SSH agent and secret agent socket servers: lifecycle (start/stop
/// per setting), SSH identity refresh, and the per-request biometric-gated
/// provision of decrypted ciphers / private keys.
///
/// Extracted from `SessionManager`. It owns the two server instances and reads
/// live vault state through its `AgentHost`. The biometric re-auth policy, the
/// locked-vault unlock fallback, and the decryption all live here.
@MainActor
final class AgentCoordinator {

    private weak var host: AgentHost?

    private var sshAgentServer: SSHAgentServer?
    private var secretAgentServer: SecretAgentServer?

    init(host: AgentHost) {
        self.host = host
    }

    // MARK: - SSH Agent

    /// Synchronize the SSH agent state with user settings and start/stop as needed.
    func syncSSHAgentState() async {
        guard let host else { return }
        let isEnabled = UserDefaults.standard.bool(forKey: "sshAgentEnabled")

        if isEnabled {
            if sshAgentServer == nil {
                if SSHAgentServer.isLaunchAgentRunning() {
                    host.isSSHAgentRunning = true
                    logger.info("SSH agent is already running")
                } else {
                    let handler = SSHAgentHandler { [weak self] cipherId, reason, requiresUserPresence in
                        guard let self = self else { return nil }
                        return await self.getPrivateKeyData(
                            for: cipherId,
                            reason: reason,
                            requiresUserPresence: requiresUserPresence
                        )
                    }
                    handler.setIdentities(SharedCredentialStore.shared.fetchSSHIdentities())
                    let server = SSHAgentServer(handler: handler)
                    do {
                        try await server.start()
                        self.sshAgentServer = server
                        host.isSSHAgentRunning = true
                        logger.info("SSH agent started successfully")
                    } catch {
                        logger.error("Failed to start SSH agent: \(error.localizedDescription)")
                        host.isSSHAgentRunning = SSHAgentServer.isLaunchAgentRunning()
                    }
                }
            }
            if host.agentVaultUnlocked {
                try? await updateSSHIdentities()
            }
        } else {
            if let server = sshAgentServer {
                await server.stop()
                self.sshAgentServer = nil
                host.isSSHAgentRunning = false
                logger.info("SSH agent stopped")
            } else {
                host.isSSHAgentRunning = SSHAgentServer.isLaunchAgentRunning()
            }
        }
    }

    /// Update the SSH identities available to the agent.
    func updateSSHIdentities() async throws {
        guard let host, let accountId = host.agentAccountId, let vaultKey = host.agentVaultKey else { return }
        guard let container = host.agentModelContainer else { return }

        Task.detached {
            let context = ModelContext(container)
            let descriptor = FetchDescriptor<PersistedCipher>(predicate: #Predicate {
                $0.accountId == accountId && $0.deletedDate == nil
            })

            guard let ciphers = try? context.fetch(descriptor) else { return }

            var identities: [SSHIdentity] = []
            for persisted in ciphers {
                guard let cipher = try? persisted.toCipher(), cipher.type == .sshKey, let sshKey = cipher.sshKey else { continue }

                let cipherId = cipher.id ?? persisted.id
                guard let publicKeyEnc = sshKey.publicKey else { continue }

                // We need itemKey
                let itemKey: SymmetricCryptoKey?
                if let keyEnc = cipher.key,
                   let keyData = try? CipherEncryption.decryptData(keyEnc, key: vaultKey) {
                    itemKey = try? SymmetricCryptoKey(keyData: keyData)
                } else {
                    itemKey = vaultKey
                }

                guard let key = itemKey else { continue }
                guard let publicKeyStr = try? CipherEncryption.decryptString(publicKeyEnc, key: key) else { continue }

                let parts = publicKeyStr.split(separator: " ")
                if parts.count >= 2, let blobData = Data(base64Encoded: String(parts[1])) {
                    let comment: String
                    if parts.count >= 3 {
                        comment = String(parts[2...].joined(separator: " "))
                    } else {
                        let nameDecrypted = (try? CipherEncryption.decryptString(cipher.name!, key: key)) ?? "Vault Key"
                        comment = nameDecrypted
                    }
                    identities.append(SSHIdentity(publicKeyBlob: blobData, comment: comment, cipherId: cipherId))
                }
            }

            await MainActor.run {
                self.sshAgentServer?.handler.setIdentities(identities)
                SharedCredentialStore.shared.storeSSHIdentities(identities)
                if self.sshAgentServer == nil, UserDefaults.standard.bool(forKey: "sshAgentEnabled") {
                    try? SSHAgentServer.kickstartLaunchAgent()
                }
                self.host?.isSSHAgentRunning = self.sshAgentServer != nil
                    || SSHAgentServer.isLaunchAgentRunning()
                logger.debug("Loaded \(identities.count) SSH identities into agent")
            }
        }
    }

    // MARK: - Lock / shutdown

    /// Drop cached plaintext key material on vault lock. Sockets stay alive so a
    /// later request can re-prompt for local authentication.
    func clearCachesOnLock() {
        sshAgentServer?.handler.clearCachedPrivateKeys()
        secretAgentServer?.handler.clearCache()
        // Out-of-process agents (SSH LaunchAgent) watch the lock-generation marker
        // and drop their cached key material too; SessionManager bumps it.
    }

    /// Drop identities and caches when background services stop. Sockets are kept
    /// alive for local authentication while the UI is closed.
    func clearForStop() {
        sshAgentServer?.handler.clearIdentities()
        secretAgentServer?.handler.clearCache()
    }

    // MARK: - Secret Agent

    /// Synchronize the secret agent state — starts the socket server and provides
    /// a cipher-provider callback that handles local authentication when the vault is locked.
    func syncSecretAgentState() async {
        guard let host else { return }
        if secretAgentServer == nil {
            let handler = SecretAgentHandler { [weak self] reason in
                guard let self = self else { return nil }
                return await self.provideDecryptedCiphers(reason: reason)
            }
            let server = SecretAgentServer(handler: handler)
            do {
                try await server.start()
                self.secretAgentServer = server
                host.isSecretAgentRunning = true
                logger.info("Secret agent started successfully")
            } catch {
                logger.error("Failed to start secret agent: \(error.localizedDescription)")
                host.isSecretAgentRunning = false
            }
        }
    }

    // MARK: - Request handling

    /// Enforce the "ask every time" agent re-auth policy with fresh local authentication.
    ///
    /// Must be checked even while the GUI vault is unlocked: the policy gates every
    /// agent request, not just the handler caches — otherwise any local process could
    /// read secrets silently whenever the vault key happens to be in memory.
    private func confirmAgentRequestIfRequired(reason: String?) async -> Bool {
        guard AgentUnlockPolicyStore.current().mode == .everyTime else { return true }

        do {
            return try await authenticateUserPresence(reason: reason, fallbackReason: "Authorize secret access")
        } catch {
            logger.error("Agent re-authentication failed: \(error.localizedDescription)")
            return false
        }
    }

    /// Authenticate the local user for an agent request. Touch ID is used when
    /// available; macOS falls back to device-owner authentication when it is not.
    private func authenticateUserPresence(reason: String?, fallbackReason: String) async throws -> Bool {
        let promptReason = reason?.isEmpty == false ? reason! : fallbackReason
        let context = LAContext()
        context.localizedReason = promptReason
        return try await context.evaluatePolicy(
            .deviceOwnerAuthentication,
            localizedReason: promptReason
        )
    }

    /// Provide all ciphers with their decryption keys for the secret agent handler.
    /// If the vault is locked, authenticates locally to get a temporary vault key.
    private func provideDecryptedCiphers(reason: String? = nil) async -> [(cipher: Cipher, key: SymmetricCryptoKey)]? {
        guard let host, let container = host.agentModelContainer, let accountId = host.agentAccountId else { return nil }

        // Determine vault key
        let vKey: SymmetricCryptoKey

        if let currentKey = host.agentVaultKey {
            guard await confirmAgentRequestIfRequired(reason: reason) else { return nil }
            vKey = currentKey
        } else {
            // Vault is locked — authenticate locally and retrieve the protected key.
            do {
                let storage = BiometricKeyStorage()
                guard storage.hasStoredKeys(for: accountId) else {
                    logger.error("Secret agent authentication failed: no stored protected keys")
                    return nil
                }

                let context = LAContext()
                let promptReason = reason?.isEmpty == false ? reason! : "Unlock Secret"
                context.localizedReason = promptReason
                let success = try await context.evaluatePolicy(
                    .deviceOwnerAuthentication,
                    localizedReason: promptReason
                )
                guard success else { return nil }

                let keys = try storage.retrieveKeys(for: accountId, context: context)
                vKey = keys.vaultKey
            } catch {
                logger.error("Secret agent authentication failed: \(error.localizedDescription)")
                return nil
            }
        }

        // A biometrically-unlocked temporary key is wiped automatically once the
        // returned item keys are released (see SymmetricCryptoKey); the cached
        // key, when used, stays owned by the session.

        // Fetch all ciphers
        let ciphers = await MainActor.run { () -> [Cipher] in
            let context = container.mainContext
            let descriptor = FetchDescriptor<PersistedCipher>(predicate: #Predicate {
                $0.accountId == accountId && $0.deletedDate == nil
            })
            guard let persisted = try? context.fetch(descriptor) else { return [] }
            return persisted.compactMap { try? $0.toCipher() }
        }

        // Resolve item keys
        return ciphers.compactMap { cipher -> (cipher: Cipher, key: SymmetricCryptoKey)? in
            if let keyEnc = cipher.key,
               let keyData = try? CipherEncryption.decryptData(keyEnc, key: vKey),
               let itemKey = try? SymmetricCryptoKey(keyData: keyData) {
                return (cipher, itemKey)
            }
            return (cipher, vKey)
        }
    }

    /// Fetch and decrypt a private key for the SSH agent handler.
    private func getPrivateKeyData(
        for cipherId: String,
        reason: String? = nil,
        requiresUserPresence: Bool = false
    ) async -> Data? {
        guard let host, let container = host.agentModelContainer, let accountId = host.agentAccountId else { return nil }

        // Fetch cipher directly from ModelContainer, bypassing SyncEngine which might be nil when locked
        let cipherResult = await MainActor.run { () -> Cipher? in
            let context = container.mainContext
            let descriptor = FetchDescriptor<PersistedCipher>(predicate: #Predicate { $0.id == cipherId && $0.accountId == accountId })
            if let persisted = try? context.fetch(descriptor).first {
                return try? persisted.toCipher()
            }
            return nil
        }

        guard let cipher = cipherResult,
              let sshKey = cipher.sshKey,
              let privateKeyEnc = sshKey.privateKey else { return nil }

        // Determine Vault Key
        let vKey: SymmetricCryptoKey

        if let currentKey = host.agentVaultKey {
            if requiresUserPresence {
                do {
                    guard try await authenticateUserPresence(reason: reason, fallbackReason: "Authorize SSH key access") else {
                        return nil
                    }
                } catch {
                    logger.error("SSH agent forced authentication failed: \(error.localizedDescription)")
                    return nil
                }
            } else {
                guard await confirmAgentRequestIfRequired(reason: reason) else { return nil }
            }
            vKey = currentKey
        } else {
            // Vault is locked. Authenticate locally for this request.
            do {
                let storage = BiometricKeyStorage()
                guard storage.hasStoredKeys(for: accountId) else {
                    logger.error("SSH agent authentication failed: no stored protected keys")
                    return nil
                }

                let promptReason = reason?.isEmpty == false ? reason! : "Unlock SSH Key"
                let context = LAContext()
                context.localizedReason = promptReason
                let success = try await context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: promptReason)
                guard success else { return nil }

                let keys = try storage.retrieveKeys(for: accountId, context: context)
                vKey = keys.vaultKey
            } catch {
                logger.error("SSH agent authentication failed: \(error.localizedDescription)")
                return nil
            }
        }

        // The temporary key (and any item key derived from it) is wiped once this
        // scope releases its references — no explicit zeroize needed.

        // Derive item key
        let itemKey: SymmetricCryptoKey
        if let keyEnc = cipher.key,
           let keyData = try? CipherEncryption.decryptData(keyEnc, key: vKey) {
            itemKey = (try? SymmetricCryptoKey(keyData: keyData)) ?? vKey
        } else {
            itemKey = vKey
        }

        guard let privateKeyStr = try? CipherEncryption.decryptString(privateKeyEnc, key: itemKey) else { return nil }
        return privateKeyStr.data(using: .utf8)
    }
}
