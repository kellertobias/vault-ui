// MARK: - VaultServices/PendingCredentialManager.swift
// Processes pending login credentials from the Safari Web Extension

import Foundation
import VaultModels
import VaultCrypto
import VaultSync
import OSLog

private let pendingCredentialLogger = Logger(subsystem: "com.vaultui", category: "PendingCredentialManager")

/// Encrypts and saves credentials captured by the browser extension.
public enum PendingCredentialManager {
    public static func processPendingCredentials(syncEngine: SyncEngine, vaultKey: SymmetricCryptoKey) async {
        let store = SharedCredentialStore.shared
        let pendingList = store.fetchPendingCredentials()

        guard !pendingList.isEmpty else { return }

        pendingCredentialLogger.info("Processing \(pendingList.count) pending credentials from Safari extension")

        var hasErrors = false
        var modifiedCiphers = false

        for pending in pendingList {
            do {
                let normalizedURL = normalizedCredentialURL(pending.url)
                var cipher = Cipher(type: .login)
                cipher.name = try CipherEncryption.encrypt(string: pending.name, key: vaultKey)
                cipher.creationDate = pending.creationDate
                cipher.revisionDate = Date()

                let uri = LoginUri(
                    uri: try CipherEncryption.encrypt(string: normalizedURL, key: vaultKey),
                    match: .domain
                )

                var login = LoginData(
                    username: try CipherEncryption.encrypt(string: pending.username, key: vaultKey),
                    password: try CipherEncryption.encrypt(string: pending.password, key: vaultKey),
                    uris: [uri]
                )
                login.passwordRevisionDate = Date()
                cipher.login = login

                try await MainActor.run {
                    try syncEngine.saveCipherLocally(cipher, operation: .create)
                }
                modifiedCiphers = true
            } catch {
                pendingCredentialLogger.error("Failed to process pending credential for \(pending.url): \(error.localizedDescription)")
                hasErrors = true
            }
        }

        if !hasErrors {
            store.clearPendingCredentials()
            pendingCredentialLogger.info("Successfully processed all pending credentials and cleared the queue")
            await MainActor.run {
                SharedCredentialStore.shared.exportCredentials(from: syncEngine, vaultKey: vaultKey)
            }

            if modifiedCiphers {
                try? await syncEngine.fullSync()
            }
        } else {
            pendingCredentialLogger.warning("Some pending credentials failed to process; queue not cleared")
        }
    }

    private static func normalizedCredentialURL(_ urlString: String) -> String {
        guard let url = URL(string: urlString), let host = url.host else {
            return urlString
        }

        var components = URLComponents()
        components.scheme = url.scheme ?? "https"
        components.host = host
        return components.url?.absoluteString ?? host
    }
}
