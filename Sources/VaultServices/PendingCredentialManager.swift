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
                if let existingTemporary = await findTemporaryCipher(
                    matchingURL: normalizedURL,
                    username: pending.username,
                    syncEngine: syncEngine,
                    vaultKey: vaultKey
                ) {
                    var promoted = existingTemporary
                    let itemKey = itemEncryptionKey(for: promoted, vaultKey: vaultKey)
                    var login = promoted.login ?? LoginData()
                    login.username = try CipherEncryption.encrypt(string: pending.username, key: itemKey)
                    login.password = try CipherEncryption.encrypt(string: pending.password, key: itemKey)
                    login.passwordRevisionDate = Date()
                    if login.uris?.isEmpty ?? true {
                        login.uris = [
                            LoginUri(
                                uri: try CipherEncryption.encrypt(string: normalizedURL, key: itemKey),
                                match: .domain
                            )
                        ]
                    }
                    promoted.login = login
                    promoted.fields = promoted.fields?.filter { field in
                        guard let encryptedFieldName = field.name else { return false }
                        let fieldName = try? CipherEncryption.decryptString(encryptedFieldName, key: itemKey)
                        return fieldName != "vaultui-temporary" && fieldName != "vaultui-temporary-url"
                    }
                    if promoted.creationDate == nil {
                        promoted.creationDate = pending.creationDate
                    }
                    try await MainActor.run {
                        try syncEngine.promoteTemporaryCipherLocally(promoted)
                    }
                    modifiedCiphers = true
                } else {
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
                }
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

    private static func findTemporaryCipher(
        matchingURL url: String,
        username: String,
        syncEngine: SyncEngine,
        vaultKey: SymmetricCryptoKey
    ) async -> Cipher? {
        return await MainActor.run {
            let persisted = (try? syncEngine.fetchCiphers(includeDeleted: true)) ?? []

            for item in persisted {
                guard item.syncStatus == .temporaryDraft,
                      let cipher = try? item.toCipher(),
                      let login = cipher.login else { continue }

                let itemKey = itemEncryptionKey(for: cipher, vaultKey: vaultKey)
                let decryptedUsername = login.username.flatMap { try? CipherEncryption.decryptString($0, key: itemKey) } ?? ""
                guard decryptedUsername == username else { continue }

                let uris: [String] = (login.uris ?? []).compactMap { uri in
                    guard let encryptedURI = uri.uri else { return nil }
                    return try? CipherEncryption.decryptString(encryptedURI, key: itemKey)
                }
                if uris.contains(where: { normalizedCredentialURL($0) == url }) {
                    return cipher
                }
            }
            return nil
        }
    }

    private static func itemEncryptionKey(for cipher: Cipher, vaultKey: SymmetricCryptoKey) -> SymmetricCryptoKey {
        if let itemKeyEnc = cipher.key,
           let itemKeyData = try? CipherEncryption.decryptData(itemKeyEnc, key: vaultKey),
           let itemKey = try? SymmetricCryptoKey(keyData: itemKeyData) {
            return itemKey
        }
        return vaultKey
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
