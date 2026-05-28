// MARK: - VaultServices/TemporaryCredentialManager.swift
// Imports and manages temporary credential drafts from the browser extension.

import Foundation
import VaultModels
import VaultCrypto
import VaultSync
import OSLog

private let temporaryCredentialLogger = Logger(subsystem: "com.vaultui", category: "TemporaryCredentialManager")

public enum TemporaryCredentialManager {
    private static let temporaryMarkerFieldName = "vaultui-temporary"
    private static let temporaryURLFieldName = "vaultui-temporary-url"

    /// Import queued browser drafts as local-only temporary ciphers.
    public static func processTemporaryCredentialDrafts(syncEngine: SyncEngine, vaultKey: SymmetricCryptoKey) async {
        let store = SharedCredentialStore.shared
        let drafts = store.fetchTemporaryCredentialDrafts()

        guard !drafts.isEmpty else { return }

        temporaryCredentialLogger.info("Processing \(drafts.count) temporary credential draft(s) from Safari extension")

        var hasErrors = false

        for draft in drafts {
            do {
                if try await temporaryDraftExists(username: draft.username, url: draft.url, syncEngine: syncEngine, vaultKey: vaultKey) {
                    continue
                }

                let normalizedURL = normalizedCredentialURL(draft.url)
                var cipher = Cipher(type: .login)
                cipher.id = UUID().uuidString
                cipher.name = try CipherEncryption.encrypt(string: draft.name, key: vaultKey)
                cipher.creationDate = draft.creationDate
                cipher.revisionDate = Date()

                var login = LoginData()
                login.username = try CipherEncryption.encrypt(string: draft.username, key: vaultKey)
                let uri = LoginUri(
                    uri: try CipherEncryption.encrypt(string: normalizedURL, key: vaultKey),
                    match: .domain
                )
                login.uris = [uri]
                cipher.login = login

                let tempField = try CipherEncryption.encrypt(string: "true", key: vaultKey)
                let tempUrlField = try CipherEncryption.encrypt(string: draft.url, key: vaultKey)
                cipher.fields = [
                    CustomField(name: try CipherEncryption.encrypt(string: temporaryMarkerFieldName, key: vaultKey), value: tempField, type: .hidden),
                    CustomField(name: try CipherEncryption.encrypt(string: temporaryURLFieldName, key: vaultKey), value: tempUrlField, type: .hidden)
                ]

                try await MainActor.run {
                    try syncEngine.saveTemporaryCipherLocally(cipher)
                }
            } catch {
                temporaryCredentialLogger.error("Failed to import temporary draft for \(draft.url): \(error.localizedDescription)")
                hasErrors = true
            }
        }

        if !hasErrors {
            store.clearTemporaryCredentialDrafts()
            temporaryCredentialLogger.info("Successfully imported temporary drafts and cleared the queue")
        }
    }

    /// Remove local-only drafts that have expired.
    public static func cleanupExpiredTemporaryCredentials(syncEngine: SyncEngine) async {
        let cutoff = Date().addingTimeInterval(-24 * 60 * 60)
        let store = SharedCredentialStore.shared
        store.clearExpiredTemporaryCredentialDrafts(olderThan: cutoff)

        await MainActor.run {
            guard let ciphers = try? syncEngine.fetchCiphers(includeDeleted: true) else { return }
            for persisted in ciphers {
                guard persisted.syncStatus == .temporaryDraft,
                      let created = persisted.creationDate,
                      created < cutoff,
                      let cipher = try? persisted.toCipher() else { continue }
                try? syncEngine.deleteLocalCipher(cipher)
            }
        }
    }
}

private func normalizedCredentialURL(_ urlString: String) -> String {
    guard let url = URL(string: urlString), let host = url.host else {
        return urlString.lowercased()
    }
    var components = URLComponents()
    components.scheme = url.scheme ?? "https"
    components.host = host
    return components.url?.absoluteString.lowercased() ?? host.lowercased()
}

private func temporaryDraftExists(
    username: String,
    url: String,
    syncEngine: SyncEngine,
    vaultKey: SymmetricCryptoKey
) async throws -> Bool {
    let normalizedTargetURL = normalizedCredentialURL(url)

    return try await MainActor.run {
        let persisted = try syncEngine.fetchCiphers(includeDeleted: true)

        for item in persisted {
            guard item.syncStatus == .temporaryDraft,
                  let cipher = try? item.toCipher(),
                  let login = cipher.login else { continue }

            let decryptedUsername = login.username.flatMap { try? CipherEncryption.decryptString($0, key: vaultKey) } ?? ""
            guard decryptedUsername == username else { continue }

            let uris: [String] = (login.uris ?? []).compactMap { uri in
                guard let encryptedURI = uri.uri else { return nil }
                return try? CipherEncryption.decryptString(encryptedURI, key: vaultKey)
            }
            if uris.contains(where: { normalizedCredentialURL($0) == normalizedTargetURL }) {
                return true
            }
        }
        return false
    }
}
