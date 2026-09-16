// MARK: - VaultServices/URIChecksumRepair.swift
// Adds the URI checksums that older versions of this app never wrote.

import Foundation
import OSLog
import VaultCrypto
import VaultModels
import VaultSync

private let logger = Logger(subsystem: "com.vaultui", category: "URIChecksumRepair")

/// Repairs login URIs saved without a `uriChecksum`.
///
/// Official Bitwarden clients hide a URI on any item with its own item key unless
/// the URI carries a valid checksum (see `LoginUri.encrypted`). This app wrote
/// URIs without one until that was fixed, so websites on items it saved are
/// invisible in the official apps and never match in extension autofill. This
/// pass adds the missing checksums and uploads the items.
///
/// It is idempotent — once an item is repaired there is nothing left to do — so
/// it runs with the rest of the startup maintenance on every unlock.
public enum URIChecksumRepair {

    /// The repaired cipher, or `nil` when there is nothing to repair or it cannot
    /// be repaired safely.
    ///
    /// Only items with an item key are touched: official clients skip the check
    /// for items without one, so those URIs are already visible. The item key is
    /// opened with the key ring, and any item whose key does not open — an
    /// organization without an available key, or a damaged key — is left alone
    /// rather than guessed at. A checksum is only ever *added*; an existing one,
    /// even a wrong one, is kept, since it may be the tamper evidence it exists for.
    public static func repaired(_ cipher: Cipher, keyRing: VaultKeyRing) -> Cipher? {
        guard let encryptedItemKey = cipher.key,
              var login = cipher.login,
              let uris = login.uris,
              uris.contains(where: { $0.uri != nil && $0.uriChecksum == nil }),
              let baseKey = keyRing.baseKey(for: cipher),
              let itemKeyData = try? CipherEncryption.decryptData(encryptedItemKey, key: baseKey),
              let itemKey = try? SymmetricCryptoKey(keyData: itemKeyData) else {
            return nil
        }

        let repairedUris = uris.map { $0.addingChecksumIfMissing(key: itemKey) }
        guard repairedUris != uris else { return nil }

        login.uris = repairedUris
        var repaired = cipher
        repaired.login = login
        return repaired
    }

    /// Repair every eligible item in the local store and queue it for upload.
    ///
    /// Items with local changes that have not reached the server yet are skipped,
    /// so the repair never races an edit; they get their checksums when saved.
    ///
    /// - Parameter canEdit: Whether this account may write the item. Read-only
    ///   shared items are skipped: the server would reject the upload.
    /// - Returns: The IDs of the items queued for upload.
    @MainActor
    public static func repairLocally(
        syncEngine: SyncEngine,
        keyRing: VaultKeyRing,
        canEdit: (Cipher) -> Bool
    ) throws -> [String] {
        var repairedIds = [String]()

        for persisted in try syncEngine.fetchCiphers(includeDeleted: false) {
            guard persisted.syncStatus == .synced, persisted.pendingOperation == nil,
                  let cipher = try? persisted.toCipher(),
                  canEdit(cipher),
                  let repaired = repaired(cipher, keyRing: keyRing) else {
                continue
            }
            try syncEngine.saveCipherLocally(repaired, operation: .update)
            repairedIds.append(persisted.id)
        }

        return repairedIds
    }

    /// Repair locally, then sync so the repaired items reach the server.
    ///
    /// - Returns: The number of items repaired and uploaded.
    @discardableResult
    public static func run(
        syncEngine: SyncEngine,
        keyRing: VaultKeyRing,
        canEdit: @MainActor (Cipher) -> Bool
    ) async -> Int {
        let repairedIds: [String]
        do {
            repairedIds = try await MainActor.run {
                try repairLocally(syncEngine: syncEngine, keyRing: keyRing, canEdit: canEdit)
            }
        } catch {
            logger.error("URI checksum repair failed: \(error.localizedDescription, privacy: .public)")
            return 0
        }

        guard !repairedIds.isEmpty else { return 0 }
        logger.info("Added missing URI checksums to \(repairedIds.count) item(s)")

        do {
            try await syncEngine.fullSync()
        } catch {
            // The items stay queued; the next sync uploads them.
            logger.error("Could not upload URI checksum repairs yet: \(error.localizedDescription, privacy: .public)")
        }
        return repairedIds.count
    }
}
