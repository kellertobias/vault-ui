// MARK: - VaultServices/OrganizationSharing.swift
// Preparing ciphers for an organization: new shared items and moving existing ones.

import Foundation
import VaultModels
import VaultCrypto

/// The key work behind creating a shared item and moving a personal item into an
/// organization.
///
/// Both operations come down to one rule: everything an organization must be able
/// to read has to end up under that organization's key. A shared cipher's item key
/// is wrapped with the org key, and its fields with the item key — so every member
/// can unwrap the chain, and no personal key is ever involved.
public enum OrganizationSharing {

    public enum SharingError: Error, LocalizedError {
        case alreadyShared
        case noCollectionSelected
        case unknownOrganization(String)
        case missingCipherId

        public var errorDescription: String? {
            switch self {
            case .alreadyShared:
                return "This item already belongs to an organization."
            case .noCollectionSelected:
                return "Pick at least one collection to share this item into."
            case .unknownOrganization(let id):
                return "No key available for organization \(id)."
            case .missingCipherId:
                return "This item has not been saved to the server yet."
            }
        }
    }

    /// Generate an item key for a new cipher, wrapped under its owner's key.
    ///
    /// Pass `nil` for a personal item (wrapped under the vault key) or an
    /// organization ID for a shared one (wrapped under that org's key), so a new
    /// shared item is readable by the organization from the moment it is created.
    public static func makeItemKey(
        forOrganization organizationId: String?,
        keyRing: VaultKeyRing
    ) throws -> (itemKey: SymmetricCryptoKey, encryptedItemKey: EncString) {
        guard let baseKey = keyRing.baseKey(forOrganization: organizationId) else {
            throw SharingError.unknownOrganization(organizationId ?? "?")
        }
        let itemKey = try SymmetricCryptoKey.generate()
        let encryptedItemKey = try CipherEncryption.encrypt(data: itemKey.keyData, key: baseKey)
        return (itemKey, encryptedItemKey)
    }

    /// Re-key a personal cipher so an organization can read it.
    ///
    /// Modern items keep their item key and only have its wrapper swapped from the
    /// vault key to the org key — fields and attachments are untouched, which is
    /// both faster and impossible to get subtly wrong. Pre-2023 items have no item
    /// key, so they get a fresh one and every field is re-encrypted under it.
    ///
    /// The returned cipher is ready to send to `PUT /ciphers/{id}/share`; it is not
    /// persisted, and the local copy stays untouched until the server accepts it.
    public static func prepareForSharing(
        _ cipher: Cipher,
        organizationId: String,
        collectionIds: [String],
        keyRing: VaultKeyRing
    ) throws -> Cipher {
        guard cipher.organizationId == nil else { throw SharingError.alreadyShared }
        guard cipher.id != nil else { throw SharingError.missingCipherId }
        guard !collectionIds.isEmpty else { throw SharingError.noCollectionSelected }
        guard let orgKey = keyRing.organizationKeys[organizationId] else {
            throw SharingError.unknownOrganization(organizationId)
        }

        // An attachment with no key of its own has its ciphertext tied to the
        // personal vault key, so no re-keying of the cipher can make the
        // organization able to read it — it would have to be re-uploaded.
        if let attachments = cipher.attachments {
            for attachment in attachments where attachment.key == nil {
                throw CipherKeyRewrap.RewrapError.attachmentWithoutKey(attachment.id ?? "unnamed")
            }
        }

        let vaultKey = keyRing.vaultKey
        var shared: Cipher

        if let encryptedItemKey = cipher.key {
            // Same item key, new wrapper.
            let itemKeyData = try CipherEncryption.decryptData(encryptedItemKey, key: vaultKey)
            shared = cipher
            shared.key = try CipherEncryption.encrypt(data: itemKeyData, key: orgKey)
        } else {
            // No item key: mint one under the org key and move every field onto it.
            let itemKey = try SymmetricCryptoKey.generate()
            shared = try CipherKeyRewrap.rewrapFields(cipher, from: vaultKey, to: itemKey)
            shared.key = try CipherEncryption.encrypt(data: itemKey.keyData, key: orgKey)
        }

        shared.organizationId = organizationId
        shared.collectionIds = collectionIds
        // `folderId` is per-user, so the item stays in whatever personal folder
        // the user filed it under — the same as the official clients.
        return shared
    }
}
