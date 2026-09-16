// MARK: - VaultServices/VaultCryptoFacade.swift
// Pure vault-item crypto operations, parameterized on the vault key.

import Foundation
import VaultModels
import VaultCrypto

/// Stateless vault-item encryption/decryption, extracted from `SessionManager`.
///
/// Every operation is a pure function of the supplied vault key and its inputs —
/// it holds no session state — so it is independently testable and reusable. The
/// "is the vault unlocked?" guard stays in `SessionManager`, which owns the
/// cached key and forwards to these helpers.
enum VaultCryptoFacade {

    // MARK: - Key-ring aware entry points
    //
    // An organization cipher's item key — and, for older ciphers without one, its
    // fields directly — are wrapped under the *organization* key. These overloads
    // resolve the base key from the cipher's `organizationId` before doing any
    // work, and return nil rather than falling back to the personal vault key when
    // that org key is unavailable: a personal-key fallback would decrypt to blank
    // and, on save, re-encrypt shared data into something no one else can read.

    /// Decrypt an EncString belonging to `organizationId` (nil = personal item).
    static func decrypt(
        _ encString: EncString?,
        itemKey: EncString?,
        organizationId: String?,
        keyRing: VaultKeyRing
    ) -> String? {
        guard let baseKey = keyRing.baseKey(forOrganization: organizationId) else { return nil }
        return decrypt(encString, itemKey: itemKey, vaultKey: baseKey)
    }

    /// Extract the symmetric key a cipher's fields are encrypted with.
    ///
    /// Falls back to the cipher's base key (personal vault key or org key) when the
    /// cipher carries no item key of its own.
    static func itemKey(for cipher: Cipher, keyRing: VaultKeyRing) throws -> SymmetricCryptoKey {
        guard let baseKey = keyRing.baseKey(for: cipher) else {
            throw CryptoError.missingKey(
                "No key available for organization \(cipher.organizationId ?? "?")"
            )
        }
        return try itemKey(for: cipher, vaultKey: baseKey)
    }

    // MARK: - Vault-key entry points

    /// Decrypt an EncString using the item key (if provided) or the vault key.
    static func decrypt(_ encString: EncString?, itemKey: EncString?, vaultKey: SymmetricCryptoKey) -> String? {
        guard let encString = encString else { return nil }

        let key: SymmetricCryptoKey
        if let itemKeyEnc = itemKey,
           let itemKeyData = try? CipherEncryption.decryptData(itemKeyEnc, key: vaultKey),
           let symKey = try? SymmetricCryptoKey(keyData: itemKeyData) {
            key = symKey
        } else {
            key = vaultKey
        }

        if let result = try? CipherEncryption.decryptString(encString, key: key) {
            return result
        }

        // Fallback: If itemKey failed (e.g. due to bug during passkey creation), try the vaultKey directly
        if itemKey != nil {
            return try? CipherEncryption.decryptString(encString, key: vaultKey)
        }

        return nil
    }

    /// Encrypt a string using the vault key.
    static func encrypt(_ string: String, vaultKey: SymmetricCryptoKey) throws -> EncString {
        try CipherEncryption.encrypt(string: string, key: vaultKey)
    }

    /// Encrypt a string using a specific item key.
    static func encrypt(_ string: String, using key: SymmetricCryptoKey) throws -> EncString {
        try CipherEncryption.encrypt(string: string, key: key)
    }

    /// Generate a new 512-bit item key and return its encrypted form under the vault key.
    static func generateItemKey(vaultKey: SymmetricCryptoKey) throws -> (SymmetricCryptoKey, EncString) {
        let itemKey = try SymmetricCryptoKey.generate()
        let encryptedItemKey = try CipherEncryption.encrypt(data: itemKey.keyData, key: vaultKey)
        return (itemKey, encryptedItemKey)
    }

    /// Generate a Bitwarden Send secret, its derived field encryption key, and encrypted stored form.
    static func generateSendKey(vaultKey: SymmetricCryptoKey) throws -> (key: SymmetricCryptoKey, secret: Data, encryptedSecret: EncString) {
        let secret = try SendKeyDerivation.generateSecret()
        let sendKey = try SendKeyDerivation.deriveKey(from: secret)
        let encryptedSecret = try CipherEncryption.encrypt(data: secret, key: vaultKey)
        return (sendKey, secret, encryptedSecret)
    }

    /// Extract the symmetric key for a cipher (falls back to the vault key if `cipher.key` is nil).
    static func itemKey(for cipher: Cipher, vaultKey: SymmetricCryptoKey) throws -> SymmetricCryptoKey {
        if let keyEnc = cipher.key,
           let keyData = try? CipherEncryption.decryptData(keyEnc, key: vaultKey) {
            return try SymmetricCryptoKey(keyData: keyData)
        }
        return vaultKey
    }

    /// Extract the derived symmetric key for a Send.
    static func sendKey(for send: SendItem, vaultKey: SymmetricCryptoKey) throws -> SymmetricCryptoKey {
        let keyData = try sendKeyData(for: send, vaultKey: vaultKey)
        switch keyData.count {
        case SendKeyDerivation.secretSize:
            return try SendKeyDerivation.deriveKey(from: keyData)
        case CryptoConstants.aesKeySize + CryptoConstants.hmacKeySize:
            return try SymmetricCryptoKey(keyData: keyData)
        default:
            throw CryptoError.invalidKeyLength(expected: SendKeyDerivation.secretSize, actual: keyData.count)
        }
    }

    /// Extract the raw Send URL secret. This is intentionally not the derived field key.
    static func sendURLKey(for send: SendItem, vaultKey: SymmetricCryptoKey) throws -> Data {
        let keyData = try sendKeyData(for: send, vaultKey: vaultKey)
        guard keyData.count == SendKeyDerivation.secretSize else {
            throw CryptoError.invalidKeyLength(expected: SendKeyDerivation.secretSize, actual: keyData.count)
        }
        return keyData
    }

    static func hasLegacySendKey(for send: SendItem, vaultKey: SymmetricCryptoKey) -> Bool {
        (try? sendKeyData(for: send, vaultKey: vaultKey).count) == CryptoConstants.aesKeySize + CryptoConstants.hmacKeySize
    }

    static func decryptSend(_ encString: EncString?, send: SendItem, vaultKey: SymmetricCryptoKey) -> String? {
        guard let encString else { return nil }

        if let sendKey = try? sendKey(for: send, vaultKey: vaultKey),
           let value = try? CipherEncryption.decryptString(encString, key: sendKey) {
            return value
        }

        guard let keyData = try? sendKeyData(for: send, vaultKey: vaultKey),
              keyData.count == SendKeyDerivation.secretSize,
              let legacyKey = try? SendKeyDerivation.deriveLegacyIncorrectKey(from: keyData) else {
            return nil
        }
        return try? CipherEncryption.decryptString(encString, key: legacyKey)
    }

    static func sendKeyData(for send: SendItem, vaultKey: SymmetricCryptoKey) throws -> Data {
        guard let keyEnc = send.key else {
            throw CryptoError.missingKey("Send is missing its encryption key")
        }
        return try CipherEncryption.decryptData(keyEnc, key: vaultKey)
    }
}
