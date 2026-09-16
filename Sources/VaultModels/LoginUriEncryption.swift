// MARK: - VaultModels/LoginUriEncryption.swift
// Encrypting login URIs the way official Bitwarden clients expect them.

import Foundation
import CryptoKit
import VaultCrypto

extension LoginUri {

    /// An encrypted URI together with its `uriChecksum`.
    ///
    /// Official Bitwarden clients drop a URI from any item that has its own item
    /// key unless `uriChecksum` holds the encrypted base64 SHA-256 of the
    /// plaintext URI — a guard against a server swapping URIs. Without it, the
    /// item still opens but its websites vanish, and autofill never matches it.
    /// Always writing the checksum is harmless for items without an item key,
    /// which the clients don't validate.
    ///
    /// - Parameter key: The key the item's fields are encrypted with (its item
    ///   key, or the base key for an item without one).
    public static func encrypted(
        _ uri: String,
        match: UriMatchType? = nil,
        key: SymmetricCryptoKey
    ) throws -> LoginUri {
        LoginUri(
            uri: try CipherEncryption.encrypt(string: uri, key: key),
            match: match,
            uriChecksum: try CipherEncryption.encrypt(string: checksum(for: uri), key: key).serialized()
        )
    }

    /// Base64 SHA-256 of the URI's UTF-8 bytes — the plaintext of `uriChecksum`.
    public static func checksum(for uri: String) -> String {
        Data(SHA256.hash(data: Data(uri.utf8))).base64EncodedString()
    }

    /// This URI with a checksum added, if it has none.
    ///
    /// For URIs written before the checksum was, or by clients that omit it.
    /// Leaves the URI untouched when it already has a checksum or cannot be
    /// decrypted with `key`.
    public func addingChecksumIfMissing(key: SymmetricCryptoKey) -> LoginUri {
        guard uriChecksum == nil,
              let encryptedUri = uri,
              let plaintext = try? CipherEncryption.decryptString(encryptedUri, key: key),
              let checksum = try? CipherEncryption.encrypt(string: Self.checksum(for: plaintext), key: key) else {
            return self
        }
        var updated = self
        updated.uriChecksum = checksum.serialized()
        return updated
    }
}
