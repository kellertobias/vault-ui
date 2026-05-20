// MARK: - VaultCrypto/MasterKey.swift
// Master key derivation and stretching per the Bitwarden protocol

import Foundation
import CryptoKit

/// Represents the master key derived from a user's master password and email.
///
/// The Bitwarden key derivation chain:
/// 1. MasterKey = KDF(password, email)           → 256-bit
/// 2. StretchedMasterKey = HKDF(MasterKey)       → 512-bit (encKey + macKey)
/// 3. Decrypt ProtectedSymmetricKey from server  → 512-bit vault key
public struct MasterKey: Sendable {
    /// The raw 256-bit master key
    public let keyData: Data

    private init(keyData: Data) {
        self.keyData = keyData
    }

    /// Derive the master key from a password and email using the specified KDF.
    ///
    /// - Parameters:
    ///   - password: The user's master password
    ///   - email: The user's email address (used as salt, lowercased)
    ///   - kdfConfig: KDF configuration from the server's prelogin response
    /// - Returns: The derived master key
    public static func derive(
        password: String,
        email: String,
        kdfConfig: KDFConfig
    ) throws -> MasterKey {
        guard let passwordData = password.data(using: .utf8) else {
            throw CryptoError.keyDerivationFailed("Password is not valid UTF-8")
        }
        guard let saltData = email.lowercased().data(using: .utf8) else {
            throw CryptoError.keyDerivationFailed("Email is not valid UTF-8")
        }

        let keyData = try KeyDerivation.deriveKey(
            password: passwordData,
            salt: saltData,
            config: kdfConfig
        )

        return MasterKey(keyData: keyData)
    }

    /// Stretch the 256-bit master key to a 512-bit key using HKDF-Expand.
    ///
    /// This produces the StretchedMasterKey which is used to decrypt
    /// the ProtectedSymmetricKey received from the server.
    ///
    /// - Returns: A 512-bit SymmetricCryptoKey (encKey + macKey)
    public func stretch() throws -> SymmetricCryptoKey {
        let inputKey = SymmetricKey(data: keyData)

        // HKDF-Expand with "enc" info to get 32-byte encryption key
        let encKey = HKDF<SHA256>.expand(
            pseudoRandomKey: inputKey,
            info: Data("enc".utf8),
            outputByteCount: CryptoConstants.aesKeySize
        )

        // HKDF-Expand with "mac" info to get 32-byte MAC key
        let macKey = HKDF<SHA256>.expand(
            pseudoRandomKey: inputKey,
            info: Data("mac".utf8),
            outputByteCount: CryptoConstants.hmacKeySize
        )

        let encKeyData = encKey.withUnsafeBytes { Data($0) }
        let macKeyData = macKey.withUnsafeBytes { Data($0) }

        return try SymmetricCryptoKey(encryptionKey: encKeyData, macKey: macKeyData)
    }
}
