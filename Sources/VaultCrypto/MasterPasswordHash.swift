// MARK: - VaultCrypto/MasterPasswordHash.swift
// Generate the master password hash sent to the server for authentication

import Foundation
import CryptoKit

/// Utilities for generating the master password hash used for server authentication.
///
/// The hash is computed as: PBKDF2-SHA256(MasterKey, password, 1 iteration)
/// This ensures the server never sees the actual master password or master key.
public enum MasterPasswordHash {
    /// Compute the master password hash for server authentication.
    ///
    /// - Parameters:
    ///   - masterKey: The derived master key (from MasterKey.derive())
    ///   - password: The user's master password (used as salt in this step)
    /// - Returns: Base64-encoded password hash string
    public static func compute(
        masterKey: MasterKey,
        password: String
    ) throws -> String {
        guard let passwordData = password.data(using: .utf8) else {
            throw CryptoError.keyDerivationFailed("Password is not valid UTF-8")
        }

        // PBKDF2-SHA256(masterKey, password, 1 iteration)
        // Note: masterKey is the "password" input, actual password is the "salt"
        let hash = try KeyDerivation.derivePBKDF2(
            password: masterKey.keyData,
            salt: passwordData,
            iterations: 1
        )

        return hash.base64EncodedString()
    }
}
