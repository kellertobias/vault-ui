// MARK: - VaultCrypto/CipherEncryption.swift
// High-level encryption/decryption operations for vault items

import Foundation

/// High-level encryption and decryption operations for vault data.
///
/// This ties together EncString parsing, AES-CBC engine, and key management
/// to provide simple encrypt/decrypt interfaces for vault items.
public enum CipherEncryption {

    /// Encrypt a plaintext string into an EncString using AES-256-CBC + HMAC-SHA256.
    ///
    /// - Parameters:
    ///   - plaintext: The string to encrypt
    ///   - key: The symmetric key to use for encryption
    /// - Returns: An EncString (type 2)
    public static func encrypt(
        string plaintext: String,
        key: SymmetricCryptoKey
    ) throws -> EncString {
        guard let data = plaintext.data(using: .utf8) else {
            throw CryptoError.invalidUTF8
        }
        return try encrypt(data: data, key: key)
    }

    /// Encrypt raw data into an EncString using AES-256-CBC + HMAC-SHA256.
    ///
    /// - Parameters:
    ///   - data: The data to encrypt
    ///   - key: The symmetric key to use for encryption
    /// - Returns: An EncString (type 2)
    public static func encrypt(
        data: Data,
        key: SymmetricCryptoKey
    ) throws -> EncString {
        let (iv, ciphertext, mac) = try AESCBCEngine.encrypt(plaintext: data, key: key)
        return EncString(
            type: .aesCBC256_HMACSHA256_B64,
            iv: iv,
            ciphertext: ciphertext,
            mac: mac
        )
    }

    /// Decrypt an EncString to a plaintext string.
    ///
    /// - Parameters:
    ///   - encString: The encrypted string to decrypt
    ///   - key: The symmetric key to use for decryption
    /// - Returns: The decrypted plaintext string
    public static func decryptString(
        _ encString: EncString,
        key: SymmetricCryptoKey
    ) throws -> String {
        let data = try decryptData(encString, key: key)
        guard let string = String(data: data, encoding: .utf8) else {
            throw CryptoError.invalidUTF8
        }
        return string
    }

    /// Decrypt an EncString to raw data.
    ///
    /// - Parameters:
    ///   - encString: The encrypted string to decrypt
    ///   - key: The symmetric key to use for decryption
    /// - Returns: The decrypted data
    public static func decryptData(
        _ encString: EncString,
        key: SymmetricCryptoKey
    ) throws -> Data {
        switch encString.type {
        case .aesCBC256_HMACSHA256_B64:
            guard let iv = encString.iv, let mac = encString.mac else {
                throw CryptoError.decryptionFailed("Missing IV or MAC for type 2 encryption")
            }
            return try AESCBCEngine.decrypt(
                iv: iv,
                ciphertext: encString.ciphertext,
                mac: mac,
                key: key
            )

        case .aesCBC256_B64:
            // Legacy mode without HMAC — REJECTED for security.
            // AES-CBC without authentication is vulnerable to padding oracle attacks.
            // Bitwarden deprecated this type; items should be re-encrypted with type 2.
            throw CryptoError.unsupportedEncryptionType(encString.type.rawValue)

        case .rsa2048_OAEPSHA256_B64, .rsa2048_OAEPSHA1_B64,
             .rsa2048_OAEPSHA256_HMACSHA256_B64, .rsa2048_OAEPSHA1_HMACSHA256_B64:
            throw CryptoError.decryptionFailed(
                "RSA decryption requires an RSA private key — use AsymmetricCrypto"
            )

        default:
            throw CryptoError.unsupportedEncryptionType(encString.type.rawValue)
        }
    }

    /// Decrypt the ProtectedSymmetricKey from the server using the stretched master key.
    ///
    /// The server stores the user's vault encryption key encrypted with their
    /// stretched master key. This function decrypts it to obtain the vault key.
    ///
    /// - Parameters:
    ///   - protectedKey: The encrypted symmetric key from the server (EncString format)
    ///   - stretchedMasterKey: The stretched master key derived from the password
    /// - Returns: The decrypted vault encryption key
    public static func decryptProtectedSymmetricKey(
        _ protectedKey: EncString,
        stretchedMasterKey: SymmetricCryptoKey
    ) throws -> SymmetricCryptoKey {
        let keyData = try decryptData(protectedKey, key: stretchedMasterKey)
        return try SymmetricCryptoKey(keyData: keyData)
    }

    /// Decrypt the user's protected vault key using the master key, supporting both
    /// the modern and the legacy protection scheme:
    ///
    /// - Type 2 (`AesCbc256_HmacSha256_B64`): decrypted with the **stretched** master
    ///   key, HMAC-verified. This is every account created/rotated since ~2020.
    /// - Type 0 (`AesCbc256_B64`): legacy pre-2023 accounts store the account key
    ///   encrypted with the **raw (unstretched)** master key and no MAC. Official
    ///   clients support this fallback; without it those accounts cannot unlock.
    ///
    /// The unauthenticated type-0 path is scoped to the protected account key only —
    /// vault items still hard-reject type 0 in `decryptData`.
    public static func decryptUserKey(
        _ protectedKey: EncString,
        masterKey: MasterKey
    ) throws -> SymmetricCryptoKey {
        switch protectedKey.type {
        case .aesCBC256_HMACSHA256_B64:
            return try decryptProtectedSymmetricKey(
                protectedKey,
                stretchedMasterKey: masterKey.stretch()
            )

        case .aesCBC256_B64:
            guard let iv = protectedKey.iv else {
                throw CryptoError.decryptionFailed("Missing IV for legacy protected key")
            }
            let keyData = try AESCBCEngine.decryptUnauthenticated(
                iv: iv,
                ciphertext: protectedKey.ciphertext,
                key: masterKey.keyData
            )
            return try SymmetricCryptoKey(keyData: keyData)

        default:
            throw CryptoError.unsupportedEncryptionType(protectedKey.type.rawValue)
        }
    }

    /// Decrypt an optional EncString, returning nil if the input is nil.
    public static func decryptStringOptional(
        _ encString: EncString?,
        key: SymmetricCryptoKey
    ) throws -> String? {
        guard let encString = encString else { return nil }
        return try decryptString(encString, key: key)
    }
}
