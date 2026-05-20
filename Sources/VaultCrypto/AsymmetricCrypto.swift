// MARK: - VaultCrypto/AsymmetricCrypto.swift
// RSA-OAEP encryption/decryption for organization key sharing

import Foundation
import Security

/// RSA-OAEP asymmetric encryption operations.
///
/// Used for organization key sharing: each org member has an RSA key pair,
/// and the org's symmetric key is encrypted with each member's public key.
public enum AsymmetricCrypto {

    /// Generate an RSA-2048 key pair.
    ///
    /// - Returns: Tuple of (publicKey DER, privateKey DER)
    public static func generateRSAKeyPair() throws -> (publicKey: Data, privateKey: Data) {
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeySizeInBits as String: CryptoConstants.rsaKeySize,
        ]

        var error: Unmanaged<CFError>?
        guard let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
            throw CryptoError.rsaOperationFailed(
                "Failed to generate RSA key: \(error?.takeRetainedValue().localizedDescription ?? "unknown")"
            )
        }

        guard let publicKey = SecKeyCopyPublicKey(privateKey) else {
            throw CryptoError.rsaOperationFailed("Failed to extract public key")
        }

        guard let publicKeyData = SecKeyCopyExternalRepresentation(publicKey, &error) as Data? else {
            throw CryptoError.rsaOperationFailed("Failed to export public key")
        }

        guard let privateKeyData = SecKeyCopyExternalRepresentation(privateKey, &error) as Data? else {
            throw CryptoError.rsaOperationFailed("Failed to export private key")
        }

        return (publicKeyData, privateKeyData)
    }

    /// Encrypt data using RSA-OAEP-SHA1.
    ///
    /// - Parameters:
    ///   - data: The data to encrypt (must be small enough for RSA)
    ///   - publicKeyData: DER-encoded public key
    /// - Returns: Encrypted data
    public static func encrypt(
        data: Data,
        publicKeyData: Data
    ) throws -> Data {
        let publicKey = try importPublicKey(data: publicKeyData)

        var error: Unmanaged<CFError>?
        guard let encrypted = SecKeyCreateEncryptedData(
            publicKey,
            .rsaEncryptionOAEPSHA1,
            data as CFData,
            &error
        ) as Data? else {
            throw CryptoError.rsaOperationFailed(
                "RSA encryption failed: \(error?.takeRetainedValue().localizedDescription ?? "unknown")"
            )
        }

        return encrypted
    }

    /// Decrypt data using RSA-OAEP-SHA1.
    ///
    /// - Parameters:
    ///   - encString: The EncString containing RSA-encrypted data
    ///   - privateKeyData: DER-encoded private key
    /// - Returns: Decrypted data
    public static func decrypt(
        encString: EncString,
        privateKeyData: Data
    ) throws -> Data {
        let algorithm: SecKeyAlgorithm
        switch encString.type {
        case .rsa2048_OAEPSHA1_B64, .rsa2048_OAEPSHA1_HMACSHA256_B64:
            algorithm = .rsaEncryptionOAEPSHA1
        case .rsa2048_OAEPSHA256_B64, .rsa2048_OAEPSHA256_HMACSHA256_B64:
            algorithm = .rsaEncryptionOAEPSHA256
        default:
            throw CryptoError.unsupportedEncryptionType(encString.type.rawValue)
        }

        let privateKey = try importPrivateKey(data: privateKeyData)

        var error: Unmanaged<CFError>?
        guard let decrypted = SecKeyCreateDecryptedData(
            privateKey,
            algorithm,
            encString.ciphertext as CFData,
            &error
        ) as Data? else {
            throw CryptoError.rsaOperationFailed(
                "RSA decryption failed: \(error?.takeRetainedValue().localizedDescription ?? "unknown")"
            )
        }

        return decrypted
    }

    /// Decrypt an RSA-encrypted SymmetricCryptoKey (used for org key decryption).
    public static func decryptKey(
        encString: EncString,
        privateKeyData: Data
    ) throws -> SymmetricCryptoKey {
        let keyData = try decrypt(encString: encString, privateKeyData: privateKeyData)
        return try SymmetricCryptoKey(keyData: keyData)
    }

    // MARK: - Key Import

    private static func importPublicKey(data: Data) throws -> SecKey {
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
            kSecAttrKeySizeInBits as String: CryptoConstants.rsaKeySize,
        ]

        var error: Unmanaged<CFError>?
        guard let key = SecKeyCreateWithData(data as CFData, attributes as CFDictionary, &error) else {
            throw CryptoError.rsaOperationFailed(
                "Failed to import public key: \(error?.takeRetainedValue().localizedDescription ?? "unknown")"
            )
        }
        return key
    }

    private static func importPrivateKey(data: Data) throws -> SecKey {
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
            kSecAttrKeySizeInBits as String: CryptoConstants.rsaKeySize,
        ]

        var error: Unmanaged<CFError>?
        guard let key = SecKeyCreateWithData(data as CFData, attributes as CFDictionary, &error) else {
            throw CryptoError.rsaOperationFailed(
                "Failed to import private key: \(error?.takeRetainedValue().localizedDescription ?? "unknown")"
            )
        }
        return key
    }
}
