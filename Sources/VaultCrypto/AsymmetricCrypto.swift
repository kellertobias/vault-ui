// MARK: - VaultCrypto/AsymmetricCrypto.swift
// RSA-OAEP encryption/decryption for organization key sharing

import Foundation
import Security

/// RSA-OAEP asymmetric encryption operations.
///
/// Used for organization key sharing: each org member has an RSA key pair,
/// and the org's symmetric key is encrypted with each member's public key.
public enum AsymmetricCrypto {

    /// Generate an RSA-2048 key pair in the formats Bitwarden/Vaultwarden use.
    ///
    /// - Returns: Tuple of (publicKey SPKI DER, privateKey PKCS#8 DER) — Security
    ///   exports PKCS#1, so both halves are re-wrapped before returning.
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

        return (
            ASN1DER.spkiPublicKey(fromPKCS1: publicKeyData),
            ASN1DER.pkcs8PrivateKey(fromPKCS1: privateKeyData)
        )
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

    /// Import an RSA public key.
    ///
    /// Bitwarden ships the account public key as SPKI; Security wants PKCS#1.
    static func importPublicKey(data: Data) throws -> SecKey {
        do {
            let pkcs1 = try ASN1DER.rsaPublicKeyPKCS1(from: data)
            return try createKey(
                pkcs1: pkcs1,
                keyClass: kSecAttrKeyClassPublic,
                bitCount: try ASN1DER.rsaModulusBitCount(pkcs1PublicKey: pkcs1),
                label: "public"
            )
        } catch let error as ASN1DER.ASN1Error {
            throw CryptoError.rsaOperationFailed("Failed to parse public key: \(error.localizedDescription)")
        }
    }

    /// Import an RSA private key.
    ///
    /// The decrypted account private key arrives as PKCS#8; Security wants PKCS#1.
    static func importPrivateKey(data: Data) throws -> SecKey {
        do {
            let pkcs1 = try ASN1DER.rsaPrivateKeyPKCS1(from: data)
            return try createKey(
                pkcs1: pkcs1,
                keyClass: kSecAttrKeyClassPrivate,
                bitCount: try ASN1DER.rsaModulusBitCount(pkcs1PrivateKey: pkcs1),
                label: "private"
            )
        } catch let error as ASN1DER.ASN1Error {
            throw CryptoError.rsaOperationFailed("Failed to parse private key: \(error.localizedDescription)")
        }
    }

    private static func createKey(
        pkcs1: Data,
        keyClass: CFString,
        bitCount: Int,
        label: String
    ) throws -> SecKey {
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeyClass as String: keyClass,
            kSecAttrKeySizeInBits as String: bitCount,
        ]

        var error: Unmanaged<CFError>?
        guard let key = SecKeyCreateWithData(pkcs1 as CFData, attributes as CFDictionary, &error) else {
            throw CryptoError.rsaOperationFailed(
                "Failed to import \(label) key: \(error?.takeRetainedValue().localizedDescription ?? "unknown")"
            )
        }
        return key
    }
}
