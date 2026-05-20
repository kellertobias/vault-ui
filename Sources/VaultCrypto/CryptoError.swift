// MARK: - VaultCrypto/CryptoError.swift
// Error types for cryptographic operations

import Foundation

/// Errors that can occur during cryptographic operations.
public enum CryptoError: Error, LocalizedError, Sendable {
    case invalidKeyLength(expected: Int, actual: Int)
    case invalidEncryptedString(String)
    case unsupportedEncryptionType(Int)
    case decryptionFailed(String)
    case encryptionFailed(String)
    case hmacVerificationFailed
    case randomGenerationFailed
    case invalidBase64(String)
    case keyDerivationFailed(String)
    case invalidUTF8
    case rsaOperationFailed(String)
    case missingKey(String)

    public var errorDescription: String? {
        switch self {
        case .invalidKeyLength(let expected, let actual):
            return "Invalid key length: expected \(expected) bytes, got \(actual) bytes"
        case .invalidEncryptedString(let detail):
            return "Invalid encrypted string format: \(detail)"
        case .unsupportedEncryptionType(let type):
            return "Unsupported encryption type: \(type)"
        case .decryptionFailed(let detail):
            return "Decryption failed: \(detail)"
        case .encryptionFailed(let detail):
            return "Encryption failed: \(detail)"
        case .hmacVerificationFailed:
            return "HMAC verification failed — data may be corrupted or tampered with"
        case .randomGenerationFailed:
            return "Failed to generate cryptographically secure random bytes"
        case .invalidBase64(let detail):
            return "Invalid Base64 encoding: \(detail)"
        case .keyDerivationFailed(let detail):
            return "Key derivation failed: \(detail)"
        case .invalidUTF8:
            return "Invalid UTF-8 encoding in decrypted data"
        case .rsaOperationFailed(let detail):
            return "RSA operation failed: \(detail)"
        case .missingKey(let detail):
            return "Missing key: \(detail)"
        }
    }
}
