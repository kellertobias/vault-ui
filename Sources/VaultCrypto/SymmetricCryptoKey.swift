// MARK: - VaultCrypto/SymmetricCryptoKey.swift
// Represents a symmetric encryption key pair (encryption key + MAC key)

import Foundation
import CryptoKit

/// A symmetric key pair used for AES-256-CBC encryption with HMAC-SHA256 authentication.
///
/// Bitwarden uses a 512-bit key split into:
/// - First 256 bits: AES-256-CBC encryption key
/// - Last 256 bits: HMAC-SHA256 authentication key
public struct SymmetricCryptoKey: Sendable {
    /// The raw 512-bit key material (encKey + macKey)
    public var keyData: Data

    /// The 256-bit AES encryption key (first half)
    public var encryptionKey: Data {
        keyData.prefix(CryptoConstants.aesKeySize)
    }

    /// The 256-bit HMAC authentication key (second half)
    public var macKey: Data {
        keyData.suffix(CryptoConstants.hmacKeySize)
    }

    /// Initialize from raw 512-bit key data
    public init(keyData: Data) throws {
        guard keyData.count == CryptoConstants.aesKeySize + CryptoConstants.hmacKeySize else {
            throw CryptoError.invalidKeyLength(
                expected: CryptoConstants.aesKeySize + CryptoConstants.hmacKeySize,
                actual: keyData.count
            )
        }
        self.keyData = keyData
    }

    /// Initialize from separate encryption and MAC keys
    public init(encryptionKey: Data, macKey: Data) throws {
        guard encryptionKey.count == CryptoConstants.aesKeySize else {
            throw CryptoError.invalidKeyLength(
                expected: CryptoConstants.aesKeySize,
                actual: encryptionKey.count
            )
        }
        guard macKey.count == CryptoConstants.hmacKeySize else {
            throw CryptoError.invalidKeyLength(
                expected: CryptoConstants.hmacKeySize,
                actual: macKey.count
            )
        }
        self.keyData = encryptionKey + macKey
    }

    /// Generate a new random symmetric key
    public static func generate() throws -> SymmetricCryptoKey {
        var keyData = Data(count: CryptoConstants.aesKeySize + CryptoConstants.hmacKeySize)
        let result = keyData.withUnsafeMutableBytes { buffer in
            SecRandomCopyBytes(kSecRandomDefault, buffer.count, buffer.baseAddress!)
        }
        guard result == errSecSuccess else {
            throw CryptoError.randomGenerationFailed
        }
        return try SymmetricCryptoKey(keyData: keyData)
    }

    /// Overwrite key material with zeros to limit exposure in memory.
    ///
    /// Call before releasing a key reference (e.g. on vault lock).
    /// Note: Swift's value-type semantics and Data's COW mean this is
    /// best-effort; it zeroes the current backing buffer.
    public mutating func zeroize() {
        keyData.resetBytes(in: keyData.startIndex ..< keyData.endIndex)
    }
}
