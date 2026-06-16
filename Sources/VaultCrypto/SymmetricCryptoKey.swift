// MARK: - VaultCrypto/SymmetricCryptoKey.swift
// Represents a symmetric encryption key pair (encryption key + MAC key)

import Foundation
import CryptoKit

/// Heap-allocated, reference-counted storage for raw key material.
///
/// `SymmetricCryptoKey` is backed by this class rather than storing `Data`
/// inline, so every copy of a key shares one buffer. The buffer is wiped in
/// `deinit`, which means the bytes are zeroed from memory as soon as the last
/// `SymmetricCryptoKey` referencing them is released — including copies handed
/// to detached tasks, background agents, or the AutoFill export pipeline.
///
/// This replaces a value-type `zeroize()` that was effectively cosmetic: with
/// copy-on-write `Data`, zeroing one copy reallocated a fresh buffer and left
/// every other outstanding copy's plaintext intact. Tying the wipe to `deinit`
/// also avoids a data race — `deinit` only runs once no other reference exists,
/// so there is never a concurrent reader when the bytes are cleared.
///
/// Best-effort caveat: callers that extract `keyData`/`encryptionKey`/`macKey`
/// into a standalone `Data` and retain it past the key's lifetime hold an
/// independent COW buffer this type cannot reach. Sensitive bytes should be
/// consumed promptly and not stored.
private final class KeyStorage: @unchecked Sendable {
    /// Mutated only in `deinit`; treated as immutable for the lifetime of any
    /// shared reference, which is what makes the `@unchecked Sendable` sound.
    fileprivate var bytes: Data

    init(_ bytes: Data) {
        self.bytes = bytes
    }

    deinit {
        bytes.resetBytes(in: bytes.startIndex ..< bytes.endIndex)
    }
}

/// A symmetric key pair used for AES-256-CBC encryption with HMAC-SHA256 authentication.
///
/// Bitwarden uses a 512-bit key split into:
/// - First 256 bits: AES-256-CBC encryption key
/// - Last 256 bits: HMAC-SHA256 authentication key
///
/// Key material is wiped automatically when the last copy is released; see
/// `KeyStorage`. There is no explicit `zeroize()` — dropping every reference
/// (e.g. setting the cached vault key to `nil` on lock) is what clears it.
public struct SymmetricCryptoKey: @unchecked Sendable {
    /// Shared, reference-counted backing buffer for the raw key material.
    private let storage: KeyStorage

    /// The raw 512-bit key material (encKey + macKey)
    public var keyData: Data { storage.bytes }

    /// The 256-bit AES encryption key (first half)
    public var encryptionKey: Data {
        storage.bytes.prefix(CryptoConstants.aesKeySize)
    }

    /// The 256-bit HMAC authentication key (second half)
    public var macKey: Data {
        storage.bytes.suffix(CryptoConstants.hmacKeySize)
    }

    /// Initialize from raw 512-bit key data
    public init(keyData: Data) throws {
        guard keyData.count == CryptoConstants.aesKeySize + CryptoConstants.hmacKeySize else {
            throw CryptoError.invalidKeyLength(
                expected: CryptoConstants.aesKeySize + CryptoConstants.hmacKeySize,
                actual: keyData.count
            )
        }
        self.storage = KeyStorage(keyData)
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
        self.storage = KeyStorage(encryptionKey + macKey)
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
}
