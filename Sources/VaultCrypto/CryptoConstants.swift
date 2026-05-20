// MARK: - VaultCrypto/CryptoConstants.swift
// Constants for the Bitwarden encryption protocol

import Foundation

/// Constants defining the Bitwarden-compatible encryption protocol parameters.
public enum CryptoConstants {
    /// Default PBKDF2 iteration count (Bitwarden default as of 2024)
    public static let defaultPBKDF2Iterations: UInt32 = 600_000

    /// Default Argon2id parameters
    public static let defaultArgon2Iterations: UInt32 = 3
    public static let defaultArgon2Memory: UInt32 = 64  // MiB
    public static let defaultArgon2Parallelism: UInt32 = 4

    /// AES key size in bytes
    public static let aesKeySize = 32  // 256 bits

    /// HMAC key size in bytes
    public static let hmacKeySize = 32  // 256 bits

    /// AES-CBC IV size in bytes
    public static let ivSize = 16

    /// RSA key size in bits
    public static let rsaKeySize = 2048

    /// Minimum PBKDF2 iterations
    public static let minimumPBKDF2Iterations: UInt32 = 100_000
}
