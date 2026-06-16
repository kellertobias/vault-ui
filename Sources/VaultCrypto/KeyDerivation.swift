import Foundation
import Crypto
import CommonCrypto
import Argon2Swift

/// KDF type matching the Bitwarden server's prelogin response.
public enum KDFType: Int, Codable, Sendable {
    case pbkdf2 = 0
    case argon2id = 1
}

/// KDF configuration from the server's prelogin response.
public struct KDFConfig: Codable, Sendable, Equatable {
    public let type: KDFType
    public let iterations: UInt32
    public let memory: UInt32?       // Argon2id only (MiB)
    public let parallelism: UInt32?  // Argon2id only

    public init(
        type: KDFType,
        iterations: UInt32,
        memory: UInt32? = nil,
        parallelism: UInt32? = nil
    ) {
        self.type = type
        self.iterations = iterations
        self.memory = memory
        self.parallelism = parallelism
    }

    /// Default PBKDF2 configuration
    public static let defaultPBKDF2 = KDFConfig(
        type: .pbkdf2,
        iterations: CryptoConstants.defaultPBKDF2Iterations
    )
}

/// Key derivation operations.
public enum KeyDerivation {
    /// Derive a key using the configured KDF.
    ///
    /// - Parameters:
    ///   - password: The input password bytes
    ///   - salt: The salt bytes (typically email for Bitwarden)
    ///   - config: KDF configuration from the server
    ///   - allowWeakKDF: Permit PBKDF2 iteration counts below the enforced minimum.
    ///     Only the login/unlock flow may pass `true`, and only after surfacing a
    ///     weak-KDF warning to the user — legacy (pre-2023) accounts legitimately
    ///     use low iteration counts and would otherwise be locked out.
    /// - Returns: Derived key bytes (32 bytes / 256 bits)
    public static func deriveKey(
        password: Data,
        salt: Data,
        config: KDFConfig,
        allowWeakKDF: Bool = false
    ) throws -> Data {
        switch config.type {
        case .pbkdf2:
            guard allowWeakKDF || config.iterations >= CryptoConstants.minimumPBKDF2Iterations else {
                throw CryptoError.keyDerivationFailed(
                    "PBKDF2 iterations (\(config.iterations)) below minimum (\(CryptoConstants.minimumPBKDF2Iterations))"
                )
            }
            return try derivePBKDF2(
                password: password,
                salt: salt,
                iterations: config.iterations
            )
        case .argon2id:
            return try deriveArgon2id(
                password: password,
                salt: salt,
                iterations: config.iterations,
                memory: config.memory ?? CryptoConstants.defaultArgon2Memory,
                parallelism: config.parallelism ?? CryptoConstants.defaultArgon2Parallelism
            )
        }
    }

    /// Derive a key using PBKDF2-HMAC-SHA256.
    ///
    /// - Parameters:
    ///   - password: The input password bytes
    ///   - salt: The salt bytes
    ///   - iterations: Number of PBKDF2 iterations
    /// - Returns: 32-byte derived key
    public static func derivePBKDF2(
        password: Data,
        salt: Data,
        iterations: UInt32
    ) throws -> Data {
        return try derivePBKDF2SHA256(
            password: password,
            salt: salt,
            iterations: Int(iterations),
            keyLength: CryptoConstants.aesKeySize
        )
    }

    /// Derive a key using Argon2id.
    ///
    /// Bitwarden uses Argon2id with:
    /// - iterations: time cost (t_cost)
    /// - memory: memory in MiB (m_cost in KiB = memory * 1024)
    /// - parallelism: thread count (p_cost)
    /// - salt: SHA-256 hash of the email (32 bytes)
    /// - output: 32 bytes
    public static func deriveArgon2id(
        password: Data,
        salt: Data,
        iterations: UInt32,
        memory: UInt32,
        parallelism: UInt32
    ) throws -> Data {
        // Bitwarden hashes the salt (email) with SHA-256 to get a 32-byte salt
        let hashedSalt = Data(SHA256.hash(data: salt))

        do {
            let result = try Argon2Swift.hashPasswordBytes(
                password: password,
                salt: Salt(bytes: hashedSalt),
                iterations: Int(iterations),
                memory: Int(memory) * 1024,  // Convert MiB to KiB
                parallelism: Int(parallelism),
                length: CryptoConstants.aesKeySize,
                type: .id,
                version: .V13
            )
            return result.hashData()
        } catch {
            throw CryptoError.keyDerivationFailed(
                "Argon2id derivation failed: \(error.localizedDescription)"
            )
        }
    }

    // MARK: - Private PBKDF2 Implementation

    /// PBKDF2-HMAC-SHA256 via CommonCrypto's `CCKeyDerivationPBKDF`.
    ///
    /// This replaces a hand-rolled RFC 2898 loop built on `HMAC<SHA256>`. The
    /// manual version re-derived the HMAC key schedule on every one of the
    /// (up to 600k) iterations, making unlock noticeably slow; the platform
    /// routine is the optimized, well-reviewed implementation and produces
    /// byte-identical output.
    private static func derivePBKDF2SHA256(
        password: Data,
        salt: Data,
        iterations: Int,
        keyLength: Int
    ) throws -> Data {
        var derivedKey = Data(count: keyLength)

        // CommonCrypto requires non-null pointers even when a buffer is empty;
        // substitute a 1-byte buffer but keep the real (0) length so the result
        // matches PBKDF2 over empty input.
        let passwordData = password.isEmpty ? Data([0]) : password
        let saltData = salt.isEmpty ? Data([0]) : salt

        let status: Int32 = derivedKey.withUnsafeMutableBytes { derivedPtr in
            passwordData.withUnsafeBytes { passwordPtr in
                saltData.withUnsafeBytes { saltPtr in
                    CCKeyDerivationPBKDF(
                        CCPBKDFAlgorithm(kCCPBKDF2),
                        passwordPtr.baseAddress!.assumingMemoryBound(to: CChar.self),
                        password.count,
                        saltPtr.baseAddress!.assumingMemoryBound(to: UInt8.self),
                        salt.count,
                        CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256),
                        UInt32(iterations),
                        derivedPtr.baseAddress!.assumingMemoryBound(to: UInt8.self),
                        keyLength
                    )
                }
            }
        }

        guard status == kCCSuccess else {
            throw CryptoError.keyDerivationFailed("PBKDF2 derivation failed with status \(status)")
        }
        return derivedKey
    }
}
