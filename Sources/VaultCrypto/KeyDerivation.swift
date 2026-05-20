import Foundation
import Crypto
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
    /// - Returns: Derived key bytes (32 bytes / 256 bits)
    public static func deriveKey(
        password: Data,
        salt: Data,
        config: KDFConfig
    ) throws -> Data {
        switch config.type {
        case .pbkdf2:
            guard config.iterations >= CryptoConstants.minimumPBKDF2Iterations else {
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
        // Use swift-crypto's PBKDF2 implementation
        let key = try derivePBKDF2SHA256(
            password: password,
            salt: salt,
            iterations: Int(iterations),
            keyLength: CryptoConstants.aesKeySize
        )
        return key
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

    /// PBKDF2-HMAC-SHA256 implementation using swift-crypto.
    private static func derivePBKDF2SHA256(
        password: Data,
        salt: Data,
        iterations: Int,
        keyLength: Int
    ) throws -> Data {
        let derivedKey = try password.withUnsafeBytes { passwordBytes in
            try salt.withUnsafeBytes { saltBytes in
                let passwordBuffer = Array(passwordBytes.bindMemory(to: UInt8.self))
                let saltBuffer = Array(saltBytes.bindMemory(to: UInt8.self))

                // Use CryptoKit's HMAC for PBKDF2 implementation
                return try Self.pbkdf2HMACSHA256(
                    password: passwordBuffer,
                    salt: saltBuffer,
                    iterations: iterations,
                    keyLength: keyLength
                )
            }
        }
        return Data(derivedKey)
    }

    /// Manual PBKDF2-HMAC-SHA256 implementation per RFC 2898.
    ///
    /// Swift Crypto doesn't expose PBKDF2 directly as a top-level function,
    /// so we implement it using HMAC<SHA256>.
    private static func pbkdf2HMACSHA256(
        password: [UInt8],
        salt: [UInt8],
        iterations: Int,
        keyLength: Int
    ) throws -> [UInt8] {
        let hashLength = SHA256.Digest.byteCount  // 32
        let blockCount = (keyLength + hashLength - 1) / hashLength

        var derivedKey = [UInt8]()
        derivedKey.reserveCapacity(blockCount * hashLength)

        let symmetricKey = SymmetricKey(data: password)

        for blockIndex in 1...blockCount {
            // U1 = PRF(Password, Salt || INT_32_BE(i))
            let blockIndexBytes = withUnsafeBytes(of: UInt32(blockIndex).bigEndian) {
                Array($0)
            }
            var u = Array(
                HMAC<SHA256>.authenticationCode(
                    for: salt + blockIndexBytes,
                    using: symmetricKey
                )
            )
            var result = u

            // U2...Uc
            if iterations > 1 {
                for _ in 2...iterations {
                    u = Array(
                        HMAC<SHA256>.authenticationCode(
                            for: u,
                            using: symmetricKey
                        )
                    )
                    // XOR
                    for j in 0..<result.count {
                        result[j] ^= u[j]
                    }
                }
            }

            derivedKey.append(contentsOf: result)
        }

        return Array(derivedKey.prefix(keyLength))
    }
}
