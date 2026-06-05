// MARK: - VaultCrypto/SendKeyDerivation.swift
// Bitwarden Send share key derivation

import Foundation
import CryptoKit

/// Derives the field encryption key used by Bitwarden Sends from the
/// 128-bit secret carried in the public Send URL fragment.
public enum SendKeyDerivation {
    public static let secretSize = 16
    private static let salt = Data("bitwarden-send".utf8)
    private static let purpose = Data("send".utf8)

    public static func generateSecret() throws -> Data {
        var secret = Data(count: secretSize)
        let result = secret.withUnsafeMutableBytes { buffer in
            SecRandomCopyBytes(kSecRandomDefault, buffer.count, buffer.baseAddress!)
        }
        guard result == errSecSuccess else {
            throw CryptoError.randomGenerationFailed
        }
        return secret
    }

    public static func deriveKey(from secret: Data) throws -> SymmetricCryptoKey {
        guard secret.count == secretSize else {
            throw CryptoError.invalidKeyLength(expected: secretSize, actual: secret.count)
        }

        let prk = Data(HMAC<SHA256>.authenticationCode(
            for: secret,
            using: SymmetricKey(data: salt)
        ))
        let keyData = hkdfExpand(prk: prk, info: purpose, outputByteCount: CryptoConstants.aesKeySize + CryptoConstants.hmacKeySize)
        return try SymmetricCryptoKey(keyData: keyData)
    }

    public static func deriveLegacyIncorrectKey(from secret: Data) throws -> SymmetricCryptoKey {
        guard secret.count == secretSize else {
            throw CryptoError.invalidKeyLength(expected: secretSize, actual: secret.count)
        }

        let legacyContext = Data("send".utf8)
        let prk = Data(HMAC<SHA256>.authenticationCode(
            for: secret,
            using: SymmetricKey(data: legacyContext)
        ))
        let keyData = hkdfExpand(prk: prk, info: legacyContext, outputByteCount: CryptoConstants.aesKeySize + CryptoConstants.hmacKeySize)
        return try SymmetricCryptoKey(keyData: keyData)
    }

    private static func hkdfExpand(prk: Data, info: Data, outputByteCount: Int) -> Data {
        var output = Data()
        var previous = Data()
        var counter: UInt8 = 1

        while output.count < outputByteCount {
            var input = Data()
            input.append(previous)
            input.append(info)
            input.append(counter)

            previous = Data(HMAC<SHA256>.authenticationCode(
                for: input,
                using: SymmetricKey(data: prk)
            ))
            output.append(previous)
            counter += 1
        }

        return output.prefix(outputByteCount)
    }
}
