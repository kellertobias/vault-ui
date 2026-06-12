// MARK: - VaultCrypto/AESCBCEngine.swift
// AES-256-CBC encryption with HMAC-SHA256 authentication

import Foundation
import CryptoKit
import CommonCrypto

/// Low-level AES-256-CBC encryption and decryption with HMAC-SHA256 authentication.
///
/// Bitwarden uses AES-256-CBC (not GCM) for vault encryption, with a separate
/// HMAC-SHA256 for data authentication (Encrypt-then-MAC pattern).
public enum AESCBCEngine {

    /// Encrypt plaintext using AES-256-CBC with HMAC-SHA256 authentication.
    ///
    /// - Parameters:
    ///   - plaintext: The data to encrypt
    ///   - key: The symmetric key pair (encKey + macKey)
    /// - Returns: Tuple of (iv, ciphertext, mac)
    public static func encrypt(
        plaintext: Data,
        key: SymmetricCryptoKey
    ) throws -> (iv: Data, ciphertext: Data, mac: Data) {
        // Generate random IV
        var iv = Data(count: CryptoConstants.ivSize)
        let ivResult = iv.withUnsafeMutableBytes { buffer in
            SecRandomCopyBytes(kSecRandomDefault, buffer.count, buffer.baseAddress!)
        }
        guard ivResult == errSecSuccess else {
            throw CryptoError.randomGenerationFailed
        }

        // AES-256-CBC encrypt
        let ciphertext = try aesCBCEncrypt(plaintext: plaintext, key: key.encryptionKey, iv: iv)

        // HMAC-SHA256(macKey, iv + ciphertext)
        let macData = iv + ciphertext
        let mac = computeHMAC(data: macData, key: key.macKey)

        return (iv, ciphertext, mac)
    }

    /// Decrypt ciphertext using AES-256-CBC with HMAC-SHA256 verification.
    ///
    /// - Parameters:
    ///   - iv: The initialization vector
    ///   - ciphertext: The encrypted data
    ///   - mac: The HMAC-SHA256 authentication tag
    ///   - key: The symmetric key pair (encKey + macKey)
    /// - Returns: Decrypted plaintext
    public static func decrypt(
        iv: Data,
        ciphertext: Data,
        mac: Data,
        key: SymmetricCryptoKey
    ) throws -> Data {
        // Verify HMAC first (Encrypt-then-MAC: verify before decrypt)
        let macData = iv + ciphertext
        let computedMac = computeHMAC(data: macData, key: key.macKey)

        guard constantTimeEqual(computedMac, mac) else {
            throw CryptoError.hmacVerificationFailed
        }

        // AES-256-CBC decrypt
        return try aesCBCDecrypt(ciphertext: ciphertext, key: key.encryptionKey, iv: iv)
    }

    /// Decrypt AES-256-CBC ciphertext WITHOUT MAC verification (legacy type 0).
    ///
    /// Unauthenticated CBC is padding-oracle prone, so this is deliberately
    /// internal and must only be used for the legacy protected account key
    /// (see `CipherEncryption.decryptUserKey`) — never for vault items.
    static func decryptUnauthenticated(
        iv: Data,
        ciphertext: Data,
        key: Data
    ) throws -> Data {
        try aesCBCDecrypt(ciphertext: ciphertext, key: key, iv: iv)
    }

    // MARK: - Private AES-CBC Implementation

    /// AES-256-CBC encryption using CommonCrypto.
    private static func aesCBCEncrypt(plaintext: Data, key: Data, iv: Data) throws -> Data {
        let bufferSize = plaintext.count + kCCBlockSizeAES128
        var ciphertext = Data(count: bufferSize)
        var numBytesEncrypted = 0

        let status = ciphertext.withUnsafeMutableBytes { ciphertextBuffer in
            plaintext.withUnsafeBytes { plaintextBuffer in
                key.withUnsafeBytes { keyBuffer in
                    iv.withUnsafeBytes { ivBuffer in
                        CCCrypt(
                            CCOperation(kCCEncrypt),
                            CCAlgorithm(kCCAlgorithmAES),
                            CCOptions(kCCOptionPKCS7Padding),
                            keyBuffer.baseAddress, key.count,
                            ivBuffer.baseAddress,
                            plaintextBuffer.baseAddress, plaintext.count,
                            ciphertextBuffer.baseAddress, bufferSize,
                            &numBytesEncrypted
                        )
                    }
                }
            }
        }

        guard status == kCCSuccess else {
            throw CryptoError.encryptionFailed("AES-CBC encryption failed with status \(status)")
        }

        return ciphertext.prefix(numBytesEncrypted)
    }

    /// AES-256-CBC decryption using CommonCrypto.
    private static func aesCBCDecrypt(ciphertext: Data, key: Data, iv: Data) throws -> Data {
        let bufferSize = ciphertext.count + kCCBlockSizeAES128
        var plaintext = Data(count: bufferSize)
        var numBytesDecrypted = 0

        let status = plaintext.withUnsafeMutableBytes { plaintextBuffer in
            ciphertext.withUnsafeBytes { ciphertextBuffer in
                key.withUnsafeBytes { keyBuffer in
                    iv.withUnsafeBytes { ivBuffer in
                        CCCrypt(
                            CCOperation(kCCDecrypt),
                            CCAlgorithm(kCCAlgorithmAES),
                            CCOptions(kCCOptionPKCS7Padding),
                            keyBuffer.baseAddress, key.count,
                            ivBuffer.baseAddress,
                            ciphertextBuffer.baseAddress, ciphertext.count,
                            plaintextBuffer.baseAddress, bufferSize,
                            &numBytesDecrypted
                        )
                    }
                }
            }
        }

        guard status == kCCSuccess else {
            throw CryptoError.decryptionFailed("AES-CBC decryption failed with status \(status)")
        }

        return plaintext.prefix(numBytesDecrypted)
    }

    // MARK: - HMAC

    /// Compute HMAC-SHA256.
    private static func computeHMAC(data: Data, key: Data) -> Data {
        let symmetricKey = SymmetricKey(data: key)
        let mac = HMAC<SHA256>.authenticationCode(for: data, using: symmetricKey)
        return Data(mac)
    }

    /// Constant-time comparison to prevent timing attacks.
    private static func constantTimeEqual(_ a: Data, _ b: Data) -> Bool {
        guard a.count == b.count else { return false }
        var result: UInt8 = 0
        for i in 0..<a.count {
            result |= a[a.startIndex + i] ^ b[b.startIndex + i]
        }
        return result == 0
    }
}
