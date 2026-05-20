// MARK: - VaultCrypto/EncString.swift
// Bitwarden encrypted string format parser and builder

import Foundation

/// Represents a Bitwarden encrypted string.
///
/// Bitwarden uses a specific format for encrypted strings:
/// - Type 0: AES-256-CBC (no HMAC — legacy, not supported)
/// - Type 1: AES-128-CBC + HMAC-SHA256 (legacy, not supported)
/// - Type 2: AES-256-CBC + HMAC-SHA256 (current standard)
/// - Type 3: Not used
/// - Type 4: RSA-2048-OAEP-SHA256 (asymmetric)
/// - Type 5: RSA-2048-OAEP-SHA1 (asymmetric, legacy)
/// - Type 6: RSA-2048-OAEP-SHA256 + HMAC-SHA256 (asymmetric authenticated)
///
/// Format: `{type}.{iv_base64}|{ciphertext_base64}|{mac_base64}`
/// For RSA: `{type}.{ciphertext_base64}`
public struct EncString: Codable, Sendable, Equatable {
    /// The encryption type identifier
    public let type: EncryptionType

    /// Initialization vector (AES modes only)
    public let iv: Data?

    /// The encrypted ciphertext
    public let ciphertext: Data

    /// HMAC authentication tag (authenticated modes only)
    public let mac: Data?

    /// Supported encryption types
    public enum EncryptionType: Int, Codable, Sendable {
        case aesCBC256_B64 = 0                   // Legacy: AES-256-CBC, no HMAC
        case aesCBC128_HMACSHA256_B64 = 1         // Legacy: AES-128-CBC + HMAC
        case aesCBC256_HMACSHA256_B64 = 2         // Current: AES-256-CBC + HMAC
        case rsa2048_OAEPSHA256_B64 = 3           // RSA-OAEP-SHA256
        case rsa2048_OAEPSHA1_B64 = 4             // RSA-OAEP-SHA1
        case rsa2048_OAEPSHA256_HMACSHA256_B64 = 5 // RSA + HMAC
        case rsa2048_OAEPSHA1_HMACSHA256_B64 = 6   // RSA-SHA1 + HMAC
    }

    /// Parse an encrypted string from its serialized form.
    ///
    /// Format: `{type}.{iv}|{ct}|{mac}` or `{type}.{ct}` for RSA
    public init(serialized: String) throws {
        let parts = serialized.split(separator: ".", maxSplits: 1)
        guard parts.count == 2 else {
            throw CryptoError.invalidEncryptedString("Missing type prefix")
        }

        guard let typeInt = Int(parts[0]),
              let encType = EncryptionType(rawValue: typeInt) else {
            throw CryptoError.invalidEncryptedString("Invalid encryption type: \(parts[0])")
        }

        self.type = encType

        let payload = String(parts[1])

        switch encType {
        case .aesCBC256_HMACSHA256_B64, .aesCBC128_HMACSHA256_B64:
            // Format: iv|ct|mac (all base64)
            let segments = payload.split(separator: "|")
            guard segments.count == 3 else {
                throw CryptoError.invalidEncryptedString(
                    "Expected 3 segments (iv|ct|mac), got \(segments.count)"
                )
            }

            guard let ivData = Data(base64Encoded: String(segments[0])) else {
                throw CryptoError.invalidBase64("IV")
            }
            guard let ctData = Data(base64Encoded: String(segments[1])) else {
                throw CryptoError.invalidBase64("ciphertext")
            }
            guard let macData = Data(base64Encoded: String(segments[2])) else {
                throw CryptoError.invalidBase64("MAC")
            }

            self.iv = ivData
            self.ciphertext = ctData
            self.mac = macData

        case .aesCBC256_B64:
            // Format: iv|ct (no mac — legacy)
            let segments = payload.split(separator: "|")
            guard segments.count == 2 else {
                throw CryptoError.invalidEncryptedString(
                    "Expected 2 segments (iv|ct), got \(segments.count)"
                )
            }

            guard let ivData = Data(base64Encoded: String(segments[0])) else {
                throw CryptoError.invalidBase64("IV")
            }
            guard let ctData = Data(base64Encoded: String(segments[1])) else {
                throw CryptoError.invalidBase64("ciphertext")
            }

            self.iv = ivData
            self.ciphertext = ctData
            self.mac = nil

        case .rsa2048_OAEPSHA256_B64, .rsa2048_OAEPSHA1_B64:
            // Format: ct (just ciphertext)
            guard let ctData = Data(base64Encoded: payload) else {
                throw CryptoError.invalidBase64("RSA ciphertext")
            }
            self.iv = nil
            self.ciphertext = ctData
            self.mac = nil

        case .rsa2048_OAEPSHA256_HMACSHA256_B64, .rsa2048_OAEPSHA1_HMACSHA256_B64:
            // Format: ct|mac
            let segments = payload.split(separator: "|")
            guard segments.count == 2 else {
                throw CryptoError.invalidEncryptedString(
                    "Expected 2 segments (ct|mac), got \(segments.count)"
                )
            }

            guard let ctData = Data(base64Encoded: String(segments[0])) else {
                throw CryptoError.invalidBase64("RSA ciphertext")
            }
            guard let macData = Data(base64Encoded: String(segments[1])) else {
                throw CryptoError.invalidBase64("MAC")
            }

            self.iv = nil
            self.ciphertext = ctData
            self.mac = macData
        }
    }

    /// Create an EncString from components.
    public init(type: EncryptionType, iv: Data?, ciphertext: Data, mac: Data?) {
        self.type = type
        self.iv = iv
        self.ciphertext = ciphertext
        self.mac = mac
    }

    /// Serialize the encrypted string to its wire format.
    public func serialized() -> String {
        switch type {
        case .aesCBC256_HMACSHA256_B64, .aesCBC128_HMACSHA256_B64:
            let ivB64 = iv!.base64EncodedString()
            let ctB64 = ciphertext.base64EncodedString()
            let macB64 = mac!.base64EncodedString()
            return "\(type.rawValue).\(ivB64)|\(ctB64)|\(macB64)"

        case .aesCBC256_B64:
            let ivB64 = iv!.base64EncodedString()
            let ctB64 = ciphertext.base64EncodedString()
            return "\(type.rawValue).\(ivB64)|\(ctB64)"

        case .rsa2048_OAEPSHA256_B64, .rsa2048_OAEPSHA1_B64:
            let ctB64 = ciphertext.base64EncodedString()
            return "\(type.rawValue).\(ctB64)"

        case .rsa2048_OAEPSHA256_HMACSHA256_B64, .rsa2048_OAEPSHA1_HMACSHA256_B64:
            let ctB64 = ciphertext.base64EncodedString()
            let macB64 = mac!.base64EncodedString()
            return "\(type.rawValue).\(ctB64)|\(macB64)"
        }
    }

    // MARK: - Codable

    public init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        let serialized = try container.decode(String.self)
        try self.init(serialized: serialized)
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(serialized())
    }
}
