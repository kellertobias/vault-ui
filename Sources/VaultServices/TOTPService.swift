// MARK: - VaultServices/TOTPService.swift
// TOTP code generation per RFC 6238

import Foundation
import CryptoKit

/// TOTP (Time-based One-Time Password) code generator per RFC 6238.
public enum TOTPService {

    /// Parse a TOTP URI or raw secret and generate the current code.
    ///
    /// Supports both:
    /// - Raw Base32 secrets: `JBSWY3DPEHPK3PXP`
    /// - otpauth URIs: `otpauth://totp/Example:user@test.com?secret=JBSWY3DPEHPK3PXP&digits=6&period=30`
    public static func generateCode(from input: String, at date: Date = Date()) -> TOTPCode? {
        let config = parseInput(input)
        guard let secretData = base32Decode(config.secret) else { return nil }

        let timeInterval = date.timeIntervalSince1970
        let counter = UInt64(timeInterval / Double(config.period))

        let code: String
        if config.isSteam {
            code = generateSteamCode(secret: secretData, counter: counter)
        } else {
            code = generateHOTP(
                secret: secretData,
                counter: counter,
                digits: config.digits,
                algorithm: config.algorithm
            )
        }

        let elapsed = Int(timeInterval) % config.period
        let remaining = config.period - elapsed

        return TOTPCode(
            code: code,
            period: config.period,
            remaining: remaining,
            digits: config.digits
        )
    }

    /// TOTP configuration parsed from input.
    struct TOTPConfig {
        var secret: String
        var digits: Int = 6
        var period: Int = 30
        var algorithm: TOTPAlgorithm = .sha1
        /// Steam Guard uses a 5-character alphanumeric encoding instead of digits.
        var isSteam: Bool = false
    }

    /// Steam Guard's custom alphabet for its 5-character codes.
    private static let steamAlphabet = Array("23456789BCDFGHJKMNPQRTVWXY")

    enum TOTPAlgorithm {
        case sha1, sha256, sha512
    }

    /// Parse a TOTP input (raw secret or otpauth URI).
    static func parseInput(_ input: String) -> TOTPConfig {
        if input.lowercased().hasPrefix("otpauth://") {
            return parseOTPAuthURI(input)
        }

        // Might be "steam://" for Steam Guard
        if input.lowercased().hasPrefix("steam://") {
            let secret = String(input.dropFirst("steam://".count))
            return TOTPConfig(secret: secret, digits: 5, period: 30, isSteam: true)
        }

        // Raw Base32 secret
        return TOTPConfig(secret: input)
    }

    /// Parse an otpauth:// URI.
    static func parseOTPAuthURI(_ uri: String) -> TOTPConfig {
        guard let url = URL(string: uri),
              let components = URLComponents(url: url, resolvingAgainstBaseURL: false) else {
            return TOTPConfig(secret: uri)
        }

        let queryItems = components.queryItems ?? []
        let secret = queryItems.first(where: { $0.name == "secret" })?.value ?? ""
        let digits = queryItems.first(where: { $0.name == "digits" })?.value.flatMap(Int.init) ?? 6
        let period = queryItems.first(where: { $0.name == "period" })?.value.flatMap(Int.init) ?? 30
        let algorithmStr = queryItems.first(where: { $0.name == "algorithm" })?.value?.lowercased() ?? "sha1"

        let algorithm: TOTPAlgorithm
        switch algorithmStr {
        case "sha256": algorithm = .sha256
        case "sha512": algorithm = .sha512
        default: algorithm = .sha1
        }

        return TOTPConfig(secret: secret, digits: digits, period: period, algorithm: algorithm)
    }

    /// Generate an HOTP code using HMAC.
    static func generateHOTP(
        secret: Data,
        counter: UInt64,
        digits: Int,
        algorithm: TOTPAlgorithm
    ) -> String {
        // Counter as big-endian bytes
        var counterBE = counter.bigEndian
        let counterData = Data(bytes: &counterBE, count: 8)
        let key = SymmetricKey(data: secret)

        // Compute HMAC
        let hmacBytes: [UInt8]
        switch algorithm {
        case .sha1:
            hmacBytes = Array(HMAC<Insecure.SHA1>.authenticationCode(for: counterData, using: key))
        case .sha256:
            hmacBytes = Array(HMAC<SHA256>.authenticationCode(for: counterData, using: key))
        case .sha512:
            hmacBytes = Array(HMAC<SHA512>.authenticationCode(for: counterData, using: key))
        }

        // Dynamic truncation
        let offset = Int(hmacBytes[hmacBytes.count - 1] & 0x0F)
        let truncated = (UInt32(hmacBytes[offset]) & 0x7F) << 24
            | UInt32(hmacBytes[offset + 1]) << 16
            | UInt32(hmacBytes[offset + 2]) << 8
            | UInt32(hmacBytes[offset + 3])

        let modulo = UInt32(pow(10, Double(digits)))
        let code = truncated % modulo

        return String(format: "%0\(digits)d", code)
    }

    /// Generate a Steam Guard code: 5 characters from Steam's custom alphabet.
    ///
    /// Uses the same HMAC-SHA1 dynamic truncation as RFC 4226, but maps the
    /// truncated integer into 5 symbols of the Steam alphabet instead of decimal
    /// digits. Numeric digits (the previous behaviour) are simply wrong for Steam.
    static func generateSteamCode(secret: Data, counter: UInt64) -> String {
        var counterBE = counter.bigEndian
        let counterData = Data(bytes: &counterBE, count: 8)
        let key = SymmetricKey(data: secret)
        let hmacBytes = Array(HMAC<Insecure.SHA1>.authenticationCode(for: counterData, using: key))

        let offset = Int(hmacBytes[hmacBytes.count - 1] & 0x0F)
        var truncated = (UInt32(hmacBytes[offset]) & 0x7F) << 24
            | UInt32(hmacBytes[offset + 1]) << 16
            | UInt32(hmacBytes[offset + 2]) << 8
            | UInt32(hmacBytes[offset + 3])

        var code = ""
        let alphabetCount = UInt32(steamAlphabet.count)
        for _ in 0..<5 {
            code.append(steamAlphabet[Int(truncated % alphabetCount)])
            truncated /= alphabetCount
        }
        return code
    }

    // MARK: - Base32 Decoding

    /// Decode a Base32-encoded string (RFC 4648).
    static func base32Decode(_ input: String) -> Data? {
        let alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
        let cleaned = input.uppercased().replacingOccurrences(of: " ", with: "")
            .replacingOccurrences(of: "=", with: "")

        var bits = ""
        for char in cleaned {
            guard let index = alphabet.firstIndex(of: char) else { return nil }
            let value = alphabet.distance(from: alphabet.startIndex, to: index)
            bits += String(value, radix: 2).leftPadded(toLength: 5, with: "0")
        }

        var bytes = [UInt8]()
        var i = 0
        while i + 8 <= bits.count {
            let startIdx = bits.index(bits.startIndex, offsetBy: i)
            let endIdx = bits.index(startIdx, offsetBy: 8)
            if let byte = UInt8(bits[startIdx..<endIdx], radix: 2) {
                bytes.append(byte)
            }
            i += 8
        }

        return Data(bytes)
    }
}

/// A generated TOTP code with metadata.
public struct TOTPCode: Sendable {
    public let code: String
    public let period: Int
    public let remaining: Int
    public let digits: Int

    /// Formatted code with a space in the middle (e.g., "482 193")
    public var formatted: String {
        let mid = code.count / 2
        let idx = code.index(code.startIndex, offsetBy: mid)
        return "\(code[..<idx]) \(code[idx...])"
    }
}

// MARK: - String Helpers

extension String {
    func leftPadded(toLength length: Int, with pad: Character) -> String {
        if count >= length { return self }
        return String(repeating: pad, count: length - count) + self
    }
}
