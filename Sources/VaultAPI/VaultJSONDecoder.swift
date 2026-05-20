// MARK: - VaultAPI/VaultJSONDecoder.swift
// Shared JSON decoder with Bitwarden-compatible date handling

import Foundation

/// Shared JSON decoder configured for Bitwarden's date formats.
///
/// Bitwarden uses multiple ISO 8601 date formats across its API, so this
/// decoder tries several parsing strategies in sequence.
public enum VaultJSONDecoder {
    /// The shared decoder instance.
    public static let shared: JSONDecoder = {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .custom { decoder in
            let container = try decoder.singleValueContainer()
            let dateString = try container.decode(String.self)

            // Try ISO 8601 with fractional seconds
            if let date = ISO8601DateFormatter.bitwarden.date(from: dateString) {
                return date
            }
            // Try without fractional seconds
            if let date = ISO8601DateFormatter.bitwardenNoFraction.date(from: dateString) {
                return date
            }
            // Try basic date format (truncated)
            let formatter = DateFormatter()
            formatter.dateFormat = "yyyy-MM-dd'T'HH:mm:ss"
            formatter.locale = Locale(identifier: "en_US_POSIX")
            if let date = formatter.date(from: String(dateString.prefix(19))) {
                return date
            }
            throw DecodingError.dataCorrupted(
                DecodingError.Context(
                    codingPath: decoder.codingPath,
                    debugDescription: "Cannot decode date: \(dateString)"
                )
            )
        }
        return decoder
    }()

    /// Shared encoder.
    public static let encoder: JSONEncoder = {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        return encoder
    }()
}
