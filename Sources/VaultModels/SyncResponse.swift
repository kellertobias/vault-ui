// MARK: - VaultModels/SyncResponse.swift
// Full sync API response model

import Foundation

/// The complete sync response from `GET /api/sync`.
///
/// Contains the user's profile, all vault items, folders, collections,
/// sends, and organization data.
public struct SyncResponse: Codable, Sendable {
    public var profile: Profile?
    public var folders: [Folder]?
    public var collections: [Collection]?
    public var ciphers: [Cipher]?
    public var sends: [SendItem]?
    public var policies: [PolicyData]?
    public var domains: DomainData?

    public init() {}

    private enum CodingKeys: String, CodingKey {
        case profile, folders, collections, ciphers, sends, policies, domains
    }
}

/// Equivalent domain data for URI matching.
public struct DomainData: Codable, Sendable {
    public var equivalentDomains: [[String]]?
    public var globalEquivalentDomains: [GlobalEquivalentDomain]?

    public init() {}
}

/// A global equivalent domain entry.
public struct GlobalEquivalentDomain: Codable, Sendable {
    public var type: Int?
    public var domains: [String]?
    public var excluded: Bool?

    public init() {}
}

/// Organization policy data.
public struct PolicyData: Codable, Sendable {
    public var id: String?
    public var organizationId: String?
    public var type: Int?
    public var data: [String: AnyCodableValue]?
    public var enabled: Bool?

    public init() {}
}

/// A type-erased Codable value for flexible JSON handling.
public enum AnyCodableValue: Codable, Sendable, Equatable {
    case string(String)
    case int(Int)
    case double(Double)
    case bool(Bool)
    case null

    public init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        if let value = try? container.decode(Bool.self) {
            self = .bool(value)
        } else if let value = try? container.decode(Int.self) {
            self = .int(value)
        } else if let value = try? container.decode(Double.self) {
            self = .double(value)
        } else if let value = try? container.decode(String.self) {
            self = .string(value)
        } else if container.decodeNil() {
            self = .null
        } else {
            throw DecodingError.dataCorrupted(
                DecodingError.Context(codingPath: decoder.codingPath, debugDescription: "Unsupported value type")
            )
        }
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        switch self {
        case .string(let value): try container.encode(value)
        case .int(let value): try container.encode(value)
        case .double(let value): try container.encode(value)
        case .bool(let value): try container.encode(value)
        case .null: try container.encodeNil()
        }
    }
}
