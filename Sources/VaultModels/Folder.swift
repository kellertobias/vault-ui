// MARK: - VaultModels/Folder.swift
// Folder model

import Foundation
import VaultCrypto

/// A folder for organizing vault items.
public struct Folder: Codable, Sendable, Identifiable, Equatable {
    public var id: String?
    public var name: EncString?
    public var revisionDate: Date?

    public init(id: String? = nil, name: EncString? = nil, revisionDate: Date? = nil) {
        self.id = id
        self.name = name
        self.revisionDate = revisionDate
    }
}

/// A collection (organization-level folder).
public struct Collection: Codable, Sendable, Identifiable, Equatable {
    public var id: String?
    public var organizationId: String?
    public var name: EncString?
    public var externalId: String?
    public var readOnly: Bool?
    public var manage: Bool?
    public var hidePasswords: Bool?

    public init(id: String? = nil, organizationId: String? = nil, name: EncString? = nil) {
        self.id = id
        self.organizationId = organizationId
        self.name = name
    }
}
