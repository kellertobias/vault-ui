// MARK: - VaultModels/SendItem.swift
// Bitwarden Send model

import Foundation
import VaultCrypto

/// A Bitwarden Send item for securely sharing text or files.
public struct SendItem: Codable, Sendable, Identifiable, Equatable {
    public var id: String?
    public var accessId: String?
    public var type: SendType
    public var name: EncString?
    public var notes: EncString?
    public var key: EncString?

    // Text send data
    public var text: SendTextData?

    // File send data
    public var file: SendFileData?

    // Access controls
    public var maxAccessCount: Int?
    public var accessCount: Int?
    public var password: String?
    public var disabled: Bool?
    public var hideEmail: Bool?

    // Dates
    public var revisionDate: Date?
    public var expirationDate: Date?
    public var deletionDate: Date?

    public init(
        id: String? = nil,
        type: SendType,
        name: EncString? = nil
    ) {
        self.id = id
        self.type = type
        self.name = name
    }
}

/// Text content for a Send.
public struct SendTextData: Codable, Sendable, Equatable {
    public var text: EncString?
    public var hidden: Bool?

    public init(text: EncString? = nil, hidden: Bool? = nil) {
        self.text = text
        self.hidden = hidden
    }
}

/// File metadata for a Send.
public struct SendFileData: Codable, Sendable, Equatable {
    public var id: String?
    public var fileName: EncString?
    public var size: String?
    public var sizeName: String?

    public init(id: String? = nil, fileName: EncString? = nil) {
        self.id = id
        self.fileName = fileName
    }
}
