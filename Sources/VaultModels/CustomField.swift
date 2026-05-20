// MARK: - VaultModels/CustomField.swift
// Custom fields on vault items

import Foundation
import VaultCrypto

/// A custom field attached to a cipher.
public struct CustomField: Codable, Sendable, Equatable {
    public var name: EncString?
    public var value: EncString?
    public var type: FieldType
    public var linkedId: LinkedIdType?

    public init(
        name: EncString? = nil,
        value: EncString? = nil,
        type: FieldType = .text,
        linkedId: LinkedIdType? = nil
    ) {
        self.name = name
        self.value = value
        self.type = type
        self.linkedId = linkedId
    }
}

/// Password history entry for a cipher.
public struct PasswordHistoryEntry: Codable, Sendable, Equatable {
    public var password: EncString?
    public var lastUsedDate: Date?

    public init(password: EncString? = nil, lastUsedDate: Date? = nil) {
        self.password = password
        self.lastUsedDate = lastUsedDate
    }
}
