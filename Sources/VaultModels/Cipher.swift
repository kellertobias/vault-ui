// MARK: - VaultModels/Cipher.swift
// Main vault item (cipher) model

import Foundation
import VaultCrypto

/// A vault item (cipher) — the core data model for all stored credentials.
///
/// Each cipher contains encrypted data specific to its type (login, card, etc.)
/// plus common metadata like name, notes, folder assignment, and custom fields.
public struct Cipher: Codable, Sendable, Identifiable, Equatable {
    public var id: String?
    public var organizationId: String?
    public var folderId: String?
    public var collectionIds: [String]?
    public var type: CipherType
    public var name: EncString?
    public var notes: EncString?
    public var favorite: Bool
    public var reprompt: CipherRepromptType

    // Type-specific data
    public var login: LoginData?
    public var secureNote: SecureNoteData?
    public var card: CardData?
    public var identity: IdentityData?
    public var sshKey: SSHKeyData?

    // Common collections
    public var fields: [CustomField]?
    public var attachments: [Attachment]?
    public var passwordHistory: [PasswordHistoryEntry]?

    // Item-level encryption key (for attachments and shared items)
    public var key: EncString?

    // Metadata (not encrypted)
    public var creationDate: Date?
    public var revisionDate: Date?
    public var deletedDate: Date?
    public var edit: Bool?
    public var viewPassword: Bool?
    public var organizationUseTotp: Bool?

    public init(
        id: String? = nil,
        type: CipherType,
        name: EncString? = nil,
        favorite: Bool = false,
        reprompt: CipherRepromptType = .none
    ) {
        self.id = id
        self.type = type
        self.name = name
        self.favorite = favorite
        self.reprompt = reprompt
    }

    /// Whether this item is in the trash.
    public var isDeleted: Bool {
        deletedDate != nil
    }
}
