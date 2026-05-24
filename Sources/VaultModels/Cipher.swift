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

/// WiFi credential details parsed from custom fields.
public struct WifiDetails: Sendable, Equatable {
    public let ssid: String
    public let security: String

    public init(ssid: String, security: String) {
        self.ssid = ssid
        self.security = security
    }
}

extension Cipher {
    /// Detects if this cipher is a WiFi credential by checking its custom fields
    /// for network name (SSID) and security type.
    public func wifiDetails(decrypt: (EncString?) -> String?) -> WifiDetails? {
        guard let fields = self.fields else { return nil }
        var ssid: String?
        var security: String?

        for field in fields {
            guard let name = decrypt(field.name)?.lowercased() else { continue }
            if name == "netzwerkname" || name == "ssid" || name == "network name" {
                ssid = decrypt(field.value)
            } else if name == "sicherheit" || name == "security" {
                security = decrypt(field.value)
            }
        }

        if let ssid = ssid, !ssid.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
           let security = security, !security.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            return WifiDetails(ssid: ssid, security: security)
        }
        return nil
    }

    /// Helper to check if this cipher matches the WiFi credential criteria.
    public func isWifiCredential(decrypt: (EncString?) -> String?) -> Bool {
        wifiDetails(decrypt: decrypt) != nil
    }
}
