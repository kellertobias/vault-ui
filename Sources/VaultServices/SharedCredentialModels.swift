// MARK: - VaultServices/SharedCredentialModels.swift
// Cross-target data models shared (via the keychain) between the app, the
// AutoFill credential provider, and the Safari web extension.

import Foundation

// MARK: - SharedCredentialEntry

/// A lightweight, decrypted credential entry for AutoFill suggestions.
///
/// Stored as a JSON array in the shared Keychain so the AutoFill extension
/// can display credential suggestions without needing the vault key.
/// Passwords are intentionally omitted — they are stored separately and
/// fetched only when the user selects a credential.
public struct SharedCredentialEntry: Codable, Sendable, Identifiable, Equatable {
    /// The unique cipher ID
    public let id: String
    /// The descriptive name of the item
    public let name: String
    /// The username (for logins and identities)
    public let username: String?
    /// List of URIs/URLs associated with this item
    public let uris: [String]
    /// The raw cipher type integer
    public let type: Int
    /// Whether this credential has a TOTP secret
    public let hasTotp: Bool
    /// Whether this credential has a FIDO2 passkey
    public let hasPasskey: Bool?
    /// Custom field order for sorting
    public let order: Int?
    /// Whether this entry is a local temporary credential.
    public let isTemporary: Bool?
    /// Whether this entry has an attached PFX/P12 certificate.
    public let hasCertificate: Bool?
    /// Certificate expiry date, if known.
    public let certificateExpiresAt: Date?
    /// The vault account this entry belongs to. `nil` only for entries written
    /// by pre-multi-account builds (treated as the single legacy account).
    public let accountId: String?
    /// Non-secret passkey identity metadata, so credential identities can be
    /// (re-)registered with the system without decrypting any account's vault.
    public let passkeyIdentities: [SharedPasskeyIdentityMeta]?

    public var supportsTotp: Bool { hasTotp }
    public var supportsPasskey: Bool { hasPasskey ?? false }
    public var isTemporaryCredential: Bool { isTemporary ?? false }
    public var supportsCertificateFill: Bool { hasCertificate ?? false }

    public init(
        id: String,
        name: String,
        username: String?,
        uris: [String],
        type: Int,
        hasTotp: Bool = false,
        hasPasskey: Bool? = false,
        order: Int? = nil,
        isTemporary: Bool? = false,
        hasCertificate: Bool? = false,
        certificateExpiresAt: Date? = nil,
        accountId: String? = nil,
        passkeyIdentities: [SharedPasskeyIdentityMeta]? = nil
    ) {
        self.id = id
        self.name = name
        self.username = username
        self.uris = uris
        self.type = type
        self.hasTotp = hasTotp
        self.hasPasskey = hasPasskey
        self.order = order
        self.isTemporary = isTemporary
        self.hasCertificate = hasCertificate
        self.certificateExpiresAt = certificateExpiresAt
        self.accountId = accountId
        self.passkeyIdentities = passkeyIdentities
    }
}

/// Non-secret passkey identity metadata (everything `ASPasskeyCredentialIdentity`
/// needs). The private key stays sealed in the per-credential keychain item.
public struct SharedPasskeyIdentityMeta: Codable, Sendable, Equatable {
    public let credentialId: String
    public let relyingPartyId: String
    public let userHandle: String

    public init(credentialId: String, relyingPartyId: String, userHandle: String) {
        self.credentialId = credentialId
        self.relyingPartyId = relyingPartyId
        self.userHandle = userHandle
    }
}

/// On-device account metadata shared with the AutoFill / Safari extensions:
/// drives the extension's account picker and the "[ACCOUNT]" QuickType labels.
public struct SharedAccountInfo: Codable, Sendable, Identifiable, Equatable {
    public let id: String
    public let email: String
    public let serverHost: String
    /// Resolved display label (Short Name → Alias → domain → host → email).
    public let label: String
    /// Index into `AccountAvatarPalette`.
    public let colorIndex: Int

    public init(id: String, email: String, serverHost: String, label: String, colorIndex: Int) {
        self.id = id
        self.email = email
        self.serverHost = serverHost
        self.label = label
        self.colorIndex = colorIndex
    }
}

/// Certificate bytes shared with the Safari Web Extension for explicit file-upload fills.
public struct SharedCertificateData: Codable, Sendable, Equatable {
    public let fileName: String
    public let dataBase64: String
    public let password: String
    public let expiresAt: Date?

    public init(fileName: String, dataBase64: String, password: String, expiresAt: Date?) {
        self.fileName = fileName
        self.dataBase64 = dataBase64
        self.password = password
        self.expiresAt = expiresAt
    }
}

/// One-shot fallback fill request written by the AutoFill extension for Safari pages.
public struct AutoFillCredentialFillRequest: Codable, Sendable, Equatable {
    public let url: String
    public let name: String
    public let username: String
    public let password: String
    public let createdAt: Date

    public init(url: String, name: String, username: String, password: String, createdAt: Date = Date()) {
        self.url = url
        self.name = name
        self.username = username
        self.password = password
        self.createdAt = createdAt
    }
}

/// Decrypted passkey data shared with the AutoFill extension.
public struct SharedPasskeyData: Codable, Sendable {
    public let credentialId: String
    public let privateKey: String
    public let relyingPartyId: String
    public let userHandle: String

    public init(credentialId: String, privateKey: String, relyingPartyId: String, userHandle: String) {
        self.credentialId = credentialId
        self.privateKey = privateKey
        self.relyingPartyId = relyingPartyId
        self.userHandle = userHandle
    }
}

// MARK: - Sync Dates

public struct SharedSyncDates: Codable, Sendable {
    public let lastSyncWithServer: Date?
    public let lastSyncWithApp: Date?

    public init(lastSyncWithServer: Date?, lastSyncWithApp: Date?) {
        self.lastSyncWithServer = lastSyncWithServer
        self.lastSyncWithApp = lastSyncWithApp
    }
}
