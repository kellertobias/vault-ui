// MARK: - VaultModels/Account.swift
// Account and server configuration models

import Foundation
import VaultCrypto

/// Represents a configured Vaultwarden/Bitwarden server account.
public struct Account: Codable, Sendable, Identifiable, Equatable {
    public var id: String
    public var email: String
    public var serverURL: URL
    public var kdfConfig: KDFConfig
    public var profile: Profile?

    /// User-assigned alias shown in account lists (Settings → Accounts).
    public var alias: String?

    /// User-assigned short name, preferred for AutoFill label prefixes.
    public var shortName: String?

    /// Stable index into `AccountAvatarPalette`, assigned once at account creation.
    public var avatarColorIndex: Int

    /// Display name — uses profile name if available, otherwise email.
    public var displayName: String {
        alias?.nilIfBlank ?? profile?.name ?? email
    }

    /// The identity endpoint URL.
    public var identityURL: URL {
        serverURL.appendingPathComponent("identity")
    }

    /// The API endpoint URL.
    public var apiURL: URL {
        serverURL.appendingPathComponent("api")
    }

    public init(
        id: String = UUID().uuidString,
        email: String,
        serverURL: URL,
        kdfConfig: KDFConfig = .defaultPBKDF2,
        alias: String? = nil,
        shortName: String? = nil,
        avatarColorIndex: Int = 0
    ) {
        self.id = id
        self.email = email
        self.serverURL = serverURL
        self.kdfConfig = kdfConfig
        self.alias = alias
        self.shortName = shortName
        self.avatarColorIndex = avatarColorIndex
    }

    private enum CodingKeys: String, CodingKey {
        case id, email, serverURL, kdfConfig, profile, alias, shortName, avatarColorIndex
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        id = try container.decode(String.self, forKey: .id)
        email = try container.decode(String.self, forKey: .email)
        serverURL = try container.decode(URL.self, forKey: .serverURL)
        kdfConfig = try container.decode(KDFConfig.self, forKey: .kdfConfig)
        profile = try container.decodeIfPresent(Profile.self, forKey: .profile)
        alias = try container.decodeIfPresent(String.self, forKey: .alias)
        shortName = try container.decodeIfPresent(String.self, forKey: .shortName)
        avatarColorIndex = try container.decodeIfPresent(Int.self, forKey: .avatarColorIndex) ?? 0
    }
}

/// Authentication tokens for an active session.
public struct AuthTokens: Codable, Sendable {
    public var accessToken: String
    public var refreshToken: String?
    public var expiresIn: Int?
    public var tokenType: String?

    /// The protected symmetric key returned during login.
    public var encryptedKey: String?

    /// The encrypted private key for asymmetric operations.
    public var encryptedPrivateKey: String?

    public init(
        accessToken: String,
        refreshToken: String? = nil,
        expiresIn: Int? = nil,
        encryptedKey: String? = nil,
        encryptedPrivateKey: String? = nil
    ) {
        self.accessToken = accessToken
        self.refreshToken = refreshToken
        self.expiresIn = expiresIn
        self.encryptedKey = encryptedKey
        self.encryptedPrivateKey = encryptedPrivateKey
    }
}
