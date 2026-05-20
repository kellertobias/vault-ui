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

    /// Display name — uses profile name if available, otherwise email.
    public var displayName: String {
        profile?.name ?? email
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
        kdfConfig: KDFConfig = .defaultPBKDF2
    ) {
        self.id = id
        self.email = email
        self.serverURL = serverURL
        self.kdfConfig = kdfConfig
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
