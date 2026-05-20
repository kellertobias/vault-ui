// MARK: - VaultModels/Login.swift
// Login cipher sub-model

import Foundation
import VaultCrypto

/// A login URI entry.
public struct LoginUri: Codable, Sendable, Equatable {
    public var uri: EncString?
    public var match: UriMatchType?
    public var uriChecksum: String?

    public init(uri: EncString? = nil, match: UriMatchType? = nil, uriChecksum: String? = nil) {
        self.uri = uri
        self.match = match
        self.uriChecksum = uriChecksum
    }

    private enum CodingKeys: String, CodingKey {
        case uri, match, uriChecksum
    }
}

/// FIDO2/Passkey credential stored within a login.
public struct Fido2Credential: Codable, Sendable, Equatable {
    public var credentialId: EncString?
    public var keyType: EncString?
    public var keyAlgorithm: EncString?
    public var keyCurve: EncString?
    public var keyValue: EncString?
    public var rpId: EncString?
    public var rpName: EncString?
    public var userHandle: EncString?
    public var userName: EncString?
    public var userDisplayName: EncString?
    public var discoverable: EncString?
    public var creationDate: Date?
    public var counter: EncString?

    public init() {}

    private enum CodingKeys: String, CodingKey {
        case credentialId, keyType, keyAlgorithm, keyCurve, keyValue
        case rpId, rpName, userHandle, userName, userDisplayName
        case discoverable, creationDate, counter
    }
}

/// Login-specific cipher data.
public struct LoginData: Codable, Sendable, Equatable {
    public var username: EncString?
    public var password: EncString?
    public var passwordRevisionDate: Date?
    public var totp: EncString?
    public var uris: [LoginUri]?
    public var fido2Credentials: [Fido2Credential]?
    public var autofillOnPageLoad: Bool?

    public init(
        username: EncString? = nil,
        password: EncString? = nil,
        totp: EncString? = nil,
        uris: [LoginUri]? = nil
    ) {
        self.username = username
        self.password = password
        self.totp = totp
        self.uris = uris
    }

    private enum CodingKeys: String, CodingKey {
        case username, password, passwordRevisionDate
        case totp, totpCapitalized = "Totp", totpUpper = "TOTP"
        case uris, fido2Credentials, autofillOnPageLoad
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        
        username = try container.decodeIfPresent(EncString.self, forKey: .username)
        password = try container.decodeIfPresent(EncString.self, forKey: .password)
        passwordRevisionDate = try container.decodeIfPresent(Date.self, forKey: .passwordRevisionDate)
        
        // Try multiple totp keys
        if let t = try container.decodeIfPresent(EncString.self, forKey: .totp) {
            totp = t
        } else if let t = try container.decodeIfPresent(EncString.self, forKey: .totpCapitalized) {
            totp = t
        } else if let t = try container.decodeIfPresent(EncString.self, forKey: .totpUpper) {
            totp = t
        }
        
        uris = try container.decodeIfPresent([LoginUri].self, forKey: .uris)
        fido2Credentials = try container.decodeIfPresent([Fido2Credential].self, forKey: .fido2Credentials)
        autofillOnPageLoad = try container.decodeIfPresent(Bool.self, forKey: .autofillOnPageLoad)
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        
        try container.encodeIfPresent(username, forKey: .username)
        try container.encodeIfPresent(password, forKey: .password)
        try container.encodeIfPresent(passwordRevisionDate, forKey: .passwordRevisionDate)
        try container.encodeIfPresent(totp, forKey: .totp)
        try container.encodeIfPresent(uris, forKey: .uris)
        try container.encodeIfPresent(fido2Credentials, forKey: .fido2Credentials)
        try container.encodeIfPresent(autofillOnPageLoad, forKey: .autofillOnPageLoad)
    }
}
