// MARK: - VaultModels/CipherType.swift
// Bitwarden cipher type identifiers

import Foundation

/// The type of a vault item (cipher).
public enum CipherType: Int, Codable, Sendable, CaseIterable, Identifiable {
    case login = 1
    case secureNote = 2
    case card = 3
    case identity = 4
    case sshKey = 5

    public var id: Int { rawValue }

    public var displayName: String {
        switch self {
        case .login: return "Login"
        case .secureNote: return "Secure Note"
        case .card: return "Card"
        case .identity: return "Identity"
        case .sshKey: return "SSH Key"
        }
    }

    public var iconName: String {
        switch self {
        case .login: return "key.fill"
        case .secureNote: return "note.text"
        case .card: return "creditcard.fill"
        case .identity: return "person.text.rectangle.fill"
        case .sshKey: return "terminal.fill"
        }
    }
}

/// The type of a Bitwarden Send item.
public enum SendType: Int, Codable, Sendable {
    case text = 0
    case file = 1
}

/// Field types for custom fields on vault items.
public enum FieldType: Int, Codable, Sendable {
    case text = 0
    case hidden = 1
    case boolean = 2
    case linked = 3
}

/// URI match detection strategy.
public enum UriMatchType: Int, Codable, Sendable {
    case domain = 0
    case host = 1
    case startsWith = 2
    case exact = 3
    case regularExpression = 4
    case never = 5
}

/// Linked field identifiers (for auto-fill linking).
public enum LinkedIdType: Int, Codable, Sendable {
    case loginUsername = 100
    case loginPassword = 101
    case cardCardholderName = 300
    case cardExpMonth = 301
    case cardExpYear = 302
    case cardCode = 303
    case cardBrand = 304
    case cardNumber = 305
    case identityTitle = 400
    case identityMiddleName = 401
    case identityAddress1 = 402
    case identityAddress2 = 403
    case identityAddress3 = 404
    case identityCity = 405
    case identityState = 406
    case identityPostalCode = 407
    case identityCountry = 408
    case identityCompany = 409
    case identityEmail = 410
    case identityPhone = 411
    case identitySsn = 412
    case identityUsername = 413
    case identityPassportNumber = 414
    case identityLicenseNumber = 415
    case identityFirstName = 416
    case identityLastName = 417
    case identityFullName = 418
}

/// Two-factor authentication provider types.
public enum TwoFactorProviderType: Int, Codable, Sendable {
    case authenticator = 0
    case email = 1
    case duo = 2
    case yubikey = 3
    case u2f = 4
    case remember = 5
    case organizationDuo = 6
    case webAuthn = 7
}

/// Cipher reprompt type (require master password before viewing).
public enum CipherRepromptType: Int, Codable, Sendable {
    case none = 0
    case password = 1
}
