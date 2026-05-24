// MARK: - VaultModels/TwoFactorChallenge.swift
// Two-factor authentication challenge and policy models

import Foundation

/// Structured 2FA challenge data returned by the server.
///
/// Contains both the list of available provider types and the per-provider
/// data from `TwoFactorProviders2` (e.g. WebAuthn challenge, obfuscated email).
public struct TwoFactorChallenge: Sendable, Equatable {
    public let providers: [Int]
    public let providerData: [Int: TwoFactorProviderData]

    public init(providers: [Int], providerData: [Int: TwoFactorProviderData] = [:]) {
        self.providers = providers
        self.providerData = providerData
    }

    /// Sorted list of available provider types (excluding "remember").
    public var availableProviders: [TwoFactorProviderType] {
        providers
            .compactMap { TwoFactorProviderType(rawValue: $0) }
            .filter { $0 != .remember }
            .sorted { $0.displayPriority < $1.displayPriority }
    }

    /// Whether a specific provider type is available.
    public func hasProvider(_ type: TwoFactorProviderType) -> Bool {
        providers.contains(type.rawValue)
    }
}

/// Per-provider challenge data from `TwoFactorProviders2`.
public enum TwoFactorProviderData: Sendable, Equatable {
    /// Provider 0 (Authenticator TOTP) — no extra data needed.
    case authenticator

    /// Provider 1 (Email) — server sends the obfuscated email address.
    case email(obfuscatedAddress: String)

    /// Provider 3 (YubiKey OTP) — no extra data needed (key types into text field).
    case yubikey

    /// Provider 7 (WebAuthn/FIDO2) — server sends the assertion challenge.
    case webAuthn(WebAuthnChallengeData)
}

/// WebAuthn assertion challenge data from the server.
public struct WebAuthnChallengeData: Sendable, Equatable {
    public let challenge: Data
    public let rpId: String
    public let allowCredentials: [WebAuthnAllowedCredential]
    public let userVerification: String
    public let timeout: Int?

    public init(
        challenge: Data,
        rpId: String,
        allowCredentials: [WebAuthnAllowedCredential],
        userVerification: String = "preferred",
        timeout: Int? = nil
    ) {
        self.challenge = challenge
        self.rpId = rpId
        self.allowCredentials = allowCredentials
        self.userVerification = userVerification
        self.timeout = timeout
    }
}

/// A credential the server will accept for WebAuthn assertion.
public struct WebAuthnAllowedCredential: Sendable, Equatable {
    public let id: Data
    public let type: String
    public let transports: [String]?

    public init(id: Data, type: String = "public-key", transports: [String]? = nil) {
        self.id = id
        self.type = type
        self.transports = transports
    }
}

// MARK: - Display Priority

extension TwoFactorProviderType {
    /// Sort priority for display (lower = shown first / preferred).
    public var displayPriority: Int {
        switch self {
        case .authenticator: return 0
        case .email: return 1
        case .webAuthn: return 2
        case .yubikey: return 3
        case .duo: return 4
        case .organizationDuo: return 5
        case .u2f: return 6
        case .remember: return 99
        }
    }

    /// Human-readable label.
    public var displayName: String {
        switch self {
        case .authenticator: return "Authenticator App"
        case .email: return "Email"
        case .yubikey: return "YubiKey"
        case .webAuthn: return "Security Key"
        case .duo: return "Duo"
        case .organizationDuo: return "Duo (Organization)"
        case .u2f: return "U2F"
        case .remember: return "Remember"
        }
    }

    /// SF Symbol icon name.
    public var iconName: String {
        switch self {
        case .authenticator: return "lock.badge.clock.fill"
        case .email: return "envelope.fill"
        case .yubikey: return "key.fill"
        case .webAuthn: return "person.badge.key.fill"
        case .duo: return "shield.checkered"
        case .organizationDuo: return "shield.checkered"
        case .u2f: return "key.fill"
        case .remember: return "checkmark.circle.fill"
        }
    }

    /// Whether this provider uses a text code input (vs. hardware interaction).
    public var isCodeBased: Bool {
        switch self {
        case .authenticator, .email, .yubikey: return true
        default: return false
        }
    }
}
