// MARK: - VaultAPI/APIError.swift
// API error types

import Foundation
import VaultModels

/// Errors from the Vaultwarden/Bitwarden API.
public enum APIError: Error, LocalizedError, Sendable {
    case invalidURL(String)
    case invalidResponse(Int)
    case unauthorized
    case forbidden
    case notFound
    case twoFactorRequired(challenge: TwoFactorChallenge)
    case captchaRequired(siteKey: String)
    case serverError(Int, String?)
    case networkError(Error)
    case decodingError(Error)
    case encodingError(Error)
    case noAccessToken
    case tokenExpired
    case invalidServerURL
    case serverMessage(String)

    public var errorDescription: String? {
        switch self {
        case .invalidURL(let url): return "Invalid URL: \(url)"
        case .invalidResponse(let code): return "Unexpected response code: \(code)"
        case .unauthorized: return "Authentication required"
        case .forbidden: return "Access denied"
        case .notFound: return "Resource not found"
        case .twoFactorRequired: return "Two-factor authentication required"
        case .captchaRequired: return "CAPTCHA verification required"
        case .serverError(let code, let msg): return "Server error \(code): \(msg ?? "unknown")"
        case .networkError(let err): return "Network error: \(err.localizedDescription)"
        case .decodingError(let err): return "Failed to decode response: \(err.localizedDescription)"
        case .encodingError(let err): return "Failed to encode request: \(err.localizedDescription)"
        case .noAccessToken: return "No access token available"
        case .tokenExpired: return "Access token expired"
        case .invalidServerURL: return "Invalid server URL"
        case .serverMessage(let msg): return msg
        }
    }
}

/// Error response from the Bitwarden API.
struct APIErrorResponse: Decodable {
    let errorModel: APIErrorModel?
    let error: String?
    let errorDescription: String?
    let message: String?
    let twoFactorProviders: [Int]?
    let twoFactorProviders2: [String: TwoFactorProvider2Data]?
    let captchaSiteKey: String?

    private enum CodingKeys: String, CodingKey {
        case errorModel = "ErrorModel"
        case error
        case errorDescription = "error_description"
        case message
        case messageUpper = "Message"
        case twoFactorProviders = "TwoFactorProviders"
        case twoFactorProviders2 = "TwoFactorProviders2"
        case captchaSiteKey = "CaptchaSiteKey"
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        errorModel = try container.decodeIfPresent(APIErrorModel.self, forKey: .errorModel)
        error = try container.decodeIfPresent(String.self, forKey: .error)
        errorDescription = try container.decodeIfPresent(String.self, forKey: .errorDescription)
        
        if let msg = try container.decodeIfPresent(String.self, forKey: .message) {
            message = msg
        } else {
            message = try container.decodeIfPresent(String.self, forKey: .messageUpper)
        }
        
        // TwoFactorProviders can be [Int] or [String] depending on server
        var parsedProviders: [Int]?
        if let intArray = try? container.decodeIfPresent([Int].self, forKey: .twoFactorProviders) {
            parsedProviders = intArray
        } else if let stringArray = try? container.decodeIfPresent([String].self, forKey: .twoFactorProviders) {
            parsedProviders = stringArray.compactMap { Int($0) }
        }

        // TwoFactorProviders2 values can be null for providers with no extra data (e.g. TOTP)
        var rawProviders2Keys: [String] = []
        if let rawProviders2 = try? container.decodeIfPresent([String: TwoFactorProvider2Data?].self, forKey: .twoFactorProviders2) {
            rawProviders2Keys = Array(rawProviders2.keys)
            twoFactorProviders2 = rawProviders2.compactMapValues { $0 }
        } else {
            twoFactorProviders2 = nil
        }

        // Fallback: if TwoFactorProviders was missing/empty but TwoFactorProviders2 has keys,
        // derive the provider list from the keys (including null-value entries)
        if (parsedProviders == nil || parsedProviders!.isEmpty), !rawProviders2Keys.isEmpty {
            parsedProviders = rawProviders2Keys.compactMap { Int($0) }.sorted()
        }

        twoFactorProviders = parsedProviders
        captchaSiteKey = try container.decodeIfPresent(String.self, forKey: .captchaSiteKey)
    }

    /// Build a structured `TwoFactorChallenge` from the parsed providers.
    func buildChallenge() -> TwoFactorChallenge? {
        guard let providers = twoFactorProviders, !providers.isEmpty else { return nil }

        var providerData: [Int: TwoFactorProviderData] = [:]

        if let providers2 = twoFactorProviders2 {
            for (key, data) in providers2 {
                guard let typeInt = Int(key) else { continue }
                guard let providerType = TwoFactorProviderType(rawValue: typeInt) else { continue }

                switch providerType {
                case .authenticator:
                    providerData[typeInt] = .authenticator

                case .email:
                    let email = data.email ?? "***"
                    providerData[typeInt] = .email(obfuscatedAddress: email)

                case .yubikey:
                    providerData[typeInt] = .yubikey

                case .webAuthn:
                    if let challengeData = data.buildWebAuthnChallenge() {
                        providerData[typeInt] = .webAuthn(challengeData)
                    }

                default:
                    break
                }
            }
        }

        return TwoFactorChallenge(providers: providers, providerData: providerData)
    }
}

/// Per-provider data from `TwoFactorProviders2`.
///
/// This is a flexible container since different provider types return
/// different shapes. We decode known fields and ignore the rest.
struct TwoFactorProvider2Data: Decodable {
    // Email provider
    let email: String?

    // WebAuthn provider
    let challenge: String?
    let rpId: String?
    let allowCredentials: [WebAuthnAllowedCredentialResponse]?
    let userVerification: String?
    let timeout: Int?

    private enum CodingKeys: String, CodingKey {
        case email = "Email"
        case challenge
        case rpId
        case allowCredentials
        case userVerification
        case timeout
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        email = try container.decodeIfPresent(String.self, forKey: .email)
        challenge = try container.decodeIfPresent(String.self, forKey: .challenge)
        rpId = try container.decodeIfPresent(String.self, forKey: .rpId)
        allowCredentials = try container.decodeIfPresent([WebAuthnAllowedCredentialResponse].self, forKey: .allowCredentials)
        userVerification = try container.decodeIfPresent(String.self, forKey: .userVerification)
        timeout = try container.decodeIfPresent(Int.self, forKey: .timeout)
    }

    /// Build WebAuthn challenge data from the raw response.
    func buildWebAuthnChallenge() -> WebAuthnChallengeData? {
        guard let challengeStr = challenge,
              let challengeData = Data(base64URLDecoded: challengeStr),
              let rpId = rpId else { return nil }

        let creds = (allowCredentials ?? []).compactMap { cred -> WebAuthnAllowedCredential? in
            guard let idData = Data(base64URLDecoded: cred.id) else { return nil }
            return WebAuthnAllowedCredential(
                id: idData,
                type: cred.type ?? "public-key",
                transports: cred.transports
            )
        }

        return WebAuthnChallengeData(
            challenge: challengeData,
            rpId: rpId,
            allowCredentials: creds,
            userVerification: userVerification ?? "preferred",
            timeout: timeout
        )
    }
}

/// Credential entry in the WebAuthn `allowCredentials` array.
struct WebAuthnAllowedCredentialResponse: Decodable {
    let id: String
    let type: String?
    let transports: [String]?
}

/// Nested error model.
struct APIErrorModel: Codable {
    let message: String?
    let validationErrors: [String: [String]]?

    private enum CodingKeys: String, CodingKey {
        case message = "Message"
        case validationErrors = "ValidationErrors"
    }
}

// MARK: - Base64URL Decoding

extension Data {
    /// Decode a base64url-encoded string (used by WebAuthn).
    init?(base64URLDecoded string: String) {
        var base64 = string
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        // Pad to multiple of 4
        let remainder = base64.count % 4
        if remainder > 0 {
            base64 += String(repeating: "=", count: 4 - remainder)
        }
        self.init(base64Encoded: base64)
    }
}

