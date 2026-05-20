// MARK: - VaultAPI/APIError.swift
// API error types

import Foundation

/// Errors from the Vaultwarden/Bitwarden API.
public enum APIError: Error, LocalizedError, Sendable {
    case invalidURL(String)
    case invalidResponse(Int)
    case unauthorized
    case forbidden
    case notFound
    case twoFactorRequired(providers: [Int])
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
    let captchaSiteKey: String?

    private enum CodingKeys: String, CodingKey {
        case errorModel = "ErrorModel"
        case error
        case errorDescription = "error_description"
        case message
        case messageUpper = "Message"
        case twoFactorProviders = "TwoFactorProviders"
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
        
        twoFactorProviders = try container.decodeIfPresent([Int].self, forKey: .twoFactorProviders)
        captchaSiteKey = try container.decodeIfPresent(String.self, forKey: .captchaSiteKey)
    }
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
