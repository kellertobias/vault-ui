// MARK: - VaultAPI/APIClient.swift
// Base HTTP client with token management and retry logic

import Foundation
import VaultModels
import VaultCrypto

/// The base API client for communicating with Vaultwarden/Bitwarden servers.
///
/// Handles:
/// - Token management (access + refresh tokens)
/// - Automatic token refresh on 401
/// - JSON encoding/decoding with Bitwarden's date format
/// - Request construction with proper headers
public actor APIClient {
    /// The account this client is configured for.
    public let account: Account

    /// Current authentication tokens.
    private var tokens: AuthTokens?

    /// Shared URLSession with appropriate configuration.
    private let session: URLSession

    /// JSON decoder configured for Bitwarden's date formats.
    public static let decoder: JSONDecoder = {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .custom { decoder in
            let container = try decoder.singleValueContainer()
            let dateString = try container.decode(String.self)

            // Try ISO 8601 with fractional seconds
            if let date = ISO8601DateFormatter.bitwarden.date(from: dateString) {
                return date
            }
            // Try without fractional seconds
            if let date = ISO8601DateFormatter.bitwardenNoFraction.date(from: dateString) {
                return date
            }
            // Try basic date format
            let formatter = DateFormatter()
            formatter.dateFormat = "yyyy-MM-dd'T'HH:mm:ss"
            formatter.locale = Locale(identifier: "en_US_POSIX")
            if let date = formatter.date(from: String(dateString.prefix(19))) {
                return date
            }
            throw DecodingError.dataCorrupted(
                DecodingError.Context(
                    codingPath: decoder.codingPath,
                    debugDescription: "Cannot decode date: \(dateString)"
                )
            )
        }
        return decoder
    }()

    /// JSON encoder configured for Bitwarden's format.
    public static let encoder: JSONEncoder = {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        return encoder
    }()

    /// Device identifier for this client (persisted per-account).
    private let deviceId: String

    /// Device name reported to the server.
    private let deviceName: String

    /// Callback for token storage updates.
    public var onTokensUpdated: ((AuthTokens) -> Void)?

    public init(account: Account, tokens: AuthTokens? = nil) {
        self.account = account
        self.tokens = tokens
        self.deviceId = Self.getOrCreateDeviceId(for: account)
        self.deviceName = Host.current().localizedName ?? "Vault UI macOS"

        let config = URLSessionConfiguration.default
        config.timeoutIntervalForRequest = 30
        config.timeoutIntervalForResource = 120
        config.httpAdditionalHeaders = [
            "Accept": "application/json",
        ]
        self.session = URLSession(configuration: config)
    }

    // MARK: - Token Management

    /// Update stored tokens.
    public func setTokens(_ tokens: AuthTokens) {
        self.tokens = tokens
        onTokensUpdated?(tokens)
    }

    /// Get the current access token.
    public func getAccessToken() -> String? {
        tokens?.accessToken
    }

    /// Check if we have valid tokens.
    public var isAuthenticated: Bool {
        tokens?.accessToken != nil
    }

    // MARK: - HTTP Methods

    /// Perform an authenticated GET request.
    public func get<T: Decodable>(
        path: String,
        baseURL: URL? = nil
    ) async throws -> T {
        let request = try buildRequest(method: "GET", path: path, baseURL: baseURL)
        return try await performRequest(request)
    }

    /// Perform an authenticated POST request with a JSON body.
    public func post<T: Decodable, B: Encodable>(
        path: String,
        body: B,
        baseURL: URL? = nil,
        authenticated: Bool = true
    ) async throws -> T {
        var request = try buildRequest(method: "POST", path: path, baseURL: baseURL, authenticated: authenticated)
        request.httpBody = try Self.encoder.encode(body)
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        return try await performRequest(request)
    }

    /// Perform an authenticated POST request with no response body.
    public func postNoResponse<B: Encodable>(
        path: String,
        body: B,
        baseURL: URL? = nil
    ) async throws {
        var request = try buildRequest(method: "POST", path: path, baseURL: baseURL)
        request.httpBody = try Self.encoder.encode(body)
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        try await performRequestNoResponse(request)
    }

    /// Perform an authenticated PUT request with a JSON body.
    public func put<T: Decodable, B: Encodable>(
        path: String,
        body: B,
        baseURL: URL? = nil
    ) async throws -> T {
        var request = try buildRequest(method: "PUT", path: path, baseURL: baseURL)
        request.httpBody = try Self.encoder.encode(body)
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        return try await performRequest(request)
    }

    /// Perform an authenticated PUT request with no response decoding.
    public func putNoResponse<B: Encodable>(
        path: String,
        body: B,
        baseURL: URL? = nil
    ) async throws {
        var request = try buildRequest(method: "PUT", path: path, baseURL: baseURL)
        request.httpBody = try Self.encoder.encode(body)
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        try await performRequestNoResponse(request)
    }

    /// Perform an authenticated DELETE request.
    public func delete(
        path: String,
        baseURL: URL? = nil
    ) async throws {
        let request = try buildRequest(method: "DELETE", path: path, baseURL: baseURL)
        try await performRequestNoResponse(request)
    }

    /// Perform a form-encoded POST (used for OAuth token requests).
    public func postForm<T: Decodable>(
        path: String,
        parameters: [String: String],
        baseURL: URL? = nil,
        authenticated: Bool = false
    ) async throws -> T {
        var request = try buildRequest(
            method: "POST",
            path: path,
            baseURL: baseURL,
            authenticated: authenticated
        )
        request.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")

        let formBody = parameters.map { key, value in
            "\(key.urlEncoded)=\(value.urlEncoded)"
        }.joined(separator: "&")
        request.httpBody = formBody.data(using: .utf8)

        return try await performRequest(request)
    }

    /// Download raw data (for attachments).
    public func downloadData(from url: URL) async throws -> Data {
        var request = URLRequest(url: url)
        if let token = tokens?.accessToken {
            request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        }

        let (data, response) = try await session.data(for: request)
        guard let httpResponse = response as? HTTPURLResponse else {
            throw APIError.invalidResponse(0)
        }
        guard (200...299).contains(httpResponse.statusCode) else {
            throw APIError.invalidResponse(httpResponse.statusCode)
        }
        return data
    }

    /// Post multipart/form-data (for file Send uploads).
    public func postMultipart<T: Decodable>(
        path: String,
        jsonPart: (name: String, data: Data),
        filePart: (name: String, filename: String, data: Data, mimeType: String)
    ) async throws -> T {
        let boundary = "VaultUI-\(UUID().uuidString)"
        var request = try buildRequest(method: "POST", path: path, authenticated: true)
        request.setValue("multipart/form-data; boundary=\(boundary)", forHTTPHeaderField: "Content-Type")

        var body = Data()

        // JSON metadata part
        body.append("--\(boundary)\r\n")
        body.append("Content-Disposition: form-data; name=\"\(jsonPart.name)\"\r\n")
        body.append("Content-Type: application/json\r\n\r\n")
        body.append(jsonPart.data)
        body.append("\r\n")

        // File data part
        body.append("--\(boundary)\r\n")
        body.append("Content-Disposition: form-data; name=\"\(filePart.name)\"; filename=\"\(filePart.filename)\"\r\n")
        body.append("Content-Type: \(filePart.mimeType)\r\n\r\n")
        body.append(filePart.data)
        body.append("\r\n")

        body.append("--\(boundary)--\r\n")

        request.httpBody = body
        return try await performRequest(request)
    }

    // MARK: - Request Building

    private func buildRequest(
        method: String,
        path: String,
        baseURL: URL? = nil,
        authenticated: Bool = true
    ) throws -> URLRequest {
        let base = baseURL ?? account.apiURL
        let url = base.appendingPathComponent(path)

        var request = URLRequest(url: url)
        request.httpMethod = method
        request.setValue("Vault UI", forHTTPHeaderField: "Bitwarden-Client-Name")
        request.setValue("2025.1.0", forHTTPHeaderField: "Bitwarden-Client-Version")
        request.setValue("7", forHTTPHeaderField: "Device-Type")

        if authenticated {
            guard let token = tokens?.accessToken else {
                throw APIError.noAccessToken
            }
            request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        }

        return request
    }

    // MARK: - Request Execution

    private func performRequest<T: Decodable>(_ request: URLRequest) async throws -> T {
        let (data, response) = try await executeWithRetry(request)

        guard let httpResponse = response as? HTTPURLResponse else {
            throw APIError.invalidResponse(0)
        }

        try validateResponse(httpResponse, data: data)

        do {
            return try Self.decoder.decode(T.self, from: data)
        } catch {
            throw APIError.decodingError(error)
        }
    }

    private func performRequestNoResponse(_ request: URLRequest) async throws {
        let (data, response) = try await executeWithRetry(request)

        guard let httpResponse = response as? HTTPURLResponse else {
            throw APIError.invalidResponse(0)
        }

        try validateResponse(httpResponse, data: data)
    }

    private func executeWithRetry(_ request: URLRequest) async throws -> (Data, URLResponse) {
        do {
            let (data, response) = try await session.data(for: request)

            // Auto-refresh on 401 if we have a refresh token
            if let httpResponse = response as? HTTPURLResponse,
               httpResponse.statusCode == 401,
               let refreshToken = tokens?.refreshToken {
                try await refreshAccessToken(refreshToken: refreshToken)

                // Retry with new token
                var retryRequest = request
                if let newToken = tokens?.accessToken {
                    retryRequest.setValue("Bearer \(newToken)", forHTTPHeaderField: "Authorization")
                }
                return try await session.data(for: retryRequest)
            }

            return (data, response)
        } catch let error as APIError {
            throw error
        } catch {
            throw APIError.networkError(error)
        }
    }

    private func validateResponse(_ response: HTTPURLResponse, data: Data) throws {
        switch response.statusCode {
        case 200...299:
            return
        case 401:
            throw APIError.unauthorized
        case 403:
            throw APIError.forbidden
        case 404:
            throw APIError.notFound
        case 400, 422:
            // Check for 2FA, captcha, or validation error details
            if let errorResponse = try? Self.decoder.decode(APIErrorResponse.self, from: data) {
                if let providers = errorResponse.twoFactorProviders, !providers.isEmpty {
                    throw APIError.twoFactorRequired(providers: providers)
                }
                if let siteKey = errorResponse.captchaSiteKey {
                    throw APIError.captchaRequired(siteKey: siteKey)
                }
                // Extract validation errors into a readable message
                if let validationErrors = errorResponse.errorModel?.validationErrors, !validationErrors.isEmpty {
                    let details = validationErrors.flatMap { (field, messages) in
                        messages.map { "\(field): \($0)" }
                    }.joined(separator: "\n")
                    let prefix = errorResponse.errorModel?.message ?? "Validation failed"
                    throw APIError.serverMessage("\(prefix)\n\(details)")
                }
                if let msg = errorResponse.errorModel?.message ?? errorResponse.message ?? errorResponse.errorDescription ?? errorResponse.error {
                    throw APIError.serverMessage(msg)
                }
            }
            
            // Fallback: Show the raw body text
            let rawString = String(data: data, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
            if !rawString.isEmpty {
                throw APIError.serverMessage("HTTP \(response.statusCode): \(rawString)")
            }
            throw APIError.invalidResponse(response.statusCode)
        default:
            let msg = String(data: data, encoding: .utf8)
            throw APIError.serverError(response.statusCode, msg)
        }
    }

    // MARK: - Token Refresh

    private func refreshAccessToken(refreshToken: String) async throws {
        let parameters: [String: String] = [
            "grant_type": "refresh_token",
            "refresh_token": refreshToken,
            "client_id": "desktop",
        ]

        var request = try buildRequest(
            method: "POST",
            path: "connect/token",
            baseURL: account.identityURL,
            authenticated: false
        )
        request.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")

        let formBody = parameters.map { "\($0.key.urlEncoded)=\($0.value.urlEncoded)" }
            .joined(separator: "&")
        request.httpBody = formBody.data(using: .utf8)

        let (data, response) = try await session.data(for: request)
        guard let httpResponse = response as? HTTPURLResponse,
              (200...299).contains(httpResponse.statusCode) else {
            throw APIError.tokenExpired
        }

        let tokenResponse = try Self.decoder.decode(TokenResponse.self, from: data)
        let newTokens = AuthTokens(
            accessToken: tokenResponse.accessToken,
            refreshToken: tokenResponse.refreshToken ?? refreshToken,
            expiresIn: tokenResponse.expiresIn,
            encryptedKey: tokens?.encryptedKey,
            encryptedPrivateKey: tokens?.encryptedPrivateKey
        )
        self.tokens = newTokens
        onTokensUpdated?(newTokens)
    }

    // MARK: - Device ID

    public static func getOrCreateDeviceId(for account: Account) -> String {
        let key = "device_id_\(account.id)"
        if let existing = UserDefaults.standard.string(forKey: key) {
            return existing
        }
        let newId = UUID().uuidString
        UserDefaults.standard.set(newId, forKey: key)
        return newId
    }
}

// MARK: - Token Response

/// Response from the identity token endpoint.
struct TokenResponse: Codable {
    let accessToken: String
    let refreshToken: String?
    let expiresIn: Int?
    let tokenType: String?
    let key: String?           // Protected symmetric key
    let privateKey: String?    // Encrypted RSA private key

    private enum CodingKeys: String, CodingKey {
        case accessToken = "access_token"
        case refreshToken = "refresh_token"
        case expiresIn = "expires_in"
        case tokenType = "token_type"
        case key = "Key"
        case privateKey = "PrivateKey"
    }
}

// MARK: - ISO8601 Formatters

extension ISO8601DateFormatter {
    /// Bitwarden uses fractional seconds in some responses.
    nonisolated(unsafe) static let bitwarden: ISO8601DateFormatter = {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return formatter
    }()

    /// Some dates come without fractional seconds.
    nonisolated(unsafe) static let bitwardenNoFraction: ISO8601DateFormatter = {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime]
        return formatter
    }()
}

// MARK: - URL Encoding Helper

extension String {
    var urlEncoded: String {
        addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed)?
            .replacingOccurrences(of: "+", with: "%2B")
            .replacingOccurrences(of: "&", with: "%26")
            .replacingOccurrences(of: "=", with: "%3D")
            ?? self
    }
}

extension Data {
    mutating func append(_ string: String) {
        if let data = string.data(using: .utf8) {
            append(data)
        }
    }
}
