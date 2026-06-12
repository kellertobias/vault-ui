// MARK: - VaultAPI/AuthService.swift
// Authentication flow: prelogin, login, 2FA

import Foundation
import VaultModels
import VaultCrypto

/// Handles the full Bitwarden authentication flow.
public struct AuthService: Sendable {
    private let client: APIClient

    public init(client: APIClient) {
        self.client = client
    }

    // MARK: - Prelogin

    /// Fetch KDF parameters for a user before login.
    ///
    /// This is the first step in the auth flow — the server tells us
    /// which KDF algorithm and parameters to use for key derivation.
    public func prelogin(email: String) async throws -> KDFConfig {
        struct PreloginRequest: Encodable {
            let email: String
        }
        struct PreloginResponse: Decodable {
            let kdf: Int
            let kdfIterations: Int
            let kdfMemory: Int?
            let kdfParallelism: Int?

            private enum CodingKeys: String, CodingKey {
                case kdf, kdfIterations, kdfMemory, kdfParallelism
            }
        }

        let account = client.account

        let response: PreloginResponse = try await client.post(
            path: "accounts/prelogin",
            body: PreloginRequest(email: email),
            baseURL: account.apiURL,
            authenticated: false
        )

        guard let kdfType = KDFType(rawValue: response.kdf) else {
            throw APIError.serverMessage("Unknown KDF type: \(response.kdf)")
        }

        return KDFConfig(
            type: kdfType,
            iterations: UInt32(response.kdfIterations),
            memory: response.kdfMemory.map { UInt32($0) },
            parallelism: response.kdfParallelism.map { UInt32($0) }
        )
    }

    // MARK: - Login

    /// Login request parameters.
    public struct LoginRequest: Sendable {
        public let email: String
        public let masterPasswordHash: String
        public let deviceId: String

        // Optional 2FA
        public var twoFactorProvider: TwoFactorProviderType?
        public var twoFactorToken: String?
        public var twoFactorRemember: Bool?

        public init(
            email: String,
            masterPasswordHash: String,
            deviceId: String = UUID().uuidString,
            twoFactorProvider: TwoFactorProviderType? = nil,
            twoFactorToken: String? = nil,
            twoFactorRemember: Bool? = nil
        ) {
            self.email = email
            self.masterPasswordHash = masterPasswordHash
            self.deviceId = deviceId
            self.twoFactorProvider = twoFactorProvider
            self.twoFactorToken = twoFactorToken
            self.twoFactorRemember = twoFactorRemember
        }
    }

    /// Login result containing tokens and encrypted keys.
    public struct LoginResult: Sendable {
        public let tokens: AuthTokens
        public let kdfConfig: KDFConfig
        /// Device remember token (returned when 2FA with twoFactorRemember=1 succeeds).
        public let twoFactorToken: String?
    }

    /// Perform login via `/identity/connect/token`.
    ///
    /// - Parameter request: Login credentials and optional 2FA
    /// - Returns: Auth tokens and encrypted vault key
    /// - Throws: `APIError.twoFactorRequired` if 2FA is needed
    public func login(_ request: LoginRequest) async throws -> LoginResult {
        let account = client.account

        var parameters: [String: String] = [
            "grant_type": "password",
            "username": request.email,
            "password": request.masterPasswordHash,
            "scope": "api offline_access",
            "client_id": "desktop",
            "deviceType": "7",  // macOS desktop
            "deviceIdentifier": request.deviceId,
            "deviceName": "Vault UI macOS",
        ]

        if let provider = request.twoFactorProvider,
           let token = request.twoFactorToken {
            parameters["twoFactorProvider"] = String(provider.rawValue)
            parameters["twoFactorToken"] = token
            if let remember = request.twoFactorRemember, remember {
                parameters["twoFactorRemember"] = "1"
            }
        }

        // Bitwarden's identity server rejects password grants without the
        // Auth-Email header (base64url of the username). Vaultwarden ignores
        // it, so it is always sent.
        let authEmail = Data(request.email.utf8).base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")

        let response: TokenResponse = try await client.postForm(
            path: "connect/token",
            parameters: parameters,
            baseURL: account.identityURL,
            authenticated: false,
            headers: ["Auth-Email": authEmail]
        )

        let tokens = AuthTokens(
            accessToken: response.accessToken,
            refreshToken: response.refreshToken,
            expiresIn: response.expiresIn,
            encryptedKey: response.key,
            encryptedPrivateKey: response.privateKey
        )

        await client.setTokens(tokens)

        return LoginResult(
            tokens: tokens,
            kdfConfig: account.kdfConfig,
            twoFactorToken: response.twoFactorToken
        )
    }
}
