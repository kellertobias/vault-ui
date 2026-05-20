// MARK: - VaultServices/SafariExtensionService.swift
// Safari Web Extension message handling
//
// This module contains the native message handler logic for the Safari
// Web Extension. The actual extension target needs to be created in
// Xcode with:
//   - SafariServices.framework
//   - A bundled web extension (manifest.json + content/background scripts)
//   - App Groups for data sharing

import Foundation
import VaultModels
import VaultCrypto
import OSLog

private let logger = Logger(subsystem: "com.vaultui", category: "SafariExtension")

/// Message types exchanged between the Safari web extension and the native app.
public enum SafariExtensionMessageType: String, Codable, Sendable {
    case getCredentials = "getCredentials"
    case fillCredential = "fillCredential"
    case generatePassword = "generatePassword"
    case saveCredential = "saveCredential"
    case getVaultStatus = "getVaultStatus"
    case lockVault = "lockVault"
    case copyTotp = "copyTotp"
}

/// A message from the Safari web extension.
public struct SafariExtensionMessage: Codable, Sendable {
    public let type: SafariExtensionMessageType
    public let url: String?
    public let cipherId: String?
    public let data: [String: String]?

    public init(type: SafariExtensionMessageType, url: String? = nil, cipherId: String? = nil, data: [String: String]? = nil) {
        self.type = type
        self.url = url
        self.cipherId = cipherId
        self.data = data
    }
}

/// A response to the Safari web extension.
public struct SafariExtensionResponse: Codable, Sendable {
    public let success: Bool
    public let type: SafariExtensionMessageType
    public let credentials: [SafariCredential]?
    public let password: String?
    public let vaultLocked: Bool?
    public let error: String?

    public init(
        success: Bool,
        type: SafariExtensionMessageType,
        credentials: [SafariCredential]? = nil,
        password: String? = nil,
        vaultLocked: Bool? = nil,
        error: String? = nil
    ) {
        self.success = success
        self.type = type
        self.credentials = credentials
        self.password = password
        self.vaultLocked = vaultLocked
        self.error = error
    }
}

/// A credential formatted for the Safari web extension.
public struct SafariCredential: Codable, Identifiable, Sendable {
    public let id: String
    public let name: String
    public let username: String
    public let hasPassword: Bool
    public let hasTotp: Bool

    public init(id: String, name: String, username: String, hasPassword: Bool, hasTotp: Bool) {
        self.id = id
        self.name = name
        self.username = username
        self.hasPassword = hasPassword
        self.hasTotp = hasTotp
    }
}

/// Handles messages from the Safari Web Extension.
///
/// The Safari extension sends messages via `browser.runtime.sendNativeMessage()`
/// which are received by the app extension handler. This service processes
/// those messages and returns appropriate responses.
public enum SafariExtensionService {

    /// Process an incoming message from the Safari web extension.
    public static func handleMessage(
        _ message: SafariExtensionMessage,
        ciphers: [Cipher],
        key: SymmetricCryptoKey?,
        passwordGenerator: () -> String
    ) -> SafariExtensionResponse {
        // Check if vault is locked
        guard let key = key else {
            return SafariExtensionResponse(
                success: false,
                type: message.type,
                vaultLocked: true,
                error: "Vault is locked"
            )
        }

        switch message.type {
        case .getCredentials:
            return handleGetCredentials(url: message.url ?? "", ciphers: ciphers, key: key)

        case .fillCredential:
            return handleFillCredential(cipherId: message.cipherId ?? "", ciphers: ciphers, key: key)

        case .generatePassword:
            return SafariExtensionResponse(
                success: true,
                type: .generatePassword,
                password: passwordGenerator()
            )

        case .getVaultStatus:
            return SafariExtensionResponse(
                success: true,
                type: .getVaultStatus,
                vaultLocked: false
            )

        case .saveCredential:
            // Save requires more complex flow — return acknowledgment
            logger.info("Save credential request for: \(message.url ?? "unknown")")
            return SafariExtensionResponse(success: true, type: .saveCredential)

        case .lockVault:
            return SafariExtensionResponse(success: true, type: .lockVault)

        case .copyTotp:
            return handleCopyTotp(cipherId: message.cipherId ?? "", ciphers: ciphers, key: key)
        }
    }

    private static func handleGetCredentials(
        url: String,
        ciphers: [Cipher],
        key: SymmetricCryptoKey
    ) -> SafariExtensionResponse {
        let matching = CredentialProviderService.findCredentials(
            for: url,
            ciphers: ciphers,
            key: key
        )

        let safariCredentials = matching.compactMap { credential -> SafariCredential? in
            guard let cipher = ciphers.first(where: { $0.id == credential.cipherId }) else { return nil }
            let name = cipher.name.flatMap { try? CipherEncryption.decryptString($0, key: key) } ?? "Unnamed"
            return SafariCredential(
                id: credential.cipherId,
                name: name,
                username: credential.username,
                hasPassword: cipher.login?.password != nil,
                hasTotp: cipher.login?.totp != nil
            )
        }

        return SafariExtensionResponse(
            success: true,
            type: .getCredentials,
            credentials: safariCredentials
        )
    }

    private static func handleFillCredential(
        cipherId: String,
        ciphers: [Cipher],
        key: SymmetricCryptoKey
    ) -> SafariExtensionResponse {
        guard let password = CredentialProviderService.getPassword(for: cipherId, ciphers: ciphers, key: key) else {
            return SafariExtensionResponse(success: false, type: .fillCredential, error: "Credential not found")
        }

        return SafariExtensionResponse(
            success: true,
            type: .fillCredential,
            password: password
        )
    }

    private static func handleCopyTotp(
        cipherId: String,
        ciphers: [Cipher],
        key: SymmetricCryptoKey
    ) -> SafariExtensionResponse {
        guard let cipher = ciphers.first(where: { $0.id == cipherId }),
              let totpEnc = cipher.login?.totp,
              let secret = try? CipherEncryption.decryptString(totpEnc, key: key) else {
            return SafariExtensionResponse(success: false, type: .copyTotp, error: "TOTP not available")
        }

        guard let code = TOTPService.generateCode(from: secret) else {
            return SafariExtensionResponse(success: false, type: .copyTotp, error: "Failed to generate TOTP")
        }

        return SafariExtensionResponse(
            success: true,
            type: .copyTotp,
            password: code.code
        )
    }
}
