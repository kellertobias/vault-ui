// MARK: - VaultServices/CredentialProviderService.swift
// AutoFill Credential Provider Extension logic
//
// This module contains the business logic for the macOS AutoFill
// Credential Provider Extension. The actual extension target needs
// to be created in Xcode with:
//   - AuthenticationServices.framework
//   - com.apple.developer.authentication-services.autofill-credential-provider entitlement
//   - App Groups for sharing data with the main app

import Foundation
import VaultModels
import VaultCrypto

/// Credential items prepared for AutoFill display.
public struct AutoFillCredential: Identifiable, Sendable {
    public let id: String
    public let serviceIdentifier: String  // URL or app bundle ID
    public let username: String
    public let cipherId: String

    public init(id: String, serviceIdentifier: String, username: String, cipherId: String) {
        self.id = id
        self.serviceIdentifier = serviceIdentifier
        self.username = username
        self.cipherId = cipherId
    }
}

/// Passkey credential for FIDO2/WebAuthn AutoFill.
public struct AutoFillPasskeyCredential: Identifiable, Sendable {
    public let id: String
    public let relyingPartyIdentifier: String
    public let username: String
    public let userHandle: Data
    public let cipherId: String

    public init(id: String, relyingPartyIdentifier: String, username: String, userHandle: Data, cipherId: String) {
        self.id = id
        self.relyingPartyIdentifier = relyingPartyIdentifier
        self.username = username
        self.userHandle = userHandle
        self.cipherId = cipherId
    }
}

/// Business logic for the Credential Provider Extension.
///
/// This service searches the local vault for matching credentials
/// and provides them to the AutoFill system.
public enum CredentialProviderService {

    /// Find matching password credentials for a given service identifier (URL).
    public static func findCredentials(
        for serviceIdentifier: String,
        ciphers: [Cipher],
        key: SymmetricCryptoKey
    ) -> [AutoFillCredential] {
        let domain = extractDomain(from: serviceIdentifier)

        return ciphers.compactMap { cipher -> AutoFillCredential? in
            guard cipher.type == .login,
                  let login = cipher.login,
                  !cipher.isDeleted else {
                return nil
            }

            // Check if any URI matches
            let matches = login.uris?.contains { uri in
                guard let encUri = uri.uri,
                      let decryptedUri = try? CipherEncryption.decryptString(encUri, key: key) else {
                    return false
                }
                return uriMatches(decryptedUri, serviceIdentifier: serviceIdentifier, domain: domain, matchType: uri.match)
            } ?? false

            guard matches else { return nil }

            let username = login.username.flatMap { try? CipherEncryption.decryptString($0, key: key) } ?? ""

            return AutoFillCredential(
                id: cipher.id ?? UUID().uuidString,
                serviceIdentifier: serviceIdentifier,
                username: username,
                cipherId: cipher.id ?? ""
            )
        }
    }

    /// Find passkey credentials for a relying party.
    public static func findPasskeyCredentials(
        for relyingPartyId: String,
        ciphers: [Cipher],
        key: SymmetricCryptoKey
    ) -> [AutoFillPasskeyCredential] {
        return ciphers.compactMap { cipher -> AutoFillPasskeyCredential? in
            guard cipher.type == .login,
                  let login = cipher.login,
                  let fido2 = login.fido2Credentials?.first,
                  !cipher.isDeleted else {
                return nil
            }

            // Check relying party matches
            guard let rpId = fido2.rpId,
                  let decryptedRpId = try? CipherEncryption.decryptString(rpId, key: key),
                  decryptedRpId == relyingPartyId else {
                return nil
            }

            let username = fido2.userName.flatMap { try? CipherEncryption.decryptString($0, key: key) } ?? ""
            let userHandle = fido2.userHandle.flatMap { try? CipherEncryption.decryptString($0, key: key) }
                .flatMap { Data(base64Encoded: $0) } ?? Data()

            return AutoFillPasskeyCredential(
                id: cipher.id ?? UUID().uuidString,
                relyingPartyIdentifier: relyingPartyId,
                username: username,
                userHandle: userHandle,
                cipherId: cipher.id ?? ""
            )
        }
    }

    /// Get the password for a credential to fill.
    public static func getPassword(
        for cipherId: String,
        ciphers: [Cipher],
        key: SymmetricCryptoKey
    ) -> String? {
        guard let cipher = ciphers.first(where: { $0.id == cipherId }),
              let password = cipher.login?.password else {
            return nil
        }
        return try? CipherEncryption.decryptString(password, key: key)
    }

    // MARK: - URI Matching

    /// Check if a URI matches a service identifier.
    private static func uriMatches(
        _ uri: String,
        serviceIdentifier: String,
        domain: String?,
        matchType: UriMatchType?
    ) -> Bool {
        let type = matchType ?? .domain  // Default to domain matching

        switch type {
        case .domain:
            guard let uriDomain = extractDomain(from: uri) else { return false }
            return uriDomain == domain

        case .host:
            guard let uriHost = URL(string: uri)?.host,
                  let serviceHost = URL(string: serviceIdentifier)?.host else {
                return false
            }
            return uriHost == serviceHost

        case .startsWith:
            return serviceIdentifier.hasPrefix(uri) || uri.hasPrefix(serviceIdentifier)

        case .exact:
            return uri == serviceIdentifier

        case .regularExpression:
            return (try? NSRegularExpression(pattern: uri))
                .map { $0.firstMatch(in: serviceIdentifier, range: NSRange(serviceIdentifier.startIndex..., in: serviceIdentifier)) != nil }
                ?? false

        case .never:
            return false
        }
    }

    /// Extract the effective domain from a URL string.
    private static func extractDomain(from urlString: String) -> String? {
        // Add scheme if missing
        var normalized = urlString
        if !normalized.contains("://") {
            normalized = "https://\(normalized)"
        }

        guard let url = URL(string: normalized),
              let host = url.host else {
            return nil
        }

        // Get base domain (strip www.)
        let parts = host.split(separator: ".")
        if parts.count >= 2 {
            return parts.suffix(2).joined(separator: ".")
        }
        return host
    }
}
