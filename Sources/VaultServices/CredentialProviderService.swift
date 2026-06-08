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
                return uriMatches(decryptedUri, serviceIdentifier: serviceIdentifier, matchType: uri.match)
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
                .flatMap { Data(base64URLDecoded: $0) } ?? Data()

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

    /// Check if a stored URI matches a requesting service identifier.
    ///
    /// Domain/host/startsWith matching all go through the shared, boundary-aware
    /// `CredentialMatcher` so a look-alike origin (e.g. `paypal.com.evil.com`)
    /// cannot satisfy a credential stored for `paypal.com`. Regex matches are
    /// anchored so a pattern cannot match an arbitrary substring of the URL.
    private static func uriMatches(
        _ uri: String,
        serviceIdentifier: String,
        matchType: UriMatchType?
    ) -> Bool {
        let type = matchType ?? .domain  // Default to domain matching

        switch type {
        case .domain:
            // Boundary-aware domain/subdomain match (plus protocol & path rules).
            return CredentialMatcher.matches(storedURI: uri, siteIdentifier: serviceIdentifier)

        case .host:
            // Strict: exact host equality (no subdomain widening).
            let uriHost = CredentialMatcher.deconstruct(uri).host
            let serviceHost = CredentialMatcher.deconstruct(serviceIdentifier).host
            return !uriHost.isEmpty && uriHost == serviceHost

        case .startsWith:
            // Was an unbounded prefix compare (a stored "https://" matched every
            // site). Use the boundary-aware matcher instead.
            return CredentialMatcher.matches(storedURI: uri, siteIdentifier: serviceIdentifier)

        case .exact:
            return uri == serviceIdentifier

        case .regularExpression:
            // Anchor the pattern so it must match the whole identifier, not an
            // arbitrary substring (`paypal` no longer matches `evil.com/paypal`).
            let anchored = "^(?:\(uri))$"
            return (try? NSRegularExpression(pattern: anchored, options: [.caseInsensitive]))
                .map { $0.firstMatch(in: serviceIdentifier, range: NSRange(serviceIdentifier.startIndex..., in: serviceIdentifier)) != nil }
                ?? false

        case .never:
            return false
        }
    }
}
