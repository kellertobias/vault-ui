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
            return serviceIdentifier.hasPrefix(uri)

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

    /// Extract the effective registrable domain from a URL string.
    ///
    /// Handles multi-part TLDs like `.co.uk`, `.com.au`, `.github.io` by checking
    /// against a curated list of common multi-part public suffixes. Falls back to
    /// the last 2 labels for standard TLDs.
    private static func extractDomain(from urlString: String) -> String? {
        // Add scheme if missing
        var normalized = urlString
        if !normalized.contains("://") {
            normalized = "https://\(normalized)"
        }

        guard let url = URL(string: normalized),
              let host = url.host?.lowercased() else {
            return nil
        }

        // Strip www. prefix
        let cleanHost = host.hasPrefix("www.") ? String(host.dropFirst(4)) : host

        let parts = cleanHost.split(separator: ".").map(String.init)
        guard parts.count >= 2 else { return cleanHost }

        // Common multi-part public suffixes (registrable domain = suffix + 1 label).
        // This covers the vast majority of real-world cases without bundling
        // the full Mozilla PSL.
        let multiPartSuffixes: Set<String> = [
            // Country-code second-level domains
            "co.uk", "org.uk", "me.uk", "ac.uk", "gov.uk", "net.uk",
            "co.jp", "or.jp", "ne.jp", "ac.jp", "go.jp",
            "com.au", "net.au", "org.au", "edu.au", "gov.au",
            "co.nz", "net.nz", "org.nz", "govt.nz",
            "co.kr", "or.kr", "ne.kr", "go.kr",
            "co.in", "net.in", "org.in", "gov.in", "ac.in",
            "com.br", "net.br", "org.br", "gov.br",
            "co.za", "org.za", "net.za", "gov.za",
            "com.cn", "net.cn", "org.cn", "gov.cn",
            "com.tw", "net.tw", "org.tw", "gov.tw",
            "com.hk", "net.hk", "org.hk", "gov.hk",
            "com.sg", "net.sg", "org.sg", "gov.sg",
            "co.il", "org.il", "net.il", "ac.il",
            "com.mx", "net.mx", "org.mx", "gob.mx",
            "com.ar", "net.ar", "org.ar", "gov.ar",
            "co.id", "or.id", "web.id", "go.id",
            "co.th", "or.th", "in.th", "go.th",
            "com.pl", "net.pl", "org.pl",
            "com.tr", "net.tr", "org.tr", "gov.tr",
            "com.ua", "net.ua", "org.ua",
            "co.ke", "or.ke", "go.ke",
            // Platform hosting suffixes
            "github.io", "gitlab.io", "herokuapp.com", "netlify.app",
            "vercel.app", "pages.dev", "workers.dev", "fly.dev",
            "azurewebsites.net", "cloudfront.net", "amazonaws.com",
            "appspot.com", "firebaseapp.com", "web.app",
            "blogspot.com", "blogspot.co.uk",
        ]

        // Check if the last 2 labels form a known multi-part suffix
        if parts.count >= 3 {
            let lastTwo = "\(parts[parts.count - 2]).\(parts[parts.count - 1])"
            if multiPartSuffixes.contains(lastTwo) {
                // Registrable domain = 1 label + the 2-part suffix
                return parts.suffix(3).joined(separator: ".")
            }
        }

        // Default: last 2 labels (standard TLDs like .com, .net, .org, .de)
        return parts.suffix(2).joined(separator: ".")
    }
}
