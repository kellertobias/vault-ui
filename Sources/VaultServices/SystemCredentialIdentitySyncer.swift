// MARK: - VaultServices/SystemCredentialIdentitySyncer.swift
// Mirrors the (non-secret) credential index into the system ASCredentialIdentityStore.

import Foundation
import CryptoKit
import OSLog
import VaultModels
import VaultCrypto
import AuthenticationServices

private let logger = Logger(subsystem: "com.vaultui", category: "SystemCredentialIdentitySyncer")

/// Dedup state for the system identity sync, persisted in the shared keychain so
/// repeated syncs with an unchanged index are skipped and failures back off.
private struct CredentialIdentitySyncCache: Codable, Sendable {
    var fingerprint: String?
    var failureFingerprint: String?
    var failureDate: Date?
}

/// Mirrors the credential index into the system `ASCredentialIdentityStore` so
/// logins, TOTP labels, and passkeys appear inline in QuickType / passkey
/// suggestions.
///
/// Extracted from `SharedCredentialStore`: it works purely from non-secret index
/// metadata (`SharedCredentialEntry`), so it can rebuild identities for every
/// on-device account — including locked ones — which the atomic
/// `replaceCredentialIdentities` call requires. No secret ever passes through it.
final class SystemCredentialIdentitySyncer: Sendable {

    static let shared = SystemCredentialIdentitySyncer()

    init() {}

    private static let cacheServiceName = AppIdentifiers.serviceName("identitySyncCache")
    private static let cacheAccountName = "credential-identity-sync-cache"
    private static let failureCooldown: TimeInterval = 5 * 60

    // MARK: - Public API

    /// Mirror the credential index into the system `ASCredentialIdentityStore`.
    ///
    /// - Parameters:
    ///   - allEntries: The full merged index across every on-device account.
    ///   - accountLabels: accountId → resolved label. With more than one account,
    ///     identities are registered as "[LABEL] user" so QuickType suggestions
    ///     are attributable and directly usable.
    func sync(allEntries: [SharedCredentialEntry], accountLabels: [String: String]) async {
        guard #available(macOS 11.0, *) else { return }
        guard SharedCredentialStore.isSystemCredentialIdentitySyncEnabled else {
            logger.info("Skipping ASCredentialIdentityStore sync because automatic system identity sync is disabled")
            return
        }

        let multiAccount = accountLabels.count > 1

        var passwordIdentities: [ASPasswordCredentialIdentity] = []
        var totpIdentities: [Any] = []
        var passkeyIdentities: [Any] = []
        var identityFingerprintParts: [String] = []

        for entry in allEntries {
            let accountPrefix: String = {
                guard multiAccount,
                      let accountId = entry.accountId,
                      let label = accountLabels[accountId] else { return "" }
                return "[\(label)] "
            }()
            let identifiers = entry.uris.flatMap { uri -> [ASCredentialServiceIdentifier] in
                let domain = self.extractDomain(from: uri)
                if domain.isEmpty { return [] }

                let isIP = domain.range(of: "^[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+$", options: .regularExpression) != nil

                if uri.contains("*") {
                    var cleanDomain = domain
                    if cleanDomain.hasPrefix("*.") {
                        cleanDomain = String(cleanDomain.dropFirst(2))
                    } else {
                        cleanDomain = cleanDomain.replacingOccurrences(of: "*", with: "")
                    }
                    if isIP { return [] }
                    return [ASCredentialServiceIdentifier(identifier: cleanDomain, type: .domain)]
                } else {
                    let lowerUri = uri.lowercased()
                    if uri.contains("://") && !lowerUri.hasPrefix("http://") && !lowerUri.hasPrefix("https://") {
                        return [ASCredentialServiceIdentifier(identifier: uri, type: .URL)]
                    } else {
                        let fullURL = lowerUri.hasPrefix("http") ? uri : "https://\(uri)"
                        return [ASCredentialServiceIdentifier(identifier: fullURL, type: .URL)]
                    }
                }
            }

            let baseUser = (entry.username?.isEmpty == false) ? entry.username! : entry.name
            let userToRegister = accountPrefix + baseUser

            // recordIdentifier formats: "accountId|cipherId|serviceId" (multi-account)
            // and legacy "cipherId|serviceId" for entries from pre-multi-account builds.
            let recordIdPrefix = entry.accountId.map { "\($0)|" } ?? ""

            for serviceId in identifiers {
                let uniqueRecordId = "\(recordIdPrefix)\(entry.id)|\(serviceId.identifier)"
                let identity = ASPasswordCredentialIdentity(
                    serviceIdentifier: serviceId,
                    user: userToRegister,
                    recordIdentifier: uniqueRecordId
                )
                identity.rank = 1
                passwordIdentities.append(identity)
                identityFingerprintParts.append("password|\(identityFingerprintServiceType(serviceId))|\(serviceId.identifier)|\(userToRegister)|\(uniqueRecordId)|\(identity.rank)")
                let typeStr = serviceId.type == .URL ? "URL" : "domain"
                logger.info("Registering identity: '\(entry.name, privacy: .public)' user='\(userToRegister, privacy: .public)' identifier='\(serviceId.identifier, privacy: .public)' type=\(typeStr, privacy: .public) rank=\(identity.rank, privacy: .public)")

                if #available(macOS 14.0, *) {
                    if entry.hasTotp == true {
                        let totpLabel = accountPrefix + entry.name
                        let totpIdentity = ASOneTimeCodeCredentialIdentity(
                            serviceIdentifier: serviceId,
                            label: totpLabel,
                            recordIdentifier: uniqueRecordId
                        )
                        totpIdentities.append(totpIdentity)
                        identityFingerprintParts.append("totp|\(identityFingerprintServiceType(serviceId))|\(serviceId.identifier)|\(totpLabel)|\(uniqueRecordId)")
                    }
                }
            }

            if #available(macOS 14.0, *) {
                for passkey in entry.passkeyIdentities ?? [] {
                    guard let credId = Data(bitwardenFido2CredentialId: passkey.credentialId) else { continue }
                    let userHandle = Data(base64URLDecoded: passkey.userHandle) ?? Data()

                    let uniqueRecordId = "\(recordIdPrefix)\(entry.id)|\(passkey.relyingPartyId)"
                    let pkIdentity = ASPasskeyCredentialIdentity(
                        relyingPartyIdentifier: passkey.relyingPartyId,
                        userName: userToRegister,
                        credentialID: credId,
                        userHandle: userHandle,
                        recordIdentifier: uniqueRecordId
                    )
                    passkeyIdentities.append(pkIdentity)
                    identityFingerprintParts.append("passkey|\(passkey.relyingPartyId)|\(userToRegister)|\(credId.base64URLEncodedString())|\(userHandle.base64URLEncodedString())|\(uniqueRecordId)")
                }
            }
        }

        let identityFingerprint = credentialIdentityFingerprint(parts: identityFingerprintParts)
        guard shouldSyncCredentialIdentities(fingerprint: identityFingerprint) else {
            return
        }

        // Use atomic replace on macOS 14+ to avoid race conditions.
        // Falls back to remove+save on older macOS.
        if #available(macOS 14.0, *) {
            var allIdentities: [ASCredentialIdentity] = passwordIdentities
            if let totps = totpIdentities as? [ASOneTimeCodeCredentialIdentity] {
                allIdentities.append(contentsOf: totps)
            }
            if let pks = passkeyIdentities as? [ASPasskeyCredentialIdentity] {
                allIdentities.append(contentsOf: pks)
            }
            let allCount = allIdentities.count
            await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
                ASCredentialIdentityStore.shared.replaceCredentialIdentities(allIdentities) { success, error in
                    if let error = error {
                        logger.error("Failed to replace identities in ASCredentialIdentityStore: \(error.localizedDescription, privacy: .public)")
                        self.markCredentialIdentitySyncFailed(fingerprint: identityFingerprint)
                    } else if success {
                        self.markCredentialIdentitySyncSucceeded(fingerprint: identityFingerprint)
                        logger.info("Replaced ASCredentialIdentityStore with \(allCount) identities")
                    } else {
                        logger.error("ASCredentialIdentityStore replace failed without an error")
                        self.markCredentialIdentitySyncFailed(fingerprint: identityFingerprint)
                    }
                    continuation.resume()
                }
            }
        } else {
            // macOS 11 - 13 fallback: remove then save
            let identities = passwordIdentities
            let pwCount = identities.count
            await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
                ASCredentialIdentityStore.shared.removeAllCredentialIdentities { removeSuccess, removeError in
                    if let removeError = removeError {
                        logger.error("Failed to clear ASCredentialIdentityStore: \(removeError.localizedDescription, privacy: .public)")
                        self.markCredentialIdentitySyncFailed(fingerprint: identityFingerprint)
                        continuation.resume()
                        return
                    }
                    guard removeSuccess else {
                        logger.error("ASCredentialIdentityStore removeAll failed without an error")
                        self.markCredentialIdentitySyncFailed(fingerprint: identityFingerprint)
                        continuation.resume()
                        return
                    }

                    ASCredentialIdentityStore.shared.saveCredentialIdentities(identities) { success, error in
                        if let error = error {
                            logger.error("Failed to save identities to ASCredentialIdentityStore: \(error.localizedDescription, privacy: .public)")
                            self.markCredentialIdentitySyncFailed(fingerprint: identityFingerprint)
                        } else if success {
                            self.markCredentialIdentitySyncSucceeded(fingerprint: identityFingerprint)
                            logger.info("Saved \(pwCount) password identities to ASCredentialIdentityStore")
                        } else {
                            logger.error("ASCredentialIdentityStore save failed without an error")
                            self.markCredentialIdentitySyncFailed(fingerprint: identityFingerprint)
                        }
                        continuation.resume()
                    }
                }
            }
        }
    }

    /// Remove every identity Vault UI registered with the system credential store and
    /// forget the sync fingerprint, so a later re-enable performs a full re-registration.
    func removeAll() async {
        clearCache()
        await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
            ASCredentialIdentityStore.shared.removeAllCredentialIdentities { success, error in
                if let error = error {
                    logger.error("Failed to clear ASCredentialIdentityStore: \(error.localizedDescription, privacy: .public)")
                } else if !success {
                    logger.error("ASCredentialIdentityStore removeAll failed without an error")
                } else {
                    logger.info("Removed all identities from ASCredentialIdentityStore")
                }
                continuation.resume()
            }
        }
    }

    /// Forget the dedup fingerprint so the next sync performs a full re-registration.
    func clearCache() {
        SharedKeychain.delete(
            service: Self.cacheServiceName,
            account: Self.cacheAccountName
        )
    }

    // MARK: - Fingerprint & dedup cache

    private func credentialIdentityFingerprint(parts: [String]) -> String {
        let canonical = parts.sorted().joined(separator: "\u{1F}")
        let digest = SHA256.hash(data: Data(canonical.utf8))
        return digest.map { String(format: "%02x", $0) }.joined()
    }

    private func identityFingerprintServiceType(_ serviceIdentifier: ASCredentialServiceIdentifier) -> String {
        serviceIdentifier.type == .URL ? "URL" : "domain"
    }

    private func shouldSyncCredentialIdentities(fingerprint: String) -> Bool {
        let cache = fetchCache()

        if cache.fingerprint == fingerprint {
            logger.info("Skipping ASCredentialIdentityStore sync because credential identities are unchanged")
            return false
        }

        if cache.failureFingerprint == fingerprint,
           let failureDate = cache.failureDate {
            let elapsed = Date().timeIntervalSince(failureDate)
            if elapsed < Self.failureCooldown {
                let remaining = Int(Self.failureCooldown - elapsed)
                logger.warning("Skipping ASCredentialIdentityStore sync for \(remaining, privacy: .public)s after a recent failure")
                return false
            }
        }

        return true
    }

    private func markCredentialIdentitySyncSucceeded(fingerprint: String) {
        storeCache(
            CredentialIdentitySyncCache(
                fingerprint: fingerprint,
                failureFingerprint: nil,
                failureDate: nil
            )
        )
    }

    private func markCredentialIdentitySyncFailed(fingerprint: String) {
        var cache = fetchCache()
        cache.failureFingerprint = fingerprint
        cache.failureDate = Date()
        storeCache(cache)
    }

    private func fetchCache() -> CredentialIdentitySyncCache {
        guard let data = try? SharedKeychain.load(
            service: Self.cacheServiceName,
            account: Self.cacheAccountName
        ) else {
            return CredentialIdentitySyncCache()
        }

        return (try? JSONDecoder().decode(CredentialIdentitySyncCache.self, from: data))
            ?? CredentialIdentitySyncCache()
    }

    private func storeCache(_ cache: CredentialIdentitySyncCache) {
        guard let data = try? JSONEncoder().encode(cache) else { return }
        try? SharedKeychain.save(
            data: data,
            service: Self.cacheServiceName,
            account: Self.cacheAccountName
        )
    }

    /// Extract the domain from a URL string.
    private func extractDomain(from input: String) -> String {
        if let url = URL(string: input), let host = url.host {
            return host
        }
        if !input.contains("://"), let url = URL(string: "https://\(input)"), let host = url.host {
            return host
        }
        return input
    }
}
