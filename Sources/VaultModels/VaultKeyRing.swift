// MARK: - VaultModels/VaultKeyRing.swift
// The set of symmetric keys an unlocked session can decrypt with.

import Foundation
import VaultCrypto

/// The personal vault key plus every organization key the account can unwrap.
///
/// Organization ciphers are encrypted under the **org** key, not the personal
/// vault key, so every decrypt/encrypt path needs to pick a base key from the
/// cipher's `organizationId`. Passing this ring instead of a bare vault key is
/// what makes that routing impossible to forget.
public struct VaultKeyRing: Sendable {

    /// The account's personal vault key. Used for items with no `organizationId`.
    public let vaultKey: SymmetricCryptoKey

    /// Organization ID → that organization's symmetric key.
    ///
    /// An org the user belongs to but whose key failed to unwrap is absent here,
    /// so its items resolve to `nil` rather than silently falling back to the
    /// personal key (which would produce unreadable ciphertext on save).
    public let organizationKeys: [String: SymmetricCryptoKey]

    public init(vaultKey: SymmetricCryptoKey, organizationKeys: [String: SymmetricCryptoKey] = [:]) {
        self.vaultKey = vaultKey
        self.organizationKeys = organizationKeys
    }

    /// The base key for an organization, or the personal vault key when `id` is nil.
    ///
    /// Returns `nil` for an organization whose key is not available — callers must
    /// treat that as "cannot decrypt", never as "use the personal key".
    public func baseKey(forOrganization id: String?) -> SymmetricCryptoKey? {
        guard let id, !id.isEmpty else { return vaultKey }
        return organizationKeys[id]
    }

    /// The base key a cipher's fields (and its item key) are wrapped under.
    public func baseKey(for cipher: Cipher) -> SymmetricCryptoKey? {
        baseKey(forOrganization: cipher.organizationId)
    }

    /// Whether this ring can read items belonging to `organizationId`.
    public func canDecrypt(organizationId: String?) -> Bool {
        baseKey(forOrganization: organizationId) != nil
    }
}

/// Unwraps organization keys from a sync profile using the account's RSA private key.
public enum OrganizationKeyResolver {

    /// The outcome of unwrapping a set of organization keys.
    public struct Result: Sendable {
        public let keys: [String: SymmetricCryptoKey]
        /// Organizations whose key could not be unwrapped, with the reason.
        public let failures: [(organizationId: String, error: Error)]

        public var isComplete: Bool { failures.isEmpty }
    }

    /// Decrypt each organization's symmetric key with the account private key.
    ///
    /// Each `Organization.key` is the org's symmetric key sealed to this user's
    /// RSA public key at invite-accept time, so the account private key (itself
    /// decrypted from the profile with the vault key) opens it.
    ///
    /// - Parameters:
    ///   - organizations: Organizations from the sync profile.
    ///   - privateKeyData: The decrypted account private key (PKCS#8 or PKCS#1 DER).
    public static func resolve(
        organizations: [Organization],
        privateKeyData: Data?
    ) -> Result {
        guard let privateKeyData, !privateKeyData.isEmpty else {
            let failures = organizations.compactMap { org -> (String, Error)? in
                guard let id = org.id else { return nil }
                return (id, CryptoError.missingKey("No account private key available"))
            }
            return Result(keys: [:], failures: failures)
        }

        var keys = [String: SymmetricCryptoKey]()
        var failures = [(organizationId: String, error: Error)]()

        for organization in organizations {
            guard let id = organization.id else { continue }

            // The server only seals the org key to a member once their membership
            // is *confirmed*; a disabled, revoked, invited or merely accepted
            // membership legitimately has no key, so skip those quietly.
            guard organization.enabled != false,
                  organization.status == nil || organization.status == OrganizationUserStatus.confirmed.rawValue else {
                continue
            }

            guard let encryptedKey = organization.key else {
                failures.append((id, CryptoError.missingKey("Organization \(id) has no key")))
                continue
            }

            do {
                keys[id] = try AsymmetricCrypto.decryptKey(
                    encString: encryptedKey,
                    privateKeyData: privateKeyData
                )
            } catch {
                failures.append((id, error))
            }
        }

        return Result(keys: keys, failures: failures)
    }
}

/// Membership status values Bitwarden uses in `Organization.status`.
public enum OrganizationUserStatus: Int, Sendable {
    case invited = 0
    case accepted = 1
    case confirmed = 2
    case revoked = -1
}
