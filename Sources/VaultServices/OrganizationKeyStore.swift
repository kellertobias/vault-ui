// MARK: - VaultServices/OrganizationKeyStore.swift
// Loads organization keys out of local storage and into an in-memory key ring.

import Foundation
import SwiftData
import OSLog
import VaultCrypto
import VaultModels
import VaultSync

private let logger = Logger(subsystem: "com.vaultui", category: "OrganizationKeyStore")

/// Builds a `VaultKeyRing` from the organizations a full sync persisted.
///
/// Each organization's symmetric key is stored on disk exactly as the server sent
/// it — sealed to the account's RSA public key — and is only ever unwrapped here,
/// in memory, while the vault is unlocked. Every consumer (the app session, the
/// AutoFill export, the SSH/secret agents) goes through this one path so they all
/// agree on which organizations are readable.
enum OrganizationKeyStore {

    /// Organizations persisted for an account, in sync-response form.
    @MainActor
    static func organizations(container: ModelContainer, accountId: String) -> [Organization] {
        let context = container.mainContext
        let descriptor = FetchDescriptor<PersistedOrganization>(
            predicate: #Predicate { $0.accountId == accountId }
        )
        guard let persisted = try? context.fetch(descriptor) else { return [] }
        return persisted.map { $0.toOrganization() }
    }

    /// Collections persisted for an account, carrying their permission flags.
    @MainActor
    static func collections(container: ModelContainer, accountId: String) -> [VaultModels.Collection] {
        let context = container.mainContext
        let descriptor = FetchDescriptor<PersistedCollection>(
            predicate: #Predicate { $0.accountId == accountId }
        )
        guard let persisted = try? context.fetch(descriptor) else { return [] }
        return persisted.map { $0.toCollection() }
    }

    /// Unwrap every available organization key and return the resulting ring.
    ///
    /// Organizations whose key cannot be unwrapped are logged and left out, so their
    /// items stay unreadable rather than silently falling back to the personal key.
    @MainActor
    static func keyRing(
        container: ModelContainer?,
        accountId: String?,
        vaultKey: SymmetricCryptoKey,
        privateKeyData: Data?
    ) -> VaultKeyRing {
        guard let container, let accountId else {
            return VaultKeyRing(vaultKey: vaultKey)
        }

        let result = OrganizationKeyResolver.resolve(
            organizations: organizations(container: container, accountId: accountId),
            privateKeyData: privateKeyData
        )

        for failure in result.failures {
            logger.error(
                "Could not unwrap key for organization \(failure.organizationId, privacy: .public): \(failure.error.localizedDescription, privacy: .public)"
            )
        }

        if !result.keys.isEmpty {
            logger.info("Unwrapped \(result.keys.count) organization key(s)")
        }

        return VaultKeyRing(vaultKey: vaultKey, organizationKeys: result.keys)
    }
}
