// MARK: - VaultServices/SharedCredentialStore.swift
// Shared credential data for the AutoFill Credential Provider extension

import Foundation
import Security
import CryptoKit
import LocalAuthentication
import VaultModels
import VaultCrypto
import VaultSync
import VaultSSH
import OSLog
import AuthenticationServices
import SwiftData

private let logger = Logger(subsystem: "com.vaultui", category: "SharedCredentialStore")

// MARK: - SharedCredentialEntry

/// A lightweight, decrypted credential entry for AutoFill suggestions.
///
/// Stored as a JSON array in the shared Keychain so the AutoFill extension
/// can display credential suggestions without needing the vault key.
/// Passwords are intentionally omitted — they are stored separately and
/// fetched only when the user selects a credential.
public struct SharedCredentialEntry: Codable, Sendable, Identifiable, Equatable {
    /// The unique cipher ID
    public let id: String
    /// The descriptive name of the item
    public let name: String
    /// The username (for logins and identities)
    public let username: String?
    /// List of URIs/URLs associated with this item
    public let uris: [String]
    /// The raw cipher type integer
    public let type: Int
    /// Whether this credential has a TOTP secret
    public let hasTotp: Bool
    /// Whether this credential has a FIDO2 passkey
    public let hasPasskey: Bool?
    /// Custom field order for sorting
    public let order: Int?
    /// Whether this entry is a local temporary credential.
    public let isTemporary: Bool?
    /// Whether this entry has an attached PFX/P12 certificate.
    public let hasCertificate: Bool?
    /// Certificate expiry date, if known.
    public let certificateExpiresAt: Date?
    /// The vault account this entry belongs to. `nil` only for entries written
    /// by pre-multi-account builds (treated as the single legacy account).
    public let accountId: String?
    /// Non-secret passkey identity metadata, so credential identities can be
    /// (re-)registered with the system without decrypting any account's vault.
    public let passkeyIdentities: [SharedPasskeyIdentityMeta]?

    public var supportsTotp: Bool { hasTotp }
    public var supportsPasskey: Bool { hasPasskey ?? false }
    public var isTemporaryCredential: Bool { isTemporary ?? false }
    public var supportsCertificateFill: Bool { hasCertificate ?? false }

    public init(
        id: String,
        name: String,
        username: String?,
        uris: [String],
        type: Int,
        hasTotp: Bool = false,
        hasPasskey: Bool? = false,
        order: Int? = nil,
        isTemporary: Bool? = false,
        hasCertificate: Bool? = false,
        certificateExpiresAt: Date? = nil,
        accountId: String? = nil,
        passkeyIdentities: [SharedPasskeyIdentityMeta]? = nil
    ) {
        self.id = id
        self.name = name
        self.username = username
        self.uris = uris
        self.type = type
        self.hasTotp = hasTotp
        self.hasPasskey = hasPasskey
        self.order = order
        self.isTemporary = isTemporary
        self.hasCertificate = hasCertificate
        self.certificateExpiresAt = certificateExpiresAt
        self.accountId = accountId
        self.passkeyIdentities = passkeyIdentities
    }
}

/// Non-secret passkey identity metadata (everything `ASPasskeyCredentialIdentity`
/// needs). The private key stays sealed in the per-credential keychain item.
public struct SharedPasskeyIdentityMeta: Codable, Sendable, Equatable {
    public let credentialId: String
    public let relyingPartyId: String
    public let userHandle: String

    public init(credentialId: String, relyingPartyId: String, userHandle: String) {
        self.credentialId = credentialId
        self.relyingPartyId = relyingPartyId
        self.userHandle = userHandle
    }
}

/// On-device account metadata shared with the AutoFill / Safari extensions:
/// drives the extension's account picker and the "[ACCOUNT]" QuickType labels.
public struct SharedAccountInfo: Codable, Sendable, Identifiable, Equatable {
    public let id: String
    public let email: String
    public let serverHost: String
    /// Resolved display label (Short Name → Alias → domain → host → email).
    public let label: String
    /// Index into `AccountAvatarPalette`.
    public let colorIndex: Int

    public init(id: String, email: String, serverHost: String, label: String, colorIndex: Int) {
        self.id = id
        self.email = email
        self.serverHost = serverHost
        self.label = label
        self.colorIndex = colorIndex
    }
}

/// Certificate bytes shared with the Safari Web Extension for explicit file-upload fills.
public struct SharedCertificateData: Codable, Sendable, Equatable {
    public let fileName: String
    public let dataBase64: String
    public let password: String
    public let expiresAt: Date?

    public init(fileName: String, dataBase64: String, password: String, expiresAt: Date?) {
        self.fileName = fileName
        self.dataBase64 = dataBase64
        self.password = password
        self.expiresAt = expiresAt
    }
}

/// One-shot fallback fill request written by the AutoFill extension for Safari pages.
public struct AutoFillCredentialFillRequest: Codable, Sendable, Equatable {
    public let url: String
    public let name: String
    public let username: String
    public let password: String
    public let createdAt: Date

    public init(url: String, name: String, username: String, password: String, createdAt: Date = Date()) {
        self.url = url
        self.name = name
        self.username = username
        self.password = password
        self.createdAt = createdAt
    }
}

/// Decrypted passkey data shared with the AutoFill extension.
public struct SharedPasskeyData: Codable, Sendable {
    public let credentialId: String
    public let privateKey: String
    public let relyingPartyId: String
    public let userHandle: String
    
    public init(credentialId: String, privateKey: String, relyingPartyId: String, userHandle: String) {
        self.credentialId = credentialId
        self.privateKey = privateKey
        self.relyingPartyId = relyingPartyId
        self.userHandle = userHandle
    }
}

// MARK: - Sync Dates

public struct SharedSyncDates: Codable, Sendable {
    public let lastSyncWithServer: Date?
    public let lastSyncWithApp: Date?
    
    public init(lastSyncWithServer: Date?, lastSyncWithApp: Date?) {
        self.lastSyncWithServer = lastSyncWithServer
        self.lastSyncWithApp = lastSyncWithApp
    }
}

// MARK: - SharedCredentialStore

/// Manages shared credential data in the Keychain for cross-target access.
///
/// The main app writes credential metadata after each successful sync.
/// The AutoFill extension reads it to populate credential suggestions.
///
/// Data flow:
/// 1. Main app syncs vault → decrypts metadata → writes index to shared Keychain
/// 2. Extension reads index → shows suggestions → fetches password on selection
///
/// Security model:
/// - The credential index contains names/usernames/URIs but **never** passwords
/// - Passwords are stored as individual Keychain items, one per credential
/// - All items use `kSecAttrAccessibleAfterFirstUnlock` for background access
/// - Items are scoped to the shared Keychain access group
public final class SharedCredentialStore: Sendable {

    /// Shared singleton instance.
    public static let shared = SharedCredentialStore()

    // MARK: - Constants

    /// Keychain access group for sharing between app and extension.
    ///
    /// Must match the keychain-access-groups entitlement.
    public static let keychainAccessGroup = AppIdentifiers.keychainAccessGroup

    /// Service name for the credential index keychain item.
    private static let indexServiceName = AppIdentifiers.serviceName("credentials")

    /// Account name for the credential index keychain item.
    private static let indexAccountName = "credential-index"

    /// Service name prefix for individual password keychain items.
    private static let passwordServiceName = AppIdentifiers.serviceName("password")

    /// Service name for TOTP secrets in the shared Keychain.
    private static let totpServiceName = AppIdentifiers.serviceName("totp")
    /// Service name for certificate data in the shared Keychain.
    private static let certificateServiceName = AppIdentifiers.serviceName("certificate")
    /// Service name for passkeys in the shared Keychain.
    private static let passkeyServiceName = AppIdentifiers.serviceName("passkey")

    /// Service + account for the AutoFill vault key. This is the account vault key
    /// itself, stored behind a Secure Enclave `.userPresence` access control so the
    /// AutoFill / Safari extensions can decrypt the (ciphertext) secret cache only
    /// after a successful Touch ID / device-password authentication. It is the single
    /// cryptographic gate for every exported secret.
    private static let autoFillVaultKeyServiceName = AppIdentifiers.serviceName("autoFillVaultKey")
    private static let autoFillVaultKeyAccountName = "autofill-vault-key"

    /// Service + account for the shared on-device account list.
    private static let accountInfoServiceName = AppIdentifiers.serviceName("accounts")
    private static let accountInfoAccountName = "account-list"

    /// Service name for pending passkey queue.
    private static let pendingPasskeysServiceName = AppIdentifiers.serviceName("pendingPasskeys")
    private static let pendingPasskeysAccountName = "pending-passkeys-queue"
    private static let pendingCredentialsServiceName = AppIdentifiers.serviceName("pendingCredentials")
    private static let pendingCredentialsAccountName = "pending-credentials-queue"
    private static let temporaryCredentialsServiceName = AppIdentifiers.serviceName("temporaryCredentials")
    private static let temporaryCredentialsAccountName = "temporary-credentials-queue"
    private static let autoFillFormContextServiceName = AppIdentifiers.serviceName("autoFillFormContext")
    private static let autoFillFormContextAccountName = "latest-form-context"
    private static let autoFillCredentialFillServiceName = AppIdentifiers.serviceName("autoFillCredentialFill")
    private static let autoFillCredentialFillAccountName = "latest-fill-request"

    private static let syncDatesServiceName = AppIdentifiers.serviceName("syncDates")
    private static let syncDatesAccountName = "sync-dates"
    private static let sshIdentityCacheServiceName = AppIdentifiers.serviceName("sshIdentityCache")
    private static let sshIdentityCacheAccountName = "ssh-identity-cache"
    public static let systemCredentialIdentitySyncEnabledKey = "systemCredentialIdentitySyncEnabled"

    /// Whether credential identities (passwords, TOTP labels, passkey metadata) are
    /// mirrored into the system `ASCredentialIdentityStore` so they appear inline in
    /// QuickType / passkey suggestions. Defaults to enabled; only metadata is shared —
    /// secrets stay encrypted behind the biometric-gated vault key.
    public static var isSystemCredentialIdentitySyncEnabled: Bool {
        UserDefaults.standard.object(forKey: systemCredentialIdentitySyncEnabledKey) as? Bool ?? true
    }

    private struct CachedSSHIdentity: Codable {
        let publicKeyBlobBase64: String
        let comment: String
        let cipherId: String
    }

    public init() {}

    /// Pending export task for debouncing. Only the most recent export request runs.
    nonisolated(unsafe) private static var pendingExportTask: Task<Void, Never>?

    // MARK: - Export Credentials

    /// Decrypt and export credential metadata to the shared Keychain.
    ///
    /// Called after each successful sync to keep the AutoFill extension's
    /// credential list up to date. Only login and identity ciphers are exported.
    ///
    /// - Parameters:
    ///   - engine: The sync engine to fetch persisted ciphers from
    ///   - session: The session manager providing decryption keys
    @MainActor
    public func exportCredentials(from engine: SyncEngine, session: SessionManager) {
        do {
            let vaultKey = try session.getVaultKey()
            exportCredentials(from: engine, vaultKey: vaultKey)
        } catch {
            logger.error("Failed to get vault key: \(error.localizedDescription, privacy: .public)")
        }
    }
    
    @MainActor
    public func exportCredentials(from engine: SyncEngine, vaultKey: SymmetricCryptoKey) {
        let container = engine.modelContainer
        let accountId = engine.accountId
        let lastSuccessfulSyncDate = engine.lastSyncDate

        // Cancel any pending export to debounce rapid calls
        Self.pendingExportTask?.cancel()
        
        Self.pendingExportTask = Task.detached { [weak self] in
            // Wait briefly so rapid-fire calls collapse into one
            try? await Task.sleep(nanoseconds: 500_000_000) // 0.5s
            guard !Task.isCancelled, let self = self else { return }
            await self.performExport(
                container: container,
                accountId: accountId,
                vaultKey: vaultKey,
                lastSuccessfulSyncDate: lastSuccessfulSyncDate
            )
        }
    }

    @MainActor
    public func exportCredentialsAndWait(from engine: SyncEngine, session: SessionManager) async {
        do {
            let vaultKey = try session.getVaultKey()
            await exportCredentialsAndWait(from: engine, vaultKey: vaultKey)
        } catch {
            logger.error("Failed to get vault key: \(error.localizedDescription, privacy: .public)")
        }
    }

    @MainActor
    public func exportCredentialsAndWait(from engine: SyncEngine, vaultKey: SymmetricCryptoKey) async {
        let container = engine.modelContainer
        let accountId = engine.accountId
        let lastSuccessfulSyncDate = engine.lastSyncDate

        Self.pendingExportTask?.cancel()
        Self.pendingExportTask = nil

        await Task.detached { [weak self] in
            guard let self = self else { return }
            await self.performExport(
                container: container,
                accountId: accountId,
                vaultKey: vaultKey,
                lastSuccessfulSyncDate: lastSuccessfulSyncDate
            )
        }.value
    }

    private func performExport(
        container: ModelContainer,
        accountId: String,
        vaultKey: SymmetricCryptoKey,
        lastSuccessfulSyncDate: Date?
    ) async {
        // Older builds eagerly persisted typed credentials here; purge any leftover plaintext.
        purgeLegacyAutoFillFormContext()
        do {
            let context = ModelContext(container)
            let descriptor = FetchDescriptor<PersistedCipher>(predicate: #Predicate {
                $0.accountId == accountId && $0.deletedDate == nil
            })
            guard let persistedCiphers = try? context.fetch(descriptor) else { return }

            var entries: [SharedCredentialEntry] = []
            var writtenPasswordAttrs = Set<String>()
            var writtenTotpAttrs = Set<String>()
            var writtenPasskeyAttrs = Set<String>()

            for persisted in persistedCiphers {
                guard let cipherType = persisted.cipherType,
                      cipherType == .login || cipherType == .identity else {
                    continue
                }

                let cipher: Cipher
                do {
                    cipher = try persisted.toCipher()
                } catch {
                    logger.warning("Failed to decode cipher \(persisted.id, privacy: .public): \(error.localizedDescription, privacy: .public)")
                    continue
                }

                let decryptionKey: SymmetricCryptoKey
                if let itemKeyEnc = cipher.key,
                   let itemKeyData = try? CipherEncryption.decryptData(itemKeyEnc, key: vaultKey),
                   let itemKey = try? SymmetricCryptoKey(keyData: itemKeyData) {
                    decryptionKey = itemKey
                } else {
                    decryptionKey = vaultKey
                }

                guard let name = Self.decryptOptional(cipher.name, key: decryptionKey) else {
                    continue
                }

                let username: String?
                var uris: [String] = []
                var password: String?
                var totpSecret: String?
                var hasPasskey = false
                var hasCertificate = false
                var certificateExpiresAt: Date?
                var passkeyIdentityMetas: [SharedPasskeyIdentityMeta] = []

                switch cipherType {
                case .login:
                    username = Self.decryptOptional(cipher.login?.username, key: decryptionKey)
                    password = Self.decryptOptional(cipher.login?.password, key: decryptionKey)
                    totpSecret = Self.decryptOptional(cipher.login?.totp, key: decryptionKey)
                    hasPasskey = cipher.login?.fido2Credentials?.isEmpty == false
                    if let loginUris = cipher.login?.uris {
                        for loginUri in loginUris {
                            if let decryptedUri = Self.decryptOptional(loginUri.uri, key: decryptionKey) {
                                uris.append(decryptedUri)
                            }
                        }
                    }

                    if let fido2List = cipher.login?.fido2Credentials, !fido2List.isEmpty {
                        var passkeys = [SharedPasskeyData]()
                        for fido2 in fido2List {
                            if let credId = Self.decryptOptional(fido2.credentialId, key: decryptionKey),
                               let privKey = Self.decryptOptional(fido2.keyValue, key: decryptionKey),
                               let rpId = Self.decryptOptional(fido2.rpId, key: decryptionKey),
                               let userHandle = Self.decryptOptional(fido2.userHandle, key: decryptionKey) {
                                passkeys.append(SharedPasskeyData(credentialId: credId, privateKey: privKey, relyingPartyId: rpId, userHandle: userHandle))
                                passkeyIdentityMetas.append(SharedPasskeyIdentityMeta(
                                    credentialId: credId,
                                    relyingPartyId: rpId,
                                    userHandle: userHandle
                                ))
                            }
                        }
                        if !passkeys.isEmpty {
                            self.storePasskeys(id: persisted.id, accountId: accountId, passkeys: passkeys, key: vaultKey)
                            writtenPasskeyAttrs.insert(Self.secretAccountAttr(id: persisted.id, accountId: accountId))
                        }
                    }

                case .identity:
                    username = Self.decryptOptional(cipher.identity?.username, key: decryptionKey)
                        ?? Self.decryptOptional(cipher.identity?.email, key: decryptionKey)

                default:
                    continue
                }

                let hasTotp = totpSecret != nil && !totpSecret!.isEmpty

                if let attachments = cipher.attachments {
                    hasCertificate = attachments.contains { attachment in
                        guard let encryptedFileName = attachment.fileName,
                              let fileName = Self.decryptOptional(encryptedFileName, key: decryptionKey) else {
                            return false
                        }
                        return CertificateMetadata.isCertificateFileName(fileName)
                    }
                }

                var orderValue: Int? = nil
                if let fields = cipher.fields {
                    for field in fields {
                        if let nameEnc = field.name,
                           let nameDec = Self.decryptOptional(nameEnc, key: decryptionKey),
                           nameDec.lowercased() == "order",
                           let valEnc = field.value,
                           let valDec = Self.decryptOptional(valEnc, key: decryptionKey),
                           let valInt = Int(valDec) {
                            orderValue = valInt
                            break
                        }
                    }

                    certificateExpiresAt = CertificateMetadata.read(
                        fields: fields,
                        decrypt: { Self.decryptOptional($0, key: decryptionKey) }
                    )?.expiresAt
                }

                let entry = SharedCredentialEntry(
                    id: persisted.id,
                    name: name,
                    username: username,
                    uris: uris,
                    type: cipherType.rawValue,
                    hasTotp: hasTotp,
                    hasPasskey: hasPasskey,
                    order: orderValue,
                    isTemporary: persisted.syncStatus == .temporaryDraft,
                    hasCertificate: hasCertificate || certificateExpiresAt != nil,
                    certificateExpiresAt: certificateExpiresAt,
                    accountId: accountId,
                    passkeyIdentities: passkeyIdentityMetas.isEmpty ? nil : passkeyIdentityMetas
                )
                entries.append(entry)

                if let password = password, !password.isEmpty {
                    self.storePassword(id: persisted.id, accountId: accountId, password: password, key: vaultKey)
                    writtenPasswordAttrs.insert(Self.secretAccountAttr(id: persisted.id, accountId: accountId))
                }

                if let totpSecret = totpSecret, !totpSecret.isEmpty {
                    self.storeTotp(id: persisted.id, accountId: accountId, totp: totpSecret, key: vaultKey)
                    writtenTotpAttrs.insert(Self.secretAccountAttr(id: persisted.id, accountId: accountId))
                }
            }

            // Drop stale secrets for this account (removed/trashed ciphers, cleared
            // passwords) and any legacy un-scoped items from pre-multi-account
            // builds. Spared: items this export just wrote, temporary-draft
            // passwords (written outside the export), and certificates attached to
            // still-existing ciphers (also written outside the export).
            let draftAttrs = Set(fetchTemporaryCredentialDrafts().map {
                Self.secretAccountAttr(id: $0.id, accountId: $0.accountId)
            })
            // Certificates may still live under the legacy bare-cipherId attr —
            // spare both forms for ciphers that still exist (reads fall back).
            let entryAttrs = Set(entries.flatMap {
                [Self.secretAccountAttr(id: $0.id, accountId: accountId), $0.id]
            })
            let cleanupPlan: [(service: String, sparing: Set<String>)] = [
                (Self.passwordServiceName, writtenPasswordAttrs.union(draftAttrs)),
                (Self.totpServiceName, writtenTotpAttrs),
                (Self.passkeyServiceName, writtenPasskeyAttrs),
                (Self.certificateServiceName, entryAttrs),
            ]
            for step in cleanupPlan {
                deleteSecretItems(
                    service: step.service,
                    accountId: accountId,
                    includeLegacyUnscoped: true,
                    sparing: step.sparing
                )
            }

            // Publish the biometric-gated vault key so the extensions can decrypt the
            // ciphertext secrets above. This is the only key material exported, and it
            // is released only after Touch ID / device authentication. The legacy
            // un-scoped key is superseded by the per-account item.
            self.storeAutoFillVaultKey(vaultKey, accountId: accountId)
            self.clearAutoFillVaultKey(accountId: nil)

            // Merge into the shared index: replace this account's entries, keep
            // the other accounts' ones. Legacy nil-account entries are dropped —
            // they belonged to the pre-multi-account single vault.
            let otherAccountEntries = fetchStoredIndexEntries().filter {
                $0.accountId != nil && $0.accountId != accountId
            }
            let mergedEntries = otherAccountEntries + entries
            storeIndexEntries(mergedEntries)

            // Store only the sync engine's confirmed successful-sync timestamp.
            // This keeps AutoFill from treating a shared Keychain export as a sync.
            self.storeSyncDates(server: lastSuccessfulSyncDate, app: lastSuccessfulSyncDate)

            logger.info("Exported \(entries.count) credentials to shared Keychain (\(mergedEntries.count) total across accounts)")
            await SystemCredentialIdentitySyncer.shared.sync(
                allEntries: mergedEntries,
                accountLabels: self.fetchAccountLabels()
            )
        }
    }

    /// accountId → resolved label map from the shared account list.
    private func fetchAccountLabels() -> [String: String] {
        Dictionary(uniqueKeysWithValues: fetchAccountInfos().map { ($0.id, $0.label) })
    }

    /// Re-register system credential identities from the stored index, without
    /// needing any vault key. Used after account add/remove/rename so labels and
    /// prefixes stay correct even for accounts that are currently locked.
    public func resyncCredentialIdentities() async {
        guard Self.isSystemCredentialIdentitySyncEnabled else { return }
        await SystemCredentialIdentitySyncer.shared.sync(
            allEntries: fetchStoredIndexEntries(),
            accountLabels: fetchAccountLabels()
        )
    }

    // MARK: - Fetch Credentials

    /// Read the credential index from the shared Keychain.
    ///
    /// Used by the AutoFill extension to populate credential suggestions.
    /// Returns an empty array if no data is stored or decoding fails.
    public func fetchCredentials() -> [SharedCredentialEntry] {
        do {
            guard let data = try loadFromSharedKeychain(
                service: Self.indexServiceName,
                account: Self.indexAccountName
            ) else {
                return temporaryCredentialEntries()
            }
            let stored = try JSONDecoder().decode([SharedCredentialEntry].self, from: data)
            return mergedWithTemporaryCredentialEntries(stored)
        } catch {
            logger.error("Failed to fetch credentials: \(error.localizedDescription, privacy: .public)")
            return temporaryCredentialEntries()
        }
    }

    // MARK: - Shared Account Info

    /// Publish the on-device account list for the extensions (picker + labels).
    public func storeAccountInfos(_ infos: [SharedAccountInfo]) {
        guard let data = try? JSONEncoder().encode(infos) else { return }
        do {
            try saveToSharedKeychain(
                data: data,
                service: Self.accountInfoServiceName,
                account: Self.accountInfoAccountName
            )
        } catch {
            logger.error("Failed to store account infos: \(error.localizedDescription, privacy: .public)")
        }
    }

    /// Read the on-device account list. Empty for pre-multi-account installs.
    public func fetchAccountInfos() -> [SharedAccountInfo] {
        guard let data = try? loadFromSharedKeychain(
            service: Self.accountInfoServiceName,
            account: Self.accountInfoAccountName
        ) else {
            return []
        }
        return (try? JSONDecoder().decode([SharedAccountInfo].self, from: data)) ?? []
    }

    private func clearAccountInfos() {
        deleteFromSharedKeychain(
            service: Self.accountInfoServiceName,
            account: Self.accountInfoAccountName
        )
    }

    // MARK: - Per-Account Cleanup

    /// Remove every shared item belonging to one account: its index entries,
    /// per-credential secrets, and its AutoFill vault key — then re-register
    /// the system credential identities from what remains.
    ///
    /// Legacy items without an account scope are removed as well; they belonged
    /// to the single pre-multi-account vault and are re-exported (scoped) on the
    /// owning account's next unlock.
    public func clearAccountData(accountId: String) {
        // 1. Drop this account's entries (and legacy unscoped ones) from the index.
        let remaining = fetchStoredIndexEntries().filter {
            $0.accountId != nil && $0.accountId != accountId
        }
        storeIndexEntries(remaining)

        // 2. Delete this account's per-credential secrets (and legacy unscoped items).
        for service in [
            Self.passwordServiceName,
            Self.totpServiceName,
            Self.passkeyServiceName,
            Self.certificateServiceName,
        ] {
            deleteSecretItems(service: service, accountId: accountId, includeLegacyUnscoped: true)
        }

        // 3. Delete this account's (and the legacy) AutoFill vault key.
        clearAutoFillVaultKey(accountId: accountId)
        clearAutoFillVaultKey(accountId: nil)

        // 4. Drop queued items that belong to this account.
        removePendingItems(forAccountId: accountId)

        // 5. Re-register system identities from the remaining entries.
        Task { await self.resyncCredentialIdentities() }

        logger.info("Cleared shared credential data for account \(accountId, privacy: .public)")
    }

    /// Read the raw stored index (no temporary-draft merging).
    private func fetchStoredIndexEntries() -> [SharedCredentialEntry] {
        guard let data = try? loadFromSharedKeychain(
            service: Self.indexServiceName,
            account: Self.indexAccountName
        ) else {
            return []
        }
        return (try? JSONDecoder().decode([SharedCredentialEntry].self, from: data)) ?? []
    }

    private func storeIndexEntries(_ entries: [SharedCredentialEntry]) {
        if entries.isEmpty {
            deleteFromSharedKeychain(service: Self.indexServiceName, account: Self.indexAccountName)
            return
        }
        guard let data = try? JSONEncoder().encode(entries) else { return }
        try? saveToSharedKeychain(
            data: data,
            service: Self.indexServiceName,
            account: Self.indexAccountName
        )
    }

    /// Delete per-credential secret items of one account by enumerating the
    /// service and matching the `"accountId:cipherId"` prefix (the Keychain has
    /// no prefix queries). Optionally removes legacy non-prefixed items too.
    ///
    /// - Parameter sparing: keychain `account` attributes to keep (the items a
    ///   running export just wrote).
    private func deleteSecretItems(
        service: String,
        accountId: String,
        includeLegacyUnscoped: Bool,
        sparing: Set<String> = []
    ) {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccessGroup as String: Self.keychainAccessGroup,
            kSecAttrSynchronizable as String: kSecAttrSynchronizableAny,
            kSecMatchLimit as String: kSecMatchLimitAll,
            kSecReturnAttributes as String: true,
            kSecUseDataProtectionKeychain as String: true,
        ]
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        guard status == errSecSuccess, let items = result as? [[String: Any]] else { return }

        for item in items {
            guard let account = item[kSecAttrAccount as String] as? String else { continue }
            guard !sparing.contains(account) else { continue }
            let isOwn = account.hasPrefix("\(accountId):")
            let isLegacy = includeLegacyUnscoped && !account.contains(":")
            if isOwn || isLegacy {
                deleteFromSharedKeychain(service: service, account: account)
            }
        }
    }

    /// Drop pending passkeys/credentials and temporary drafts queued for one account.
    private func removePendingItems(forAccountId accountId: String) {
        let passkeys = fetchPendingPasskeys().filter { $0.accountId != nil && $0.accountId != accountId }
        if passkeys.isEmpty {
            clearPendingPasskeys()
        } else if let data = try? JSONEncoder().encode(passkeys) {
            try? saveToSharedKeychain(
                data: data,
                service: Self.pendingPasskeysServiceName,
                account: Self.pendingPasskeysAccountName
            )
        }

        let credentials = fetchPendingCredentials().filter { $0.accountId != nil && $0.accountId != accountId }
        if credentials.isEmpty {
            clearPendingCredentials()
        } else if let data = try? JSONEncoder().encode(credentials) {
            try? saveToSharedKeychain(
                data: data,
                service: Self.pendingCredentialsServiceName,
                account: Self.pendingCredentialsAccountName
            )
        }

        let drafts = fetchTemporaryCredentialDrafts().filter { $0.accountId != nil && $0.accountId != accountId }
        if drafts.isEmpty {
            clearTemporaryCredentialDrafts()
        } else if let data = try? JSONEncoder().encode(drafts) {
            try? saveToSharedKeychain(
                data: data,
                service: Self.temporaryCredentialsServiceName,
                account: Self.temporaryCredentialsAccountName
            )
        }
    }

    // MARK: - Sync Dates Storage

    public func storeSyncDates(server: Date?, app: Date?) {
        let dates = SharedSyncDates(lastSyncWithServer: server, lastSyncWithApp: app)
        guard let data = try? JSONEncoder().encode(dates) else { return }
        do {
            try saveToSharedKeychain(
                data: data,
                service: Self.syncDatesServiceName,
                account: Self.syncDatesAccountName
            )
        } catch {
            logger.error("Failed to store sync dates: \(error.localizedDescription, privacy: .public)")
        }
    }

    public func fetchSyncDates() -> SharedSyncDates? {
        do {
            guard let data = try loadFromSharedKeychain(
                service: Self.syncDatesServiceName,
                account: Self.syncDatesAccountName
            ) else { return nil }
            return try JSONDecoder().decode(SharedSyncDates.self, from: data)
        } catch {
            logger.error("Failed to fetch sync dates: \(error.localizedDescription, privacy: .public)")
            return nil
        }
    }

    // MARK: - SSH Identity Cache

    /// Store public SSH identity metadata for background agents.
    ///
    /// This contains only public key blobs, comments, and cipher IDs. Private
    /// key material is still decrypted on demand after biometric authentication.
    public func storeSSHIdentities(_ identities: [SSHIdentity]) {
        let cached = identities.map {
            CachedSSHIdentity(
                publicKeyBlobBase64: $0.publicKeyBlob.base64EncodedString(),
                comment: $0.comment,
                cipherId: $0.cipherId
            )
        }
        guard let data = try? JSONEncoder().encode(cached) else { return }

        saveSSHIdentitiesToLocalCache(data)

        do {
            try saveToSharedKeychain(
                data: data,
                service: Self.sshIdentityCacheServiceName,
                account: Self.sshIdentityCacheAccountName
            )
        } catch {
            logger.error("Failed to store SSH identity cache: \(error.localizedDescription, privacy: .public)")
        }
    }

    public func fetchSSHIdentities() -> [SSHIdentity] {
        if let data = loadSSHIdentitiesFromLocalCache(),
           let identities = decodeSSHIdentities(from: data) {
            return identities
        }

        do {
            guard let data = try loadFromSharedKeychain(
                service: Self.sshIdentityCacheServiceName,
                account: Self.sshIdentityCacheAccountName
            ),
                  let identities = decodeSSHIdentities(from: data) else {
                return []
            }

            return identities
        } catch {
            logger.error("Failed to fetch SSH identity cache: \(error.localizedDescription, privacy: .public)")
            return []
        }
    }

    public func migrateLegacySSHIdentityCacheToFileIfNeeded() {
        if let data = try? loadFromSharedKeychain(
            service: Self.sshIdentityCacheServiceName,
            account: Self.sshIdentityCacheAccountName
        ) {
            saveSSHIdentitiesToLocalCache(data)
        }
    }

    public func clearSSHIdentityCache() {
        deleteSSHIdentitiesFromLocalCache()
        deleteFromSharedKeychain(
            service: Self.sshIdentityCacheServiceName,
            account: Self.sshIdentityCacheAccountName
        )
    }

    private var sshIdentityCacheURL: URL? {
        guard let applicationSupport = applicationSupportURL else { return nil }
        return applicationSupport
            .appendingPathComponent("VaultUI", isDirectory: true)
            .appendingPathComponent("ssh-identities.json", isDirectory: false)
    }

    private var applicationSupportURL: URL? {
        if isVaultCLIProcess, let containerSupportURL = containingAppApplicationSupportURL {
            return containerSupportURL
        }

        return FileManager.default.urls(
            for: .applicationSupportDirectory,
            in: .userDomainMask
        ).first
    }

    private var containingAppApplicationSupportURL: URL? {
        guard let libraryURL = FileManager.default.urls(
            for: .libraryDirectory,
            in: .userDomainMask
        ).first else {
            return nil
        }

        return libraryURL
            .appendingPathComponent("Containers", isDirectory: true)
            .appendingPathComponent(AppIdentifiers.bundleIdentifier, isDirectory: true)
            .appendingPathComponent("Data", isDirectory: true)
            .appendingPathComponent("Library", isDirectory: true)
            .appendingPathComponent("Application Support", isDirectory: true)
    }

    private var isVaultCLIProcess: Bool {
        let executableName = URL(fileURLWithPath: CommandLine.arguments.first ?? "")
            .lastPathComponent
        return executableName == "vaultui"
    }

    private func saveSSHIdentitiesToLocalCache(_ data: Data) {
        guard let url = sshIdentityCacheURL else { return }

        do {
            try FileManager.default.createDirectory(
                at: url.deletingLastPathComponent(),
                withIntermediateDirectories: true
            )
            try data.write(to: url, options: [.atomic, .completeFileProtectionUntilFirstUserAuthentication])
        } catch {
            logger.error("Failed to store local SSH identity cache: \(error.localizedDescription, privacy: .public)")
        }
    }

    private func loadSSHIdentitiesFromLocalCache() -> Data? {
        guard let url = sshIdentityCacheURL else { return nil }
        return try? Data(contentsOf: url)
    }

    private func deleteSSHIdentitiesFromLocalCache() {
        guard let url = sshIdentityCacheURL,
              FileManager.default.fileExists(atPath: url.path) else {
            return
        }

        try? FileManager.default.removeItem(at: url)
    }

    private func decodeSSHIdentities(from data: Data) -> [SSHIdentity]? {
        guard let cached = try? JSONDecoder().decode([CachedSSHIdentity].self, from: data) else {
            return nil
        }

        return cached.compactMap { identity in
            guard let publicKeyBlob = Data(base64Encoded: identity.publicKeyBlobBase64) else { return nil }
            return SSHIdentity(
                publicKeyBlob: publicKeyBlob,
                comment: identity.comment,
                cipherId: identity.cipherId
            )
        }
    }

    // MARK: - Vault Lock Marker

    /// Bump the cross-process vault-lock marker.
    ///
    /// The GUI app writes this when the vault locks; out-of-process agents (the
    /// SSH LaunchAgent) watch the value and drop cached key material when it
    /// changes, so cached private keys do not outlive the vault session.
    public func bumpVaultLockGeneration() {
        guard let url = vaultLockMarkerURL else { return }

        do {
            try FileManager.default.createDirectory(
                at: url.deletingLastPathComponent(),
                withIntermediateDirectories: true
            )
            try Data(UUID().uuidString.utf8).write(to: url, options: [.atomic])
        } catch {
            logger.error("Failed to write vault lock marker: \(error.localizedDescription, privacy: .public)")
        }
    }

    /// Current value of the vault-lock marker (nil if the vault has never locked).
    public func fetchVaultLockGeneration() -> String? {
        guard let url = vaultLockMarkerURL,
              let data = try? Data(contentsOf: url) else { return nil }
        return String(data: data, encoding: .utf8)
    }

    private var vaultLockMarkerURL: URL? {
        guard let applicationSupport = applicationSupportURL else { return nil }
        return applicationSupport
            .appendingPathComponent("VaultUI", isDirectory: true)
            .appendingPathComponent("vault-lock-marker", isDirectory: false)
    }

    // MARK: - Per-Credential Secret Keys

    /// Keychain `account` attribute for a per-credential secret item.
    ///
    /// Multi-account format is `"accountId:cipherId"`; `nil` accountId addresses
    /// legacy items written by pre-multi-account builds (bare cipher ID).
    private static func secretAccountAttr(id: String, accountId: String?) -> String {
        accountId.map { "\($0):\(id)" } ?? id
    }

    /// Load a sealed secret, falling back to the legacy un-scoped item so reads
    /// keep working across the one-time migration window after an app update.
    private func loadSecret(service: String, id: String, accountId: String?) throws -> Data? {
        if let data = try loadFromSharedKeychain(
            service: service,
            account: Self.secretAccountAttr(id: id, accountId: accountId)
        ) {
            return data
        }
        guard accountId != nil else { return nil }
        return try loadFromSharedKeychain(service: service, account: id)
    }

    // MARK: - Password Storage

    /// Store a password for a specific credential in the shared Keychain.
    ///
    /// Each password is stored as a separate Keychain item keyed by account +
    /// cipher ID. The main app writes these after decryption so the extension
    /// can retrieve them when the user selects a credential for autofill.
    public func storePassword(id: String, accountId: String?, password: String, key: SymmetricCryptoKey) {
        guard let plaintext = password.data(using: .utf8),
              let data = Self.sealForSharing(plaintext, key: key) else { return }
        do {
            try saveToSharedKeychain(
                data: data,
                service: Self.passwordServiceName,
                account: Self.secretAccountAttr(id: id, accountId: accountId)
            )
        } catch {
            logger.error("Failed to store password for \(id, privacy: .public): \(error.localizedDescription, privacy: .public)")
        }
    }

    /// Retrieve a password for a specific credential from the shared Keychain.
    ///
    /// - Parameters:
    ///   - id: The cipher ID
    ///   - accountId: The owning vault account (nil = legacy single-account item)
    ///   - key: The vault key obtained behind biometric/device authentication.
    /// - Returns: The decrypted password, or nil if not found
    public func fetchPassword(id: String, accountId: String?, key: SymmetricCryptoKey) -> String? {
        do {
            guard let data = try loadSecret(
                service: Self.passwordServiceName,
                id: id,
                accountId: accountId
            ) else {
                return nil
            }
            guard let plaintext = Self.openShared(data, key: key) else { return nil }
            return String(data: plaintext, encoding: .utf8)
        } catch {
            logger.error("Failed to fetch password for \(id, privacy: .public): \(error.localizedDescription, privacy: .public)")
            return nil
        }
    }

    // MARK: - TOTP Storage

    /// Store a TOTP secret for a specific credential in the shared Keychain (ciphertext).
    public func storeTotp(id: String, accountId: String?, totp: String, key: SymmetricCryptoKey) {
        guard let plaintext = totp.data(using: .utf8),
              let data = Self.sealForSharing(plaintext, key: key) else { return }
        do {
            try saveToSharedKeychain(
                data: data,
                service: Self.totpServiceName,
                account: Self.secretAccountAttr(id: id, accountId: accountId)
            )
        } catch {
            logger.error("Failed to store TOTP secret for \(id, privacy: .public): \(error.localizedDescription, privacy: .public)")
        }
    }

    /// Retrieve a TOTP secret for a specific credential from the shared Keychain.
    public func fetchTotp(id: String, accountId: String?, key: SymmetricCryptoKey) -> String? {
        do {
            guard let data = try loadSecret(
                service: Self.totpServiceName,
                id: id,
                accountId: accountId
            ) else {
                return nil
            }
            guard let plaintext = Self.openShared(data, key: key) else { return nil }
            return String(data: plaintext, encoding: .utf8)
        } catch {
            logger.error("Failed to fetch TOTP for \(id, privacy: .public): \(error.localizedDescription, privacy: .public)")
            return nil
        }
    }

    // MARK: - Certificate Storage

    /// Store certificate bytes for a specific credential in the shared Keychain (ciphertext).
    ///
    /// This is used by the Safari Web Extension to complete explicit certificate
    /// upload forms such as ELSTER's PFX login flow.
    public func storeCertificate(id: String, accountId: String?, certificate: SharedCertificateData, key: SymmetricCryptoKey) {
        guard let plaintext = try? JSONEncoder().encode(certificate),
              let data = Self.sealForSharing(plaintext, key: key) else { return }
        do {
            try saveToSharedKeychain(
                data: data,
                service: Self.certificateServiceName,
                account: Self.secretAccountAttr(id: id, accountId: accountId)
            )
        } catch {
            logger.error("Failed to store certificate for \(id, privacy: .public): \(error.localizedDescription, privacy: .public)")
        }
    }

    /// Retrieve certificate bytes for a specific credential from the shared Keychain.
    public func fetchCertificate(id: String, accountId: String?, key: SymmetricCryptoKey) -> SharedCertificateData? {
        do {
            guard let data = try loadSecret(
                service: Self.certificateServiceName,
                id: id,
                accountId: accountId
            ) else {
                return nil
            }
            guard let plaintext = Self.openShared(data, key: key) else { return nil }
            return try? JSONDecoder().decode(SharedCertificateData.self, from: plaintext)
        } catch {
            logger.error("Failed to fetch certificate for \(id, privacy: .public): \(error.localizedDescription, privacy: .public)")
            return nil
        }
    }

    // MARK: - Passkey Storage

    /// Store passkey data for a specific credential in the shared Keychain (ciphertext).
    public func storePasskeys(id: String, accountId: String?, passkeys: [SharedPasskeyData], key: SymmetricCryptoKey) {
        guard let plaintext = try? JSONEncoder().encode(passkeys),
              let data = Self.sealForSharing(plaintext, key: key) else { return }
        do {
            try saveToSharedKeychain(
                data: data,
                service: Self.passkeyServiceName,
                account: Self.secretAccountAttr(id: id, accountId: accountId)
            )
        } catch {
            logger.error("Failed to store passkeys for \(id, privacy: .public): \(error.localizedDescription, privacy: .public)")
        }
    }

    /// Retrieve passkey data for a specific credential from the shared Keychain.
    public func fetchPasskeys(id: String, accountId: String?, key: SymmetricCryptoKey) -> [SharedPasskeyData] {
        do {
            guard let data = try loadSecret(
                service: Self.passkeyServiceName,
                id: id,
                accountId: accountId
            ) else {
                return []
            }
            guard let plaintext = Self.openShared(data, key: key) else { return [] }
            return (try? JSONDecoder().decode([SharedPasskeyData].self, from: plaintext)) ?? []
        } catch {
            logger.error("Failed to fetch passkeys for \(id, privacy: .public): \(error.localizedDescription, privacy: .public)")
            return []
        }
    }

    // MARK: - At-rest secret encryption

    /// Encrypt a secret payload under the account vault key for storage in the shared
    /// Keychain. The result is a serialized EncString (ciphertext) and is useless
    /// without the vault key, which is itself gated behind Touch ID / device auth.
    private static func sealForSharing(_ plaintext: Data, key: SymmetricCryptoKey) -> Data? {
        do {
            let encrypted = try CipherEncryption.encrypt(data: plaintext, key: key)
            return encrypted.serialized().data(using: .utf8)
        } catch {
            logger.error("Failed to seal shared secret: \(error.localizedDescription, privacy: .public)")
            return nil
        }
    }

    /// Decrypt a secret payload previously sealed with `sealForSharing`.
    private static func openShared(_ data: Data, key: SymmetricCryptoKey) -> Data? {
        guard let serialized = String(data: data, encoding: .utf8) else { return nil }
        do {
            let encString = try EncString(serialized: serialized)
            return try CipherEncryption.decryptData(encString, key: key)
        } catch {
            logger.error("Failed to open shared secret: \(error.localizedDescription, privacy: .public)")
            return nil
        }
    }

    // MARK: - AutoFill Vault Key (biometric-gated)

    /// Store the account vault key in the shared Keychain behind a Secure Enclave
    /// `.userPresence` access control (Touch ID, with device-passcode fallback).
    ///
    /// This is the single key that decrypts every exported secret. Writing it does
    /// not require authentication; reading it does. It lives in the shared access
    /// group so the AutoFill and Safari extensions can use it, but only after the
    /// user authenticates — nothing can read it silently.
    /// Keychain `account` attribute for an account's AutoFill vault key.
    /// `nil` addresses the legacy single-account item.
    private static func autoFillVaultKeyAttr(accountId: String?) -> String {
        accountId.map { "\(autoFillVaultKeyAccountName)-\($0)" } ?? autoFillVaultKeyAccountName
    }

    public func storeAutoFillVaultKey(_ key: SymmetricCryptoKey, accountId: String?) {
        var accessError: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(
            nil,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            .userPresence,
            &accessError
        ) else {
            let msg = accessError?.takeRetainedValue().localizedDescription ?? "unknown"
            logger.error("Failed to create AutoFill vault key access control: \(msg, privacy: .public)")
            return
        }

        // Access-controlled items can't be updated in place; remove then add.
        deleteFromSharedKeychain(
            service: Self.autoFillVaultKeyServiceName,
            account: Self.autoFillVaultKeyAttr(accountId: accountId)
        )

        let addQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: Self.autoFillVaultKeyServiceName,
            kSecAttrAccount as String: Self.autoFillVaultKeyAttr(accountId: accountId),
            kSecAttrAccessGroup as String: Self.keychainAccessGroup,
            kSecValueData as String: key.keyData,
            kSecAttrAccessControl as String: access,
            kSecUseDataProtectionKeychain as String: true,
        ]
        let status = SecItemAdd(addQuery as CFDictionary, nil)
        if status != errSecSuccess {
            logger.error("Failed to store AutoFill vault key: OSStatus \(status, privacy: .public)")
        }
    }

    /// Retrieve an account's AutoFill vault key using a pre-authenticated `LAContext`.
    ///
    /// The caller must have already evaluated a device-owner authentication policy on
    /// the context (biometry or device passcode) so the `.userPresence` ACL is
    /// satisfied without a second prompt. Returns nil if absent or auth failed.
    /// A `nil` accountId — or a missing per-account item — falls back to the legacy
    /// single-account key so reads keep working right after an app update.
    public func retrieveAutoFillVaultKey(accountId: String?, context: LAContext) -> SymmetricCryptoKey? {
        if let key = retrieveAutoFillVaultKeyItem(
            account: Self.autoFillVaultKeyAttr(accountId: accountId),
            context: context
        ) {
            return key
        }
        guard accountId != nil else { return nil }
        return retrieveAutoFillVaultKeyItem(
            account: Self.autoFillVaultKeyAttr(accountId: nil),
            context: context
        )
    }

    private func retrieveAutoFillVaultKeyItem(account: String, context: LAContext) -> SymmetricCryptoKey? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: Self.autoFillVaultKeyServiceName,
            kSecAttrAccount as String: account,
            kSecAttrAccessGroup as String: Self.keychainAccessGroup,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
            kSecUseAuthenticationContext as String: context,
            kSecUseDataProtectionKeychain as String: true,
        ]
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        guard status == errSecSuccess, let data = result as? Data else {
            if status != errSecItemNotFound && status != errSecUserCanceled {
                logger.error("Failed to retrieve AutoFill vault key: OSStatus \(status, privacy: .public)")
            }
            return nil
        }
        return try? SymmetricCryptoKey(keyData: data)
    }

    /// Remove an account's biometric-gated AutoFill vault key (logout/removal).
    public func clearAutoFillVaultKey(accountId: String?) {
        deleteFromSharedKeychain(
            service: Self.autoFillVaultKeyServiceName,
            account: Self.autoFillVaultKeyAttr(accountId: accountId)
        )
    }

    // MARK: - Pending Passkeys

    /// Add a generated passkey to the pending queue to be saved by the main app.
    public func queuePendingPasskey(_ passkey: PendingPasskey) {
        var queue = fetchPendingPasskeys()
        if queue.contains(where: {
            $0.credentialId == passkey.credentialId
            || (
                $0.targetCipherId == passkey.targetCipherId
                && $0.targetCipherName == passkey.targetCipherName
                && $0.relyingPartyId == passkey.relyingPartyId
                && $0.userHandle == passkey.userHandle
                && $0.userName == passkey.userName
            )
        }) {
            return
        }

        queue.append(passkey)
        if let data = try? JSONEncoder().encode(queue) {
            try? saveToSharedKeychain(
                data: data,
                service: Self.pendingPasskeysServiceName,
                account: Self.pendingPasskeysAccountName
            )
        }
    }

    /// Read the queue of pending passkeys.
    public func fetchPendingPasskeys() -> [PendingPasskey] {
        guard let data = try? loadFromSharedKeychain(
            service: Self.pendingPasskeysServiceName,
            account: Self.pendingPasskeysAccountName
        ) else {
            return []
        }
        return (try? JSONDecoder().decode([PendingPasskey].self, from: data)) ?? []
    }

    /// Clear the pending passkey queue.
    public func clearPendingPasskeys() {
        deleteFromSharedKeychain(
            service: Self.pendingPasskeysServiceName,
            account: Self.pendingPasskeysAccountName
        )
    }

    /// Replace the pending passkey queue (e.g. keep only other accounts' items).
    public func replacePendingPasskeys(_ queue: [PendingPasskey]) {
        if queue.isEmpty {
            clearPendingPasskeys()
            return
        }
        if let data = try? JSONEncoder().encode(queue) {
            try? saveToSharedKeychain(
                data: data,
                service: Self.pendingPasskeysServiceName,
                account: Self.pendingPasskeysAccountName
            )
        }
    }

    // MARK: - Pending Credentials

    /// Add a captured login to the pending queue so the main app can encrypt it into the vault.
    public func queuePendingCredential(_ credential: PendingCredential) {
        var queue = fetchPendingCredentials()
        if queue.contains(where: {
            $0.url == credential.url
            && $0.username == credential.username
            && $0.password == credential.password
        }) {
            return
        }

        queue.append(credential)
        if let data = try? JSONEncoder().encode(queue) {
            try? saveToSharedKeychain(
                data: data,
                service: Self.pendingCredentialsServiceName,
                account: Self.pendingCredentialsAccountName
            )
        }
    }

    /// Read captured logins waiting to be saved by the main app.
    public func fetchPendingCredentials() -> [PendingCredential] {
        guard let data = try? loadFromSharedKeychain(
            service: Self.pendingCredentialsServiceName,
            account: Self.pendingCredentialsAccountName
        ) else {
            return []
        }
        return (try? JSONDecoder().decode([PendingCredential].self, from: data)) ?? []
    }

    /// Clear the pending credential queue.
    public func clearPendingCredentials() {
        deleteFromSharedKeychain(
            service: Self.pendingCredentialsServiceName,
            account: Self.pendingCredentialsAccountName
        )
    }

    /// Replace the pending credential queue (e.g. keep only other accounts' items).
    public func replacePendingCredentials(_ queue: [PendingCredential]) {
        if queue.isEmpty {
            clearPendingCredentials()
            return
        }
        if let data = try? JSONEncoder().encode(queue) {
            try? saveToSharedKeychain(
                data: data,
                service: Self.pendingCredentialsServiceName,
                account: Self.pendingCredentialsAccountName
            )
        }
    }

    // MARK: - Temporary Credential Drafts

    /// Add a browser-seeded temporary credential draft.
    public func queueTemporaryCredentialDraft(_ draft: TemporaryCredentialDraft, key: SymmetricCryptoKey) {
        var queue = fetchTemporaryCredentialDrafts()
        if let existingIndex = queue.firstIndex(where: {
            $0.id == draft.id
            || ($0.url == draft.url && $0.username == draft.username)
        }) {
            let existing = queue[existingIndex]
            let mergedPassword: String? = {
                if let password = draft.password, !password.isEmpty {
                    return password
                }
                return existing.password
            }()
            queue[existingIndex] = TemporaryCredentialDraft(
                id: existing.id,
                name: draft.name,
                username: draft.username,
                password: mergedPassword,
                url: draft.url,
                creationDate: existing.creationDate,
                accountId: draft.accountId ?? existing.accountId
            )
        } else {
            queue.append(draft)
        }

        if let password = draft.password, !password.isEmpty {
            storePassword(id: draft.id, accountId: draft.accountId, password: password, key: key)
        }
        if let data = try? JSONEncoder().encode(queue) {
            try? saveToSharedKeychain(
                data: data,
                service: Self.temporaryCredentialsServiceName,
                account: Self.temporaryCredentialsAccountName
            )
        }
    }

    /// Read browser-seeded temporary credential drafts.
    public func fetchTemporaryCredentialDrafts() -> [TemporaryCredentialDraft] {
        guard let data = try? loadFromSharedKeychain(
            service: Self.temporaryCredentialsServiceName,
            account: Self.temporaryCredentialsAccountName
        ) else {
            return []
        }
        return (try? JSONDecoder().decode([TemporaryCredentialDraft].self, from: data)) ?? []
    }

    /// Remove a temporary credential draft after it becomes permanent.
    public func removeTemporaryCredentialDraft(url: String, username: String) {
        let remaining = fetchTemporaryCredentialDrafts().filter {
            !($0.url == url && $0.username == username)
        }
        if remaining.isEmpty {
            clearTemporaryCredentialDrafts()
            return
        }
        if let data = try? JSONEncoder().encode(remaining) {
            try? saveToSharedKeychain(
                data: data,
                service: Self.temporaryCredentialsServiceName,
                account: Self.temporaryCredentialsAccountName
            )
        }
    }

    /// Clear the temporary credential draft queue.
    public func clearTemporaryCredentialDrafts() {
        deleteFromSharedKeychain(
            service: Self.temporaryCredentialsServiceName,
            account: Self.temporaryCredentialsAccountName
        )
    }

    /// Replace the temporary draft queue (e.g. keep only other accounts' drafts).
    public func replaceTemporaryCredentialDrafts(_ queue: [TemporaryCredentialDraft]) {
        if queue.isEmpty {
            clearTemporaryCredentialDrafts()
            return
        }
        if let data = try? JSONEncoder().encode(queue) {
            try? saveToSharedKeychain(
                data: data,
                service: Self.temporaryCredentialsServiceName,
                account: Self.temporaryCredentialsAccountName
            )
        }
    }

    /// Drop temporary drafts older than the provided cutoff.
    public func clearExpiredTemporaryCredentialDrafts(olderThan cutoff: Date) {
        let remaining = fetchTemporaryCredentialDrafts().filter { $0.creationDate >= cutoff }
        if remaining.isEmpty {
            clearTemporaryCredentialDrafts()
            return
        }
        if let data = try? JSONEncoder().encode(remaining) {
            try? saveToSharedKeychain(
                data: data,
                service: Self.temporaryCredentialsServiceName,
                account: Self.temporaryCredentialsAccountName
            )
        }
    }

    /// Removes any browser form context captured by older builds. Earlier versions
    /// eagerly persisted every typed username/password to the shared keychain; that
    /// path has been removed in favour of an explicit in-page save prompt, so this
    /// purges leftover plaintext on unlock and logout.
    public func purgeLegacyAutoFillFormContext() {
        deleteFromSharedKeychain(
            service: Self.autoFillFormContextServiceName,
            account: Self.autoFillFormContextAccountName
        )
    }

    public func storeAutoFillCredentialFillRequest(_ request: AutoFillCredentialFillRequest) {
        guard let data = try? JSONEncoder().encode(request) else { return }
        try? saveToSharedKeychain(
            data: data,
            service: Self.autoFillCredentialFillServiceName,
            account: Self.autoFillCredentialFillAccountName
        )
    }

    public func fetchRecentAutoFillCredentialFillRequest(maxAge: TimeInterval = 2 * 60) -> AutoFillCredentialFillRequest? {
        guard let data = try? loadFromSharedKeychain(
            service: Self.autoFillCredentialFillServiceName,
            account: Self.autoFillCredentialFillAccountName
        ),
              let request = try? JSONDecoder().decode(AutoFillCredentialFillRequest.self, from: data),
              Date().timeIntervalSince(request.createdAt) <= maxAge else {
            clearAutoFillCredentialFillRequest()
            return nil
        }
        return request
    }

    public func clearAutoFillCredentialFillRequest() {
        deleteFromSharedKeychain(
            service: Self.autoFillCredentialFillServiceName,
            account: Self.autoFillCredentialFillAccountName
        )
    }

    // MARK: - Clear All

    /// Remove all shared credential data from the Keychain.
    ///
    /// Called on logout or lock to ensure no stale credential data remains
    /// accessible to the AutoFill extension.
    public func clearAll() {
        // Delete the credential index
        deleteFromSharedKeychain(service: Self.indexServiceName, account: Self.indexAccountName)

        // Delete all individual passwords by wiping items with the password service name
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: Self.passwordServiceName,
            kSecAttrAccessGroup as String: Self.keychainAccessGroup,
            kSecAttrSynchronizable as String: kSecAttrSynchronizableAny,
            kSecUseDataProtectionKeychain as String: true,
        ]
        let status = SecItemDelete(query as CFDictionary)
        query.removeValue(forKey: kSecUseDataProtectionKeychain as String)
        SecItemDelete(query as CFDictionary)
        if status != errSecSuccess && status != errSecItemNotFound {
            logger.warning("Failed to clear all passwords: OSStatus \(status, privacy: .public)")
        }

        // Delete all individual TOTP secrets
        var totpQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: Self.totpServiceName,
            kSecAttrAccessGroup as String: Self.keychainAccessGroup,
            kSecAttrSynchronizable as String: kSecAttrSynchronizableAny,
            kSecUseDataProtectionKeychain as String: true,
        ]
        let totpStatus = SecItemDelete(totpQuery as CFDictionary)
        totpQuery.removeValue(forKey: kSecUseDataProtectionKeychain as String)
        SecItemDelete(totpQuery as CFDictionary)
        if totpStatus != errSecSuccess && totpStatus != errSecItemNotFound {
            logger.warning("Failed to clear all TOTP secrets: OSStatus \(totpStatus, privacy: .public)")
        }
        
        // Delete all per-credential passkey private keys
        deleteAllFromSharedKeychain(service: Self.passkeyServiceName, label: "passkeys")

        // Delete all per-credential certificate bundles (P12 bytes + password)
        deleteAllFromSharedKeychain(service: Self.certificateServiceName, label: "certificates")

        clearPendingPasskeys()
        clearPendingCredentials()
        clearTemporaryCredentialDrafts()
        clearSSHIdentityCache()
        purgeLegacyAutoFillFormContext()
        // Wipe every AutoFill vault key — the legacy item and all per-account ones.
        deleteAllFromSharedKeychain(service: Self.autoFillVaultKeyServiceName, label: "AutoFill vault keys")
        clearAccountInfos()
        clearAutoFillCredentialFillRequest()
        SystemCredentialIdentitySyncer.shared.clearCache()

        logger.info("Cleared all shared credential data")
    }

    /// Delete every shared-Keychain item that matches `service`, regardless of its `account`.
    ///
    /// Used by ``clearAll()`` to wipe per-credential items (passwords, TOTP secrets,
    /// passkey private keys, certificate bundles) that are keyed by cipher ID.
    private func deleteAllFromSharedKeychain(service: String, label: String) {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccessGroup as String: Self.keychainAccessGroup,
            kSecAttrSynchronizable as String: kSecAttrSynchronizableAny,
            kSecUseDataProtectionKeychain as String: true,
        ]
        let status = SecItemDelete(query as CFDictionary)
        query.removeValue(forKey: kSecUseDataProtectionKeychain as String)
        SecItemDelete(query as CFDictionary)
        if status != errSecSuccess && status != errSecItemNotFound {
            logger.warning("Failed to clear all \(label, privacy: .public): OSStatus \(status, privacy: .public)")
        }
    }

    // MARK: - Private Keychain Helpers

    private func mergedWithTemporaryCredentialEntries(_ entries: [SharedCredentialEntry]) -> [SharedCredentialEntry] {
        let existingIds = Set(entries.map(\.id))
        return entries + temporaryCredentialEntries().filter { !existingIds.contains($0.id) }
    }

    private func temporaryCredentialEntries() -> [SharedCredentialEntry] {
        fetchTemporaryCredentialDrafts().map {
            SharedCredentialEntry(
                id: $0.id,
                name: $0.name,
                username: $0.username,
                uris: [$0.url],
                type: CipherType.login.rawValue,
                isTemporary: true,
                accountId: $0.accountId
            )
        }
    }

    private static func decryptOptional(_ encString: EncString?, key: SymmetricCryptoKey) -> String? {
        guard let encString = encString else { return nil }
        return try? CipherEncryption.decryptString(encString, key: key)
    }

    // The low-level shared-keychain CRUD now lives in `SharedKeychain`. These
    // remain as the store's public surface (used internally and by IPCHelper)
    // and simply forward.
    public func saveToSharedKeychain(data: Data, service: String, account: String) throws {
        try SharedKeychain.save(data: data, service: service, account: account)
    }

    public func loadFromSharedKeychain(service: String, account: String) throws -> Data? {
        try SharedKeychain.load(service: service, account: account)
    }

    public func deleteFromSharedKeychain(service: String, account: String) {
        SharedKeychain.delete(service: service, account: account)
    }

    // MARK: - ASCredentialIdentityStore Sync

    /// Remove every identity Vault UI registered with the system credential store.
    /// The mirroring itself lives in `SystemCredentialIdentitySyncer`.
    public func removeAllSystemCredentialIdentities() async {
        await SystemCredentialIdentitySyncer.shared.removeAll()
    }
}

// `SharedCredentialError` now lives in SharedKeychain.swift.
// The ASCredentialIdentityStore mirroring lives in SystemCredentialIdentitySyncer.swift.
