// MARK: - VaultServices/SharedCredentialStore.swift
// Shared credential data for the AutoFill Credential Provider extension

import Foundation
import Security
import VaultModels
import VaultCrypto
import VaultSync
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

    public var supportsTotp: Bool { hasTotp }
    public var supportsPasskey: Bool { hasPasskey ?? false }

    public init(id: String, name: String, username: String?, uris: [String], type: Int, hasTotp: Bool = false, hasPasskey: Bool? = false, order: Int? = nil) {
        self.id = id
        self.name = name
        self.username = username
        self.uris = uris
        self.type = type
        self.hasTotp = hasTotp
        self.hasPasskey = hasPasskey
        self.order = order
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
    /// Must include the full team identifier prefix as macOS does not
    /// auto-prepend it. This must match the keychain-access-groups entitlement.
    public static let keychainAccessGroup = "F55HNXZ7TD.de.tobisk.apps.vaultui.shared"

    /// Service name for the credential index keychain item.
    private static let indexServiceName = "de.tobisk.apps.vaultui.credentials"

    /// Account name for the credential index keychain item.
    private static let indexAccountName = "credential-index"

    /// Service name prefix for individual password keychain items.
    private static let passwordServiceName = "de.tobisk.apps.vaultui.password"

    /// Service name for TOTP secrets in the shared Keychain.
    private static let totpServiceName = "de.tobisk.apps.vaultui.totp"
    /// Service name for passkeys in the shared Keychain.
    private static let passkeyServiceName = "de.tobisk.apps.vaultui.passkey"
    
    /// Service name for pending passkey queue.
    private static let pendingPasskeysServiceName = "de.tobisk.apps.vaultui.pendingPasskeys"
    private static let pendingPasskeysAccountName = "pending-passkeys-queue"
    private static let pendingCredentialsServiceName = "de.tobisk.apps.vaultui.pendingCredentials"
    private static let pendingCredentialsAccountName = "pending-credentials-queue"
    private static let temporaryCredentialsServiceName = "de.tobisk.apps.vaultui.temporaryCredentials"
    private static let temporaryCredentialsAccountName = "temporary-credentials-queue"

    private static let syncDatesServiceName = "de.tobisk.apps.vaultui.syncDates"
    private static let syncDatesAccountName = "sync-dates"

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
        let serverSyncDate = engine.lastSyncDate

        // Cancel any pending export to debounce rapid calls
        Self.pendingExportTask?.cancel()
        
        Self.pendingExportTask = Task.detached { [weak self] in
            // Wait briefly so rapid-fire calls collapse into one
            try? await Task.sleep(nanoseconds: 500_000_000) // 0.5s
            guard !Task.isCancelled, let self = self else { return }
            self.performExport(container: container, accountId: accountId, vaultKey: vaultKey, serverSyncDate: serverSyncDate)
        }
    }

    private func performExport(container: ModelContainer, accountId: String, vaultKey: SymmetricCryptoKey, serverSyncDate: Date?) {
        do {
            let context = ModelContext(container)
            let descriptor = FetchDescriptor<PersistedCipher>(predicate: #Predicate {
                $0.accountId == accountId && $0.deletedDate == nil
            })
            guard let persistedCiphers = try? context.fetch(descriptor) else { return }

            var entries: [SharedCredentialEntry] = []

            for persisted in persistedCiphers {
                guard let cipherType = persisted.cipherType,
                      cipherType == .login || cipherType == .identity,
                      persisted.syncStatus != .temporaryDraft else {
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
                            }
                        }
                        if !passkeys.isEmpty {
                            self.storePasskeys(id: persisted.id, passkeys: passkeys)
                        }
                    }

                case .identity:
                    username = Self.decryptOptional(cipher.identity?.username, key: decryptionKey)
                        ?? Self.decryptOptional(cipher.identity?.email, key: decryptionKey)

                default:
                    continue
                }

                let hasTotp = totpSecret != nil && !totpSecret!.isEmpty

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
                }

                let entry = SharedCredentialEntry(
                    id: persisted.id,
                    name: name,
                    username: username,
                    uris: uris,
                    type: cipherType.rawValue,
                    hasTotp: hasTotp,
                    hasPasskey: hasPasskey,
                    order: orderValue
                )
                entries.append(entry)

                if let password = password, !password.isEmpty {
                    self.storePassword(id: persisted.id, password: password)
                }

                if let totpSecret = totpSecret, !totpSecret.isEmpty {
                    self.storeTotp(id: persisted.id, totp: totpSecret)
                }
            }

            let data = try JSONEncoder().encode(entries)
            try self.saveToSharedKeychain(
                data: data,
                service: Self.indexServiceName,
                account: Self.indexAccountName
            )
            
            // We fetch the server sync date directly from the engine
            self.storeSyncDates(server: serverSyncDate, app: Date())

            logger.info("Exported \(entries.count) credentials to shared Keychain")
            self.syncCredentialIdentities(entries: entries)
        } catch {
            logger.error("Failed to export credentials: \(error.localizedDescription, privacy: .public)")
        }
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
                return []
            }
            return try JSONDecoder().decode([SharedCredentialEntry].self, from: data)
        } catch {
            logger.error("Failed to fetch credentials: \(error.localizedDescription, privacy: .public)")
            return []
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

    // MARK: - Password Storage

    /// Store a password for a specific credential in the shared Keychain.
    ///
    /// Each password is stored as a separate Keychain item keyed by cipher ID.
    /// The main app writes these after decryption so the extension can retrieve
    /// them when the user selects a credential for autofill.
    ///
    /// - Parameters:
    ///   - id: The cipher ID
    ///   - password: The decrypted password
    public func storePassword(id: String, password: String) {
        guard let data = password.data(using: .utf8) else { return }
        do {
            try saveToSharedKeychain(
                data: data,
                service: Self.passwordServiceName,
                account: id
            )
        } catch {
            logger.error("Failed to store password for \(id, privacy: .public): \(error.localizedDescription, privacy: .public)")
        }
    }

    /// Retrieve a password for a specific credential from the shared Keychain.
    ///
    /// - Parameter id: The cipher ID
    /// - Returns: The decrypted password, or nil if not found
    public func fetchPassword(id: String) -> String? {
        do {
            guard let data = try loadFromSharedKeychain(
                service: Self.passwordServiceName,
                account: id
            ) else {
                return nil
            }
            return String(data: data, encoding: .utf8)
        } catch {
            logger.error("Failed to fetch password for \(id, privacy: .public): \(error.localizedDescription, privacy: .public)")
            return nil
        }
    }

    // MARK: - TOTP Storage

    /// Store a TOTP secret for a specific credential in the shared Keychain.
    ///
    /// - Parameters:
    ///   - id: The cipher ID
    ///   - totp: The decrypted TOTP secret/URI
    public func storeTotp(id: String, totp: String) {
        guard let data = totp.data(using: .utf8) else { return }
        do {
            try saveToSharedKeychain(
                data: data,
                service: Self.totpServiceName,
                account: id
            )
        } catch {
            logger.error("Failed to store TOTP secret for \(id, privacy: .public): \(error.localizedDescription, privacy: .public)")
        }
    }

    /// Retrieve a TOTP secret for a specific credential from the shared Keychain.
    ///
    /// - Parameter id: The cipher ID
    /// - Returns: The decrypted TOTP secret/URI, or nil if not found
    public func fetchTotp(id: String) -> String? {
        do {
            guard let data = try loadFromSharedKeychain(
                service: Self.totpServiceName,
                account: id
            ) else {
                return nil
            }
            return String(data: data, encoding: .utf8)
        } catch {
            logger.error("Failed to fetch TOTP for \(id, privacy: .public): \(error.localizedDescription, privacy: .public)")
            return nil
        }
    }
    
    // MARK: - Passkey Storage
    
    /// Store passkey data for a specific credential in the shared Keychain.
    ///
    /// - Parameters:
    ///   - id: The cipher ID
    ///   - passkeys: List of decrypted passkeys
    public func storePasskeys(id: String, passkeys: [SharedPasskeyData]) {
        guard let data = try? JSONEncoder().encode(passkeys) else { return }
        do {
            try saveToSharedKeychain(
                data: data,
                service: Self.passkeyServiceName,
                account: id
            )
        } catch {
            logger.error("Failed to store passkeys for \(id, privacy: .public): \(error.localizedDescription, privacy: .public)")
        }
    }
    
    /// Retrieve passkey data for a specific credential from the shared Keychain.
    ///
    /// - Parameter id: The cipher ID
    /// - Returns: The decrypted passkeys, or empty array if not found
    public func fetchPasskeys(id: String) -> [SharedPasskeyData] {
        do {
            guard let data = try loadFromSharedKeychain(
                service: Self.passkeyServiceName,
                account: id
            ) else {
                return []
            }
            return (try? JSONDecoder().decode([SharedPasskeyData].self, from: data)) ?? []
        } catch {
            logger.error("Failed to fetch passkeys for \(id, privacy: .public): \(error.localizedDescription, privacy: .public)")
            return []
        }
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

    // MARK: - Temporary Credential Drafts

    /// Add a browser-seeded temporary credential draft.
    public func queueTemporaryCredentialDraft(_ draft: TemporaryCredentialDraft) {
        var queue = fetchTemporaryCredentialDrafts()
        if queue.contains(where: {
            $0.url == draft.url
            && $0.username == draft.username
        }) {
            return
        }

        queue.append(draft)
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

    // MARK: - Clear All

    /// Remove all shared credential data from the Keychain.
    ///
    /// Called on logout or lock to ensure no stale credential data remains
    /// accessible to the AutoFill extension.
    public func clearAll() {
        // Delete the credential index
        deleteFromSharedKeychain(service: Self.indexServiceName, account: Self.indexAccountName)

        // Delete all individual passwords by wiping items with the password service name
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: Self.passwordServiceName,
            kSecAttrAccessGroup as String: Self.keychainAccessGroup,
            kSecAttrSynchronizable as String: kSecAttrSynchronizableAny,
        ]
        let status = SecItemDelete(query as CFDictionary)
        if status != errSecSuccess && status != errSecItemNotFound {
            logger.warning("Failed to clear all passwords: OSStatus \(status, privacy: .public)")
        }

        // Delete all individual TOTP secrets
        let totpQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: Self.totpServiceName,
            kSecAttrAccessGroup as String: Self.keychainAccessGroup,
            kSecAttrSynchronizable as String: kSecAttrSynchronizableAny,
        ]
        let totpStatus = SecItemDelete(totpQuery as CFDictionary)
        if totpStatus != errSecSuccess && totpStatus != errSecItemNotFound {
            logger.warning("Failed to clear all TOTP secrets: OSStatus \(totpStatus, privacy: .public)")
        }
        
        clearPendingPasskeys()
        clearPendingCredentials()
        clearTemporaryCredentialDrafts()

        logger.info("Cleared all shared credential data")
    }

    // MARK: - Private Keychain Helpers

    private static func decryptOptional(_ encString: EncString?, key: SymmetricCryptoKey) -> String? {
        guard let encString = encString else { return nil }
        return try? CipherEncryption.decryptString(encString, key: key)
    }

    public func saveToSharedKeychain(data: Data, service: String, account: String) throws {
        // Use upsert pattern: try update first, then add if not found.
        // kSecAttrSynchronizableAny ensures we find items regardless of
        // how they were originally stored (sync or non-sync).
        let searchQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecAttrAccessGroup as String: Self.keychainAccessGroup,
            kSecAttrSynchronizable as String: kSecAttrSynchronizableAny,
        ]

        let updateAttributes: [String: Any] = [
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlock,
        ]

        var status = SecItemUpdate(searchQuery as CFDictionary, updateAttributes as CFDictionary)

        if status == errSecItemNotFound {
            // Item doesn't exist yet — add it (without kSecAttrSynchronizable
            // so it's created as non-synchronizable by default)
            let addQuery: [String: Any] = [
                kSecClass as String: kSecClassGenericPassword,
                kSecAttrService as String: service,
                kSecAttrAccount as String: account,
                kSecAttrAccessGroup as String: Self.keychainAccessGroup,
                kSecValueData as String: data,
                kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlock,
            ]
            status = SecItemAdd(addQuery as CFDictionary, nil)
        }

        guard status == errSecSuccess else {
            logger.error("Keychain write failed: service=\(service, privacy: .public) account=\(account, privacy: .public) OSStatus=\(status, privacy: .public)")
            throw SharedCredentialError.keychainWriteFailed(status)
        }
    }

    public func loadFromSharedKeychain(service: String, account: String) throws -> Data? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecAttrAccessGroup as String: Self.keychainAccessGroup,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
            kSecAttrSynchronizable as String: kSecAttrSynchronizableAny,
        ]

        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)

        if status == errSecItemNotFound {
            return nil
        }

        guard status == errSecSuccess, let data = result as? Data else {
            throw SharedCredentialError.keychainReadFailed(status)
        }

        return data
    }

    public func deleteFromSharedKeychain(service: String, account: String) {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecAttrAccessGroup as String: Self.keychainAccessGroup,
            kSecAttrSynchronizable as String: kSecAttrSynchronizableAny,
        ]
        SecItemDelete(query as CFDictionary)
    }

    // MARK: - ASCredentialIdentityStore Sync

    private func syncCredentialIdentities(entries: [SharedCredentialEntry]) {
        guard #available(macOS 11.0, *) else { return }

        var passwordIdentities: [ASPasswordCredentialIdentity] = []
        var totpIdentities: [Any] = []
        var passkeyIdentities: [Any] = []

        for entry in entries {
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

            let userToRegister = (entry.username?.isEmpty == false) ? entry.username! : entry.name

            for serviceId in identifiers {
                let uniqueRecordId = "\(entry.id)|\(serviceId.identifier)"
                let identity = ASPasswordCredentialIdentity(
                    serviceIdentifier: serviceId,
                    user: userToRegister,
                    recordIdentifier: uniqueRecordId
                )
                // Experiment: Give nas.tokenet.de a much higher rank
                if serviceId.identifier.contains("nas.tokenet.de") {
                    identity.rank = 10
                } else {
                    identity.rank = 1
                }
                passwordIdentities.append(identity)
                let typeStr = serviceId.type == .URL ? "URL" : "domain"
                logger.info("Registering identity: '\(entry.name, privacy: .public)' user='\(userToRegister, privacy: .public)' identifier='\(serviceId.identifier, privacy: .public)' type=\(typeStr, privacy: .public) rank=\(identity.rank, privacy: .public)")

                if #available(macOS 14.0, *) {
                    if entry.hasTotp == true {
                        let totpIdentity = ASOneTimeCodeCredentialIdentity(
                            serviceIdentifier: serviceId,
                            label: entry.name,
                            recordIdentifier: uniqueRecordId
                        )
                        totpIdentities.append(totpIdentity)
                    }
                }
            }
            
            if #available(macOS 14.0, *) {
                if entry.hasPasskey == true {
                    let passkeys = self.fetchPasskeys(id: entry.id)
                    for passkey in passkeys {
                        guard let credId = Data(base64URLDecoded: passkey.credentialId) else { continue }
                        let userHandle = Data(base64URLDecoded: passkey.userHandle) ?? Data()
                        
                        let uniqueRecordId = "\(entry.id)|\(passkey.relyingPartyId)"
                        let pkIdentity = ASPasskeyCredentialIdentity(
                            relyingPartyIdentifier: passkey.relyingPartyId,
                            userName: userToRegister,
                            credentialID: credId,
                            userHandle: userHandle,
                            recordIdentifier: uniqueRecordId
                        )
                        passkeyIdentities.append(pkIdentity)
                    }
                }
            }
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
            ASCredentialIdentityStore.shared.replaceCredentialIdentities(allIdentities) { success, error in
                if let error = error {
                    logger.error("Failed to replace identities in ASCredentialIdentityStore: \(error.localizedDescription, privacy: .public)")
                } else {
                    logger.info("Replaced ASCredentialIdentityStore with \(allCount) identities")
                }
            }
        } else {
            // macOS 11 - 13 fallback: remove then save
            ASCredentialIdentityStore.shared.removeAllCredentialIdentities { [weak self] _, _ in
                guard self != nil else { return }
                let pwCount = passwordIdentities.count
                ASCredentialIdentityStore.shared.saveCredentialIdentities(passwordIdentities) { _, error in
                    if let error = error {
                        logger.error("Failed to save identities to ASCredentialIdentityStore: \(error.localizedDescription, privacy: .public)")
                    } else {
                        logger.info("Saved \(pwCount) password identities to ASCredentialIdentityStore")
                    }
                }
            }
        }
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

// MARK: - Errors

public enum SharedCredentialError: Error, LocalizedError, Sendable {
    case keychainWriteFailed(OSStatus)
    case keychainReadFailed(OSStatus)

    public var errorDescription: String? {
        switch self {
        case .keychainWriteFailed(let status):
            return "Failed to write to shared Keychain: OSStatus \(status)"
        case .keychainReadFailed(let status):
            return "Failed to read from shared Keychain: OSStatus \(status)"
        }
    }
}
