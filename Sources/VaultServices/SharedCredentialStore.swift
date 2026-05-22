// MARK: - VaultServices/SharedCredentialStore.swift
// Shared credential data for the AutoFill Credential Provider extension

import Foundation
import Security
import VaultModels
import VaultCrypto
import VaultSync
import OSLog

private let logger = Logger(subsystem: "com.vaultui", category: "SharedCredentialStore")

// MARK: - SharedCredentialEntry

/// A lightweight, decrypted credential entry for AutoFill suggestions.
///
/// Stored as a JSON array in the shared Keychain so the AutoFill extension
/// can display credential suggestions without needing the vault key.
/// Passwords are intentionally omitted — they are stored separately and
/// fetched only when the user selects a credential.
public struct SharedCredentialEntry: Codable, Sendable, Equatable {
    /// Server-assigned cipher ID
    public let id: String
    /// Decrypted display name
    public let name: String
    /// Decrypted username (login) or email/username (identity)
    public let username: String?
    /// Decrypted URIs for domain matching
    public let uris: [String]
    /// CipherType raw value (1 = login, 4 = identity, etc.)
    public let type: Int
    /// Whether this credential has a TOTP secret
    public let hasTotp: Bool?
    /// Whether this credential has a FIDO2 passkey
    public let hasPasskey: Bool?

    public var supportsTotp: Bool { hasTotp ?? false }
    public var supportsPasskey: Bool { hasPasskey ?? false }

    public init(id: String, name: String, username: String?, uris: [String], type: Int, hasTotp: Bool? = false, hasPasskey: Bool? = false) {
        self.id = id
        self.name = name
        self.username = username
        self.uris = uris
        self.type = type
        self.hasTotp = hasTotp
        self.hasPasskey = hasPasskey
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
    /// The system automatically prepends the team identifier (AppIdentifierPrefix)
    /// at runtime, e.g. `F55HNXZ7TD.de.tobisk.apps.vaultui.shared`.
    static let keychainAccessGroup = "de.tobisk.apps.vaultui.shared"

    /// Service name for the credential index keychain item.
    private static let indexServiceName = "de.tobisk.apps.vaultui.credentials"

    /// Account name for the credential index keychain item.
    private static let indexAccountName = "credential-index"

    /// Service name prefix for individual password keychain items.
    private static let passwordServiceName = "de.tobisk.apps.vaultui.password"

    /// Service name prefix for individual TOTP secret keychain items.
    private static let totpServiceName = "de.tobisk.apps.vaultui.totp"

    public init() {}

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
            let persistedCiphers = try engine.fetchCiphers(includeDeleted: false)

            var entries: [SharedCredentialEntry] = []

            for persisted in persistedCiphers {
                guard let cipherType = persisted.cipherType,
                      cipherType == .login || cipherType == .identity else {
                    continue
                }

                let cipher: Cipher
                do {
                    cipher = try persisted.toCipher()
                } catch {
                    logger.warning("Failed to decode cipher \(persisted.id): \(error.localizedDescription)")
                    continue
                }

                // Resolve the decryption key (item key or vault key)
                let decryptionKey: SymmetricCryptoKey
                if let itemKeyEnc = cipher.key,
                   let itemKeyData = try? CipherEncryption.decryptData(itemKeyEnc, key: vaultKey),
                   let itemKey = try? SymmetricCryptoKey(keyData: itemKeyData) {
                    decryptionKey = itemKey
                } else {
                    decryptionKey = vaultKey
                }

                // Decrypt name
                guard let name = Self.decryptOptional(cipher.name, key: decryptionKey) else {
                    continue  // Skip ciphers with no decryptable name
                }

                // Decrypt username and URIs based on type
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

                case .identity:
                    // Use identity username or email as the "username"
                    username = Self.decryptOptional(cipher.identity?.username, key: decryptionKey)
                        ?? Self.decryptOptional(cipher.identity?.email, key: decryptionKey)

                default:
                    continue
                }

                let hasTotp = totpSecret != nil && !totpSecret!.isEmpty

                let entry = SharedCredentialEntry(
                    id: persisted.id,
                    name: name,
                    username: username,
                    uris: uris,
                    type: cipherType.rawValue,
                    hasTotp: hasTotp,
                    hasPasskey: hasPasskey
                )
                entries.append(entry)

                // Store the decrypted password for this credential
                if let password = password, !password.isEmpty {
                    storePassword(id: persisted.id, password: password)
                }

                // Store the decrypted TOTP secret for this credential
                if let totpSecret = totpSecret, !totpSecret.isEmpty {
                    storeTotp(id: persisted.id, totp: totpSecret)
                }
            }

            // Serialize and store
            let data = try JSONEncoder().encode(entries)
            try saveToSharedKeychain(
                data: data,
                service: Self.indexServiceName,
                account: Self.indexAccountName
            )

            logger.info("Exported \(entries.count) credentials to shared Keychain")
        } catch {
            logger.error("Failed to export credentials: \(error.localizedDescription)")
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
            logger.error("Failed to fetch credentials: \(error.localizedDescription)")
            return []
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
            logger.error("Failed to store password for \(id): \(error.localizedDescription)")
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
            logger.error("Failed to fetch password for \(id): \(error.localizedDescription)")
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
            logger.error("Failed to store TOTP secret for \(id): \(error.localizedDescription)")
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
            logger.error("Failed to fetch TOTP secret for \(id): \(error.localizedDescription)")
            return nil
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
            logger.warning("Failed to clear all passwords: OSStatus \(status)")
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
            logger.warning("Failed to clear all TOTP secrets: OSStatus \(totpStatus)")
        }

        logger.info("Cleared all shared credential data")
    }

    // MARK: - Private Keychain Helpers

    private static func decryptOptional(_ encString: EncString?, key: SymmetricCryptoKey) -> String? {
        guard let encString = encString else { return nil }
        return try? CipherEncryption.decryptString(encString, key: key)
    }

    private func saveToSharedKeychain(data: Data, service: String, account: String) throws {
        // Delete existing item first
        deleteFromSharedKeychain(service: service, account: account)

        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecAttrAccessGroup as String: Self.keychainAccessGroup,
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlock,
        ]

        let status = SecItemAdd(query as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw SharedCredentialError.keychainWriteFailed(status)
        }
    }

    private func loadFromSharedKeychain(service: String, account: String) throws -> Data? {
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

    private func deleteFromSharedKeychain(service: String, account: String) {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecAttrAccessGroup as String: Self.keychainAccessGroup,
            kSecAttrSynchronizable as String: kSecAttrSynchronizableAny,
        ]
        SecItemDelete(query as CFDictionary)
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
