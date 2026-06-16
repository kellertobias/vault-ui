// MARK: - VaultServices/SharedKeychain.swift
// Low-level CRUD for the app-group shared keychain.

import Foundation
import Security
import OSLog
import VaultModels

private let logger = Logger(subsystem: "com.vaultui", category: "SharedKeychain")

/// Low-level read/write/delete for the app-group shared keychain.
///
/// All items live in the data-protection keychain, scoped to the keychain
/// access group, and are accessible after first unlock. Extracted from
/// `SharedCredentialStore` so the credential store, the system-identity syncer,
/// and `IPCHelper` share a single, focused implementation instead of duplicating
/// `SecItem*` query construction.
enum SharedKeychain {

    /// Keychain access group for sharing between the app and its extensions.
    /// Must match the keychain-access-groups entitlement.
    static let accessGroup = AppIdentifiers.keychainAccessGroup

    /// Upsert a value: update in place if present, otherwise add.
    static func save(data: Data, service: String, account: String) throws {
        // `kSecAttrSynchronizableAny` ensures we find items regardless of how
        // they were originally stored (sync or non-sync).
        let searchQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecAttrAccessGroup as String: accessGroup,
            kSecAttrSynchronizable as String: kSecAttrSynchronizableAny,
            kSecUseDataProtectionKeychain as String: true,
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
                kSecAttrAccessGroup as String: accessGroup,
                kSecValueData as String: data,
                kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlock,
                kSecUseDataProtectionKeychain as String: true,
            ]
            status = SecItemAdd(addQuery as CFDictionary, nil)
        }

        guard status == errSecSuccess else {
            logger.error("Keychain write failed: service=\(service, privacy: .public) account=\(account, privacy: .public) OSStatus=\(status, privacy: .public)")
            throw SharedCredentialError.keychainWriteFailed(status)
        }
    }

    static func load(service: String, account: String) throws -> Data? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecAttrAccessGroup as String: accessGroup,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
            kSecAttrSynchronizable as String: kSecAttrSynchronizableAny,
            kSecUseDataProtectionKeychain as String: true,
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

    static func delete(service: String, account: String) {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecAttrAccessGroup as String: accessGroup,
            kSecAttrSynchronizable as String: kSecAttrSynchronizableAny,
            kSecUseDataProtectionKeychain as String: true,
        ]
        SecItemDelete(query as CFDictionary)
        query.removeValue(forKey: kSecUseDataProtectionKeychain as String)
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
