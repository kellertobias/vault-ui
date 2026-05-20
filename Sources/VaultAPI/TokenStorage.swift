// MARK: - VaultAPI/TokenStorage.swift
// Secure token persistence using macOS Keychain

import Foundation
import Security
import VaultModels

/// Securely stores and retrieves authentication tokens in the macOS Keychain.
public final class TokenStorage: Sendable {

    private let serviceName = "com.vaultui.tokens"

    public init() {}

    /// Save tokens for an account.
    public func saveTokens(_ tokens: AuthTokens, for accountId: String) throws {
        let data = try JSONEncoder().encode(tokens)
        try saveToKeychain(data: data, account: accountId)
    }

    /// Load tokens for an account.
    public func loadTokens(for accountId: String) throws -> AuthTokens? {
        guard let data = try loadFromKeychain(account: accountId) else {
            return nil
        }
        return try JSONDecoder().decode(AuthTokens.self, from: data)
    }

    /// Delete tokens for an account.
    public func deleteTokens(for accountId: String) throws {
        try deleteFromKeychain(account: accountId)
    }

    // MARK: - Keychain Operations

    private func saveToKeychain(data: Data, account: String) throws {
        // Delete existing first
        try? deleteFromKeychain(account: account)

        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: serviceName,
            kSecAttrAccount as String: account,
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        ]

        let status = SecItemAdd(query as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw APIError.serverMessage("Failed to save to Keychain: \(status)")
        }
    }

    private func loadFromKeychain(account: String) throws -> Data? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: serviceName,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]

        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)

        switch status {
        case errSecSuccess:
            return item as? Data
        case errSecItemNotFound:
            return nil
        default:
            throw APIError.serverMessage("Failed to read from Keychain: \(status)")
        }
    }

    private func deleteFromKeychain(account: String) throws {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: serviceName,
            kSecAttrAccount as String: account,
        ]

        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw APIError.serverMessage("Failed to delete from Keychain: \(status)")
        }
    }
}
