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
        // First delete any existing token for this account
        try? deleteFromKeychain(account: account)
        
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: account,
            kSecAttrService as String: serviceName,
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlock
        ]
        
        let status = SecItemAdd(query as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw APIError.serverMessage("Failed to save to Keychain: \(status)")
        }
    }
    
    private func loadFromKeychain(account: String) throws -> Data? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: account,
            kSecAttrService as String: serviceName,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        
        var dataTypeRef: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &dataTypeRef)
        
        if status == errSecItemNotFound {
            return nil
        }
        
        guard status == errSecSuccess, let data = dataTypeRef as? Data else {
            throw APIError.serverMessage("Failed to read from Keychain: \(status)")
        }
        
        return data
    }
    
    private func deleteFromKeychain(account: String) throws {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: account,
            kSecAttrService as String: serviceName
        ]

        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw APIError.serverMessage("Failed to delete from Keychain: \(status)")
        }
    }
}
