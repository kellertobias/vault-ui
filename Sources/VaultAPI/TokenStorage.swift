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

    // MARK: - Two-Factor Remember Token

    private let rememberServiceName = "com.vaultui.2fa-remember"

    /// Save the 2FA remember token for an account.
    public func saveRememberToken(_ token: String, for accountId: String) throws {
        guard let data = token.data(using: .utf8) else { return }

        // Delete existing
        let deleteQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: accountId,
            kSecAttrService as String: rememberServiceName,
            kSecUseDataProtectionKeychain as String: true,
        ]
        SecItemDelete(deleteQuery as CFDictionary)

        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: accountId,
            kSecAttrService as String: rememberServiceName,
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            kSecUseDataProtectionKeychain as String: true,
        ]
        let status = SecItemAdd(query as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw APIError.serverMessage("Failed to save remember token: \(status)")
        }
    }

    /// Load the 2FA remember token for an account.
    public func loadRememberToken(for accountId: String) -> String? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: accountId,
            kSecAttrService as String: rememberServiceName,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
            kSecUseDataProtectionKeychain as String: true,
        ]
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        guard status == errSecSuccess, let data = item as? Data else { return nil }
        return String(data: data, encoding: .utf8)
    }

    /// Delete the 2FA remember token for an account.
    public func deleteRememberToken(for accountId: String) {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: accountId,
            kSecAttrService as String: rememberServiceName,
            kSecUseDataProtectionKeychain as String: true,
        ]
        SecItemDelete(query as CFDictionary)
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
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            kSecUseDataProtectionKeychain as String: true,
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
            kSecMatchLimit as String: kSecMatchLimitOne,
            kSecUseDataProtectionKeychain as String: true,
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
            kSecAttrService as String: serviceName,
            kSecUseDataProtectionKeychain as String: true,
        ]

        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw APIError.serverMessage("Failed to delete from Keychain: \(status)")
        }
    }
}
