// MARK: - VaultServices/BiometricKeyStorage.swift
// Secure vault key storage with local user-presence protection

import Foundation
import Security
import LocalAuthentication
import VaultCrypto
import OSLog

private let logger = Logger(subsystem: "com.vaultui", category: "BiometricKeyStorage")

/// Stores vault key material in the Keychain protected by local authentication.
///
/// Keys are stored with `kSecAccessControlUserPresence`, which means:
/// - Touch ID is used when available
/// - Device credentials can be used when Touch ID is unavailable
/// - The item is not included in backups or iCloud Keychain
public final class BiometricKeyStorage: Sendable {

    private let serviceName = "com.vaultui.biometric"

    public init() {}

    // MARK: - Store

    /// Store vault key and optional private key with local authentication protection.
    ///
    /// Called after a successful password-based login to enable future
    /// local-auth unlocks without re-entering the master password.
    public func storeKeys(
        vaultKey: SymmetricCryptoKey,
        privateKey: Data?,
        for accountId: String
    ) throws {
        var error: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(
            nil,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            .userPresence,
            &error
        ) else {
            let msg = error?.takeRetainedValue().localizedDescription ?? "unknown"
            logger.error("Failed to create biometric access control: \(msg)")
            throw BiometricError.accessControlCreationFailed(msg)
        }

        // Build a combined blob: [4-byte vaultKey length][vaultKey][privateKey]
        var blob = Data()
        var keyLen = UInt32(vaultKey.keyData.count).bigEndian
        blob.append(Data(bytes: &keyLen, count: 4))
        blob.append(vaultKey.keyData)
        if let pk = privateKey {
            blob.append(pk)
        }

        try storeData(blob, account: accountId, accessControl: access)
        logger.info("Successfully stored vault keys with user-presence protection for \(accountId)")
    }

    // MARK: - Retrieve

    /// Retrieve vault key using a pre-authenticated LAContext.
    ///
    /// The caller should have already evaluated device-owner authentication on
    /// the context to avoid a double authentication prompt.
    public func retrieveKeys(
        for accountId: String,
        context: LAContext
    ) throws -> (vaultKey: SymmetricCryptoKey, privateKey: Data?) {
        let blob = try retrieveData(account: accountId, context: context)

        guard blob.count >= 4 else {
            throw BiometricError.keychainError("Stored key blob too short")
        }

        let keyLen = Int(blob.withUnsafeBytes { $0.load(as: UInt32.self).bigEndian })
        guard blob.count >= 4 + keyLen else {
            throw BiometricError.keychainError("Stored key blob truncated")
        }

        let vaultKeyData = blob.subdata(in: 4 ..< (4 + keyLen))
        let vaultKey = try SymmetricCryptoKey(keyData: vaultKeyData)

        let privateKey: Data? = blob.count > 4 + keyLen
            ? blob.subdata(in: (4 + keyLen) ..< blob.count)
            : nil

        return (vaultKey, privateKey)
    }

    // MARK: - Query

    /// Check whether locally protected keys exist for the given account.
    ///
    /// This does NOT trigger an authentication prompt.
    public func hasStoredKeys(for accountId: String) -> Bool {
        let context = LAContext()
        context.interactionNotAllowed = true
        
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: serviceName,
            kSecAttrAccount as String: accountId,
            kSecUseAuthenticationContext as String: context,
            kSecReturnAttributes as String: true,
            kSecUseDataProtectionKeychain as String: true
        ]
        let status = SecItemCopyMatching(query as CFDictionary, nil)
        // errSecInteractionNotAllowed means the item exists but needs auth
        let found = status == errSecInteractionNotAllowed || status == errSecSuccess
        logger.info("hasStoredKeys(\(accountId)): \(found) (OSStatus=\(status))")
        return found
    }

    /// Delete stored locally protected keys for an account.
    public func deleteKeys(for accountId: String) {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: serviceName,
            kSecAttrAccount as String: accountId,
            kSecUseDataProtectionKeychain as String: true
        ]
        SecItemDelete(query as CFDictionary)
    }

    // MARK: - Private Keychain Helpers

    private func storeData(_ data: Data, account: String, accessControl: SecAccessControl) throws {
        // Remove existing first
        deleteKeys(for: account)

        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: serviceName,
            kSecAttrAccount as String: account,
            kSecValueData as String: data,
            kSecAttrAccessControl as String: accessControl,
            kSecUseDataProtectionKeychain as String: true
        ]

        let status = SecItemAdd(query as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw BiometricError.keychainError("Failed to store key: OSStatus \(status)")
        }
    }

    private func retrieveData(account: String, context: LAContext) throws -> Data {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: serviceName,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
            kSecUseAuthenticationContext as String: context,
            kSecUseDataProtectionKeychain as String: true
        ]

        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)

        guard status == errSecSuccess, let data = item as? Data else {
            throw BiometricError.keychainError("Failed to retrieve key: OSStatus \(status)")
        }
        return data
    }
}

// MARK: - Errors

public enum BiometricError: Error, LocalizedError, Sendable {
    case accessControlCreationFailed(String)
    case keychainError(String)
    case biometricNotAvailable
    case biometricFailed
    case noStoredKeys

    public var errorDescription: String? {
        switch self {
        case .accessControlCreationFailed(let msg): return "Access control failed: \(msg)"
        case .keychainError(let msg): return "Keychain error: \(msg)"
        case .biometricNotAvailable: return "Biometric authentication not available"
        case .biometricFailed: return "Biometric authentication failed"
        case .noStoredKeys: return "No stored keys — sign in with your master password first"
        }
    }
}
