// MARK: - VaultSync/VaultDataStore.swift
// High-level data access layer combining persistence + decryption

import Foundation
import SwiftData
import VaultModels
import VaultCrypto
import VaultAPI

/// The SwiftData model container configuration.
public enum VaultDataStore {
    public static let groupContainer = AppIdentifiers.appGroupIdentifier

    /// Create the shared model container for all persisted vault data.
    public static func createModelContainer() throws -> ModelContainer {
        let config = ModelConfiguration(
            "VaultUI",
            isStoredInMemoryOnly: false,
            allowsSave: true,
            groupContainer: .identifier(groupContainer)
        )

        let container = try ModelContainer(
            for: PersistedCipher.self, PersistedFolder.self, PersistedSend.self, PersistedAccount.self,
            configurations: config
        )

        // Apply file protection to the SQLite store so it is encrypted at rest
        // until the user unlocks the device for the first time after boot.
        let storeURL = config.url
        try? FileManager.default.setAttributes(
            [.protectionKey: FileProtectionType.completeUntilFirstUserAuthentication],
            ofItemAtPath: storeURL.path
        )
        // Also protect the WAL and SHM journal files
        for suffix in ["-wal", "-shm"] {
            let journalPath = storeURL.path + suffix
            if FileManager.default.fileExists(atPath: journalPath) {
                try? FileManager.default.setAttributes(
                    [.protectionKey: FileProtectionType.completeUntilFirstUserAuthentication],
                    ofItemAtPath: journalPath
                )
            }
        }

        return container
    }

    /// Create an in-memory container for testing.
    public static func createInMemoryContainer() throws -> ModelContainer {
        let config = ModelConfiguration(
            "VaultUITest",
            isStoredInMemoryOnly: true
        )

        return try ModelContainer(
            for: PersistedCipher.self, PersistedFolder.self, PersistedSend.self, PersistedAccount.self,
            configurations: config
        )
    }
}
