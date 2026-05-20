// MARK: - VaultSync/VaultDataStore.swift
// High-level data access layer combining persistence + decryption

import Foundation
import SwiftData
import VaultModels
import VaultCrypto
import VaultAPI

/// The SwiftData model container configuration.
public enum VaultDataStore {
    /// Create the shared model container for all persisted vault data.
    public static func createModelContainer() throws -> ModelContainer {
        let schema = Schema([
            PersistedCipher.self,
            PersistedFolder.self,
            PersistedSend.self,
            PersistedAccount.self,
        ])

        let config = ModelConfiguration(
            "VaultUI",
            schema: schema,
            isStoredInMemoryOnly: false,
            allowsSave: true
        )

        return try ModelContainer(for: schema, configurations: [config])
    }

    /// Create an in-memory container for testing.
    public static func createInMemoryContainer() throws -> ModelContainer {
        let schema = Schema([
            PersistedCipher.self,
            PersistedFolder.self,
            PersistedSend.self,
            PersistedAccount.self,
        ])

        let config = ModelConfiguration(
            "VaultUITest",
            schema: schema,
            isStoredInMemoryOnly: true
        )

        return try ModelContainer(for: schema, configurations: [config])
    }
}
