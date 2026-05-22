// MARK: - VaultSync/VaultDataStore.swift
// High-level data access layer combining persistence + decryption

import Foundation
import SwiftData
import VaultModels
import VaultCrypto
import VaultAPI

/// The SwiftData model container configuration.
public enum VaultDataStore {
    public static let groupContainer = "de.tobisk.apps.vaultui.shared"

    /// Create the shared model container for all persisted vault data.
    public static func createModelContainer() throws -> ModelContainer {
        let config = ModelConfiguration(
            "VaultUI",
            isStoredInMemoryOnly: false,
            allowsSave: true
        )

        return try ModelContainer(
            for: PersistedCipher.self, PersistedFolder.self, PersistedSend.self, PersistedAccount.self,
            configurations: config
        )
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
