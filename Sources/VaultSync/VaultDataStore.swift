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
    private static let storeFileName = "VaultUI.store"

    /// Create the shared model container for all persisted vault data.
    public static func createModelContainer() throws -> ModelContainer {
        let storeURL = try localStoreURL()
        try migrateLegacyGroupStoreIfNeeded(to: storeURL)

        let config = ModelConfiguration(
            "VaultUI",
            schema: nil,
            url: storeURL,
            allowsSave: true
        )

        let container = try ModelContainer(
            for: PersistedCipher.self, PersistedFolder.self, PersistedSend.self, PersistedAccount.self,
            configurations: config
        )

        // Apply file protection to the SQLite store so it is encrypted at rest
        // until the user unlocks the device for the first time after boot.
        let configuredStoreURL = config.url
        try? FileManager.default.setAttributes(
            [.protectionKey: FileProtectionType.completeUntilFirstUserAuthentication],
            ofItemAtPath: configuredStoreURL.path
        )
        // Also protect the WAL and SHM journal files
        for suffix in ["-wal", "-shm"] {
            let journalPath = configuredStoreURL.path + suffix
            if FileManager.default.fileExists(atPath: journalPath) {
                try? FileManager.default.setAttributes(
                    [.protectionKey: FileProtectionType.completeUntilFirstUserAuthentication],
                    ofItemAtPath: journalPath
                )
            }
        }

        return container
    }

    private static func localStoreURL() throws -> URL {
        guard let applicationSupport = applicationSupportURL else {
            throw CocoaError(.fileNoSuchFile)
        }

        let directory = applicationSupport.appendingPathComponent("VaultUI", isDirectory: true)
        try FileManager.default.createDirectory(
            at: directory,
            withIntermediateDirectories: true
        )
        return directory.appendingPathComponent(storeFileName, isDirectory: false)
    }

    private static var applicationSupportURL: URL? {
        if isVaultCLIProcess, let containerSupportURL = containingAppApplicationSupportURL {
            return containerSupportURL
        }

        return FileManager.default.urls(
            for: .applicationSupportDirectory,
            in: .userDomainMask
        ).first
    }

    private static var containingAppApplicationSupportURL: URL? {
        guard let libraryURL = FileManager.default.urls(
            for: .libraryDirectory,
            in: .userDomainMask
        ).first else {
            return nil
        }

        return libraryURL
            .appendingPathComponent("Containers", isDirectory: true)
            .appendingPathComponent(AppIdentifiers.bundleIdentifier, isDirectory: true)
            .appendingPathComponent("Data", isDirectory: true)
            .appendingPathComponent("Library", isDirectory: true)
            .appendingPathComponent("Application Support", isDirectory: true)
    }

    private static var isVaultCLIProcess: Bool {
        let executableName = URL(fileURLWithPath: CommandLine.arguments.first ?? "")
            .lastPathComponent
        return executableName == "vaultui"
    }

    private static func migrateLegacyGroupStoreIfNeeded(to destinationURL: URL) throws {
        guard !storeFamilyExists(at: destinationURL),
              let sourceURL = legacyGroupStoreURL(),
              storeFamilyExists(at: sourceURL) else {
            return
        }

        try FileManager.default.createDirectory(
            at: destinationURL.deletingLastPathComponent(),
            withIntermediateDirectories: true
        )

        for suffix in ["", "-wal", "-shm"] {
            let source = URL(fileURLWithPath: sourceURL.path + suffix)
            let destination = URL(fileURLWithPath: destinationURL.path + suffix)
            guard FileManager.default.fileExists(atPath: source.path) else { continue }
            if FileManager.default.fileExists(atPath: destination.path) {
                try FileManager.default.removeItem(at: destination)
            }
            try FileManager.default.copyItem(at: source, to: destination)
        }
    }

    private static func legacyGroupStoreURL() -> URL? {
        for identifier in [
            AppIdentifiers.appGroupIdentifier,
            AppIdentifiers.teamPrefixedAppGroupIdentifier
        ] {
            guard let containerURL = FileManager.default.containerURL(
                forSecurityApplicationGroupIdentifier: identifier
            ) else {
                continue
            }

            return containerURL
                .appendingPathComponent("Library", isDirectory: true)
                .appendingPathComponent("Application Support", isDirectory: true)
                .appendingPathComponent(storeFileName, isDirectory: false)
        }

        return nil
    }

    private static func storeFamilyExists(at url: URL) -> Bool {
        ["", "-wal", "-shm"].contains { suffix in
            FileManager.default.fileExists(atPath: url.path + suffix)
        }
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
