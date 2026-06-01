// MARK: - VaultSSH/AgentSocketDirectory.swift
// Shared Unix socket locations for Vault UI agents

import Foundation
import OSLog
import VaultModels

private let logger = Logger(subsystem: "com.vaultui", category: "AgentSocketDirectory")

/// Resolves the shared directory used for Vault UI Unix domain sockets.
public enum VaultAgentSocketDirectory {
    public static let appGroupIdentifier = AppIdentifiers.appGroupIdentifier
    private static let teamPrefixedAppGroupIdentifier = AppIdentifiers.teamPrefixedAppGroupIdentifier

    public static var directoryURL: URL {
        for identifier in [appGroupIdentifier, teamPrefixedAppGroupIdentifier] {
            if let url = FileManager.default.containerURL(
                forSecurityApplicationGroupIdentifier: identifier
            ) {
                return url.appendingPathComponent(".vaultui", isDirectory: true)
            }
        }

        if let groupContainerURL = directGroupContainerURL {
            logger.debug("App group API is unavailable; using direct group container path")
            return groupContainerURL.appendingPathComponent(".vaultui", isDirectory: true)
        }

        logger.warning("App group container is unavailable; falling back to Application Support")
        return fallbackDirectoryURL
    }

    public static func socketPath(named fileName: String) -> String {
        directoryURL
            .appendingPathComponent(fileName, isDirectory: false)
            .path
    }

    private static var fallbackDirectoryURL: URL {
        if let applicationSupport = FileManager.default.urls(
            for: .applicationSupportDirectory,
            in: .userDomainMask
        ).first {
            return applicationSupport
                .appendingPathComponent("VaultUI", isDirectory: true)
                .appendingPathComponent(".vaultui", isDirectory: true)
        }

        return URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
            .appendingPathComponent("VaultUI", isDirectory: true)
            .appendingPathComponent(".vaultui", isDirectory: true)
    }

    private static var directGroupContainerURL: URL? {
        guard let libraryURL = FileManager.default.urls(
            for: .libraryDirectory,
            in: .userDomainMask
        ).first else {
            return nil
        }

        return libraryURL
            .appendingPathComponent("Group Containers", isDirectory: true)
            .appendingPathComponent(appGroupIdentifier, isDirectory: true)
    }
}
