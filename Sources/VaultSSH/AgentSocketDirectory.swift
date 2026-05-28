// MARK: - VaultSSH/AgentSocketDirectory.swift
// Shared Unix socket locations for Vault UI agents

import Foundation

/// Resolves the shared directory used for Vault UI Unix domain sockets.
public enum VaultAgentSocketDirectory {
    public static let appGroupIdentifier = "group.de.tobisk.apps.vaultui"

    public static var directoryURL: URL {
        if let url = FileManager.default.containerURL(
            forSecurityApplicationGroupIdentifier: appGroupIdentifier
        ) {
            return url.appendingPathComponent(".vaultui", isDirectory: true)
        }

        return URL(
            fileURLWithPath: "\(realHomeDirectory)/Library/Group Containers/\(appGroupIdentifier)/.vaultui",
            isDirectory: true
        )
    }

    public static func socketPath(named fileName: String) -> String {
        directoryURL
            .appendingPathComponent(fileName, isDirectory: false)
            .path
    }

    private static var realHomeDirectory: String {
        if let pw = getpwuid(getuid()), let dir = pw.pointee.pw_dir {
            return String(cString: dir)
        }
        return NSHomeDirectory()
    }
}
