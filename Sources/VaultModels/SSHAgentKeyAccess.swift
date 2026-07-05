// MARK: - VaultModels/SSHAgentKeyAccess.swift
// Per-key SSH agent visibility and usage history.

import Foundation

public struct SSHAgentKeyUse: Codable, Sendable, Equatable {
    public let usedAt: Date
    public let peer: String?

    public init(usedAt: Date, peer: String?) {
        self.usedAt = usedAt
        self.peer = peer
    }
}

public struct SSHAgentKeyAccess: Sendable, Equatable {
    public let cipherId: String
    public let isVisible: Bool
    public let authenticationBypassUntil: Date?
    public let lastUsedAt: Date?
    public let recentUses: [SSHAgentKeyUse]

    public init(
        cipherId: String,
        isVisible: Bool,
        authenticationBypassUntil: Date?,
        lastUsedAt: Date?,
        recentUses: [SSHAgentKeyUse]
    ) {
        self.cipherId = cipherId
        self.isVisible = isVisible
        self.authenticationBypassUntil = authenticationBypassUntil
        self.lastUsedAt = lastUsedAt
        self.recentUses = recentUses
    }
}

public enum SSHAgentKeyAccessStore {
    public static let menuBarKeysEnabledKey = "sshAgentMenuBarKeysEnabled"

    private static let stateKey = "sshAgentKeyAccessState"
    private static let stateFileName = "ssh-key-access.json"
    private static let recentUseLimit = 10

    private struct Record: Codable, Equatable {
        var isDisabled: Bool
        var authenticationBypassUntil: Date?
        var recentUses: [SSHAgentKeyUse]

        static let `default` = Record(
            isDisabled: false,
            authenticationBypassUntil: nil,
            recentUses: []
        )
    }

    public static func access(for cipherId: String, defaults: UserDefaults = .standard) -> SSHAgentKeyAccess {
        let record = records(defaults: defaults)[cipherId] ?? .default
        let now = Date()
        let bypassUntil = record.authenticationBypassUntil.flatMap { $0 > now ? $0 : nil }
        return SSHAgentKeyAccess(
            cipherId: cipherId,
            isVisible: !record.isDisabled,
            authenticationBypassUntil: bypassUntil,
            lastUsedAt: record.recentUses.first?.usedAt,
            recentUses: record.recentUses
        )
    }

    public static func isVisible(cipherId: String, defaults: UserDefaults = .standard) -> Bool {
        access(for: cipherId, defaults: defaults).isVisible
    }

    public static func setVisible(_ visible: Bool, cipherId: String, defaults: UserDefaults = .standard) {
        mutate(cipherId: cipherId, defaults: defaults) { record in
            record.isDisabled = !visible
            if !visible {
                record.authenticationBypassUntil = nil
            }
        }
    }

    public static func setAuthenticationBypass(cipherId: String, until: Date, defaults: UserDefaults = .standard) {
        mutate(cipherId: cipherId, defaults: defaults) { record in
            record.authenticationBypassUntil = until
        }
    }

    public static func clearAuthenticationBypass(cipherId: String, defaults: UserDefaults = .standard) {
        mutate(cipherId: cipherId, defaults: defaults) { record in
            record.authenticationBypassUntil = nil
        }
    }

    public static func recordUse(cipherId: String, peer: String?, defaults: UserDefaults = .standard) {
        mutate(cipherId: cipherId, defaults: defaults) { record in
            let use = SSHAgentKeyUse(usedAt: Date(), peer: peer?.isEmpty == false ? peer : nil)
            record.recentUses.insert(use, at: 0)
            if record.recentUses.count > recentUseLimit {
                record.recentUses = Array(record.recentUses.prefix(recentUseLimit))
            }
        }
    }

    private static func records(defaults: UserDefaults) -> [String: Record] {
        if let data = try? Data(contentsOf: stateURL),
           let decoded = try? JSONDecoder().decode([String: Record].self, from: data) {
            return decoded
        }

        guard let data = defaults.data(forKey: stateKey),
              let decoded = try? JSONDecoder().decode([String: Record].self, from: data) else {
            return [:]
        }
        return decoded
    }

    private static func save(_ records: [String: Record], defaults: UserDefaults) {
        guard let data = try? JSONEncoder().encode(records) else { return }
        defaults.set(data, forKey: stateKey)

        do {
            try FileManager.default.createDirectory(
                at: stateURL.deletingLastPathComponent(),
                withIntermediateDirectories: true
            )
            try data.write(to: stateURL, options: [.atomic, .completeFileProtectionUntilFirstUserAuthentication])
        } catch {
            // UserDefaults remains as an in-process fallback if the shared file cannot be written.
        }
    }

    private static func mutate(
        cipherId: String,
        defaults: UserDefaults,
        update: (inout Record) -> Void
    ) {
        var allRecords = records(defaults: defaults)
        var record = allRecords[cipherId] ?? .default
        update(&record)
        allRecords[cipherId] = record
        save(allRecords, defaults: defaults)
    }

    private static var stateURL: URL {
        applicationSupportURL
            .appendingPathComponent("VaultUI", isDirectory: true)
            .appendingPathComponent(stateFileName, isDirectory: false)
    }

    private static var applicationSupportURL: URL {
        if isVaultCLIProcess, let containerSupportURL = containingAppApplicationSupportURL {
            return containerSupportURL
        }

        return FileManager.default.urls(
            for: .applicationSupportDirectory,
            in: .userDomainMask
        ).first ?? FileManager.default.homeDirectoryForCurrentUser
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
}
