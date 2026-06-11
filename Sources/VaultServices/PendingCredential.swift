// MARK: - VaultServices/PendingCredential.swift
// Pending login credentials to save from the Safari Web Extension

import Foundation

/// A login captured by the browser extension that needs to be encrypted and saved by the main app.
public struct PendingCredential: Codable, Sendable, Equatable, Identifiable {
    public let id: String
    public let name: String
    public let username: String
    public let password: String
    public let url: String
    public let creationDate: Date

    /// The vault account this credential should be saved to (nil = active account).
    public let accountId: String?

    public init(
        id: String = UUID().uuidString,
        name: String,
        username: String,
        password: String,
        url: String,
        creationDate: Date = Date(),
        accountId: String? = nil
    ) {
        self.id = id
        self.name = name
        self.username = username
        self.password = password
        self.url = url
        self.creationDate = creationDate
        self.accountId = accountId
    }
}
