// MARK: - VaultServices/TemporaryCredentialDraft.swift
// Draft credentials queued from the Safari extension before they become real vault items.

import Foundation

/// A temporary login draft seeded by the browser extension.
///
/// Drafts are recoverable and local-only until the user submits the form successfully,
/// at which point the main app promotes them into a normal vault item.
public struct TemporaryCredentialDraft: Codable, Sendable, Equatable, Identifiable {
    public let id: String
    public let name: String
    public let username: String
    public let password: String?
    public let url: String
    public let creationDate: Date

    public init(
        id: String = UUID().uuidString,
        name: String,
        username: String,
        password: String? = nil,
        url: String,
        creationDate: Date = Date()
    ) {
        self.id = id
        self.name = name
        self.username = username
        self.password = password
        self.url = url
        self.creationDate = creationDate
    }
}
