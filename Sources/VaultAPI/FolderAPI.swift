// MARK: - VaultAPI/FolderAPI.swift
// CRUD operations for folders

import Foundation
import VaultModels
import VaultCrypto

/// API for managing vault folders.
public struct FolderAPI: Sendable {
    private let client: APIClient

    public init(client: APIClient) {
        self.client = client
    }

    /// Create a new folder.
    public func create(name: EncString) async throws {
        try await client.postNoResponse(path: "folders", body: FolderRequest(name: name.serialized()))
    }

    /// Update a folder's name.
    public func update(id: String, name: EncString) async throws {
        try await client.putNoResponse(path: "folders/\(id)", body: FolderRequest(name: name.serialized()))
    }

    /// Delete a folder (items in it become unfiled, not deleted).
    public func delete(id: String) async throws {
        try await client.delete(path: "folders/\(id)")
    }
}

struct FolderRequest: Encodable {
    let name: String
}

