// MARK: - VaultAPI/CipherAPI.swift
// CRUD operations for vault items (ciphers)

import Foundation
import VaultModels

/// API for managing vault ciphers (items).
public struct CipherAPI: Sendable {
    private let client: APIClient

    public init(client: APIClient) {
        self.client = client
    }

    /// Create a new cipher.
    public func create(_ cipher: Cipher) async throws -> Cipher {
        try await client.post(path: "ciphers", body: CipherRequest(cipher: cipher))
    }

    /// Update an existing cipher.
    public func update(_ cipher: Cipher) async throws -> Cipher {
        guard let id = cipher.id else {
            throw APIError.invalidURL("Cipher has no ID")
        }
        return try await client.put(path: "ciphers/\(id)", body: CipherRequest(cipher: cipher))
    }

    /// Soft-delete a cipher (move to trash).
    public func softDelete(id: String) async throws {
        let _: EmptyResponse = try await client.put(
            path: "ciphers/\(id)/delete",
            body: EmptyBody()
        )
    }

    /// Permanently delete a cipher.
    public func delete(id: String) async throws {
        try await client.delete(path: "ciphers/\(id)")
    }

    /// Restore a soft-deleted cipher from trash.
    public func restore(id: String) async throws {
        let _: EmptyResponse = try await client.put(
            path: "ciphers/\(id)/restore",
            body: EmptyBody()
        )
    }

    /// Toggle favorite status.
    public func toggleFavorite(id: String, favorite: Bool) async throws -> Cipher {
        try await client.put(
            path: "ciphers/\(id)/partial",
            body: FavoriteRequest(favorite: favorite)
        )
    }

    /// Move a cipher to a different folder.
    public func moveToFolder(id: String, folderId: String?) async throws {
        try await client.postNoResponse(
            path: "ciphers/\(id)/move",
            body: MoveRequest(folderId: folderId)
        )
    }
}

// MARK: - Request/Response Types

/// Wrapper for cipher CRUD requests.
///
/// The Bitwarden API expects cipher fields at the top level, not nested
/// under a "cipher" key. This struct flattens the cipher during encoding.
struct CipherRequest: Encodable {
    let cipher: Cipher

    func encode(to encoder: Encoder) throws {
        try cipher.encode(to: encoder)
    }
}

struct FavoriteRequest: Encodable {
    let favorite: Bool
}

struct MoveRequest: Encodable {
    let folderId: String?
}

struct EmptyBody: Encodable {}

struct EmptyResponse: Decodable {}
