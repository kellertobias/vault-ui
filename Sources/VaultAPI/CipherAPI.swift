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
    ///
    /// An organization-owned item goes to `ciphers/create`, which takes the cipher
    /// alongside the collections it should land in; a personal item goes to the
    /// plain `ciphers` endpoint.
    public func create(_ cipher: Cipher) async throws -> Cipher {
        guard cipher.organizationId != nil else {
            return try await client.post(path: "ciphers", body: CipherRequest(cipher: cipher))
        }
        return try await client.post(
            path: "ciphers/create",
            body: CipherCollectionRequest(cipher: cipher, collectionIds: cipher.collectionIds ?? [])
        )
    }

    /// Move an existing personal cipher into an organization.
    ///
    /// The cipher must already be re-keyed to the organization — the server stores
    /// what it is given, so sending a personally-keyed item here would leave the
    /// other members with an unreadable entry.
    public func share(_ cipher: Cipher, collectionIds: [String]) async throws -> Cipher {
        guard let id = cipher.id else {
            throw APIError.invalidURL("Cipher has no ID")
        }
        return try await client.put(
            path: "ciphers/\(id)/share",
            body: CipherCollectionRequest(cipher: cipher, collectionIds: collectionIds)
        )
    }

    /// Update an existing cipher.
    public func update(_ cipher: Cipher) async throws -> Cipher {
        guard let id = cipher.id else {
            throw APIError.invalidURL("Cipher has no ID")
        }
        return try await client.put(path: "ciphers/\(id)", body: CipherRequest(cipher: cipher))
    }

    /// Soft-delete a cipher (move to trash).
    ///
    /// The server returns 200 with an empty body, so decoding a response would
    /// throw on the zero-length data and leave the item stuck pending forever.
    public func softDelete(id: String) async throws {
        try await client.putNoResponse(
            path: "ciphers/\(id)/delete",
            body: EmptyBody()
        )
    }

    /// Permanently delete a cipher.
    public func delete(id: String) async throws {
        try await client.delete(path: "ciphers/\(id)")
    }

    /// Restore a soft-deleted cipher from trash. Also returns an empty 200 body.
    public func restore(id: String) async throws {
        try await client.putNoResponse(
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

/// A cipher plus the collections it belongs to, as `ciphers/create` and
/// `ciphers/{id}/share` expect it: `{ "cipher": {...}, "collectionIds": [...] }`.
///
/// Unlike `CipherRequest`, the cipher stays nested here — these two endpoints are
/// the exception to the flattened shape the rest of the API uses.
struct CipherCollectionRequest: Encodable {
    let cipher: Cipher
    let collectionIds: [String]

    private enum CodingKeys: String, CodingKey {
        case cipher, collectionIds
    }

    func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(CipherWithRekeyedAttachments(cipher: cipher), forKey: .cipher)
        try container.encode(collectionIds, forKey: .collectionIds)
    }
}

/// A cipher that also carries its attachments' current names and keys under
/// `attachments2`.
///
/// The server ignores the `attachments` array when saving — it only re-keys an
/// attachment from the `attachments2` map. Sharing an item that had no item key
/// re-wraps its attachment keys onto a new one, so without this the files would
/// stay readable only to their original owner.
private struct CipherWithRekeyedAttachments: Encodable {
    let cipher: Cipher

    private enum ExtraKeys: String, CodingKey {
        case attachments2
    }

    private struct Attachment2: Encodable {
        let fileName: String
        let key: String
    }

    func encode(to encoder: Encoder) throws {
        try cipher.encode(to: encoder)

        let rekeyed = (cipher.attachments ?? []).reduce(into: [String: Attachment2]()) { result, attachment in
            guard let id = attachment.id,
                  let fileName = attachment.fileName?.serialized(),
                  let key = attachment.key?.serialized() else { return }
            result[id] = Attachment2(fileName: fileName, key: key)
        }

        guard !rekeyed.isEmpty else { return }
        var container = encoder.container(keyedBy: ExtraKeys.self)
        try container.encode(rekeyed, forKey: .attachments2)
    }
}

struct FavoriteRequest: Encodable {
    let favorite: Bool
}

struct MoveRequest: Encodable {
    let folderId: String?
}

struct EmptyBody: Encodable {}
