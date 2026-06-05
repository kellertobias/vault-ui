// MARK: - VaultAPI/SendAPI.swift
// CRUD operations for Bitwarden Send

import Foundation
import VaultModels

/// API for managing Bitwarden Send items.
public struct SendAPI: Sendable {
    private let client: APIClient

    public init(client: APIClient) {
        self.client = client
    }

    /// Create a new text Send.
    public func create(_ send: SendItem) async throws -> SendItem {
        try await client.post(path: "sends", body: send)
    }

    /// Update an existing Send.
    public func update(_ send: SendItem) async throws -> SendItem {
        guard let id = send.id else {
            throw APIError.invalidURL("Send has no ID")
        }
        return try await client.put(path: "sends/\(id)", body: send)
    }

    /// Delete a Send.
    public func delete(id: String) async throws {
        try await client.delete(path: "sends/\(id)")
    }

    /// Remove the password from a Send.
    public func removePassword(id: String) async throws -> SendItem {
        try await client.put(
            path: "sends/\(id)/remove-password",
            body: EmptyBody()
        )
    }

    /// Get the owner-side management URL for a Send.
    public func getAccessURL(send: SendItem) async -> URL? {
        guard let accessId = send.accessId else { return nil }
        let urlString = client.account.serverURL.absoluteString
            .trimmingCharacters(in: CharacterSet(charactersIn: "/"))
            + "/#/send/\(accessId)"
        return URL(string: urlString)
    }

    /// Build the public Send URL. The key is intentionally kept in the URL fragment.
    public func getPublicURL(send: SendItem, key: String) async -> URL? {
        guard let accessId = send.accessId else { return nil }
        let urlString = client.account.serverURL.absoluteString
            .trimmingCharacters(in: CharacterSet(charactersIn: "/"))
            + "/#/send/\(accessId)/\(key)"
        return URL(string: urlString)
    }

    /// Create a file Send with multipart upload.
    public func createFileSend(
        _ send: SendItem,
        fileData: Data,
        fileName: String
    ) async throws -> SendItem {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        let jsonData = try encoder.encode(send)

        return try await client.postMultipart(
            path: "sends/file",
            jsonPart: (name: "model", data: jsonData),
            filePart: (name: "data", filename: fileName, data: fileData, mimeType: "application/octet-stream")
        )
    }
}
