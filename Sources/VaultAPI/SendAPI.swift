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

    /// Create a file Send.
    ///
    /// Uses the two-phase `sends/file/v2` flow (request an upload slot, then
    /// upload the payload) — the only flow Bitwarden cloud still supports.
    /// Falls back to the legacy single-step `sends/file` multipart upload for
    /// old Vaultwarden servers that don't implement v2.
    public func createFileSend(
        _ send: SendItem,
        fileData: Data,
        fileName: String
    ) async throws -> SendItem {
        do {
            return try await createFileSendV2(send, fileData: fileData, fileName: fileName)
        } catch APIError.notFound {
            return try await createFileSendLegacy(send, fileData: fileData, fileName: fileName)
        } catch APIError.invalidResponse(405) {
            return try await createFileSendLegacy(send, fileData: fileData, fileName: fileName)
        }
    }

    /// The v2 create request is the Send model plus the encrypted payload size.
    private struct SendFileV2Request: Encodable {
        let send: SendItem
        let fileLength: Int

        func encode(to encoder: Encoder) throws {
            try send.encode(to: encoder)
            var container = encoder.container(keyedBy: CodingKeys.self)
            try container.encode(fileLength, forKey: .fileLength)
        }

        private enum CodingKeys: String, CodingKey {
            case fileLength
        }
    }

    private struct SendFileUploadResponse: Decodable {
        let url: String
        let fileUploadType: Int
        let sendResponse: SendItem
    }

    private func createFileSendV2(
        _ send: SendItem,
        fileData: Data,
        fileName: String
    ) async throws -> SendItem {
        let response: SendFileUploadResponse = try await client.post(
            path: "sends/file/v2",
            body: SendFileV2Request(send: send, fileLength: fileData.count)
        )
        let created = response.sendResponse

        do {
            if response.fileUploadType == 1, let azureURL = URL(string: response.url) {
                // Azure SAS upload (Bitwarden cloud / S3-backed setups).
                try await AzureBlobUpload.put(data: fileData, to: azureURL)
            } else {
                // Direct upload to the vault host. Like the official clients, build
                // the path from the response identifiers rather than trusting the
                // returned URL's host (Vaultwarden returns a relative URL here).
                guard let sendId = created.id, let fileId = created.file?.id else {
                    throw APIError.serverMessage("Send upload response is missing file identifiers")
                }
                try await client.postMultipartNoResponse(
                    path: "sends/\(sendId)/file/\(fileId)",
                    filePart: (name: "data", filename: fileName, data: fileData, mimeType: "application/octet-stream")
                )
            }
        } catch {
            // The Send was created but has no payload — remove it rather than
            // leaving a broken entry in the user's Send list.
            if let id = created.id {
                try? await delete(id: id)
            }
            throw error
        }

        return created
    }

    /// Legacy single-step multipart upload (pre-v2 Vaultwarden).
    private func createFileSendLegacy(
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
