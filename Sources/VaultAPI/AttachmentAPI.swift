// MARK: - VaultAPI/AttachmentAPI.swift
// File attachment operations

import Foundation
import VaultModels

/// API for managing file attachments on ciphers.
public struct AttachmentAPI: Sendable {
    private let client: APIClient

    public init(client: APIClient) {
        self.client = client
    }

    /// Upload attachment response (first step in two-phase upload).
    struct AttachmentUploadResponse: Decodable {
        let attachmentId: String
        let url: String
        let fileUploadType: Int
        let cipherResponse: Cipher?

        private enum CodingKeys: String, CodingKey {
            case attachmentId, url, fileUploadType, cipherResponse
        }
    }

    /// Request a new attachment upload slot.
    public func requestUpload(
        cipherId: String,
        fileName: String,
        fileSize: Int,
        key: String
    ) async throws -> (attachmentId: String, uploadURL: String, cipher: Cipher?) {
        struct UploadRequest: Encodable {
            let fileName: String
            let fileSize: Int
            let key: String
        }

        let response: AttachmentUploadResponse = try await client.post(
            path: "ciphers/\(cipherId)/attachment/v2",
            body: UploadRequest(fileName: fileName, fileSize: fileSize, key: key)
        )

        return (response.attachmentId, response.url, response.cipherResponse)
    }

    /// Upload the actual file data to the upload URL.
    public func uploadFile(
        cipherId: String,
        attachmentId: String,
        data: Data,
        fileName: String
    ) async throws {
        let url = client.account.apiURL
            .appendingPathComponent("ciphers/\(cipherId)/attachment/\(attachmentId)")

        // Build multipart form data
        let boundary = UUID().uuidString
        var body = Data()

        // Add the encrypted data as the file part
        body.append("--\(boundary)\r\n".data(using: .utf8)!)
        body.append("Content-Disposition: form-data; name=\"data\"; filename=\"\(fileName)\"\r\n".data(using: .utf8)!)
        body.append("Content-Type: application/octet-stream\r\n\r\n".data(using: .utf8)!)
        body.append(data)
        body.append("\r\n--\(boundary)--\r\n".data(using: .utf8)!)

        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.httpBody = body
        request.setValue("multipart/form-data; boundary=\(boundary)", forHTTPHeaderField: "Content-Type")
        if let token = await client.getAccessToken() {
            request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        }

        let (_, response) = try await URLSession.shared.data(for: request)
        guard let httpResponse = response as? HTTPURLResponse,
              (200...299).contains(httpResponse.statusCode) else {
            throw APIError.invalidResponse((response as? HTTPURLResponse)?.statusCode ?? 0)
        }
    }

    /// Download an attachment.
    public func download(url: URL) async throws -> Data {
        try await client.downloadData(from: url)
    }

    /// Delete an attachment.
    public func delete(cipherId: String, attachmentId: String) async throws {
        try await client.delete(path: "ciphers/\(cipherId)/attachment/\(attachmentId)")
    }
}
