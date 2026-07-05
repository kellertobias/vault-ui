// MARK: - VaultAPI/AzureBlobUpload.swift
// Raw block-blob upload for server-issued Azure SAS URLs

import Foundation

/// Uploads encrypted payloads to Azure blob storage via a SAS URL.
///
/// Bitwarden cloud (and S3/Azure-backed self-hosted servers) answer upload
/// requests with `fileUploadType == 1` and a pre-authorized SAS URL. The
/// upload is a plain `PUT` of the raw encrypted bytes — NOT multipart — with
/// the `x-ms-blob-type` header. Vaultwarden always uses direct uploads
/// (`fileUploadType == 0`), so this path never runs against it.
enum AzureBlobUpload {
    /// API version matching the official Bitwarden clients' Azure uploads.
    private static let apiVersion = "2020-04-08"

    /// PUT the payload to the SAS URL.
    ///
    /// The SAS token in the URL is the sole authorization — the vault bearer
    /// token must never be attached to this external host.
    static func put(data: Data, to url: URL) async throws {
        var request = URLRequest(url: url)
        request.httpMethod = "PUT"
        request.httpBody = data
        request.setValue("BlockBlob", forHTTPHeaderField: "x-ms-blob-type")
        request.setValue(apiVersion, forHTTPHeaderField: "x-ms-version")
        request.setValue("application/octet-stream", forHTTPHeaderField: "Content-Type")
        request.setValue(String(data.count), forHTTPHeaderField: "Content-Length")

        let (_, response) = try await URLSession.shared.data(for: request)
        guard let httpResponse = response as? HTTPURLResponse,
              (200...299).contains(httpResponse.statusCode) else {
            throw APIError.invalidResponse((response as? HTTPURLResponse)?.statusCode ?? 0)
        }
    }
}
