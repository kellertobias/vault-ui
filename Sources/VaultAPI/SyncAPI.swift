// MARK: - VaultAPI/SyncAPI.swift
// Full vault sync endpoint

import Foundation
import VaultModels

/// API for syncing the full vault.
public struct SyncAPI: Sendable {
    private let client: APIClient

    public init(client: APIClient) {
        self.client = client
    }

    /// Perform a full vault sync.
    ///
    /// Returns all ciphers, folders, collections, sends, and profile data.
    /// This is the primary way to populate the local vault after login.
    public func fullSync() async throws -> SyncResponse {
        try await client.get(path: "sync")
    }

    /// Perform a sync with a "since" date to get only changes.
    /// Note: Not all Bitwarden/Vaultwarden servers support this;
    /// falls back to full sync if unsupported.
    public func incrementalSync(since: Date) async throws -> SyncResponse {
        let dateString = ISO8601DateFormatter.bitwarden.string(from: since)
        return try await client.get(path: "sync?excludeDomains=true&since=\(dateString)")
    }
}
