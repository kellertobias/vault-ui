// MARK: - VaultSync/SyncEngine.swift
// Orchestrates full and incremental vault synchronization

import Foundation
import SwiftData
import VaultModels
import VaultAPI
import VaultCrypto
import OSLog

private let logger = Logger(subsystem: "com.vaultui", category: "SyncEngine")

/// Orchestrates vault synchronization between local SwiftData and the remote server.
///
/// Follows an offline-first strategy:
/// 1. Local changes are persisted immediately
/// 2. Changes are queued for upload
/// 3. On sync: drain the upload queue, then pull server changes
/// 4. Conflicts resolved by server revision date (last-write-wins)
@MainActor
public final class SyncEngine: ObservableObject {
    /// Current sync state
    @Published public var syncState: SyncState = .idle
    @Published public var lastSyncDate: Date?
    @Published public var pendingOperationCount: Int = 0

    private let apiClient: APIClient
    private let modelContainer: ModelContainer
    private let accountId: String
    private let encoder: JSONEncoder
    private let decoder: JSONDecoder

    public enum SyncState: Equatable {
        case idle
        case syncing
        case error(String)
    }

    public init(
        apiClient: APIClient,
        modelContainer: ModelContainer,
        accountId: String
    ) {
        self.apiClient = apiClient
        self.modelContainer = modelContainer
        self.accountId = accountId
        self.encoder = APIClient.encoder
        self.decoder = APIClient.decoder
    }

    // MARK: - Full Sync

    /// Perform a full vault sync.
    ///
    /// 1. Push any pending local changes
    /// 2. Fetch complete vault from server
    /// 3. Merge server data into local store
    public func fullSync() async throws {
        guard syncState != .syncing else {
            logger.info("Sync already in progress, skipping")
            return
        }

        syncState = .syncing
        logger.info("Starting full sync for account \(self.accountId)")

        do {
            // Step 1: Push pending local changes
            try await drainOfflineQueue()

            // Step 2: Fetch from server
            let syncAPI = SyncAPI(client: apiClient)
            let response = try await syncAPI.fullSync()

            // Step 3: Merge into local store
            try await mergeServerResponse(response)

            lastSyncDate = Date()
            syncState = .idle
            await updatePendingCount()

            logger.info("Full sync completed successfully")
        } catch {
            let errorMsg = error.localizedDescription
            syncState = .error(errorMsg)
            logger.error("Full sync failed: \(errorMsg)")
            throw error
        }
    }

    // MARK: - Merge Server Response

    /// Merge the full sync response into the local SwiftData store.
    private func mergeServerResponse(_ response: SyncResponse) async throws {
        let context = modelContainer.mainContext

        // Merge ciphers
        if let serverCiphers = response.ciphers {
            try await mergeCiphers(serverCiphers, in: context)
        }

        // Merge folders
        if let serverFolders = response.folders {
            try await mergeFolders(serverFolders, in: context)
        }

        // Merge sends
        if let serverSends = response.sends {
            try await mergeSends(serverSends, in: context)
        }

        try context.save()
    }

    /// Merge server ciphers into local store.
    private func mergeCiphers(_ serverCiphers: [Cipher], in context: ModelContext) async throws {
        // Fetch all local ciphers for this account
        let localAccountId = accountId
        let fetchDescriptor = FetchDescriptor<PersistedCipher>(
            predicate: #Predicate { $0.accountId == localAccountId }
        )
        let localCiphers = try context.fetch(fetchDescriptor)
        let localMap = Dictionary(uniqueKeysWithValues: localCiphers.compactMap { cipher in
            cipher.id.isEmpty ? nil : (cipher.id, cipher)
        })

        var serverIds = Set<String>()

        for serverCipher in serverCiphers {
            guard let serverId = serverCipher.id else { continue }
            serverIds.insert(serverId)

            if let localCipher = localMap[serverId] {
                // Item exists locally — check for conflicts
                if localCipher.syncStatus == .pendingUpload || localCipher.syncStatus == .pendingCreate {
                    // Local has pending changes — conflict
                    try resolveConflict(local: localCipher, server: serverCipher)
                } else {
                    // No conflict — update from server
                    try localCipher.update(from: serverCipher, encoder: encoder)
                }
            } else {
                // New item from server
                let persisted = try PersistedCipher.from(
                    cipher: serverCipher,
                    accountId: accountId,
                    encoder: encoder
                )
                context.insert(persisted)
            }
        }

        // Delete items that no longer exist on server (unless they have pending local ops)
        for localCipher in localCiphers {
            if !serverIds.contains(localCipher.id) && localCipher.syncStatus == .synced {
                context.delete(localCipher)
            }
        }
    }

    /// Merge server folders into local store.
    private func mergeFolders(_ serverFolders: [Folder], in context: ModelContext) async throws {
        let localAccountId = accountId
        let fetchDescriptor = FetchDescriptor<PersistedFolder>(
            predicate: #Predicate { $0.accountId == localAccountId }
        )
        let localFolders = try context.fetch(fetchDescriptor)
        let localMap = Dictionary(uniqueKeysWithValues: localFolders.compactMap { folder in
            folder.id.isEmpty ? nil : (folder.id, folder)
        })

        var serverIds = Set<String>()

        for serverFolder in serverFolders {
            guard let serverId = serverFolder.id else { continue }
            serverIds.insert(serverId)

            if let localFolder = localMap[serverId] {
                if localFolder.syncStatus == .synced {
                    localFolder.encryptedName = serverFolder.name?.serialized() ?? ""
                    localFolder.revisionDate = serverFolder.revisionDate ?? Date()
                }
            } else {
                context.insert(PersistedFolder.from(folder: serverFolder, accountId: accountId))
            }
        }

        for localFolder in localFolders {
            if !serverIds.contains(localFolder.id) && localFolder.syncStatus == .synced {
                context.delete(localFolder)
            }
        }
    }

    /// Merge server sends into local store.
    private func mergeSends(_ serverSends: [SendItem], in context: ModelContext) async throws {
        let localAccountId = accountId
        let fetchDescriptor = FetchDescriptor<PersistedSend>(
            predicate: #Predicate { $0.accountId == localAccountId }
        )
        let localSends = try context.fetch(fetchDescriptor)
        let localMap = Dictionary(uniqueKeysWithValues: localSends.compactMap { send in
            send.id.isEmpty ? nil : (send.id, send)
        })

        var serverIds = Set<String>()

        for serverSend in serverSends {
            guard let serverId = serverSend.id else { continue }
            serverIds.insert(serverId)

            if let localSend = localMap[serverId] {
                if localSend.syncStatus == .synced {
                    localSend.encryptedJSON = try encoder.encode(serverSend)
                    localSend.revisionDate = serverSend.revisionDate ?? Date()
                    localSend.expirationDate = serverSend.expirationDate
                    localSend.deletionDate = serverSend.deletionDate
                    localSend.disabled = serverSend.disabled ?? false
                }
            } else {
                context.insert(try PersistedSend.from(
                    send: serverSend,
                    accountId: accountId,
                    encoder: encoder
                ))
            }
        }

        for localSend in localSends {
            if !serverIds.contains(localSend.id) && localSend.syncStatus == .synced {
                context.delete(localSend)
            }
        }
    }

    // MARK: - Conflict Resolution

    /// Resolve conflicts using last-write-wins on revision date.
    private func resolveConflict(local: PersistedCipher, server: Cipher) throws {
        let serverDate = server.revisionDate ?? Date.distantPast
        let localDate = local.localModifiedDate ?? local.revisionDate

        if serverDate > localDate {
            // Server wins — overwrite local
            try local.update(from: server, encoder: encoder)
            logger.info("Conflict resolved: server wins for cipher \(local.id)")
        } else {
            // Local wins — keep local, mark for upload
            local.syncStatus = .pendingUpload
            logger.info("Conflict resolved: local wins for cipher \(local.id)")
        }
    }

    // MARK: - Offline Queue

    /// Drain all pending offline operations.
    private func drainOfflineQueue() async throws {
        let context = modelContainer.mainContext

        // Process pending cipher operations
        let localAccountId = accountId
        let pendingCiphers = FetchDescriptor<PersistedCipher>(
            predicate: #Predicate {
                $0.accountId == localAccountId && $0.syncStatusRawValue != 0
            }
        )
        let ciphers = try context.fetch(pendingCiphers)
        let cipherAPI = CipherAPI(client: apiClient)

        for cipher in ciphers {
            do {
                try await processPendingCipher(cipher, api: cipherAPI, context: context)
            } catch {
                logger.error("Failed to sync cipher \(cipher.id): \(error.localizedDescription)")
                cipher.syncStatus = .conflicted
            }
        }

        // Process pending folder operations
        let pendingFolders = FetchDescriptor<PersistedFolder>(
            predicate: #Predicate {
                $0.accountId == localAccountId && $0.syncStatusRawValue != 0
            }
        )
        let folders = try context.fetch(pendingFolders)
        let folderAPI = FolderAPI(client: apiClient)

        for folder in folders {
            do {
                try await processPendingFolder(folder, api: folderAPI, context: context)
            } catch {
                logger.error("Failed to sync folder \(folder.id): \(error.localizedDescription)")
                folder.syncStatus = .conflicted
            }
        }

        try context.save()
    }

    /// Process a single pending cipher operation.
    private func processPendingCipher(
        _ persisted: PersistedCipher,
        api: CipherAPI,
        context: ModelContext
    ) async throws {
        guard let operation = persisted.pendingOperation else { return }
        let cipher = try persisted.toCipher()

        switch operation {
        case .create:
            let created = try await api.create(cipher)
            try persisted.update(from: created, encoder: encoder)

        case .update:
            let updated = try await api.update(cipher)
            try persisted.update(from: updated, encoder: encoder)

        case .delete:
            try await api.delete(id: persisted.id)
            context.delete(persisted)

        case .softDelete:
            try await api.softDelete(id: persisted.id)
            persisted.syncStatus = .synced
            persisted.pendingOperation = nil

        case .restore:
            try await api.restore(id: persisted.id)
            persisted.syncStatus = .synced
            persisted.pendingOperation = nil
        }
    }

    /// Process a single pending folder operation.
    private func processPendingFolder(
        _ persisted: PersistedFolder,
        api: FolderAPI,
        context: ModelContext
    ) async throws {
        guard let operation = persisted.pendingOperation else { return }

        switch operation {
        case .create, .update:
            guard let encName = try? EncString(serialized: persisted.encryptedName) else { return }
            if operation == .create {
                try await api.create(name: encName)
                // The server-assigned ID will be picked up on the next sync
            } else {
                try await api.update(id: persisted.id, name: encName)
            }
            persisted.syncStatus = .synced
            persisted.pendingOperation = nil

        case .delete:
            try await api.delete(id: persisted.id)
            context.delete(persisted)

        case .softDelete, .restore:
            break // Folders don't support soft-delete
        }
    }

    // MARK: - Local Operations

    /// Save a cipher locally and queue for sync.
    public func saveCipherLocally(_ cipher: Cipher, operation: PendingOperation) throws {
        let context = modelContainer.mainContext

        if operation == .create {
            let persisted = try PersistedCipher.from(
                cipher: cipher,
                accountId: accountId,
                encoder: encoder
            )
            persisted.syncStatus = .pendingCreate
            persisted.pendingOperation = .create
            persisted.localModifiedDate = Date()
            context.insert(persisted)
        } else {
            let cipherId = cipher.id ?? ""
            let localAccountId = accountId
            let fetchDescriptor = FetchDescriptor<PersistedCipher>(
                predicate: #Predicate { $0.id == cipherId && $0.accountId == localAccountId }
            )
            guard let persisted = try context.fetch(fetchDescriptor).first else {
                throw SyncError.itemNotFound(cipherId)
            }

            switch operation {
            case .update:
                try persisted.update(from: cipher, encoder: encoder)
                persisted.syncStatus = .pendingUpload
                persisted.pendingOperation = .update
                persisted.localModifiedDate = Date()

            case .delete:
                persisted.syncStatus = .pendingUpload
                persisted.pendingOperation = .delete
                persisted.localModifiedDate = Date()

            case .softDelete:
                persisted.deletedDate = Date()
                persisted.syncStatus = .pendingUpload
                persisted.pendingOperation = .softDelete
                persisted.localModifiedDate = Date()

            case .restore:
                persisted.deletedDate = nil
                persisted.syncStatus = .pendingUpload
                persisted.pendingOperation = .restore
                persisted.localModifiedDate = Date()

            case .create:
                break // Handled above
            }
        }

        try context.save()
        Task { await updatePendingCount() }
    }

    // MARK: - Queries

    /// Fetch all non-deleted ciphers for the current account.
    public func fetchCiphers(includeDeleted: Bool = false) throws -> [PersistedCipher] {
        let context = modelContainer.mainContext
        let fetchDescriptor: FetchDescriptor<PersistedCipher>
        let localAccountId = accountId

        if includeDeleted {
            fetchDescriptor = FetchDescriptor<PersistedCipher>(
                predicate: #Predicate { $0.accountId == localAccountId }
            )
        } else {
            fetchDescriptor = FetchDescriptor<PersistedCipher>(
                predicate: #Predicate { $0.accountId == localAccountId && $0.deletedDate == nil }
            )
        }
        return try context.fetch(fetchDescriptor)
    }

    /// Fetch all folders for the current account.
    public func fetchFolders() throws -> [PersistedFolder] {
        let context = modelContainer.mainContext
        let localAccountId = accountId
        let fetchDescriptor = FetchDescriptor<PersistedFolder>(
            predicate: #Predicate { $0.accountId == localAccountId }
        )
        return try context.fetch(fetchDescriptor)
    }

    /// Fetch all sends for the current account.
    public func fetchSends() throws -> [PersistedSend] {
        let context = modelContainer.mainContext
        let localAccountId = accountId
        let fetchDescriptor = FetchDescriptor<PersistedSend>(
            predicate: #Predicate { $0.accountId == localAccountId }
        )
        return try context.fetch(fetchDescriptor)
    }

    // MARK: - Helpers

    private func updatePendingCount() async {
        let context = modelContainer.mainContext
        let localAccountId = accountId
        let descriptor = FetchDescriptor<PersistedCipher>(
            predicate: #Predicate {
                $0.accountId == localAccountId && $0.syncStatusRawValue != 0
            }
        )
        pendingOperationCount = (try? context.fetchCount(descriptor)) ?? 0
    }
}

// MARK: - Sync Errors

public enum SyncError: Error, LocalizedError {
    case itemNotFound(String)
    case mergeConflict(String)
    case databaseError(String)

    public var errorDescription: String? {
        switch self {
        case .itemNotFound(let id): return "Item not found: \(id)"
        case .mergeConflict(let detail): return "Merge conflict: \(detail)"
        case .databaseError(let detail): return "Database error: \(detail)"
        }
    }
}
