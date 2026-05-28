// MARK: - VaultSync/SyncEngine.swift
// Orchestrates full and incremental vault synchronization

import Foundation
import SwiftData
import VaultModels
import VaultAPI
import VaultCrypto
import OSLog

private let logger = Logger(subsystem: "com.vaultui", category: "SyncEngine")

public extension Notification.Name {
    static let vaultUIDataDidChange = Notification.Name("VaultUIDataDidChange")
}

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
    public let modelContainer: ModelContainer
    public let accountId: String
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
            let syncActor = BackgroundSyncActor(
                modelContainer: modelContainer,
                apiClient: apiClient,
                accountId: accountId,
                encoder: encoder
            )

            try await syncActor.performSync()

            let date = Date()
            lastSyncDate = date
            
            // We can optionally keep the UserDefaults write, but it's ineffective without App Groups
            let sharedDefaults = UserDefaults(suiteName: "group.de.tobisk.apps.vaultui")
            sharedDefaults?.set(date, forKey: "VaultUILastSyncWithServer")
            
            syncState = .idle
            await updatePendingCount()

            logger.info("Full sync completed successfully")
        } catch {
            syncState = .error(error.localizedDescription)
            logger.error("Full sync failed: \(error.localizedDescription)")
            throw error
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
                if persisted.syncStatus == .temporaryDraft {
                    persisted.syncStatus = .pendingCreate
                    persisted.pendingOperation = .create
                } else {
                    persisted.syncStatus = .pendingUpload
                    persisted.pendingOperation = .update
                }
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
        NotificationCenter.default.post(name: .vaultUIDataDidChange, object: nil)
    }

    /// Save a local-only temporary draft credential.
    public func saveTemporaryCipherLocally(_ cipher: Cipher) throws {
        let context = modelContainer.mainContext
        var cipher = cipher
        if cipher.id == nil {
            cipher.id = UUID().uuidString
        }
        let cipherId = cipher.id ?? ""
        let localAccountId = accountId
        let fetchDescriptor = FetchDescriptor<PersistedCipher>(
            predicate: #Predicate { $0.id == cipherId && $0.accountId == localAccountId }
        )

        if let persisted = try context.fetch(fetchDescriptor).first {
            try persisted.update(from: cipher, encoder: encoder)
            persisted.syncStatus = .temporaryDraft
            persisted.pendingOperation = nil
            persisted.localModifiedDate = Date()
        } else {
            let persisted = try PersistedCipher.from(
                cipher: cipher,
                accountId: accountId,
                encoder: encoder,
                syncStatusRawValue: SyncStatus.temporaryDraft.rawValue
            )
            persisted.syncStatus = .temporaryDraft
            persisted.pendingOperation = nil
            persisted.localModifiedDate = Date()
            context.insert(persisted)
        }
        try context.save()
        Task { await updatePendingCount() }
        NotificationCenter.default.post(name: .vaultUIDataDidChange, object: nil)
    }

    /// Promote a temporary draft into a create-on-sync item.
    public func promoteTemporaryCipherLocally(_ cipher: Cipher) throws {
        let context = modelContainer.mainContext
        let cipherId = cipher.id ?? ""
        let localAccountId = accountId
        let fetchDescriptor = FetchDescriptor<PersistedCipher>(
            predicate: #Predicate { $0.id == cipherId && $0.accountId == localAccountId }
        )
        guard let persisted = try context.fetch(fetchDescriptor).first else {
            throw SyncError.itemNotFound(cipherId)
        }

        try persisted.update(from: cipher, encoder: encoder)
        persisted.syncStatus = .pendingCreate
        persisted.pendingOperation = .create
        persisted.localModifiedDate = Date()
        try context.save()
        Task { await updatePendingCount() }
    }

    /// Delete a local cipher without syncing to the server.
    public func deleteLocalCipher(_ cipher: Cipher) throws {
        let context = modelContainer.mainContext
        let cipherId = cipher.id ?? ""
        let localAccountId = accountId
        let fetchDescriptor = FetchDescriptor<PersistedCipher>(
            predicate: #Predicate { $0.id == cipherId && $0.accountId == localAccountId }
        )
        guard let persisted = try context.fetch(fetchDescriptor).first else { return }
        context.delete(persisted)
        try context.save()
        Task { await updatePendingCount() }
        NotificationCenter.default.post(name: .vaultUIDataDidChange, object: nil)
    }

    /// Save a folder locally and queue for sync.
    public func saveFolderLocally(_ folder: Folder, operation: PendingOperation) throws {
        let context = modelContainer.mainContext

        if operation == .create {
            let persisted = PersistedFolder.from(
                folder: folder,
                accountId: accountId
            )
            persisted.syncStatus = .pendingCreate
            persisted.pendingOperation = .create
            context.insert(persisted)
        } else {
            let folderId = folder.id ?? ""
            let localAccountId = accountId
            let fetchDescriptor = FetchDescriptor<PersistedFolder>(
                predicate: #Predicate { $0.id == folderId && $0.accountId == localAccountId }
            )
            guard let persisted = try context.fetch(fetchDescriptor).first else {
                throw SyncError.itemNotFound(folderId)
            }

            switch operation {
            case .update:
                persisted.encryptedName = folder.name?.serialized() ?? ""
                persisted.syncStatus = .pendingUpload
                persisted.pendingOperation = .update

            case .delete:
                persisted.syncStatus = .pendingUpload
                persisted.pendingOperation = .delete

            case .softDelete, .restore:
                break // Folders don't support soft delete
            case .create:
                break
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
        let descriptor: FetchDescriptor<PersistedCipher> = FetchDescriptor<PersistedCipher>(
            predicate: #Predicate {
                $0.accountId == localAccountId && $0.syncStatusRawValue != 0 && $0.syncStatusRawValue != 4
            }
        )
        pendingOperationCount = (try? context.fetchCount(descriptor)) ?? 0
    }
}

// MARK: - Background Sync Actor

private actor BackgroundSyncActor {
    private let modelContainer: ModelContainer
    private let apiClient: APIClient
    private let accountId: String
    private let encoder: JSONEncoder

    init(modelContainer: ModelContainer, apiClient: APIClient, accountId: String, encoder: JSONEncoder) {
        self.modelContainer = modelContainer
        self.apiClient = apiClient
        self.accountId = accountId
        self.encoder = encoder
    }

    func performSync() async throws {
        let context = ModelContext(modelContainer)
        
        try await drainOfflineQueue(context: context)
        
        let syncAPI = SyncAPI(client: apiClient)
        let response = try await syncAPI.fullSync()
        
        try await mergeServerResponse(response, in: context)
    }

    // MARK: - Merge Server Response

    /// Merge the full sync response into the local SwiftData store.
    private func mergeServerResponse(_ response: SyncResponse, in context: ModelContext) async throws {
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

        for (index, serverCipher) in serverCiphers.enumerated() {
            if index > 0 && index % 20 == 0 { await Task.yield() }
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
        for (index, localCipher) in localCiphers.enumerated() {
            if index > 0 && index % 20 == 0 { await Task.yield() }
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

        for (index, serverFolder) in serverFolders.enumerated() {
            if index > 0 && index % 20 == 0 { await Task.yield() }
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

        for (index, localFolder) in localFolders.enumerated() {
            if index > 0 && index % 20 == 0 { await Task.yield() }
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

        for (index, serverSend) in serverSends.enumerated() {
            if index > 0 && index % 20 == 0 { await Task.yield() }
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

        for (index, localSend) in localSends.enumerated() {
            if index > 0 && index % 20 == 0 { await Task.yield() }
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
    private func drainOfflineQueue(context: ModelContext) async throws {
        // Process pending cipher operations
        let localAccountId = accountId
        let pendingCiphers = FetchDescriptor<PersistedCipher>(
            predicate: #Predicate {
                $0.accountId == localAccountId && $0.syncStatusRawValue != 0 && $0.syncStatusRawValue != 4
            }
        )
        let ciphers = try context.fetch(pendingCiphers)
        let cipherAPI = CipherAPI(client: apiClient)

        for (index, cipher) in ciphers.enumerated() {
            if index > 0 && index % 10 == 0 { await Task.yield() }
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

        for (index, folder) in folders.enumerated() {
            if index > 0 && index % 10 == 0 { await Task.yield() }
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
            persisted.syncStatus = .synced
            persisted.pendingOperation = nil

        case .update:
            let updated = try await api.update(cipher)
            try persisted.update(from: updated, encoder: encoder)
            persisted.syncStatus = .synced
            persisted.pendingOperation = nil

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
