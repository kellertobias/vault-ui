// MARK: - VaultSync/PersistedModels.swift
// SwiftData models for local vault persistence
//
// IMPORTANT: Only encrypted data and non-sensitive metadata is stored on disk.
// Raw plaintext never touches the filesystem.

import Foundation
import SwiftData
import VaultModels
import VaultCrypto
import VaultAPI

/// A locally persisted vault item (cipher).
///
/// Stores the encrypted JSON blob from the server plus sync metadata.
/// Decryption only happens in memory when the vault is unlocked.
@Model
public final class PersistedCipher {
    /// Server-assigned cipher ID
    @Attribute(.unique)
    public var id: String

    /// Account this cipher belongs to
    public var accountId: String

    /// The cipher type (raw value for SwiftData compatibility)
    public var typeRawValue: Int

    /// Folder ID (nil = unfiled)
    public var folderId: String?

    /// Organization ID (nil = personal)
    public var organizationId: String?

    /// Collection IDs (stored as JSON array string)
    public var collectionIdsJSON: String?

    /// Whether this is a favorite
    public var isFavorite: Bool

    /// The full encrypted cipher JSON blob from the server
    public var encryptedJSON: Data

    /// Server revision date for conflict resolution
    public var revisionDate: Date

    /// Creation date
    public var creationDate: Date?

    /// Soft-delete date (nil = not deleted)
    public var deletedDate: Date?

    /// Local sync status
    public var syncStatusRawValue: Int

    /// Timestamp of last local modification
    public var localModifiedDate: Date?

    /// Pending operation for offline queue (nil = synced)
    public var pendingOperationRawValue: Int?

    public init(
        id: String,
        accountId: String,
        typeRawValue: Int,
        folderId: String? = nil,
        organizationId: String? = nil,
        isFavorite: Bool = false,
        encryptedJSON: Data,
        revisionDate: Date,
        creationDate: Date? = nil,
        deletedDate: Date? = nil,
        syncStatusRawValue: Int = SyncStatus.synced.rawValue
    ) {
        self.id = id
        self.accountId = accountId
        self.typeRawValue = typeRawValue
        self.folderId = folderId
        self.organizationId = organizationId
        self.isFavorite = isFavorite
        self.encryptedJSON = encryptedJSON
        self.revisionDate = revisionDate
        self.creationDate = creationDate
        self.deletedDate = deletedDate
        self.syncStatusRawValue = syncStatusRawValue
    }

    // MARK: - Convenience

    /// The cipher type enum
    public var cipherType: CipherType? {
        CipherType(rawValue: typeRawValue)
    }

    /// The sync status
    public var syncStatus: SyncStatus {
        get { SyncStatus(rawValue: syncStatusRawValue) ?? .synced }
        set { syncStatusRawValue = newValue.rawValue }
    }

    /// The pending operation
    public var pendingOperation: PendingOperation? {
        get { pendingOperationRawValue.flatMap { PendingOperation(rawValue: $0) } }
        set { pendingOperationRawValue = newValue?.rawValue }
    }

    /// Whether this item is in the trash
    public var isDeleted: Bool {
        deletedDate != nil
    }

    /// Decode the stored encrypted JSON back to a Cipher model.
    public func toCipher() throws -> Cipher {
        try VaultJSONDecoder.shared.decode(Cipher.self, from: encryptedJSON)
    }

    /// Update from a server Cipher response.
    public func update(from cipher: Cipher, encoder: JSONEncoder) throws {
        self.typeRawValue = cipher.type.rawValue
        self.folderId = cipher.folderId
        self.organizationId = cipher.organizationId
        self.isFavorite = cipher.favorite
        self.encryptedJSON = try encoder.encode(cipher)
        self.revisionDate = cipher.revisionDate ?? Date()
        self.creationDate = cipher.creationDate
        self.deletedDate = cipher.deletedDate
        self.syncStatus = .synced
        self.pendingOperation = nil
    }

    /// Create from a server Cipher response.
    public static func from(cipher: Cipher, accountId: String, encoder: JSONEncoder) throws -> PersistedCipher {
        PersistedCipher(
            id: cipher.id ?? UUID().uuidString,
            accountId: accountId,
            typeRawValue: cipher.type.rawValue,
            folderId: cipher.folderId,
            organizationId: cipher.organizationId,
            isFavorite: cipher.favorite,
            encryptedJSON: try encoder.encode(cipher),
            revisionDate: cipher.revisionDate ?? Date(),
            creationDate: cipher.creationDate,
            deletedDate: cipher.deletedDate
        )
    }

    public static func from(
        cipher: Cipher,
        accountId: String,
        encoder: JSONEncoder,
        syncStatusRawValue: Int
    ) throws -> PersistedCipher {
        PersistedCipher(
            id: cipher.id ?? UUID().uuidString,
            accountId: accountId,
            typeRawValue: cipher.type.rawValue,
            folderId: cipher.folderId,
            organizationId: cipher.organizationId,
            isFavorite: cipher.favorite,
            encryptedJSON: try encoder.encode(cipher),
            revisionDate: cipher.revisionDate ?? Date(),
            creationDate: cipher.creationDate,
            deletedDate: cipher.deletedDate,
            syncStatusRawValue: syncStatusRawValue
        )
    }
}

/// A locally persisted folder.
@Model
public final class PersistedFolder {
    @Attribute(.unique)
    public var id: String

    public var accountId: String

    /// Encrypted folder name (serialized EncString)
    public var encryptedName: String

    public var revisionDate: Date

    public var syncStatusRawValue: Int
    public var pendingOperationRawValue: Int?

    public init(
        id: String,
        accountId: String,
        encryptedName: String,
        revisionDate: Date,
        syncStatusRawValue: Int = SyncStatus.synced.rawValue
    ) {
        self.id = id
        self.accountId = accountId
        self.encryptedName = encryptedName
        self.revisionDate = revisionDate
        self.syncStatusRawValue = syncStatusRawValue
    }

    public var syncStatus: SyncStatus {
        get { SyncStatus(rawValue: syncStatusRawValue) ?? .synced }
        set { syncStatusRawValue = newValue.rawValue }
    }

    public var pendingOperation: PendingOperation? {
        get { pendingOperationRawValue.flatMap { PendingOperation(rawValue: $0) } }
        set { pendingOperationRawValue = newValue?.rawValue }
    }

    public static func from(folder: Folder, accountId: String) -> PersistedFolder {
        PersistedFolder(
            id: folder.id ?? UUID().uuidString,
            accountId: accountId,
            encryptedName: folder.name?.serialized() ?? "",
            revisionDate: folder.revisionDate ?? Date()
        )
    }
}

/// A locally persisted Send item.
@Model
public final class PersistedSend {
    @Attribute(.unique)
    public var id: String

    public var accountId: String
    public var typeRawValue: Int
    public var encryptedJSON: Data
    public var revisionDate: Date
    public var expirationDate: Date?
    public var deletionDate: Date?
    public var disabled: Bool

    public var syncStatusRawValue: Int
    public var pendingOperationRawValue: Int?

    public init(
        id: String,
        accountId: String,
        typeRawValue: Int,
        encryptedJSON: Data,
        revisionDate: Date,
        expirationDate: Date? = nil,
        deletionDate: Date? = nil,
        disabled: Bool = false,
        syncStatusRawValue: Int = SyncStatus.synced.rawValue
    ) {
        self.id = id
        self.accountId = accountId
        self.typeRawValue = typeRawValue
        self.encryptedJSON = encryptedJSON
        self.revisionDate = revisionDate
        self.expirationDate = expirationDate
        self.deletionDate = deletionDate
        self.disabled = disabled
        self.syncStatusRawValue = syncStatusRawValue
    }

    public var syncStatus: SyncStatus {
        get { SyncStatus(rawValue: syncStatusRawValue) ?? .synced }
        set { syncStatusRawValue = newValue.rawValue }
    }

    public static func from(send: SendItem, accountId: String, encoder: JSONEncoder) throws -> PersistedSend {
        PersistedSend(
            id: send.id ?? UUID().uuidString,
            accountId: accountId,
            typeRawValue: send.type.rawValue,
            encryptedJSON: try encoder.encode(send),
            revisionDate: send.revisionDate ?? Date(),
            expirationDate: send.expirationDate,
            deletionDate: send.deletionDate,
            disabled: send.disabled ?? false
        )
    }

    public func toSendItem() throws -> SendItem {
        try VaultJSONDecoder.shared.decode(SendItem.self, from: encryptedJSON)
    }
}

/// A persisted account configuration.
@Model
public final class PersistedAccount {
    @Attribute(.unique)
    public var id: String

    public var email: String
    public var serverURLString: String
    public var kdfTypeRawValue: Int
    public var kdfIterations: Int
    public var kdfMemory: Int?
    public var kdfParallelism: Int?

    /// Last successful full sync date
    public var lastSyncDate: Date?

    /// Whether this is the currently active account
    public var isActive: Bool

    public init(
        id: String,
        email: String,
        serverURLString: String,
        kdfTypeRawValue: Int,
        kdfIterations: Int,
        kdfMemory: Int? = nil,
        kdfParallelism: Int? = nil,
        isActive: Bool = false
    ) {
        self.id = id
        self.email = email
        self.serverURLString = serverURLString
        self.kdfTypeRawValue = kdfTypeRawValue
        self.kdfIterations = kdfIterations
        self.kdfMemory = kdfMemory
        self.kdfParallelism = kdfParallelism
        self.isActive = isActive
    }

    public func toAccount() -> Account? {
        guard let url = URL(string: serverURLString),
              let kdfType = KDFType(rawValue: kdfTypeRawValue) else {
            return nil
        }
        return Account(
            id: id,
            email: email,
            serverURL: url,
            kdfConfig: KDFConfig(
                type: kdfType,
                iterations: UInt32(kdfIterations),
                memory: kdfMemory.map { UInt32($0) },
                parallelism: kdfParallelism.map { UInt32($0) }
            )
        )
    }

    public static func from(account: Account) -> PersistedAccount {
        PersistedAccount(
            id: account.id,
            email: account.email,
            serverURLString: account.serverURL.absoluteString,
            kdfTypeRawValue: account.kdfConfig.type.rawValue,
            kdfIterations: Int(account.kdfConfig.iterations),
            kdfMemory: account.kdfConfig.memory.map { Int($0) },
            kdfParallelism: account.kdfConfig.parallelism.map { Int($0) }
        )
    }
}

// MARK: - Sync Status & Operations

/// Sync state for a persisted item.
public enum SyncStatus: Int, Codable, Sendable {
    /// Item is in sync with the server
    case synced = 0
    /// Item has local changes not yet pushed
    case pendingUpload = 1
    /// Item was created locally and needs to be created on server
    case pendingCreate = 2
    /// Item failed to sync — needs manual retry or conflict resolution
    case conflicted = 3
    /// Local-only draft credential waiting to be promoted.
    case temporaryDraft = 4
}

/// Pending offline operation.
public enum PendingOperation: Int, Codable, Sendable {
    case create = 0
    case update = 1
    case delete = 2
    case softDelete = 3
    case restore = 4
}
