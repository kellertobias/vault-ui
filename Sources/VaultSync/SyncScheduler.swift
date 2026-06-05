// MARK: - VaultSync/SyncScheduler.swift
// Background sync scheduler with configurable intervals

import Foundation
import Combine
import OSLog
import VaultAPI
import VaultModels

private let logger = Logger(subsystem: "com.vaultui", category: "SyncScheduler")

/// Schedules periodic background sync operations.
@MainActor
public final class SyncScheduler: ObservableObject {
    /// Default sync interval: 5 minutes
    public static let defaultInterval: TimeInterval = 300
    private static let persistentNetworkFailureThreshold: TimeInterval = 24 * 60 * 60
    private static let persistentNetworkFailureNotificationInterval: TimeInterval = 6 * 60 * 60

    /// Whether background sync is enabled
    @Published public var isEnabled: Bool = true

    /// Sync interval in seconds
    @Published public var interval: TimeInterval = SyncScheduler.defaultInterval

    private let syncEngine: SyncEngine
    private var timer: Timer?
    private var networkMonitor: Any?  // NWPathMonitor — set up at runtime
    private var lastSuccessNotificationDate: Date?
    private var lastFailureNotificationDate: Date?
    private var persistentNetworkFailureStartedAtKey: String {
        "backgroundSyncPersistentNetworkFailureStartedAt.\(syncEngine.accountId)"
    }

    public init(syncEngine: SyncEngine) {
        self.syncEngine = syncEngine
    }

    /// Start the background sync scheduler.
    public func start() {
        stop()
        guard isEnabled else { return }

        logger.info("Starting sync scheduler with \(Int(self.interval))s interval")

        timer = Timer.scheduledTimer(withTimeInterval: interval, repeats: true) { [weak self] _ in
            Task { @MainActor [weak self] in
                guard let self = self else { return }
                await self.performBackgroundSync()
            }
        }

        // Perform an initial sync
        Task {
            await performBackgroundSync()
        }
    }

    /// Stop the scheduler.
    public func stop() {
        timer?.invalidate()
        timer = nil
    }

    /// Trigger a manual sync.
    public func syncNow() async {
        await performBackgroundSync()
    }

    private func performBackgroundSync() async {
        guard syncEngine.syncState != .syncing else { return }

        do {
            let shouldNotify = try await syncEngine.fullSync()
            resetPersistentNetworkFailureTracking()
            notifySuccessfulBackgroundSyncIfNeeded(shouldNotify: shouldNotify)
        } catch {
            logger.error("Background sync failed: \(error.localizedDescription)")
            notifyFailedBackgroundSyncIfNeeded(error)
        }
    }

    private func notifySuccessfulBackgroundSyncIfNeeded(shouldNotify: Bool) {
        guard shouldNotify else { return }

        guard defaultedBool(forKey: "backgroundSyncStatusNotifications", defaultValue: true) else {
            return
        }

        let now = Date()
        if let lastSuccessNotificationDate,
           now.timeIntervalSince(lastSuccessNotificationDate) < 30 * 60 {
            return
        }

        lastSuccessNotificationDate = now
        VaultNotificationCenter.notify(
            title: "Vault synced",
            body: "Background sync completed successfully."
        )
    }

    private func notifyFailedBackgroundSyncIfNeeded(_ error: Error) {
        if error.isNetworkError {
            notifyPersistentNetworkFailureIfNeeded(error)
            return
        }

        resetPersistentNetworkFailureTracking()

        let now = Date()
        if let lastFailureNotificationDate,
           now.timeIntervalSince(lastFailureNotificationDate) < 15 * 60 {
            return
        }

        lastFailureNotificationDate = now
        VaultNotificationCenter.notify(
            title: "Vault sync failed",
            body: error.localizedDescription
        )
    }

    private func notifyPersistentNetworkFailureIfNeeded(_ error: Error) {
        let now = Date()
        let startedAt = persistentNetworkFailureStartedAt ?? now

        if persistentNetworkFailureStartedAt == nil {
            persistentNetworkFailureStartedAt = startedAt
        }

        let duration = now.timeIntervalSince(startedAt)
        guard duration >= Self.persistentNetworkFailureThreshold else {
            logger.info("Suppressing transient background sync network failure after \(Int(duration))s")
            return
        }

        if let lastFailureNotificationDate,
           now.timeIntervalSince(lastFailureNotificationDate) < Self.persistentNetworkFailureNotificationInterval {
            return
        }

        lastFailureNotificationDate = now
        VaultNotificationCenter.notify(
            title: "Vault sync offline",
            body: "Background sync has been unable to reach the server for more than 24 hours. Latest error: \(error.localizedDescription)"
        )
    }

    private var persistentNetworkFailureStartedAt: Date? {
        get {
            let timestamp = UserDefaults.standard.double(forKey: persistentNetworkFailureStartedAtKey)
            return timestamp > 0 ? Date(timeIntervalSince1970: timestamp) : nil
        }
        set {
            if let newValue {
                UserDefaults.standard.set(newValue.timeIntervalSince1970, forKey: persistentNetworkFailureStartedAtKey)
            } else {
                UserDefaults.standard.removeObject(forKey: persistentNetworkFailureStartedAtKey)
            }
        }
    }

    private func resetPersistentNetworkFailureTracking() {
        persistentNetworkFailureStartedAt = nil
    }

    private func defaultedBool(forKey key: String, defaultValue: Bool) -> Bool {
        UserDefaults.standard.object(forKey: key) == nil
            ? defaultValue
            : UserDefaults.standard.bool(forKey: key)
    }
}

private extension Error {
    var isNetworkError: Bool {
        guard let apiError = self as? APIError else { return false }
        if case .networkError = apiError {
            return true
        }
        return false
    }
}
