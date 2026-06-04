// MARK: - VaultSync/SyncScheduler.swift
// Background sync scheduler with configurable intervals

import Foundation
import Combine
import OSLog
import VaultModels

private let logger = Logger(subsystem: "com.vaultui", category: "SyncScheduler")

/// Schedules periodic background sync operations.
@MainActor
public final class SyncScheduler: ObservableObject {
    /// Default sync interval: 5 minutes
    public static let defaultInterval: TimeInterval = 300

    /// Whether background sync is enabled
    @Published public var isEnabled: Bool = true

    /// Sync interval in seconds
    @Published public var interval: TimeInterval = SyncScheduler.defaultInterval

    private let syncEngine: SyncEngine
    private var timer: Timer?
    private var networkMonitor: Any?  // NWPathMonitor — set up at runtime
    private var lastSuccessNotificationDate: Date?
    private var lastFailureNotificationDate: Date?

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

    private func defaultedBool(forKey key: String, defaultValue: Bool) -> Bool {
        UserDefaults.standard.object(forKey: key) == nil
            ? defaultValue
            : UserDefaults.standard.bool(forKey: key)
    }
}
