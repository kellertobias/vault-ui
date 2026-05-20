// MARK: - VaultSync/SyncScheduler.swift
// Background sync scheduler with configurable intervals

import Foundation
import Combine
import OSLog

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
            try await syncEngine.fullSync()
        } catch {
            logger.error("Background sync failed: \(error.localizedDescription)")
        }
    }

}
