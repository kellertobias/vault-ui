// MARK: - VaultModels/VaultNotificationCenter.swift
// Shared macOS user notifications for vault activity.

import Foundation
@preconcurrency import UserNotifications

public enum VaultNotificationCenter {
    /// Whether the current process can host user notifications.
    ///
    /// `UNUserNotificationCenter.current()` raises an Objective-C exception
    /// (uncatchable from Swift) when the process is not a real app or app
    /// extension bundle — e.g. the `vaultui` CLI, the xctest runner, or any
    /// headless tool. Gate on the bundle being an `.app`/`.appex` so those
    /// contexts degrade to a no-op instead of crashing.
    private static let canDeliverNotifications: Bool = {
        let ext = Bundle.main.bundleURL.pathExtension
        return ext == "app" || ext == "appex"
    }()

    public static func notify(title: String, body: String) {
        guard canDeliverNotifications else { return }
        let center = UNUserNotificationCenter.current()

        center.getNotificationSettings { settings in
            switch settings.authorizationStatus {
            case .authorized, .provisional, .ephemeral:
                deliver(title: title, body: body, center: center)
            case .notDetermined:
                center.requestAuthorization(options: [.alert]) { granted, _ in
                    guard granted else { return }
                    deliver(title: title, body: body, center: center)
                }
            case .denied:
                return
            @unknown default:
                return
            }
        }
    }

    public static func notifyList(title: String, itemSingular: String, itemPlural: String, names: [String]) {
        guard !names.isEmpty else { return }

        let count = names.count
        let label = count == 1 ? itemSingular : itemPlural
        let visibleNames = names.prefix(3).joined(separator: ", ")
        let remainder = count > 3 ? " and \(count - 3) more" : ""
        notify(title: title, body: "\(count) \(label): \(visibleNames)\(remainder)")
    }

    private static func deliver(title: String, body: String, center: UNUserNotificationCenter) {
        let content = UNMutableNotificationContent()
        content.title = title
        content.body = body

        let request = UNNotificationRequest(
            identifier: "vaultui.\(UUID().uuidString)",
            content: content,
            trigger: nil
        )

        center.add(request)
    }
}
