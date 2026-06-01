// MARK: - VaultModels/VaultNotificationCenter.swift
// Shared macOS user notifications for vault activity.

import Foundation
@preconcurrency import UserNotifications

public enum VaultNotificationCenter {
    public static func notify(title: String, body: String) {
        let center = UNUserNotificationCenter.current()

        center.getNotificationSettings { settings in
            switch settings.authorizationStatus {
            case .authorized, .provisional, .ephemeral:
                deliver(title: title, body: body, center: center)
            case .notDetermined:
                center.requestAuthorization(options: [.alert, .sound]) { granted, _ in
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
        content.sound = .default

        let request = UNNotificationRequest(
            identifier: "vaultui.\(UUID().uuidString)",
            content: content,
            trigger: nil
        )

        center.add(request)
    }
}
