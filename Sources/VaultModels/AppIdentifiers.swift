// MARK: - VaultModels/AppIdentifiers.swift
// Runtime identifiers derived from Info.plist build settings.

import Foundation

public enum AppIdentifiers {
    public static var bundleIdentifier: String {
        string(for: "VaultUIBundleIdentifier")
            ?? Bundle.main.bundleIdentifier
            ?? "com.example.vaultui"
    }

    public static var autoFillExtensionBundleIdentifier: String {
        string(for: "VaultUIAutoFillExtensionBundleIdentifier")
            ?? "\(bundleIdentifier).AutoFillExtension"
    }

    public static var safariExtensionBundleIdentifier: String {
        string(for: "VaultUISafariExtensionBundleIdentifier")
            ?? "\(bundleIdentifier).SafariExtension"
    }

    public static var appGroupIdentifier: String {
        string(for: "VaultUIAppGroupIdentifier")
            ?? "group.\(bundleIdentifier)"
    }

    public static var teamPrefixedAppGroupIdentifier: String {
        string(for: "VaultUITeamPrefixedAppGroupIdentifier")
            ?? appGroupIdentifier
    }

    public static var keychainAccessGroup: String {
        string(for: "VaultUIKeychainAccessGroup")
            ?? "\(bundleIdentifier).shared"
    }

    public static func serviceName(_ suffix: String) -> String {
        "\(bundleIdentifier).\(suffix)"
    }

    private static func string(for key: String) -> String? {
        guard let value = Bundle.main.object(forInfoDictionaryKey: key) as? String else {
            return nil
        }

        let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty, !trimmed.contains("$(") else {
            return nil
        }

        return trimmed
    }
}
