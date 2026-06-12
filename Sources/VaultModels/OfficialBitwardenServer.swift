// MARK: - VaultModels/OfficialBitwardenServer.swift
// Detection of the official Bitwarden cloud, which this client does not fully support.

import Foundation

/// Vault UI targets Vaultwarden. The core Bitwarden-cloud differences
/// (Auth-Email header, Azure attachment uploads, two-phase Send upload) are
/// implemented, but support remains experimental — most notably organization
/// vaults are unsupported — so we still warn before connecting.
///
/// See `docs/missing-features/bitwarden-com-compatibility.md`.
public enum OfficialBitwardenServer {
    /// Host suffixes operated by Bitwarden's official cloud.
    private static let officialSuffixes = ["bitwarden.com", "bitwarden.eu"]

    /// Whether the host belongs to the official Bitwarden cloud.
    public static func isOfficial(host: String?) -> Bool {
        guard let host = host?.lowercased(), !host.isEmpty else { return false }
        return officialSuffixes.contains { host == $0 || host.hasSuffix(".\($0)") }
    }

    /// Whether the URL points at the official Bitwarden cloud.
    public static func isOfficial(url: URL?) -> Bool {
        isOfficial(host: url?.host)
    }

    /// Whether the string (a URL or bare host) points at the official Bitwarden cloud.
    public static func isOfficial(urlString: String) -> Bool {
        let trimmed = urlString.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return false }
        if let host = URL(string: trimmed)?.host {
            return isOfficial(host: host)
        }
        // Bare host without a scheme.
        let host = trimmed.components(separatedBy: "/").first?.components(separatedBy: ":").first
        return isOfficial(host: host)
    }

    /// User-facing warning shown when an official Bitwarden server is detected.
    public static let warningMessage =
        "Vault UI is built for Vaultwarden. Support for official Bitwarden servers "
        + "(bitwarden.com / bitwarden.eu) is experimental — organization vaults are not supported."
}
