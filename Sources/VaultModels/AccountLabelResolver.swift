// MARK: - VaultModels/AccountLabelResolver.swift
// Resolves short, unique display labels for on-device accounts.
// Used for the "[ACCOUNT] Credential Title" AutoFill prefixes.

import Foundation

/// Inputs the resolver needs per account.
public struct AccountLabelSource: Sendable {
    public let accountId: String
    public let shortName: String?
    public let alias: String?
    public let serverHost: String?
    public let email: String

    public init(accountId: String, shortName: String?, alias: String?, serverHost: String?, email: String) {
        self.accountId = accountId
        self.shortName = shortName
        self.alias = alias
        self.serverHost = serverHost
        self.email = email
    }

    public init(account: Account) {
        self.init(
            accountId: account.id,
            shortName: account.shortName,
            alias: account.alias,
            serverHost: account.serverURL.host,
            email: account.email
        )
    }
}

/// Resolves a display label per account using the chain
/// Short Name → Alias → registrable domain → full hostname → email,
/// taking the first value that is non-empty AND unique among all accounts.
public enum AccountLabelResolver {
    /// Returns accountId → label. Deterministic: candidates are claimed in
    /// priority passes, so a `shortName` always beats a colliding lower-priority
    /// candidate of another account.
    public static func resolveLabels(for accounts: [AccountLabelSource]) -> [String: String] {
        var resolved = [String: String]()
        var taken = Set<String>()

        let chains: [(id: String, candidates: [String?])] = accounts.map { source in
            let host = source.serverHost?.nilIfBlank?.lowercased()
            return (source.accountId, [
                source.shortName?.nilIfBlank,
                source.alias?.nilIfBlank,
                host.map { registrableDomain(of: $0) },
                host,
                source.email.nilIfBlank,
            ])
        }

        for pass in 0..<5 {
            // Candidates other unresolved accounts want in this same pass —
            // a value two accounts both claim now is unique for neither.
            var passCounts = [String: Int]()
            for chain in chains where resolved[chain.id] == nil {
                if let value = chain.candidates[pass] {
                    passCounts[value.lowercased(), default: 0] += 1
                }
            }
            for chain in chains where resolved[chain.id] == nil {
                guard let value = chain.candidates[pass] else { continue }
                let key = value.lowercased()
                if passCounts[key] == 1 && !taken.contains(key) {
                    resolved[chain.id] = value
                    taken.insert(key)
                }
            }
        }

        // Exhausted chain (e.g. same email on two servers, all else colliding).
        for source in accounts where resolved[source.accountId] == nil {
            let host = source.serverHost?.nilIfBlank ?? "?"
            var label = "\(source.email) (\(host))"
            var suffix = 2
            while taken.contains(label.lowercased()) {
                label = "\(source.email) (\(host)) #\(suffix)"
                suffix += 1
            }
            resolved[source.accountId] = label
            taken.insert(label.lowercased())
        }

        return resolved
    }

    /// Pragmatic registrable-domain approximation (display-only, not
    /// security-relevant): the last two host labels, or three when the TLD is
    /// two letters and the second-level label is a common SLD (`co`, `com`, …).
    public static func registrableDomain(of host: String) -> String {
        let labels = host.lowercased().split(separator: ".").map(String.init)
        let isIPAddress = labels.allSatisfy { $0.allSatisfy(\.isNumber) } || host.contains(":")
        guard labels.count > 2, !isIPAddress else { return host.lowercased() }

        let commonSLDs: Set<String> = ["co", "com", "org", "net", "gov", "edu", "ac"]
        let tld = labels[labels.count - 1]
        let sld = labels[labels.count - 2]
        let take = (tld.count == 2 && commonSLDs.contains(sld)) ? 3 : 2
        return labels.suffix(take).joined(separator: ".")
    }
}

extension String {
    /// `nil` when the string is empty or whitespace-only; trimmed otherwise.
    var nilIfBlank: String? {
        let trimmed = trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed.isEmpty ? nil : trimmed
    }
}
