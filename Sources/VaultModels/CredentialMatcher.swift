// MARK: - VaultModels/CredentialMatcher.swift
// Shared, phishing-resistant credential/URL matching.
//
// A single matcher used by every surface that decides whether a stored
// credential should be offered for a page or app (the macOS AutoFill provider,
// the Safari Web Extension bridge, and the system Credential Provider service).
// Keeping one implementation avoids the class of bug where one matcher is
// hardened while another keeps a loose `hasPrefix`/`hasSuffix` compare that a
// look-alike origin (e.g. `paypal.com.evil.com`) can satisfy.
//
// Matching is decided on three independent, boundary-aware checks. A stored URI
// matches a requesting site only if ALL three pass:
//
//   1. Domain   — site host must equal the secret's domain or be a proper
//                 subdomain of it (label boundary, never a raw string suffix).
//   2. Protocol — site scheme must be "as secure or better" than the secret's
//                 (http secret -> http/https; https secret -> https; no secret
//                 scheme -> any).
//   3. Path     — if the secret pins a path, the site path must be that path or
//                 a sub-path (segment boundary); no secret path -> any path.

import Foundation

public enum CredentialMatcher {

    /// How closely a stored credential matches the requesting site.
    /// Higher is a better match; used to rank AutoFill suggestions.
    public enum MatchQuality: Int, Comparable, Sendable {
        case none = 0
        case domainMatch = 1   // site host is a subdomain of the secret's domain (all rules satisfied)
        case fqdnMatch = 2      // site host exactly equals the secret's domain (all rules satisfied)
        case exactMatch = 3     // the full URI strings are identical

        public static func < (lhs: MatchQuality, rhs: MatchQuality) -> Bool {
            return lhs.rawValue < rhs.rawValue
        }
    }

    /// The parts of a URL/URI relevant for credential matching.
    public struct URIParts: Sendable, Equatable {
        public let scheme: String?   // nil when the input carried no scheme
        public let host: String      // lowercased host, without userinfo or port; "" if absent
        public let path: String      // normalized path without a trailing slash; "" means root / none
    }

    // MARK: - Public API

    /// Rate how well a single stored URI matches a requesting site identifier.
    public static func matchQuality(storedURI: String, siteIdentifier: String) -> MatchQuality {
        let rawSite = siteIdentifier.lowercased()
        let site = deconstruct(rawSite)

        // Without a parseable site host we cannot make a safe matching decision.
        guard !site.host.isEmpty else { return .none }

        let rawSecret = storedURI.lowercased()
        let secret = deconstruct(rawSecret)

        // Resolve the secret's base domain, honoring an optional "*." wildcard.
        let isWildcard = secret.host.hasPrefix("*.")
        let baseDomain = isWildcard ? String(secret.host.dropFirst(2)) : secret.host
        guard !baseDomain.isEmpty else { return .none }

        // 1. Domain rule (subdomain match uses a label boundary).
        let hostExact = !isWildcard && site.host == baseDomain
        let hostMatches = site.host == baseDomain || site.host.hasSuffix("." + baseDomain)
        guard hostMatches else { return .none }

        // 2. Protocol rule.
        guard protocolSatisfied(secretScheme: secret.scheme, siteScheme: site.scheme) else { return .none }

        // 3. Path rule.
        guard pathSatisfied(secretPath: secret.path, sitePath: site.path) else { return .none }

        if rawSite == rawSecret { return .exactMatch }
        if hostExact { return .fqdnMatch }
        return .domainMatch
    }

    /// The best match quality across a set of stored URIs for one credential.
    public static func bestMatchQuality(storedURIs: [String], siteIdentifier: String) -> MatchQuality {
        storedURIs.reduce(.none) { best, uri in
            max(best, matchQuality(storedURI: uri, siteIdentifier: siteIdentifier))
        }
    }

    /// Whether a stored URI matches a requesting site identifier at all.
    public static func matches(storedURI: String, siteIdentifier: String) -> Bool {
        matchQuality(storedURI: storedURI, siteIdentifier: siteIdentifier) != .none
    }

    /// Whether any of the stored URIs matches the requesting site identifier.
    public static func matchesAny(storedURIs: [String], siteIdentifier: String) -> Bool {
        storedURIs.contains { matches(storedURI: $0, siteIdentifier: siteIdentifier) }
    }

    // MARK: - URL deconstruction

    /// Split a URL/URI string into scheme, host and path.
    ///
    /// We do not use `URL`/`URLComponents` because they reject several of the
    /// shapes stored credentials and service identifiers legitimately take:
    /// `domain`, `domain/path`, `://domain`, `://domain/path`, `scheme://domain/path`.
    public static func deconstruct(_ input: String) -> URIParts {
        var rest = input.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        var scheme: String? = nil

        if let schemeRange = rest.range(of: "://") {
            let candidate = String(rest[..<schemeRange.lowerBound])
            scheme = candidate.isEmpty ? nil : candidate
            rest = String(rest[schemeRange.upperBound...])
        }

        // Separate authority (host[:port]) from the path at the first "/".
        var authority = rest
        var path = ""
        if let slash = rest.firstIndex(of: "/") {
            authority = String(rest[..<slash])
            path = String(rest[slash...])
        }

        // Drop userinfo ("user:pass@host") so it can never be mistaken for the host.
        if let at = authority.lastIndex(of: "@") {
            authority = String(authority[authority.index(after: at)...])
        }

        // Extract the host, stripping the port. Handle bracketed IPv6 literals.
        var host = authority
        if authority.hasPrefix("[") {
            if let close = authority.firstIndex(of: "]") {
                host = String(authority[authority.index(after: authority.startIndex)..<close])
            }
        } else if let colon = authority.firstIndex(of: ":") {
            host = String(authority[..<colon])
        }
        if host.hasSuffix(".") { host = String(host.dropLast()) }

        // Strip query/fragment and normalize a trailing slash off the path.
        if let cut = path.firstIndex(where: { $0 == "?" || $0 == "#" }) {
            path = String(path[..<cut])
        }
        while path.count > 1 && path.hasSuffix("/") { path = String(path.dropLast()) }
        if path == "/" { path = "" }

        return URIParts(scheme: scheme, host: host, path: path)
    }

    // MARK: - Rules

    /// Rank http/https so we can require "as secure or better". Returns nil for
    /// other schemes, which are then compared for exact equality instead.
    private static func schemeSecurityRank(_ scheme: String) -> Int? {
        switch scheme {
        case "http": return 1
        case "https": return 2
        default: return nil
        }
    }

    private static func protocolSatisfied(secretScheme: String?, siteScheme: String?) -> Bool {
        // No scheme on the secret -> the secret allows any protocol.
        guard let secretScheme = secretScheme, !secretScheme.isEmpty else { return true }

        if let secretRank = schemeSecurityRank(secretScheme) {
            // A domain-type service identifier may carry no scheme; we cannot
            // evaluate a downgrade in that case, so we allow it.
            guard let siteScheme = siteScheme, !siteScheme.isEmpty else { return true }
            guard let siteRank = schemeSecurityRank(siteScheme) else { return false }
            return siteRank >= secretRank
        }

        // Non-http(s) secret scheme (e.g. androidapp): require exact equality,
        // unless the site carried no scheme to compare against.
        guard let siteScheme = siteScheme, !siteScheme.isEmpty else { return true }
        return siteScheme == secretScheme
    }

    private static func pathSatisfied(secretPath: String, sitePath: String) -> Bool {
        // No pinned path on the secret -> any site path is acceptable.
        if secretPath.isEmpty { return true }
        if sitePath == secretPath { return true }
        // Require a path-segment boundary so "/app" does not match "/application".
        return sitePath.hasPrefix(secretPath + "/")
    }
}
