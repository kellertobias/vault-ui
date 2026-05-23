// MARK: - VaultModels/SlugValidation.swift
// Validation and parsing for vaultui-slug custom fields

import Foundation

/// Utilities for the `vaultui-slug` custom field, which enables CLI access to vault secrets.
///
/// Secrets with a `vaultui-slug` field can be addressed by the `vaultui secret` CLI commands
/// using the slug as a stable, human-readable identifier.
public enum VaultUISlug {

    /// The custom field name used to store the slug on a cipher.
    public static let fieldName = "vaultui-slug"

    /// Allowed characters: letters, digits, hyphens, underscores, dots.
    /// No spaces, no special characters.
    private static let allowedCharacters = CharacterSet.alphanumerics.union(CharacterSet(charactersIn: "._-"))

    /// Validate a slug string.
    ///
    /// - Parameter slug: The slug to validate.
    /// - Returns: `true` if the slug contains only allowed characters.
    public static func isValid(_ slug: String) -> Bool {
        !slug.isEmpty && slug.unicodeScalars.allSatisfy { allowedCharacters.contains($0) }
    }

    /// The URI scheme prefix used in `.env` files to reference vault secrets.
    public static let uriPrefix = "vaultui://"

    /// Parse a `vaultui://` URI into its slug and optional field components.
    ///
    /// Examples:
    /// - `vaultui://my-app.db` → `(slug: "my-app.db", field: nil)`
    /// - `vaultui://my-app.db/password` → `(slug: "my-app.db", field: "password")`
    ///
    /// - Parameter uri: The URI string to parse.
    /// - Returns: A tuple of `(slug, field?)`, or `nil` if the URI is malformed.
    public static func parseURI(_ uri: String) -> (slug: String, field: String?)? {
        guard uri.hasPrefix(uriPrefix) else { return nil }
        let path = String(uri.dropFirst(uriPrefix.count))
        guard !path.isEmpty else { return nil }

        let parts = path.split(separator: "/", maxSplits: 1)
        guard let slugPart = parts.first else { return nil }
        let slug = String(slugPart)

        guard isValid(slug) else { return nil }

        let field = parts.count > 1 ? String(parts[1]) : nil
        return (slug, field)
    }

    /// Parse a CLI argument like `my-slug` or `my-slug/password` into slug and optional field.
    ///
    /// - Parameter argument: The CLI argument to parse.
    /// - Returns: A tuple of `(slug, field?)`, or `nil` if invalid.
    public static func parseArgument(_ argument: String) -> (slug: String, field: String?)? {
        let parts = argument.split(separator: "/", maxSplits: 1)
        guard let slugPart = parts.first else { return nil }
        let slug = String(slugPart)

        guard isValid(slug) else { return nil }

        let field = parts.count > 1 ? String(parts[1]) : nil
        return (slug, field)
    }
}
