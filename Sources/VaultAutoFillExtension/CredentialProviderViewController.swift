import AuthenticationServices
import Cocoa
import VaultModels
import VaultServices
import VaultAPI
import OSLog

private let logger = Logger(subsystem: "com.vaultui", category: "AutoFillExtension")

/// Credential Provider Extension view controller.
///
/// macOS invokes this when the user triggers AutoFill from a login field.
/// The extension reads credential metadata from the shared Keychain
/// (populated by the main app after each sync) and provides matching
/// credentials to the system.
@objc(VaultCredentialProviderViewController)
class VaultCredentialProviderViewController: ASCredentialProviderViewController {

    private let credentialStore = SharedCredentialStore.shared

    // MARK: - Credential List

    override func prepareCredentialList(for serviceIdentifiers: [ASCredentialServiceIdentifier]) {
        logger.info("prepareCredentialList called with \(serviceIdentifiers.count) service identifiers")

        let allCredentials = credentialStore.fetchCredentials()

        if allCredentials.isEmpty {
            logger.warning("No credentials in shared store — vault may not have synced")
        }

        // Filter credentials that match the requested service identifiers
        let matching: [SharedCredentialEntry]
        if serviceIdentifiers.isEmpty {
            // No specific service requested — show all credentials
            matching = allCredentials
        } else {
            matching = allCredentials.filter { entry in
                serviceIdentifiers.contains(where: { serviceId in
                    matchesService(entry: entry, serviceIdentifier: serviceId)
                })
            }
        }

        logger.info("Found \(matching.count) matching credentials out of \(allCredentials.count) total")

        // Register the matching identities with the system
        let identities = matching.compactMap { entry -> ASPasswordCredentialIdentity? in
            guard let firstUri = entry.uris.first else {
                // For entries without URIs, use the name as the service identifier
                let serviceId = ASCredentialServiceIdentifier(
                    identifier: entry.name,
                    type: .domain
                )
                return ASPasswordCredentialIdentity(
                    serviceIdentifier: serviceId,
                    user: entry.username ?? entry.name,
                    recordIdentifier: entry.id
                )
            }

            let serviceId = ASCredentialServiceIdentifier(
                identifier: extractDomain(from: firstUri),
                type: .domain
            )
            return ASPasswordCredentialIdentity(
                serviceIdentifier: serviceId,
                user: entry.username ?? entry.name,
                recordIdentifier: entry.id
            )
        }

        // Store the identities so the system can show them
        ASCredentialIdentityStore.shared.replaceCredentialIdentities(
            with: identities
        ) { success, error in
            if let error = error {
                logger.error("Failed to update credential identity store: \(error.localizedDescription)")
            } else {
                logger.info("Updated credential identity store with \(identities.count) identities")
            }
        }
    }

    // MARK: - Provide Credential Without UI

    override func provideCredentialWithoutUserInteraction(for credentialIdentity: ASPasswordCredentialIdentity) {
        logger.info("provideCredentialWithoutUserInteraction for: \(credentialIdentity.user)")

        guard let recordId = credentialIdentity.recordIdentifier else {
            logger.error("No record identifier in credential identity")
            let error = NSError(
                domain: ASExtensionErrorDomain,
                code: ASExtensionError.credentialIdentityNotFound.rawValue
            )
            self.extensionContext.cancelRequest(withError: error)
            return
        }

        // Try to fetch the password from the shared keychain
        if let password = credentialStore.fetchPassword(id: recordId) {
            let credential = ASPasswordCredential(
                user: credentialIdentity.user,
                password: password
            )
            self.extensionContext.completeRequest(
                withSelectedCredential: credential,
                completionHandler: nil
            )
            return
        }

        // Password not in shared keychain — require user interaction
        logger.info("Password not in shared store, requesting user interaction")
        let error = NSError(
            domain: ASExtensionErrorDomain,
            code: ASExtensionError.userInteractionRequired.rawValue
        )
        self.extensionContext.cancelRequest(withError: error)
    }

    // MARK: - Provide Credential With UI

    override func prepareInterfaceToProvideCredential(for credentialIdentity: ASPasswordCredentialIdentity) {
        logger.info("prepareInterfaceToProvideCredential for: \(credentialIdentity.user)")

        guard let recordId = credentialIdentity.recordIdentifier else {
            cancelWithError(.credentialIdentityNotFound)
            return
        }

        // Try the shared keychain first
        if let password = credentialStore.fetchPassword(id: recordId) {
            let credential = ASPasswordCredential(
                user: credentialIdentity.user,
                password: password
            )
            self.extensionContext.completeRequest(
                withSelectedCredential: credential,
                completionHandler: nil
            )
            return
        }

        // If password isn't available, show an error
        logger.error("Could not retrieve password for credential \(recordId)")
        cancelWithError(.failed)
    }

    // MARK: - Helpers

    private func cancelWithError(_ code: ASExtensionError.Code) {
        let error = NSError(domain: ASExtensionErrorDomain, code: code.rawValue)
        self.extensionContext.cancelRequest(withError: error)
    }

    /// Check if a credential entry matches a service identifier.
    private func matchesService(entry: SharedCredentialEntry, serviceIdentifier: ASCredentialServiceIdentifier) -> Bool {
        let targetDomain = extractDomain(from: serviceIdentifier.identifier).lowercased()

        // Check against all URIs
        for uri in entry.uris {
            let entryDomain = extractDomain(from: uri).lowercased()

            // Exact match
            if entryDomain == targetDomain {
                return true
            }

            // Subdomain match (e.g., "login.example.com" matches "example.com")
            if entryDomain.hasSuffix(".\(targetDomain)") || targetDomain.hasSuffix(".\(entryDomain)") {
                return true
            }
        }

        // Also check the entry name as a fallback
        if entry.name.lowercased().contains(targetDomain) {
            return true
        }

        return false
    }

    /// Extract the domain from a URL string or service identifier.
    private func extractDomain(from input: String) -> String {
        // Try parsing as URL first
        if let url = URL(string: input), let host = url.host {
            return host
        }

        // Try adding scheme
        if !input.contains("://"),
           let url = URL(string: "https://\(input)"),
           let host = url.host {
            return host
        }

        // Return as-is if not a URL
        return input
    }
}
