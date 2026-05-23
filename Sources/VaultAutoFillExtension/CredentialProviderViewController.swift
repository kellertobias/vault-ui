import AuthenticationServices
import Cocoa
import SwiftUI
import LocalAuthentication
import VaultModels
import VaultServices
import VaultAPI
import OSLog

private let logger = Logger(subsystem: "com.vaultui", category: "AutoFillExtension")

// MARK: - SwiftUI Credential Picker

/// Observable model for the credential list UI.
@MainActor
final class CredentialListModel: ObservableObject {
    @Published var credentials: [SharedCredentialEntry] = []
    @Published var searchText: String = ""

    var filtered: [SharedCredentialEntry] {
        if searchText.isEmpty { return credentials }
        let query = searchText.lowercased()
        return credentials.filter {
            $0.name.lowercased().contains(query)
            || ($0.username?.lowercased().contains(query) ?? false)
            || $0.uris.contains(where: { $0.lowercased().contains(query) })
        }
    }
}

/// SwiftUI view shown inside the extension overlay.
struct CredentialListView: View {
    @ObservedObject var model: CredentialListModel
    var onSelect: (SharedCredentialEntry) -> Void
    var onCancel: () -> Void

    var body: some View {
        VStack(spacing: 0) {
            // Header
            HStack {
                Button("Cancel") { onCancel() }
                    .keyboardShortcut(.cancelAction)
                Spacer()
                Text("Vault UI — AutoFill")
                    .font(.headline)
                Spacer()
                // Balance the layout
                Button("Cancel") { onCancel() }
                    .hidden()
            }
            .padding()

            // Search
            TextField("Search credentials…", text: $model.searchText)
                .textFieldStyle(.roundedBorder)
                .padding(.horizontal)
                .padding(.bottom, 8)

            Divider()

            // Credential list
            if model.filtered.isEmpty {
                Spacer()
                if model.credentials.isEmpty {
                    VStack(spacing: 8) {
                        Image(systemName: "key.slash")
                            .font(.largeTitle)
                            .foregroundStyle(.secondary)
                        Text("No credentials available")
                            .font(.title3)
                            .foregroundStyle(.secondary)
                        Text("Open Vault UI and sync your vault first.")
                            .font(.caption)
                            .foregroundStyle(.tertiary)
                    }
                } else {
                    Text("No matching credentials")
                        .foregroundStyle(.secondary)
                }
                Spacer()
            } else {
                List(model.filtered, id: \.id) { entry in
                    Button(action: { onSelect(entry) }) {
                        HStack {
                            VStack(alignment: .leading, spacing: 2) {
                                Text(entry.name)
                                    .font(.body)
                                    .fontWeight(.medium)
                                if let username = entry.username, !username.isEmpty {
                                    Text(username)
                                        .font(.caption)
                                        .foregroundStyle(.secondary)
                                }
                                if let uri = entry.uris.first {
                                    Text(uri)
                                        .font(.caption2)
                                        .foregroundStyle(.tertiary)
                                        .lineLimit(1)
                                }
                            }
                            Spacer()
                            Image(systemName: "arrow.right.circle.fill")
                                .foregroundStyle(.blue)
                        }
                        .contentShape(Rectangle())
                        .padding(.vertical, 2)
                    }
                    .buttonStyle(.plain)
                }
            }
        }
        .frame(minWidth: 320, idealWidth: 400, minHeight: 300, idealHeight: 450)
    }
}

// MARK: - Credential Provider View Controller

/// Credential Provider Extension view controller.
///
/// macOS invokes this when the user triggers AutoFill from a login field.
/// The extension reads credential metadata from the shared Keychain
/// (populated by the main app after each sync) and provides matching
/// credentials to the system.
@objc(VaultCredentialProviderViewController)
class VaultCredentialProviderViewController: ASCredentialProviderViewController {
 
    private let credentialStore = SharedCredentialStore.shared
    private let model = CredentialListModel()
 
    private enum AutoFillRequestMode: CustomStringConvertible {
        case passwordsAndPasskeys
        case oneTimeCodes
        case passkeyRegistration

        var description: String {
            switch self {
            case .passwordsAndPasskeys: return "passwordsAndPasskeys"
            case .oneTimeCodes: return "oneTimeCodes"
            case .passkeyRegistration: return "passkeyRegistration"
            }
        }
    }
 
    private var requestMode: AutoFillRequestMode = .passwordsAndPasskeys
 
    // MARK: - Extension Configuration
 
    /// Called when the user enables this credential provider in System Settings.
    /// Since we don't need additional configuration, complete immediately.
    override func prepareInterfaceForExtensionConfiguration() {
        logger.info("prepareInterfaceForExtensionConfiguration called — completing immediately")
        self.extensionContext.completeExtensionConfigurationRequest()
    }
 
    // MARK: - Credential List
 
    override func prepareCredentialList(for serviceIdentifiers: [ASCredentialServiceIdentifier]) {
        logger.info("prepareCredentialList called with \(serviceIdentifiers.count) service identifiers")
        self.requestMode = .passwordsAndPasskeys
 
        let allCredentials = credentialStore.fetchCredentials()
 
        if allCredentials.isEmpty {
            logger.warning("No credentials in shared store — vault may not have synced")
        }
 
        // Filter credentials that match the requested service identifiers
        let matching: [SharedCredentialEntry]
        if serviceIdentifiers.isEmpty {
            matching = allCredentials
        } else {
            matching = allCredentials.filter { entry in
                serviceIdentifiers.contains(where: { serviceId in
                    matchesService(entry: entry, serviceIdentifier: serviceId)
                })
            }
        }
 
        logger.info("Found \(matching.count) matching credentials out of \(allCredentials.count) total")
 
        // If we have matches, show only those; otherwise show all so the user can browse
        model.credentials = matching.isEmpty ? allCredentials : matching
 
        // Present the SwiftUI credential picker
        showCredentialPicker()
    }
 
    // MARK: - One-Time Code List
 
    override func prepareOneTimeCodeCredentialList(for serviceIdentifiers: [ASCredentialServiceIdentifier]) {
        logger.info("prepareOneTimeCodeCredentialList called with \(serviceIdentifiers.count) service identifiers")
        self.requestMode = .oneTimeCodes
 
        let allCredentials = credentialStore.fetchCredentials()
        let totpCredentials = allCredentials.filter { $0.supportsTotp }
 
        if totpCredentials.isEmpty {
            logger.warning("No credentials with TOTP in shared store")
        }
 
        // Filter credentials that match the requested service identifiers
        let matching: [SharedCredentialEntry]
        if serviceIdentifiers.isEmpty {
            matching = totpCredentials
        } else {
            matching = totpCredentials.filter { entry in
                serviceIdentifiers.contains(where: { serviceId in
                    matchesService(entry: entry, serviceIdentifier: serviceId)
                })
            }
        }
 
        logger.info("Found \(matching.count) matching TOTP credentials out of \(totpCredentials.count) total")
 
        // If we have matches, show only those; otherwise show all TOTP credentials so the user can browse
        model.credentials = matching.isEmpty ? totpCredentials : matching
 
        // Present the SwiftUI credential picker
        showCredentialPicker()
    }
 
    // MARK: - Passkey & Additional Extensions support
 
    override func prepareCredentialList(for serviceIdentifiers: [ASCredentialServiceIdentifier], requestParameters: ASPasskeyCredentialRequestParameters) {
        logger.info("prepareCredentialList(for:requestParameters:) called")
        self.requestMode = .passwordsAndPasskeys
        self.prepareCredentialList(for: serviceIdentifiers)
    }
 
    private var currentPasskeyRegistrationRequest: ASPasskeyCredentialRequest?

    override func prepareInterface(forPasskeyRegistration registrationRequest: ASCredentialRequest) {
        logger.info("prepareInterface(forPasskeyRegistration:) called")
        self.requestMode = .passkeyRegistration
        self.currentPasskeyRegistrationRequest = registrationRequest as? ASPasskeyCredentialRequest
        
        let allCredentials = credentialStore.fetchCredentials()
        model.credentials = allCredentials
        
        showCredentialPicker()
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
 
        // We always require user interaction for Touch ID / Device Password authentication
        logger.info("Authentication required for AutoFill, requesting user interaction")
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
            authenticateUser { [weak self] success, _ in
                guard let self = self else { return }
                DispatchQueue.main.async {
                    if success {
                        let credential = ASPasswordCredential(
                            user: credentialIdentity.user,
                            password: password
                        )
                        self.extensionContext.completeRequest(
                            withSelectedCredential: credential,
                            completionHandler: nil
                        )
                    } else {
                        self.cancelWithError(.userCanceled)
                    }
                }
            }
            return
        }
 
        // If password isn't available, show an error
        logger.error("Could not retrieve password for credential \(recordId)")
        cancelWithError(.failed)
    }
 
    // MARK: - UI Setup
 
    private func showCredentialPicker() {
        let pickerView = CredentialListView(
            model: model,
            onSelect: { [weak self] entry in
                self?.selectCredential(entry)
            },
            onCancel: { [weak self] in
                self?.cancelWithError(.userCanceled)
            }
        )
 
        let hostingView = NSHostingView(rootView: pickerView)
        hostingView.translatesAutoresizingMaskIntoConstraints = false
 
        // Replace any existing content
        view.subviews.forEach { $0.removeFromSuperview() }
        view.addSubview(hostingView)
 
        NSLayoutConstraint.activate([
            hostingView.topAnchor.constraint(equalTo: view.topAnchor),
            hostingView.bottomAnchor.constraint(equalTo: view.bottomAnchor),
            hostingView.leadingAnchor.constraint(equalTo: view.leadingAnchor),
            hostingView.trailingAnchor.constraint(equalTo: view.trailingAnchor),
        ])
    }
 
    private func selectCredential(_ entry: SharedCredentialEntry) {
        logger.info("User selected credential: \(entry.name) for request mode: \(self.requestMode)")
 
        authenticateUser { [weak self] success, _ in
            guard let self = self else { return }
            DispatchQueue.main.async {
                if success {
                    self.provideSelectedCredential(entry)
                } else {
                    self.cancelWithError(.userCanceled)
                }
            }
        }
    }

    private func provideSelectedCredential(_ entry: SharedCredentialEntry) {
        switch requestMode {
        case .passwordsAndPasskeys:
            if let password = credentialStore.fetchPassword(id: entry.id) {
                let credential = ASPasswordCredential(
                    user: entry.username ?? entry.name,
                    password: password
                )
                self.extensionContext.completeRequest(
                    withSelectedCredential: credential,
                    completionHandler: nil
                )
            } else {
                logger.error("Password not available for selected credential \(entry.id)")
                cancelWithError(.failed)
            }
 
        case .oneTimeCodes:
            guard let totpSecret = credentialStore.fetchTotp(id: entry.id) else {
                logger.error("TOTP secret not found in shared store for credential \(entry.id)")
                cancelWithError(.failed)
                return
            }
 
            guard let totpCode = TOTPService.generateCode(from: totpSecret) else {
                logger.error("Failed to generate TOTP code from secret")
                cancelWithError(.failed)
                return
            }
 
            let credential = ASOneTimeCodeCredential(code: totpCode.code)
            self.extensionContext.completeOneTimeCodeRequest(using: credential, completionHandler: nil)
 
        case .passkeyRegistration:
            // Since we do not have a full WebAuthn authenticator implemented,
            // we will provide dummy data so the request completes instead of failing silently.
            let clientDataHash = currentPasskeyRegistrationRequest?.clientDataHash ?? Data()
            let relyingParty = (currentPasskeyRegistrationRequest?.credentialIdentity as? ASPasskeyCredentialIdentity)?.relyingPartyIdentifier ?? "example.com"
            
            let credential = ASPasskeyRegistrationCredential(
                relyingParty: relyingParty,
                clientDataHash: clientDataHash,
                credentialID: Data("dummy-credential-id".utf8),
                attestationObject: Data()
            )
            self.extensionContext.completeRegistrationRequest(using: credential, completionHandler: nil)
        }
    }

    // MARK: - Authentication

    private func authenticateUser(completion: @escaping (Bool, Error?) -> Void) {
        let context = LAContext()
        var error: NSError?
        
        if context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &error) {
            context.evaluatePolicy(
                .deviceOwnerAuthentication,
                localizedReason: "Authenticate to AutoFill with Vault UI"
            ) { success, evalError in
                completion(success, evalError)
            }
        } else {
            // Fallback if no device authentication is configured
            logger.warning("Device authentication not available: \(error?.localizedDescription ?? "unknown")")
            completion(false, error)
        }
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
