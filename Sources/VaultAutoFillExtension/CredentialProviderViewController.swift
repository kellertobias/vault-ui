import AuthenticationServices
import Cocoa
import SwiftUI
import LocalAuthentication
import VaultModels
import VaultServices
import VaultAPI
import VaultCrypto
import OSLog

private let logger = Logger(subsystem: "com.vaultui", category: "AutoFillExtension")

// MARK: - SwiftUI Credential Picker

/// Observable model for the credential list UI.
@MainActor
final class CredentialListModel: ObservableObject {
    enum Screen {
        case matches
        case allCredentials
        case createNew
    }

    @Published var screen: Screen = .matches
    @Published var matchedCredentials: [SharedCredentialEntry] = []
    @Published var allCredentials: [SharedCredentialEntry] = []
    @Published var searchText: String = ""
    @Published var createTitle: String = ""
    @Published var createUsername: String = ""
    @Published var createPassword: String = ""
    @Published var isCreatePasswordVisible: Bool = false
    @Published var createRequiresPassword: Bool = true
    @Published var createHost: String = ""
    @Published var createURL: String = ""

    var filtered: [SharedCredentialEntry] {
        let source = screen == .allCredentials ? allCredentials : matchedCredentials
        if searchText.isEmpty { return source }
        let query = searchText.lowercased()
        return source.filter {
            $0.name.lowercased().contains(query)
            || ($0.username?.lowercased().contains(query) ?? false)
            || $0.uris.contains(where: { $0.lowercased().contains(query) })
        }
    }
    
    @Published var isPasskeyRegistration: Bool = false
    @Published var isPasskeyMode: Bool = false
    @Published var allowsCreateNew: Bool = true
    @Published var relyingPartyId: String? = nil
    @Published var createContextHost: String? = nil

    @Published var lastConfirmedSync: Date?

    init() {
        if let dates = SharedCredentialStore.shared.fetchSyncDates() {
            lastConfirmedSync = dates.lastSyncWithServer
        }
    }

    var title: String {
        screen == .createNew ? "Vault UI - New" : "Vault UI - AutoFill"
    }

    var latestSyncAgeText: String {
        guard let latest = lastConfirmedSync else { return "never" }
        let minutes = max(0, Int(Date().timeIntervalSince(latest) / 60))
        if minutes == 0 { return "just now" }
        return "\(minutes) min ago"
    }

    var canCreateNew: Bool {
        allowsCreateNew && (!isPasskeyMode || isPasskeyRegistration)
    }

    var canSaveCreateNew: Bool {
        guard !createTitle.isEmpty, !createUsername.isEmpty, !createURL.isEmpty else { return false }
        return !createRequiresPassword || !createPassword.isEmpty
    }

    func resetCreateFields(serviceIdentifier: String? = nil, fallbackUsername: String? = nil) {
        let matchingHost = serviceIdentifier ?? createContextHost ?? relyingPartyId
        let context = SharedCredentialStore.shared.fetchRecentAutoFillFormContext(matchingHost: matchingHost)
        let fallbackName = context?.name ?? relyingPartyId ?? matchingHost ?? "New Login"
        let contextUsername = context?.username?.trimmingCharacters(in: .whitespacesAndNewlines)
        let fallbackUsername = fallbackUsername?.trimmingCharacters(in: .whitespacesAndNewlines)
        let resolvedURL = context?.url ?? matchingHost.map { $0.contains("://") ? $0 : "https://\($0)" } ?? ""
        createTitle = fallbackName
        createUsername = contextUsername?.isEmpty == false ? contextUsername! : fallbackUsername ?? ""
        createPassword = createRequiresPassword ? (context?.password ?? "") : ""
        createURL = resolvedURL
        createHost = Self.host(from: resolvedURL) ?? matchingHost.flatMap { Self.host(from: $0) } ?? ""
    }

    private static func host(from value: String) -> String? {
        let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return nil }
        if let url = URL(string: trimmed), let host = url.host {
            return host
        }
        if let url = URL(string: "https://\(trimmed)"), let host = url.host {
            return host
        }
        return trimmed.components(separatedBy: "/").first?.components(separatedBy: ":").first
    }
}

/// SwiftUI view shown inside the extension overlay.
struct CredentialListView: View {
    @ObservedObject var model: CredentialListModel
    var onSelect: (SharedCredentialEntry, Bool) -> Void
    var onSaveNew: (TemporaryCredentialDraft) -> Void
    var onCancel: () -> Void

    var body: some View {
        VStack(spacing: 0) {
            HStack(alignment: .center, spacing: 12) {
                Button("Cancel") { onCancel() }
                    .keyboardShortcut(.cancelAction)
                Spacer()
                Text(model.title)
                    .font(.headline)
                Spacer()
                VStack(alignment: .trailing, spacing: 1) {
                    Text("last sync:")
                    Text(model.latestSyncAgeText)
                }
                .font(.caption2)
                .foregroundStyle(.secondary)
            }
            .padding()

            if model.screen == .allCredentials {
                HStack(spacing: 8) {
                    Button {
                        model.searchText = ""
                        model.screen = .matches
                    } label: {
                        Image(systemName: "chevron.left")
                    }
                    .buttonStyle(.plain)
                    .help("Back")

                    TextField("Search credentials...", text: $model.searchText)
                        .textFieldStyle(.roundedBorder)
                }
                .padding(.horizontal)
                .padding(.bottom, 8)
            } else if model.isPasskeyRegistration, let rpId = model.relyingPartyId, model.screen != .createNew {
                Text("Register Passkey for \(rpId)")
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
                    .padding(.horizontal)
                    .padding(.bottom, 4)
            }

            Divider()

            if model.screen == .createNew {
                createNewView
            } else if model.filtered.isEmpty {
                Spacer()
                if model.allCredentials.isEmpty {
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
                    VStack(spacing: 12) {
                        Text("No matching credentials")
                            .foregroundStyle(.secondary)
                    }
                }
                Spacer()
            } else {
                credentialList
            }

            if model.screen == .matches {
                Divider()
                HStack {
                    Button("Show More") { model.screen = .allCredentials }
                        .buttonStyle(.bordered)
                    Spacer()
                    Button("Create New") {
                        model.resetCreateFields()
                        model.screen = .createNew
                    }
                    .buttonStyle(.borderedProminent)
                    .disabled(!model.canCreateNew)
                }
                .padding()
            } else if model.screen == .createNew {
                Divider()
                HStack {
                    Button("Back") { model.screen = .matches }
                        .buttonStyle(.bordered)
                    Spacer()
                    Button("Save") {
                        onSaveNew(
                            TemporaryCredentialDraft(
                                name: model.createTitle,
                                username: model.createUsername,
                                password: model.createRequiresPassword ? model.createPassword : nil,
                                url: model.createURL
                            )
                        )
                    }
                    .buttonStyle(.borderedProminent)
                    .disabled(!model.canSaveCreateNew)
                }
                .padding()
            }
        }
        .frame(minWidth: 320, idealWidth: 400, minHeight: 300, idealHeight: 450)
    }

    private var credentialList: some View {
        List {
            ForEach(model.filtered, id: \.id) { entry in
                Button(action: {
                    onSelect(entry, false)
                }) {
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

                        if entry.supportsTotp {
                            Image(systemName: "clock.badge.checkmark.fill")
                                .foregroundStyle(.secondary)
                                .font(.caption)
                                .help("TOTP")
                        }

                        if entry.supportsPasskey {
                            Button(action: { onSelect(entry, true) }) {
                                Image(systemName: "person.badge.key.fill")
                                    .foregroundStyle(.blue)
                                    .padding(6)
                                    .background(Color.blue.opacity(0.1))
                                    .clipShape(Circle())
                            }
                            .buttonStyle(.plain)
                            .help("Use Passkey")
                            .padding(.trailing, 4)
                        }

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

    private var createNewView: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 14) {
                labeledField("host") {
                    TextField("host", text: .constant(model.createHost))
                        .textFieldStyle(.roundedBorder)
                        .disabled(true)
                }

                labeledField("Title") {
                    TextField("Title", text: $model.createTitle)
                        .textFieldStyle(.roundedBorder)
                }

                labeledField("Username or email") {
                    TextField("Username or email", text: $model.createUsername)
                        .textFieldStyle(.roundedBorder)
                }

                if model.createRequiresPassword {
                    labeledField("Password") {
                        HStack(spacing: 8) {
                            ZStack(alignment: .trailing) {
                                if model.isCreatePasswordVisible {
                                    TextField("Password", text: $model.createPassword)
                                        .textFieldStyle(.roundedBorder)
                                } else {
                                    SecureField("Password", text: $model.createPassword)
                                        .textFieldStyle(.roundedBorder)
                                }

                                Button {
                                    model.isCreatePasswordVisible.toggle()
                                } label: {
                                    Image(systemName: model.isCreatePasswordVisible ? "eye.slash" : "eye")
                                }
                                .buttonStyle(.plain)
                                .padding(.trailing, 8)
                                .help(model.isCreatePasswordVisible ? "Hide Password" : "Show Password")
                            }

                            Menu {
                                Button("Fully Random") {
                                    model.createPassword = PasswordGenerator.generatePassword(length: 20)
                                }
                                Button("XKCD-Style") {
                                    model.createPassword = PasswordGenerator.generatePassphrase(
                                        wordCount: 4,
                                        separator: "-",
                                        capitalize: false,
                                        includeNumber: false
                                    )
                                }
                            } label: {
                                Image(systemName: "dice.fill")
                            }
                            .menuStyle(.borderlessButton)
                            .help("Generate Password")

                            Button {
                                NSPasteboard.general.clearContents()
                                NSPasteboard.general.setString(model.createPassword, forType: .string)
                            } label: {
                                Image(systemName: "doc.on.doc")
                            }
                            .disabled(model.createPassword.isEmpty)
                            .help("Copy Password")
                        }
                    }
                }
            }
            .padding(.horizontal, 14)
            .padding(.vertical, 16)
            .frame(maxWidth: .infinity, alignment: .topLeading)
        }
        .frame(maxHeight: .infinity, alignment: .top)
    }

    private func labeledField<Content: View>(_ label: String, @ViewBuilder content: () -> Content) -> some View {
        VStack(alignment: .leading, spacing: 5) {
            Text(label)
                .font(.caption)
                .foregroundStyle(.secondary)
            content()
        }
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
        case passkeys

        var description: String {
            switch self {
            case .passwordsAndPasskeys: return "passwordsAndPasskeys"
            case .oneTimeCodes: return "oneTimeCodes"
            case .passkeyRegistration: return "passkeyRegistration"
            case .passkeys: return "passkeys"
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
 
        let matching = filterAndSortCredentials(allCredentials, for: serviceIdentifiers)
 
        logger.info("Found \(matching.count) matching credentials out of \(allCredentials.count) total")
 
        model.isPasskeyMode = false
        model.isPasskeyRegistration = false
        model.allowsCreateNew = true
        model.createRequiresPassword = true
        model.relyingPartyId = nil
        model.createContextHost = serviceIdentifiers.first?.identifier
        model.allCredentials = sortCredentials(allCredentials, for: serviceIdentifiers)
        model.matchedCredentials = matching
        model.screen = .matches
        model.searchText = ""
        model.resetCreateFields(serviceIdentifier: serviceIdentifiers.first?.identifier)
 
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
 
        let matching = filterAndSortCredentials(totpCredentials, for: serviceIdentifiers)
 
        logger.info("Found \(matching.count) matching TOTP credentials out of \(totpCredentials.count) total")
 
        model.allCredentials = sortCredentials(totpCredentials, for: serviceIdentifiers)
        model.matchedCredentials = matching
        model.isPasskeyMode = false
        model.isPasskeyRegistration = false
        model.allowsCreateNew = false
        model.createRequiresPassword = false
        model.relyingPartyId = nil
        model.createContextHost = serviceIdentifiers.first?.identifier
        model.screen = .matches
        model.searchText = ""
        model.resetCreateFields(serviceIdentifier: serviceIdentifiers.first?.identifier)
 
        // Present the SwiftUI credential picker
        showCredentialPicker()
    }
    
    private func completeAssertion(for entry: SharedCredentialEntry, relyingParty: String, clientDataHash: Data, passkeyIdentity: ASPasskeyCredentialIdentity? = nil) {
        let allPasskeys = credentialStore.fetchPasskeys(id: entry.id)
        
        // Find the specific passkey matching the requested credentialID, or fallback to relyingParty match
        var selectedPasskey: SharedPasskeyData? = nil
        if let requestedCredID = passkeyIdentity?.credentialID {
            selectedPasskey = allPasskeys.first { Data(bitwardenFido2CredentialId: $0.credentialId) == requestedCredID }
        }
        if selectedPasskey == nil {
            selectedPasskey = allPasskeys.first(where: { $0.relyingPartyId == relyingParty }) ?? allPasskeys.first
        }
        
        guard let passkey = selectedPasskey else {
            logger.error("Passkey data not available for selected credential \(entry.id)")
            cancelWithError(.failed)
            return
        }
        
        guard let assertion = WebAuthnGenerator.generateAssertion(
            privateKeyBase64: passkey.privateKey,
            relyingPartyId: relyingParty,
            clientDataHash: clientDataHash
        ) else {
            logger.error("Failed to generate assertion")
            cancelWithError(.failed)
            return
        }
        
        let credentialID = passkeyIdentity?.credentialID ?? (Data(bitwardenFido2CredentialId: passkey.credentialId) ?? Data())
        let userHandle = passkeyIdentity?.userHandle ?? (Data(base64URLDecoded: passkey.userHandle) ?? Data())
        
        let credential = ASPasskeyAssertionCredential(
            userHandle: userHandle,
            relyingParty: relyingParty,
            signature: assertion.signature,
            clientDataHash: clientDataHash,
            authenticatorData: assertion.authenticatorData,
            credentialID: credentialID
        )
        
        self.extensionContext.completeAssertionRequest(using: credential, completionHandler: nil)
        logger.info("Completed passkey assertion request")
    }

    // MARK: - Passkey & Additional Extensions support
 
    override func prepareCredentialList(for serviceIdentifiers: [ASCredentialServiceIdentifier], requestParameters: ASPasskeyCredentialRequestParameters) {
        logger.info("prepareCredentialList(for:requestParameters:) called")
        self.requestMode = .passkeys
        self.currentPasskeyAssertionParameters = requestParameters
        
        let allCredentials = credentialStore.fetchCredentials()
        
        let matching = filterAndSortCredentials(allCredentials, for: serviceIdentifiers)
        
        model.isPasskeyMode = true
        model.isPasskeyRegistration = false
        model.allowsCreateNew = false
        model.createRequiresPassword = false
        model.relyingPartyId = requestParameters.relyingPartyIdentifier
        model.createContextHost = requestParameters.relyingPartyIdentifier
        model.allCredentials = sortCredentials(allCredentials, for: serviceIdentifiers)
        model.matchedCredentials = matching
        model.screen = .matches
        model.searchText = ""
        model.resetCreateFields(serviceIdentifier: requestParameters.relyingPartyIdentifier)
        showCredentialPicker()
    }
 
    private var currentPasskeyRegistrationRequest: ASPasskeyCredentialRequest?
    private var currentPasskeyAssertionRequest: ASPasskeyCredentialRequest?
    private var currentPasskeyAssertionParameters: ASPasskeyCredentialRequestParameters?
    private var rawRegistrationRequest: ASCredentialRequest?
    private var didCompletePasskeyRegistration = false

    override func prepareInterface(forPasskeyRegistration registrationRequest: ASCredentialRequest) {
        logger.info("prepareInterface(forPasskeyRegistration:) called")
        self.requestMode = .passkeyRegistration
        self.didCompletePasskeyRegistration = false

        self.rawRegistrationRequest = registrationRequest
        self.currentPasskeyRegistrationRequest = registrationRequest as? ASPasskeyCredentialRequest
        let passkeyIdentity = registrationRequest.credentialIdentity as? ASPasskeyCredentialIdentity
        let relyingParty = passkeyIdentity?.relyingPartyIdentifier
        
        let allCredentials = credentialStore.fetchCredentials()
        model.allCredentials = sortCredentials(allCredentials, for: [])
        model.matchedCredentials = filterAndSortCredentials(allCredentials, for: []) // No service identifier for passkey registration initially unless we parse relying party
        if let relyingParty {
            model.matchedCredentials = filterAndSortCredentials(allCredentials, for: [ASCredentialServiceIdentifier(identifier: relyingParty, type: .domain)])
            model.allCredentials = sortCredentials(allCredentials, for: [ASCredentialServiceIdentifier(identifier: relyingParty, type: .domain)])
        }
        model.screen = .matches
        model.searchText = ""
        model.isPasskeyRegistration = true
        model.isPasskeyMode = false
        model.allowsCreateNew = true
        model.createRequiresPassword = false
        model.relyingPartyId = relyingParty
        model.createContextHost = relyingParty
        model.resetCreateFields(serviceIdentifier: model.relyingPartyId, fallbackUsername: passkeyIdentity?.userName)
        
        showCredentialPicker()
    }
 
    // MARK: - Provide Credential Without UI
 
    override func provideCredentialWithoutUserInteraction(for credentialIdentity: ASPasswordCredentialIdentity) {
        logger.info("provideCredentialWithoutUserInteraction for: \(credentialIdentity.user)")
 
        guard let fullRecordId = credentialIdentity.recordIdentifier else {
            logger.error("No record identifier in credential identity")
            let error = NSError(
                domain: ASExtensionErrorDomain,
                code: ASExtensionError.credentialIdentityNotFound.rawValue
            )
            self.extensionContext.cancelRequest(withError: error)
            return
        }
        let recordId = fullRecordId.components(separatedBy: "|").first ?? fullRecordId
 
        // We always require user interaction for Touch ID / Device Password authentication
        logger.info("Authentication required for AutoFill, requesting user interaction")
        let error = NSError(
            domain: ASExtensionErrorDomain,
            code: ASExtensionError.userInteractionRequired.rawValue
        )
        self.extensionContext.cancelRequest(withError: error)
    }

    @available(macOS 14.0, *)
    override func provideCredentialWithoutUserInteraction(for credentialRequest: ASCredentialRequest) {
        logger.info("provideCredentialWithoutUserInteraction for credentialRequest")
        // We always require user interaction
        let error = NSError(
            domain: ASExtensionErrorDomain,
            code: ASExtensionError.userInteractionRequired.rawValue
        )
        self.extensionContext.cancelRequest(withError: error)
    }
 
    // MARK: - Provide Credential With UI
 
    override func prepareInterfaceToProvideCredential(for credentialIdentity: ASPasswordCredentialIdentity) {
        logger.info("prepareInterfaceToProvideCredential for: \(credentialIdentity.user)")
 
        guard let fullRecordId = credentialIdentity.recordIdentifier else {
            cancelWithError(.credentialIdentityNotFound)
            return
        }
        let recordId = fullRecordId.components(separatedBy: "|").first ?? fullRecordId
 
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

    @available(macOS 14.0, *)
    override func prepareInterfaceToProvideCredential(for credentialRequest: ASCredentialRequest) {
        logger.info("prepareInterfaceToProvideCredential for credentialRequest")

        if let passwordRequest = credentialRequest as? ASPasswordCredentialRequest,
           let identity = passwordRequest.credentialIdentity as? ASPasswordCredentialIdentity {
            self.prepareInterfaceToProvideCredential(for: identity)
        } else if let otpRequest = credentialRequest as? ASOneTimeCodeCredentialRequest {
            self.requestMode = .oneTimeCodes
            let identity = otpRequest.credentialIdentity
            
            guard let fullRecordId = identity.recordIdentifier else {
                cancelWithError(.credentialIdentityNotFound)
                return
            }
            let recordId = fullRecordId.components(separatedBy: "|").first ?? fullRecordId

            // Immediately provide the OTP if we can authenticate
            authenticateUser { [weak self] success, _ in
                guard let self = self else { return }
                DispatchQueue.main.async {
                    if success {
                        if let entry = self.credentialStore.fetchCredentials().first(where: { $0.id == recordId }) {
                            self.provideSelectedCredential(entry)
                        } else {
                            self.cancelWithError(.failed)
                        }
                    } else {
                        self.cancelWithError(.userCanceled)
                    }
                }
            }
        } else if let assertionRequest = credentialRequest as? ASPasskeyCredentialRequest {
            logger.info("prepareInterfaceToProvideCredential for ASPasskeyCredentialRequest")
            self.requestMode = .passkeys
            self.currentPasskeyAssertionRequest = assertionRequest
            let identity = assertionRequest.credentialIdentity
            
            guard let fullRecordId = identity.recordIdentifier else {
                cancelWithError(.credentialIdentityNotFound)
                return
            }
            let recordId = fullRecordId.components(separatedBy: "|").first ?? fullRecordId
            
            authenticateUser { [weak self] success, _ in
                guard let self = self else { return }
                DispatchQueue.main.async {
                    if success {
                        if let entry = self.credentialStore.fetchCredentials().first(where: { $0.id == recordId }) {
                            self.provideSelectedCredential(entry, usePasskey: true)
                        } else {
                            self.cancelWithError(.failed)
                        }
                    } else {
                        self.cancelWithError(.userCanceled)
                    }
                }
            }
        } else {
            cancelWithError(.failed)
        }
    }
 
    // MARK: - UI Setup
 
    private func showCredentialPicker() {
        let pickerView = CredentialListView(
            model: model,
            onSelect: { [weak self] entry, usePasskey in
                self?.selectCredential(entry, usePasskey: usePasskey)
            },
            onSaveNew: { [weak self] draft in
                self?.saveTemporaryCredential(draft)
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
 
    private func selectCredential(_ entry: SharedCredentialEntry, usePasskey: Bool = false) {
        logger.info("User selected credential: \(entry.name) for request mode: \(self.requestMode)")
 
        authenticateUser { [weak self] success, _ in
            guard let self = self else { return }
            DispatchQueue.main.async {
                if success {
                    if self.requestMode == .passkeyRegistration {
                        self.processPasskeyRegistration(targetCipherId: entry.id, username: entry.username)
                    } else {
                        self.provideSelectedCredential(entry, usePasskey: usePasskey)
                    }
                } else {
                    self.cancelWithError(.userCanceled)
                }
            }
        }
    }
    
    private func saveTemporaryCredential(_ draft: TemporaryCredentialDraft) {
        let resolvedDraft = TemporaryCredentialDraft(
            id: existingTemporaryCredentialId(url: draft.url, username: draft.username) ?? draft.id,
            name: draft.name,
            username: draft.username,
            password: draft.password,
            url: draft.url,
            creationDate: draft.creationDate
        )
        logger.info("User selected to create temporary credential: \(resolvedDraft.name)")
        authenticateUser { [weak self] success, _ in
            guard let self = self else { return }
            DispatchQueue.main.async {
                if success {
                    self.credentialStore.queueTemporaryCredentialDraft(resolvedDraft)
                    if let password = resolvedDraft.password, !password.isEmpty {
                        self.credentialStore.storeAutoFillCredentialFillRequest(
                            AutoFillCredentialFillRequest(
                                url: resolvedDraft.url,
                                name: resolvedDraft.name,
                                username: resolvedDraft.username,
                                password: password
                            )
                        )
                    }

                    if self.requestMode == .passkeyRegistration {
                        self.processPasskeyRegistration(
                            targetCipherId: resolvedDraft.id,
                            targetCipherName: resolvedDraft.name,
                            username: resolvedDraft.username
                        )
                    } else {
                        let credential = ASPasswordCredential(
                            user: resolvedDraft.username,
                            password: resolvedDraft.password ?? ""
                        )
                        self.extensionContext.completeRequest(
                            withSelectedCredential: credential,
                            completionHandler: nil
                        )
                    }
                } else {
                    self.cancelWithError(.userCanceled)
                }
            }
        }
    }

    private func existingTemporaryCredentialId(url: String, username: String) -> String? {
        let targetDomain = extractDomain(from: url)
        return credentialStore.fetchCredentials().first { entry in
            guard entry.isTemporaryCredential, entry.username == username else { return false }
            return entry.uris.contains { extractDomain(from: $0) == targetDomain }
        }?.id
    }

    private func provideSelectedCredential(_ entry: SharedCredentialEntry, usePasskey: Bool = false) {
        switch requestMode {
        case .passwordsAndPasskeys, .passkeys:
            if let assertionRequest = currentPasskeyAssertionRequest {
                guard let passkeyIdentity = assertionRequest.credentialIdentity as? ASPasskeyCredentialIdentity else {
                    logger.error("Credential identity is not ASPasskeyCredentialIdentity")
                    cancelWithError(.credentialIdentityNotFound)
                    return
                }
                
                let relyingParty = passkeyIdentity.relyingPartyIdentifier
                let clientDataHash = assertionRequest.clientDataHash
                
                completeAssertion(for: entry, relyingParty: relyingParty, clientDataHash: clientDataHash, passkeyIdentity: passkeyIdentity)
                
            } else if let params = currentPasskeyAssertionParameters {
                let relyingParty = params.relyingPartyIdentifier
                let clientDataHash = params.clientDataHash
                
                if usePasskey && entry.supportsPasskey {
                    completeAssertion(for: entry, relyingParty: relyingParty, clientDataHash: clientDataHash, passkeyIdentity: nil)
                } else {
                    let password = credentialStore.fetchPassword(id: entry.id) ?? ""
                    let credential = ASPasswordCredential(
                        user: entry.username ?? entry.name,
                        password: password
                    )
                    self.extensionContext.completeRequest(
                        withSelectedCredential: credential,
                        completionHandler: nil
                    )
                }
                
            } else {
                let password = credentialStore.fetchPassword(id: entry.id) ?? ""
                let credential = ASPasswordCredential(
                    user: entry.username ?? entry.name,
                    password: password
                )
                self.extensionContext.completeRequest(
                    withSelectedCredential: credential,
                    completionHandler: nil
                )
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
            logger.error("Passkey registration should be handled by processPasskeyRegistration")
            cancelWithError(.failed)
        }
    }
    
    private func processPasskeyRegistration(targetCipherId: String?, targetCipherName: String? = nil, username: String?) {
        guard !didCompletePasskeyRegistration else {
            logger.warning("Ignoring duplicate passkey registration completion attempt")
            return
        }
        didCompletePasskeyRegistration = true

        guard let currentPasskeyRegistrationRequest = currentPasskeyRegistrationRequest else {
            logger.error("No active passkey registration request")
            cancelWithError(.failed)
            return
        }
        
        let relyingParty = (currentPasskeyRegistrationRequest.credentialIdentity as? ASPasskeyCredentialIdentity)?.relyingPartyIdentifier ?? model.relyingPartyId ?? "example.com"
        
        let finalClientDataHash = currentPasskeyRegistrationRequest.clientDataHash
        
        guard let generated = WebAuthnGenerator.generatePasskey(relyingPartyId: relyingParty) else {
            logger.error("Failed to generate passkey")
            cancelWithError(.failed)
            return
        }
        let identityUserHandle = (currentPasskeyRegistrationRequest.credentialIdentity as? ASPasskeyCredentialIdentity)?.userHandle
        let userHandle = identityUserHandle?.isEmpty == false ? identityUserHandle! : generated.credentialID
        
        let pending = PendingPasskey(
            targetCipherId: targetCipherId,
            targetCipherName: targetCipherName,
            relyingPartyId: relyingParty,
            userHandle: userHandle,
            userName: username,
            credentialId: generated.credentialID,
            privateKeyBase64: generated.privateKey
        )
        
        credentialStore.queuePendingPasskey(pending)
        
        let credential = ASPasskeyRegistrationCredential(
            relyingParty: relyingParty,
            clientDataHash: finalClientDataHash,
            credentialID: generated.credentialID,
            attestationObject: generated.attestationObject
        )
        self.extensionContext.completeRegistrationRequest(using: credential, completionHandler: nil)
        logger.info("Completed passkey registration and queued PendingPasskey to SharedCredentialStore")
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

    private enum MatchQuality: Int, Comparable {
        case none = 0
        case fqdnMatch = 1
        case prefixMatch = 2
        case exactMatch = 3
        
        static func < (lhs: MatchQuality, rhs: MatchQuality) -> Bool {
            return lhs.rawValue < rhs.rawValue
        }
    }

    private func sortCredentials(_ allCredentials: [SharedCredentialEntry], for serviceIdentifiers: [ASCredentialServiceIdentifier]) -> [SharedCredentialEntry] {
        allCredentials.sorted { a, b in
            let qualityA = serviceIdentifiers.map { evaluateMatchQuality(entry: a, serviceIdentifier: $0) }.max() ?? .none
            let qualityB = serviceIdentifiers.map { evaluateMatchQuality(entry: b, serviceIdentifier: $0) }.max() ?? .none
            if qualityA != qualityB {
                return qualityA > qualityB
            }
            let orderA = a.order ?? Int.max
            let orderB = b.order ?? Int.max
            if orderA != orderB {
                return orderA < orderB
            }
            return a.name.localizedStandardCompare(b.name) == .orderedAscending
        }
    }

    private func filterAndSortCredentials(_ allCredentials: [SharedCredentialEntry], for serviceIdentifiers: [ASCredentialServiceIdentifier]) -> [SharedCredentialEntry] {
        let matchingWithQuality: [(SharedCredentialEntry, MatchQuality)]
        if serviceIdentifiers.isEmpty {
            matchingWithQuality = allCredentials.map { ($0, .none) }
        } else {
            matchingWithQuality = allCredentials.compactMap { entry in
                let bestQuality = serviceIdentifiers.map { evaluateMatchQuality(entry: entry, serviceIdentifier: $0) }.max() ?? .none
                return bestQuality > .none ? (entry, bestQuality) : nil
            }
        }
        
        return matchingWithQuality.sorted { a, b in
            if a.1 != b.1 {
                return a.1 > b.1 // Higher quality first
            }
            let orderA = a.0.order ?? Int.max
            let orderB = b.0.order ?? Int.max
            if orderA != orderB {
                return orderA < orderB
            }
            return a.0.name.localizedStandardCompare(b.0.name) == .orderedAscending
        }.map { $0.0 }
    }

    private func evaluateMatchQuality(entry: SharedCredentialEntry, serviceIdentifier: ASCredentialServiceIdentifier) -> MatchQuality {
        let browserStr = serviceIdentifier.identifier.lowercased()
        
        var bestQuality: MatchQuality = .none
        
        for uri in entry.uris {
            let secretStr = uri.lowercased()
            let cleanSecret = secretStr.replacingOccurrences(of: "https://", with: "").replacingOccurrences(of: "http://", with: "")
            
            if cleanSecret.isEmpty || cleanSecret == "/" {
                continue
            }
            
            if browserStr == secretStr {
                bestQuality = max(bestQuality, .exactMatch)
                continue
            }
            
            if browserStr.hasPrefix(secretStr) {
                bestQuality = max(bestQuality, .prefixMatch)
                continue
            }
            
            let browserHost = extractDomain(from: browserStr)
            let secretHost = extractDomain(from: secretStr)
            
            if browserHost == secretHost {
                bestQuality = max(bestQuality, .fqdnMatch)
                continue
            }
            
            if secretHost.contains("*") {
                var regexPattern = NSRegularExpression.escapedPattern(for: secretHost)
                if regexPattern.hasPrefix("\\*\\.") {
                    let rest = String(regexPattern.dropFirst(4))
                    regexPattern = "(?:.*\\.)?" + rest
                } else {
                    regexPattern = regexPattern.replacingOccurrences(of: "\\*", with: ".*")
                }
                let pattern = "^" + regexPattern + "$"
                if let regex = try? NSRegularExpression(pattern: pattern, options: .caseInsensitive) {
                    let range = NSRange(location: 0, length: browserHost.utf16.count)
                    if regex.firstMatch(in: browserHost, options: [], range: range) != nil {
                        bestQuality = max(bestQuality, .fqdnMatch)
                    }
                }
            }
        }
        
        return bestQuality
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
