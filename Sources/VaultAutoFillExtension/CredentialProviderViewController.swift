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
        case accountPicker
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

    /// On-device accounts published by the main app. With more than one, an
    /// account picker is shown before the credential list.
    @Published var accounts: [SharedAccountInfo] = []
    @Published var selectedAccountId: String?

    var isMultiAccount: Bool { accounts.count > 1 }

    var selectedAccount: SharedAccountInfo? {
        accounts.first { $0.id == selectedAccountId }
    }

    /// Show the account picker first when several accounts exist, otherwise
    /// resolve the single account directly.
    func prepareAccountSelection() {
        accounts = SharedCredentialStore.shared.fetchAccountInfos()
        if isMultiAccount {
            selectedAccountId = nil
            screen = .accountPicker
        } else {
            selectedAccountId = accounts.first?.id
        }
    }

    var filtered: [SharedCredentialEntry] {
        let source = screen == .allCredentials ? allCredentials : matchedCredentials
        let accountScoped = source.filter { entry in
            // Legacy entries (nil accountId) predate multi-account and behave
            // as belonging to whichever account is selected.
            selectedAccountId == nil || entry.accountId == nil || entry.accountId == selectedAccountId
        }
        if searchText.isEmpty { return accountScoped }
        let query = searchText.lowercased()
        return accountScoped.filter {
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
        switch screen {
        case .createNew: return "Vault UI - New"
        case .accountPicker: return "Vault UI - Accounts"
        default: return "Vault UI - AutoFill"
        }
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
        let fallbackName = relyingPartyId ?? matchingHost ?? "New Login"
        let fallbackUsername = fallbackUsername?.trimmingCharacters(in: .whitespacesAndNewlines)
        let resolvedURL = matchingHost.map { $0.contains("://") ? $0 : "https://\($0)" } ?? ""
        createTitle = fallbackName
        createUsername = fallbackUsername ?? ""
        createPassword = ""
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
            } else if model.screen == .matches, model.isMultiAccount, let account = model.selectedAccount {
                HStack(spacing: 8) {
                    Button {
                        model.searchText = ""
                        model.selectedAccountId = nil
                        model.screen = .accountPicker
                    } label: {
                        HStack(spacing: 4) {
                            Image(systemName: "chevron.left")
                            AccountThumbnailView(colorIndex: account.colorIndex, label: account.label, size: 16)
                            Text(account.label)
                                .lineLimit(1)
                        }
                    }
                    .buttonStyle(.plain)
                    .help("Choose a different account")
                    Spacer()
                    Text(account.serverHost)
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                }
                .padding(.horizontal)
                .padding(.bottom, 6)
            } else if model.isPasskeyRegistration, let rpId = model.relyingPartyId, model.screen != .createNew {
                Text("Register Passkey for \(rpId)")
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
                    .padding(.horizontal)
                    .padding(.bottom, 4)
            }

            Divider()

            if model.screen == .accountPicker {
                accountPickerList
            } else if model.screen == .createNew {
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

    private var accountPickerList: some View {
        VStack(spacing: 0) {
            Text("Choose an account")
                .font(.subheadline)
                .foregroundStyle(.secondary)
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(.horizontal)
                .padding(.vertical, 8)

            List {
                ForEach(model.accounts) { account in
                    Button {
                        model.selectedAccountId = account.id
                        model.searchText = ""
                        model.screen = .matches
                    } label: {
                        HStack(spacing: 10) {
                            AccountThumbnailView(colorIndex: account.colorIndex, label: account.label, size: 32)
                            VStack(alignment: .leading, spacing: 2) {
                                Text(account.label)
                                    .font(.body)
                                    .fontWeight(.medium)
                                Text(account.email)
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                                Text(account.serverHost)
                                    .font(.caption2)
                                    .foregroundStyle(.tertiary)
                            }
                            Spacer()
                            Image(systemName: "chevron.right")
                                .foregroundStyle(.secondary)
                        }
                        .contentShape(Rectangle())
                        .padding(.vertical, 4)
                    }
                    .buttonStyle(.plain)
                }
            }
        }
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

/// Round per-account thumbnail using the shared avatar palette.
struct AccountThumbnailView: View {
    let colorIndex: Int
    let label: String
    let size: CGFloat

    var body: some View {
        let colors = AccountAvatarPalette.gradient(for: colorIndex)
        ZStack {
            Circle()
                .fill(
                    .linearGradient(
                        colors: [colors.start, colors.end],
                        startPoint: .topLeading,
                        endPoint: .bottomTrailing
                    )
                )
            Text(label.prefix(1).uppercased())
                .font(.system(size: size * 0.45, weight: .semibold, design: .rounded))
                .foregroundStyle(.white)
        }
        .frame(width: size, height: size)
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
        model.prepareAccountSelection()
 
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
        model.prepareAccountSelection()
 
        // Present the SwiftUI credential picker
        showCredentialPicker()
    }
    
    private func completeAssertion(for entry: SharedCredentialEntry, relyingParty: String, clientDataHash: Data, vaultKey: SymmetricCryptoKey, passkeyIdentity: ASPasskeyCredentialIdentity? = nil) {
        let allPasskeys = credentialStore.fetchPasskeys(
            id: entry.id,
            accountId: entry.accountId ?? model.selectedAccountId,
            key: vaultKey
        )

        // Find the specific passkey matching the requested credentialID, or fall back to an
        // rpId match. A passkey is only ever valid for its own relying party, so we never
        // fall back to an arbitrary passkey: doing so would let a passkey registered for
        // domain A sign an assertion bound to domain B (cross-domain credential leak).
        var selectedPasskey: SharedPasskeyData? = nil
        if let requestedCredID = passkeyIdentity?.credentialID {
            selectedPasskey = allPasskeys.first { Data(bitwardenFido2CredentialId: $0.credentialId) == requestedCredID }
        }
        if selectedPasskey == nil {
            selectedPasskey = allPasskeys.first(where: { $0.relyingPartyId == relyingParty })
        }

        guard let passkey = selectedPasskey else {
            logger.error("Passkey data not available for selected credential \(entry.id)")
            cancelWithError(.failed)
            return
        }

        // Defense in depth: the chosen passkey must belong to the relying party the
        // assertion is for. This guards the credentialID-match path too, in case a stored
        // credentialID ever collides across relying parties.
        guard passkey.relyingPartyId == relyingParty else {
            logger.error("Refusing assertion: passkey rpId does not match requested relying party for credential \(entry.id)")
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

        // For passkey assertions the system may pass an empty service-identifier list and
        // carry the relying party only in the request parameters. filterAndSortCredentials
        // treats an empty list as "everything matches", so without folding the rpId in,
        // every vault entry showed up as a match for the page.
        var matchIdentifiers = serviceIdentifiers
        let rpId = requestParameters.relyingPartyIdentifier
        if !rpId.isEmpty && !matchIdentifiers.contains(where: { $0.identifier == rpId }) {
            matchIdentifiers.append(ASCredentialServiceIdentifier(identifier: rpId, type: .domain))
        }

        // Passkey-capable entries first: the page asked for a passkey, password rows are
        // only a fallback the system also accepts here.
        let matching = filterAndSortCredentials(allCredentials, for: matchIdentifiers)
        let prioritized = matching.filter(\.supportsPasskey) + matching.filter { !$0.supportsPasskey }

        model.isPasskeyMode = true
        model.isPasskeyRegistration = false
        model.allowsCreateNew = false
        model.createRequiresPassword = false
        model.relyingPartyId = requestParameters.relyingPartyIdentifier
        model.createContextHost = requestParameters.relyingPartyIdentifier
        model.allCredentials = sortCredentials(allCredentials, for: matchIdentifiers)
        model.matchedCredentials = prioritized
        model.screen = .matches
        model.searchText = ""
        model.resetCreateFields(serviceIdentifier: requestParameters.relyingPartyIdentifier)
        model.prepareAccountSelection()
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
        model.prepareAccountSelection()
        
        showCredentialPicker()
    }
 
    // MARK: - Record Identifier Parsing

    /// recordIdentifier formats: `"accountId|cipherId|serviceId"` (multi-account)
    /// and legacy `"cipherId|serviceId"` / bare `"cipherId"` from older builds.
    private func parseRecordIdentifier(_ raw: String) -> (accountId: String?, cipherId: String) {
        let parts = raw.components(separatedBy: "|")
        if parts.count >= 3 {
            return (parts[0], parts[1])
        }
        return (nil, parts.first ?? raw)
    }

    /// Resolve the owning account for a QuickType selection: prefer the account
    /// encoded in the record identifier, fall back to the index entry (covers
    /// legacy two-part identifiers), then to a sole on-device account.
    private func resolveAccountId(parsed: String?, cipherId: String) -> String? {
        if let parsed { return parsed }
        if let accountId = credentialStore.fetchCredentials().first(where: { $0.id == cipherId })?.accountId {
            return accountId
        }
        let accounts = credentialStore.fetchAccountInfos()
        return accounts.count == 1 ? accounts.first?.id : nil
    }

    // MARK: - Provide Credential Without UI

    override func provideCredentialWithoutUserInteraction(for credentialIdentity: ASPasswordCredentialIdentity) {
        logger.info("provideCredentialWithoutUserInteraction for: \(credentialIdentity.user)")

        guard credentialIdentity.recordIdentifier != nil else {
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
        let parsed = parseRecordIdentifier(fullRecordId)
        let recordId = parsed.cipherId
        let accountId = resolveAccountId(parsed: parsed.accountId, cipherId: recordId)

        // The registered identity user may carry a "[ACCOUNT] " prefix — the
        // actual username comes from the stored entry.
        let storedUsername = credentialStore.fetchCredentials()
            .first(where: { $0.id == recordId })
            .map { $0.username ?? $0.name }

        // Authenticate, then decrypt the password on demand with the unlocked vault key.
        authenticateAndUnlock(accountId: accountId) { [weak self] vaultKey in
            guard let self = self else { return }
            DispatchQueue.main.async {
                guard let vaultKey = vaultKey else {
                    self.cancelWithError(.userCanceled)
                    return
                }
                guard let password = self.credentialStore.fetchPassword(id: recordId, accountId: accountId, key: vaultKey) else {
                    logger.error("Could not retrieve password for credential \(recordId)")
                    self.cancelWithError(.failed)
                    return
                }
                let credential = ASPasswordCredential(
                    user: storedUsername ?? credentialIdentity.user,
                    password: password
                )
                self.extensionContext.completeRequest(
                    withSelectedCredential: credential,
                    completionHandler: nil
                )
            }
        }
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
            let parsed = parseRecordIdentifier(fullRecordId)
            let recordId = parsed.cipherId
            guard let entry = credentialStore.fetchCredentials().first(where: { $0.id == recordId }) else {
                cancelWithError(.failed)
                return
            }
            let accountId = parsed.accountId ?? entry.accountId
            model.selectedAccountId = accountId

            // Immediately provide the OTP if we can authenticate
            authenticateAndUnlock(accountId: accountId) { [weak self] vaultKey in
                guard let self = self else { return }
                DispatchQueue.main.async {
                    guard let vaultKey = vaultKey else {
                        self.cancelWithError(.userCanceled)
                        return
                    }
                    self.provideSelectedCredential(entry, vaultKey: vaultKey)
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
            let parsed = parseRecordIdentifier(fullRecordId)
            let recordId = parsed.cipherId
            guard let entry = credentialStore.fetchCredentials().first(where: { $0.id == recordId }) else {
                cancelWithError(.failed)
                return
            }
            let accountId = parsed.accountId ?? entry.accountId
            model.selectedAccountId = accountId

            authenticateAndUnlock(accountId: accountId) { [weak self] vaultKey in
                guard let self = self else { return }
                DispatchQueue.main.async {
                    guard let vaultKey = vaultKey else {
                        self.cancelWithError(.userCanceled)
                        return
                    }
                    self.provideSelectedCredential(entry, vaultKey: vaultKey, usePasskey: true)
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

        let accountId = entry.accountId ?? model.selectedAccountId

        authenticate { [weak self] context in
            guard let self = self else { return }
            DispatchQueue.main.async {
                guard let context = context else {
                    self.cancelWithError(.userCanceled)
                    return
                }
                if self.requestMode == .passkeyRegistration {
                    // Registration generates a new key; it does not read vault secrets.
                    self.processPasskeyRegistration(targetCipherId: entry.id, username: entry.username, accountId: accountId)
                } else {
                    guard let vaultKey = self.credentialStore.retrieveAutoFillVaultKey(accountId: accountId, context: context) else {
                        logger.error("Authenticated but could not retrieve AutoFill vault key")
                        self.cancelWithError(.failed)
                        return
                    }
                    self.provideSelectedCredential(entry, vaultKey: vaultKey, usePasskey: usePasskey)
                }
            }
        }
    }

    private func saveTemporaryCredential(_ draft: TemporaryCredentialDraft) {
        let accountId = model.selectedAccountId
        let resolvedDraft = TemporaryCredentialDraft(
            id: existingTemporaryCredentialId(url: draft.url, username: draft.username) ?? draft.id,
            name: draft.name,
            username: draft.username,
            password: draft.password,
            url: draft.url,
            creationDate: draft.creationDate,
            accountId: accountId
        )
        logger.info("User selected to create temporary credential: \(resolvedDraft.name)")
        authenticateAndUnlock(accountId: accountId) { [weak self] vaultKey in
            guard let self = self else { return }
            DispatchQueue.main.async {
                guard let vaultKey = vaultKey else {
                    self.cancelWithError(.userCanceled)
                    return
                }
                self.credentialStore.queueTemporaryCredentialDraft(resolvedDraft, key: vaultKey)
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
                        username: resolvedDraft.username,
                        accountId: resolvedDraft.accountId
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

    private func provideSelectedCredential(_ entry: SharedCredentialEntry, vaultKey: SymmetricCryptoKey, usePasskey: Bool = false) {
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

                completeAssertion(for: entry, relyingParty: relyingParty, clientDataHash: clientDataHash, vaultKey: vaultKey, passkeyIdentity: passkeyIdentity)

            } else if let params = currentPasskeyAssertionParameters {
                let relyingParty = params.relyingPartyIdentifier
                let clientDataHash = params.clientDataHash

                if usePasskey && entry.supportsPasskey {
                    completeAssertion(for: entry, relyingParty: relyingParty, clientDataHash: clientDataHash, vaultKey: vaultKey, passkeyIdentity: nil)
                } else {
                    let password = credentialStore.fetchPassword(id: entry.id, accountId: entry.accountId ?? model.selectedAccountId, key: vaultKey) ?? ""
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
                let password = credentialStore.fetchPassword(id: entry.id, accountId: entry.accountId ?? model.selectedAccountId, key: vaultKey) ?? ""
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
            guard let totpSecret = credentialStore.fetchTotp(id: entry.id, accountId: entry.accountId ?? model.selectedAccountId, key: vaultKey) else {
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
    
    private func processPasskeyRegistration(targetCipherId: String?, targetCipherName: String? = nil, username: String?, accountId: String? = nil) {
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
            privateKeyBase64: generated.privateKey,
            accountId: accountId ?? model.selectedAccountId
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

    /// Authenticate the user (Touch ID, with device-passcode fallback) and return the
    /// evaluated `LAContext`, or nil if authentication failed or is unavailable.
    ///
    /// The same context is reused to retrieve the biometric-gated vault key, so a
    /// single prompt satisfies both the policy evaluation and the keychain read.
    private func authenticate(completion: @escaping (LAContext?) -> Void) {
        let context = LAContext()
        context.touchIDAuthenticationAllowableReuseDuration = 10
        var error: NSError?

        if context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &error) {
            context.evaluatePolicy(
                .deviceOwnerAuthentication,
                localizedReason: "Authenticate to AutoFill with Vault UI"
            ) { success, _ in
                completion(success ? context : nil)
            }
        } else {
            logger.warning("Device authentication not available: \(error?.localizedDescription ?? "unknown")")
            completion(nil)
        }
    }

    /// Authenticate and return the unlocked vault key of the given account,
    /// needed to decrypt exported secrets. Returns nil if authentication failed
    /// or no key is available.
    private func authenticateAndUnlock(accountId: String?, completion: @escaping (SymmetricCryptoKey?) -> Void) {
        authenticate { [weak self] context in
            guard let self = self, let context = context else {
                completion(nil)
                return
            }
            let key = self.credentialStore.retrieveAutoFillVaultKey(accountId: accountId, context: context)
            if key == nil {
                logger.error("Authenticated but could not retrieve AutoFill vault key")
            }
            completion(key)
        }
    }

    // MARK: - Helpers

    private func cancelWithError(_ code: ASExtensionError.Code) {
        let error = NSError(domain: ASExtensionErrorDomain, code: code.rawValue)
        self.extensionContext.cancelRequest(withError: error)
    }

    // Credential/URL matching is centralized in `CredentialMatcher` (VaultModels)
    // so every AutoFill surface shares the same phishing-resistant logic.
    private typealias MatchQuality = CredentialMatcher.MatchQuality

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

    /// Decide how well a stored credential matches the page/app being filled.
    /// Delegates to the shared, phishing-resistant `CredentialMatcher`.
    private func evaluateMatchQuality(entry: SharedCredentialEntry, serviceIdentifier: ASCredentialServiceIdentifier) -> MatchQuality {
        CredentialMatcher.bestMatchQuality(storedURIs: entry.uris, siteIdentifier: serviceIdentifier.identifier)
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
