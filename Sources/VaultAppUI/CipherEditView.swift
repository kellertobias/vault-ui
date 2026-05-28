// MARK: - VaultAppUI/CipherEditView.swift
// Create and edit vault items

import SwiftUI
import AppKit
import VaultModels
import VaultCrypto
import VaultServices
import VaultAPI
import VaultSync
import CryptoKit

/// Mode for the cipher editor.
enum CipherEditMode {
    case create(CipherType)
    case edit(String)  // cipher ID
}

/// Create/edit view for vault items.
struct CipherEditView: View {
    let mode: CipherEditMode
    let onDismiss: () -> Void
    @EnvironmentObject var session: SessionManager

    // Common fields
    @State private var name = ""
    @State private var notes = ""
    @State private var isFavorite = false
    @State private var selectedFolderId: String?

    // Login fields
    @State private var loginUsername = ""
    @State private var loginPassword = ""
    @State private var loginTotp = ""
    @State private var hasExistingTotp = false
    @State private var clearExistingTotp = false
    @State private var loginUris: [String] = [""]

    // Card fields
    @State private var cardholderName = ""
    @State private var cardNumber = ""
    @State private var cardBrand = ""
    @State private var cardExpMonth = ""
    @State private var cardExpYear = ""
    @State private var cardCode = ""

    // Identity fields
    @State private var idTitle = ""
    @State private var idFirstName = ""
    @State private var idMiddleName = ""
    @State private var idLastName = ""
    @State private var idUsername = ""
    @State private var idCompany = ""
    @State private var idEmail = ""
    @State private var idPhone = ""
    @State private var idAddress1 = ""
    @State private var idAddress2 = ""
    @State private var idCity = ""
    @State private var idState = ""
    @State private var idPostalCode = ""
    @State private var idCountry = ""

    // SSH Key fields
    @State private var sshPublicKey = ""
    @State private var sshPrivateKey = ""

    // Custom fields
    @State private var customFields: [(name: String, value: String, type: FieldType)] = []

    // CLI slug (vaultui-slug custom field)
    @State private var vaultuiSlug = ""
    @State private var slugError: String?

    @State private var isSaving = false
    @State private var errorMessage: String?
    @State private var loadedCipherType: CipherType?
    @State private var loadedCipher: Cipher?
    @State private var isTemporaryDraft = false
    @State private var copiedError = false

    private var cipherType: CipherType {
        switch mode {
        case .create(let type): return type
        case .edit: return loadedCipherType ?? .login
        }
    }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                // Header
                HStack {
                    Text(isCreating ? "New \(cipherType.displayName)" : "Edit Item")
                        .font(.title2.bold())
                    Spacer()
                    if let error = errorMessage {
                        HStack(alignment: .top, spacing: 6) {
                            Image(systemName: "exclamationmark.circle.fill")
                                .foregroundStyle(.red)
                                .padding(.top, 2)

                            Text(error)
                                .font(.caption)
                                .foregroundStyle(.red)
                                .lineLimit(nil)
                                .fixedSize(horizontal: false, vertical: true)
                                .textSelection(.enabled)

                            Button {
                                NSPasteboard.general.clearContents()
                                NSPasteboard.general.setString(error, forType: .string)
                                withAnimation { copiedError = true }
                                DispatchQueue.main.asyncAfter(deadline: .now() + 1.5) {
                                    withAnimation { copiedError = false }
                                }
                            } label: {
                                Image(systemName: copiedError ? "checkmark" : "doc.on.doc")
                                    .font(.caption)
                                    .foregroundStyle(copiedError ? .green : .secondary)
                            }
                            .buttonStyle(.plain)
                            .help("Copy error message")
                        }
                    }

                    Spacer()

                    Button("Cancel") { onDismiss() }
                        .keyboardShortcut(.cancelAction)

                    Button {
                        save()
                    } label: {
                        if isSaving {
                            ProgressView()
                                .controlSize(.small)
                        } else {
                            Text("Save")
                        }
                    }
                    .buttonStyle(.borderedProminent)
                    .keyboardShortcut(.defaultAction)
                    .disabled(name.isEmpty || isSaving || session.isOffline)
                }

                if session.isOffline {
                    Label("Cannot save changes while offline", systemImage: "wifi.slash")
                        .font(.caption)
                        .padding(8)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .background(.orange.opacity(0.2))
                        .foregroundStyle(.orange)
                        .clipShape(RoundedRectangle(cornerRadius: 8))
                }

                if isTemporaryDraft {
                    HStack(spacing: 8) {
                        Image(systemName: "clock.badge.exclamationmark")
                        Text("Temporary credential")
                        Spacer()
                        Text("This draft stays local until the browser confirms a successful submit.")
                            .foregroundStyle(.secondary)
                    }
                    .font(.caption)
                    .padding(10)
                    .background(.orange.opacity(0.12))
                    .foregroundStyle(.orange)
                    .clipShape(RoundedRectangle(cornerRadius: 8))
                }

                // Common fields
                GroupBox("Details") {
                    VStack(spacing: 12) {
                        LabeledTextField(label: "Name", text: $name, icon: "textformat")

                        // CLI Slug
                        VStack(alignment: .leading, spacing: 4) {
                            LabeledTextField(label: "CLI Slug", text: $vaultuiSlug, icon: "terminal.fill")
                                .onChange(of: vaultuiSlug) { _, newValue in
                                    if newValue.isEmpty || VaultUISlug.isValid(newValue) {
                                        slugError = nil
                                    } else {
                                        slugError = "Only a-zA-Z0-9, hyphens, underscores, and dots"
                                    }
                                }
                            if let slugError {
                                Text(slugError)
                                    .font(.caption2)
                                    .foregroundStyle(.red)
                                    .padding(.leading, 26)
                            } else if !vaultuiSlug.isEmpty {
                                Text("Usage: vaultui secret get \(vaultuiSlug)")
                                    .font(.caption2)
                                    .foregroundStyle(.secondary)
                                    .padding(.leading, 26)
                            }
                        }
                    }
                    .padding(8)
                }

                // Type-specific fields
                switch cipherType {
                case .login:
                    loginFields
                case .secureNote:
                    EmptyView()
                case .card:
                    cardFields
                case .identity:
                    identityFields
                case .sshKey:
                    sshKeyFields
                }

                // Notes
                GroupBox("Notes") {
                    TextEditor(text: $notes)
                        .font(.body)
                        .frame(minHeight: 80)
                        .padding(4)
                }

                // Custom fields
                GroupBox {
                    VStack(alignment: .leading, spacing: 8) {
                        ForEach(Array(customFields.enumerated()), id: \.offset) { idx, _ in
                            HStack {
                                TextField("Name", text: Binding(
                                    get: { customFields[idx].name },
                                    set: { customFields[idx].name = $0 }
                                ))
                                .textFieldStyle(.roundedBorder)

                                TextField("Value", text: Binding(
                                    get: { customFields[idx].value },
                                    set: { customFields[idx].value = $0 }
                                ))
                                .textFieldStyle(.roundedBorder)

                                Button(role: .destructive) {
                                    customFields.remove(at: idx)
                                } label: {
                                    Image(systemName: "minus.circle.fill")
                                }
                                .buttonStyle(.plain)
                            }
                        }

                        Button {
                            customFields.append((name: "", value: "", type: .text))
                        } label: {
                            Label("Add Field", systemImage: "plus.circle")
                        }
                        .buttonStyle(.plain)
                    }
                    .padding(8)
                } label: {
                    Text("Custom Fields")
                }

            }
            .padding(24)
        }
        .frame(minWidth: 500, minHeight: 600)
        .task { loadExistingCipher() }
    }

    // MARK: - Login Fields

    private var loginFields: some View {
        GroupBox("Login") {
            VStack(spacing: 12) {
                LabeledTextField(label: "Username", text: $loginUsername, icon: "person.fill")

                HStack {
                    LabeledTextField(
                        label: "Password",
                        text: $loginPassword,
                        icon: "lock.fill",
                        isSecure: true
                    )

                    VStack(spacing: 8) {
                        Button {
                            loginPassword = PasswordGenerator.generatePassword(length: 20)
                        } label: {
                            Label("Suggest Strong Password", systemImage: "wand.and.stars")
                        }
                        .help("Suggest Strong Password")

                        if !isTemporaryDraft {
                            Button {
                                loginPassword = PasswordGenerator.generatePassword(length: 20)
                            } label: {
                                Image(systemName: "dice.fill")
                            }
                            .help("Generate Password")
                        }
                    }
                }

                if hasExistingTotp && !clearExistingTotp {
                    HStack(spacing: 8) {
                        Image(systemName: "clock.badge.checkmark.fill")
                            .font(.system(size: 13))
                            .foregroundStyle(.secondary)
                            .frame(width: 18)
                        
                        VStack(alignment: .leading, spacing: 2) {
                            Text("TOTP Secret")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                            Text("Secret configured (hidden)")
                                .font(.body)
                                .foregroundStyle(.secondary)
                                .padding(.vertical, 4)
                        }
                        
                        Spacer()
                        
                        Button(role: .destructive) {
                            clearExistingTotp = true
                        } label: {
                            Text("Remove")
                        }
                        .buttonStyle(.bordered)
                    }
                } else {
                    LabeledTextField(label: hasExistingTotp ? "New TOTP Secret" : "TOTP Secret", text: $loginTotp, icon: "clock.badge.checkmark.fill")
                }

                VStack(alignment: .leading, spacing: 8) {
                    Text("URIs")
                        .font(.caption)
                        .foregroundStyle(.secondary)

                    ForEach(Array(loginUris.enumerated()), id: \.offset) { idx, _ in
                        HStack {
                            TextField("https://", text: Binding(
                                get: { loginUris[idx] },
                                set: { loginUris[idx] = $0 }
                            ))
                            .textFieldStyle(.roundedBorder)

                            if loginUris.count > 1 {
                                Button(role: .destructive) {
                                    loginUris.remove(at: idx)
                                } label: {
                                    Image(systemName: "minus.circle.fill")
                                }
                                .buttonStyle(.plain)
                            }
                        }
                    }

                    Button {
                        loginUris.append("")
                    } label: {
                        Label("Add URI", systemImage: "plus.circle")
                    }
                    .buttonStyle(.plain)
                }
            }
            .padding(8)
        }
    }

    // MARK: - Card Fields

    private var cardFields: some View {
        GroupBox("Card") {
            VStack(spacing: 12) {
                LabeledTextField(label: "Cardholder Name", text: $cardholderName, icon: "person.fill")
                LabeledTextField(label: "Number", text: $cardNumber, icon: "creditcard.fill")
                LabeledTextField(label: "Brand", text: $cardBrand, icon: "tag.fill")
                HStack {
                    LabeledTextField(label: "Exp Month", text: $cardExpMonth, icon: "calendar")
                    LabeledTextField(label: "Exp Year", text: $cardExpYear, icon: "calendar")
                }
                LabeledTextField(label: "CVV", text: $cardCode, icon: "lock.rectangle.fill", isSecure: true)
            }
            .padding(8)
        }
    }

    // MARK: - Identity Fields

    private var identityFields: some View {
        GroupBox("Identity") {
            VStack(spacing: 12) {
                LabeledTextField(label: "Title", text: $idTitle, icon: "person.text.rectangle")
                HStack {
                    LabeledTextField(label: "First Name", text: $idFirstName, icon: "person.fill")
                    LabeledTextField(label: "Middle", text: $idMiddleName, icon: "person.fill")
                    LabeledTextField(label: "Last Name", text: $idLastName, icon: "person.fill")
                }
                LabeledTextField(label: "Username", text: $idUsername, icon: "at")
                LabeledTextField(label: "Company", text: $idCompany, icon: "building.2.fill")
                LabeledTextField(label: "Email", text: $idEmail, icon: "envelope.fill")
                LabeledTextField(label: "Phone", text: $idPhone, icon: "phone.fill")
                LabeledTextField(label: "Address 1", text: $idAddress1, icon: "house.fill")
                LabeledTextField(label: "Address 2", text: $idAddress2, icon: "house.fill")
                HStack {
                    LabeledTextField(label: "City", text: $idCity, icon: "mappin")
                    LabeledTextField(label: "State", text: $idState, icon: "mappin")
                }
                HStack {
                    LabeledTextField(label: "Postal Code", text: $idPostalCode, icon: "number")
                    LabeledTextField(label: "Country", text: $idCountry, icon: "globe")
                }
            }
            .padding(8)
        }
    }

    // MARK: - SSH Key Fields

    private var sshKeyFields: some View {
        GroupBox("SSH Key") {
            VStack(spacing: 12) {
                VStack(alignment: .leading, spacing: 4) {
                    Text("Public Key")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                    TextEditor(text: $sshPublicKey)
                        .font(.system(.body, design: .monospaced))
                        .frame(minHeight: 60)
                }

                VStack(alignment: .leading, spacing: 4) {
                    Text("Private Key")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                    TextEditor(text: $sshPrivateKey)
                        .font(.system(.body, design: .monospaced))
                        .frame(minHeight: 100)
                }

                HStack {
                    Button("Generate Ed25519 Key") {
                        generateSSHKey()
                    }

                    Button("Import from File…") {
                        importSSHKeyFromFile()
                    }
                }
            }
            .padding(8)
        }
    }

    // MARK: - Helpers

    private var isCreating: Bool {
        if case .create = mode { return true }
        return false
    }

    private func loadExistingCipher() {
        guard case .edit(let cipherId) = mode else { return }
        guard let engine = try? session.getSyncEngine() else { return }
        guard let ciphers = try? engine.fetchCiphers(includeDeleted: false) else { return }
        guard let persisted = ciphers.first(where: { $0.id == cipherId }),
              let cipher = try? persisted.toCipher() else { return }

        loadedCipherType = cipher.type
        loadedCipher = cipher
        isTemporaryDraft = persisted.syncStatus == .temporaryDraft
        
        let decrypt: (EncString?) -> String? = { session.decrypt($0, itemKey: cipher.key) }
        
        name = decrypt(cipher.name) ?? ""
        notes = decrypt(cipher.notes) ?? ""
        isFavorite = cipher.favorite
        selectedFolderId = cipher.folderId

        switch cipher.type {
        case .login:
            if let login = cipher.login {
                loginUsername = decrypt(login.username) ?? ""
                loginPassword = decrypt(login.password) ?? ""
                let existingTotp = decrypt(login.totp) ?? ""
                if !existingTotp.isEmpty {
                    hasExistingTotp = true
                }
                loginUris = login.uris?.compactMap { decrypt($0.uri) } ?? [""]
                if loginUris.isEmpty { loginUris = [""] }
            }

        case .card:
            if let card = cipher.card {
                cardholderName = decrypt(card.cardholderName) ?? ""
                cardNumber = decrypt(card.number) ?? ""
                cardBrand = decrypt(card.brand) ?? ""
                cardExpMonth = decrypt(card.expMonth) ?? ""
                cardExpYear = decrypt(card.expYear) ?? ""
                cardCode = decrypt(card.code) ?? ""
            }

        case .identity:
            if let id = cipher.identity {
                idTitle = decrypt(id.title) ?? ""
                idFirstName = decrypt(id.firstName) ?? ""
                idMiddleName = decrypt(id.middleName) ?? ""
                idLastName = decrypt(id.lastName) ?? ""
                idUsername = decrypt(id.username) ?? ""
                idCompany = decrypt(id.company) ?? ""
                idEmail = decrypt(id.email) ?? ""
                idPhone = decrypt(id.phone) ?? ""
                idAddress1 = decrypt(id.address1) ?? ""
                idAddress2 = decrypt(id.address2) ?? ""
                idCity = decrypt(id.city) ?? ""
                idState = decrypt(id.state) ?? ""
                idPostalCode = decrypt(id.postalCode) ?? ""
                idCountry = decrypt(id.country) ?? ""
            }

        case .sshKey:
            if let ssh = cipher.sshKey {
                sshPublicKey = decrypt(ssh.publicKey) ?? ""
                sshPrivateKey = decrypt(ssh.privateKey) ?? ""
            }

        case .secureNote:
            break // No additional fields to load
        }

        // Load custom fields (separate vaultui-slug from regular custom fields)
        if let fields = cipher.fields {
            var regularFields: [(name: String, value: String, type: FieldType)] = []
            for field in fields {
                let fieldName = decrypt(field.name) ?? ""
                let fieldValue = decrypt(field.value) ?? ""
                if fieldName == VaultUISlug.fieldName {
                    vaultuiSlug = fieldValue
                } else if fieldName == "vaultui-temporary" || fieldName == "vaultui-temporary-url" {
                    continue
                } else {
                    regularFields.append((name: fieldName, value: fieldValue, type: field.type))
                }
            }
            customFields = regularFields
        }
    }

    private static func computeSSHFingerprint(_ publicKeyLine: String) -> String? {
        let parts = publicKeyLine.split(separator: " ")
        guard parts.count >= 2,
              let keyData = Data(base64Encoded: String(parts[1])) else {
            return nil
        }

        let hash = SHA256.hash(data: keyData)
        let base64 = Data(hash).base64EncodedString()
            .replacingOccurrences(of: "=", with: "")
        return "SHA256:\(base64)"
    }

    private func save() {
        isSaving = true
        errorMessage = nil

        Task {
            do {
                // When editing, start from the loaded cipher to preserve
                // server-required fields (organizationId, collectionIds, key, etc.)
                var cipher: Cipher
                let itemKey: SymmetricCryptoKey
                
                if case .edit = mode, let existing = loadedCipher {
                    cipher = existing
                    itemKey = try session.getItemKey(for: cipher)
                } else {
                    cipher = Cipher(type: cipherType)
                    // Generate item-level key for new items
                    let (newKey, encryptedKey) = try session.generateItemKey()
                    itemKey = newKey
                    cipher.key = encryptedKey
                }
                
                let encryptIfPresent: (String) -> EncString? = { text in
                    guard !text.isEmpty else { return nil }
                    return try? session.encrypt(text, using: itemKey)
                }
                cipher.name = encryptIfPresent(name)
                cipher.notes = encryptIfPresent(notes)
                cipher.favorite = isFavorite
                cipher.folderId = selectedFolderId

                switch cipherType {
                case .login:
                    var login = cipher.login ?? LoginData()
                    login.username = encryptIfPresent(loginUsername)
                    login.password = encryptIfPresent(loginPassword)
                    
                    if !loginTotp.isEmpty {
                        login.totp = encryptIfPresent(loginTotp)
                    } else if clearExistingTotp {
                        login.totp = nil
                    }
                    
                    let validUris = loginUris.filter { !$0.isEmpty }
                    if !validUris.isEmpty {
                        login.uris = validUris.compactMap { uri in
                            LoginUri(uri: encryptIfPresent(uri), match: nil)
                        }
                    } else {
                        login.uris = nil
                    }
                    cipher.login = login

                case .card:
                    var card = cipher.card ?? CardData()
                    card.cardholderName = encryptIfPresent(cardholderName)
                    card.number = encryptIfPresent(cardNumber)
                    card.brand = encryptIfPresent(cardBrand)
                    card.expMonth = encryptIfPresent(cardExpMonth)
                    card.expYear = encryptIfPresent(cardExpYear)
                    card.code = encryptIfPresent(cardCode)
                    cipher.card = card

                case .identity:
                    var id = cipher.identity ?? IdentityData()
                    id.title = encryptIfPresent(idTitle)
                    id.firstName = encryptIfPresent(idFirstName)
                    id.middleName = encryptIfPresent(idMiddleName)
                    id.lastName = encryptIfPresent(idLastName)
                    id.username = encryptIfPresent(idUsername)
                    id.company = encryptIfPresent(idCompany)
                    id.email = encryptIfPresent(idEmail)
                    id.phone = encryptIfPresent(idPhone)
                    id.address1 = encryptIfPresent(idAddress1)
                    id.address2 = encryptIfPresent(idAddress2)
                    id.city = encryptIfPresent(idCity)
                    id.state = encryptIfPresent(idState)
                    id.postalCode = encryptIfPresent(idPostalCode)
                    id.country = encryptIfPresent(idCountry)
                    cipher.identity = id

                case .secureNote:
                    cipher.secureNote = cipher.secureNote ?? SecureNoteData(type: .generic)

                case .sshKey:
                    var ssh = cipher.sshKey ?? SSHKeyData()
                    ssh.publicKey = encryptIfPresent(sshPublicKey)
                    ssh.privateKey = encryptIfPresent(sshPrivateKey)
                    if let fingerprint = Self.computeSSHFingerprint(sshPublicKey) {
                        ssh.keyFingerprint = encryptIfPresent(fingerprint)
                    }
                    cipher.sshKey = ssh
                }

                // Build custom fields list
                var allFields: [CustomField] = []

                // Add vaultui-slug field if set
                if !vaultuiSlug.isEmpty {
                    if !VaultUISlug.isValid(vaultuiSlug) {
                        errorMessage = "Invalid CLI slug format. Use only a-zA-Z0-9, hyphens, underscores, and dots."
                        isSaving = false
                        return
                    }
                    allFields.append(CustomField(
                        name: encryptIfPresent(VaultUISlug.fieldName),
                        value: encryptIfPresent(vaultuiSlug),
                        type: .text
                    ))
                }

                // Add regular custom fields
                let validFields = customFields.filter { !$0.name.isEmpty }
                for field in validFields {
                    allFields.append(CustomField(
                        name: encryptIfPresent(field.name),
                        value: encryptIfPresent(field.value),
                        type: field.type
                    ))
                }

                cipher.fields = allFields.isEmpty ? nil : allFields

                if let engine = try? session.getSyncEngine() {
                    if isTemporaryDraft {
                        if case .edit(let id) = mode {
                            cipher.id = id
                        }
                        try engine.saveTemporaryCipherLocally(cipher)
                    } else {
                        let operation: PendingOperation
                        if case .edit = mode {
                            operation = .update
                        } else {
                            operation = .create
                        }
                        
                        if case .edit(let id) = mode {
                            cipher.id = id
                        }
                        
                        try engine.saveCipherLocally(cipher, operation: operation)
                        
                        // Push to server in background
                        Task {
                            try? await engine.fullSync()
                        }
                    }
                }
                
                onDismiss()
            } catch {
                errorMessage = error.localizedDescription
                isSaving = false
            }
        }
    }

    private func generateSSHKey() {
        let key = Curve25519.Signing.PrivateKey()
        let pub = key.publicKey

        // Format public key in OpenSSH format
        let pubBlob = ImportService.formatEd25519PublicKeyBlob(pub.rawRepresentation)
        sshPublicKey = "ssh-ed25519 \(pubBlob.base64EncodedString())"

        // Format private key as proper OpenSSH PEM
        sshPrivateKey = ImportService.formatOpenSSHPrivateKey(
            privateKey: key.rawRepresentation,
            publicKey: pub.rawRepresentation,
            comment: ""
        )
    }

    private func importSSHKeyFromFile() {
        let panel = NSOpenPanel()
        panel.canChooseDirectories = false
        panel.allowsMultipleSelection = true
        panel.showsHiddenFiles = true
        panel.directoryURL = FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent(".ssh")
        
        panel.begin { response in
            guard response == .OK else { return }
            
            for url in panel.urls {
                if let data = try? Data(contentsOf: url), let text = String(data: data, encoding: .utf8) {
                    let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
                    
                    if url.pathExtension == "pub" || trimmed.hasPrefix("ssh-") || trimmed.hasPrefix("ecdsa-") {
                        sshPublicKey = trimmed
                    } else if trimmed.contains("PRIVATE KEY") {
                        // Process key: auto-converts PKCS#1 RSA to OpenSSH format
                        let processed = ImportService.processImportedSSHKey(trimmed)
                        sshPrivateKey = processed.privateKey
                        
                        // Auto-populate public key if not already set
                        if sshPublicKey.isEmpty {
                            // Try sibling .pub file first (may fail in sandbox)
                            let pubURL = url.appendingPathExtension("pub")
                            if let pubData = try? Data(contentsOf: pubURL),
                               let pubText = String(data: pubData, encoding: .utf8) {
                                sshPublicKey = pubText.trimmingCharacters(in: .whitespacesAndNewlines)
                            }
                            // Use the public key extracted during processing
                            if sshPublicKey.isEmpty, let pubKey = processed.publicKey {
                                sshPublicKey = pubKey
                            }
                        }
                    } else {
                        if url.pathExtension == "pub" {
                            sshPublicKey = trimmed
                        } else {
                            sshPrivateKey = trimmed
                        }
                    }
                }
            }
        }
    }
}

// MARK: - Labeled Text Field

/// A styled text field with icon and label.
struct LabeledTextField: View {
    let label: String
    @Binding var text: String
    let icon: String
    var isSecure: Bool = false

    @State private var isRevealed = false

    var body: some View {
        HStack(spacing: 8) {
            Image(systemName: icon)
                .font(.system(size: 13))
                .foregroundStyle(.secondary)
                .frame(width: 18)

            VStack(alignment: .leading, spacing: 2) {
                Text(label)
                    .font(.caption)
                    .foregroundStyle(.secondary)

                if isSecure && !isRevealed {
                    SecureField(label, text: $text)
                        .textFieldStyle(.roundedBorder)
                } else {
                    TextField(label, text: $text)
                        .textFieldStyle(.roundedBorder)
                }
            }

            if isSecure {
                Button {
                    isRevealed.toggle()
                } label: {
                    Image(systemName: isRevealed ? "eye.slash" : "eye")
                        .font(.system(size: 13))
                        .foregroundStyle(.secondary)
                }
                .buttonStyle(.plain)
            }
        }
    }
}
