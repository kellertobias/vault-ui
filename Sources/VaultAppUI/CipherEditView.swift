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
    @EnvironmentObject var session: SessionManager
    @Environment(\.dismiss) private var dismiss

    // Common fields
    @State private var name = ""
    @State private var notes = ""
    @State private var isFavorite = false
    @State private var selectedFolderId: String?

    // Login fields
    @State private var loginUsername = ""
    @State private var loginPassword = ""
    @State private var loginTotp = ""
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

    @State private var isSaving = false
    @State private var errorMessage: String?
    @State private var loadedCipherType: CipherType?
    @State private var loadedCipher: Cipher?

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

                            Spacer()

                            Button {
                                NSPasteboard.general.clearContents()
                                NSPasteboard.general.setString(error, forType: .string)
                            } label: {
                                Image(systemName: "doc.on.doc")
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                            }
                            .buttonStyle(.plain)
                            .help("Copy error message")
                        }
                    }
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

                // Common fields
                GroupBox("Details") {
                    VStack(spacing: 12) {
                        LabeledTextField(label: "Name", text: $name, icon: "textformat")
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

                // Action buttons
                HStack {
                    Button("Cancel") { dismiss() }
                        .keyboardShortcut(.cancelAction)

                    Spacer()

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

                    Button {
                        loginPassword = PasswordGenerator.generatePassword(length: 20)
                    } label: {
                        Image(systemName: "dice.fill")
                    }
                    .help("Generate Password")
                }

                LabeledTextField(label: "TOTP Secret", text: $loginTotp, icon: "clock.badge.checkmark.fill")

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
        name = session.decrypt(cipher.name) ?? ""
        notes = session.decrypt(cipher.notes) ?? ""
        isFavorite = cipher.favorite
        selectedFolderId = cipher.folderId

        switch cipher.type {
        case .login:
            if let login = cipher.login {
                loginUsername = session.decrypt(login.username) ?? ""
                loginPassword = session.decrypt(login.password) ?? ""
                loginTotp = session.decrypt(login.totp) ?? ""
                loginUris = login.uris?.compactMap { session.decrypt($0.uri) } ?? [""]
                if loginUris.isEmpty { loginUris = [""] }
            }

        case .card:
            if let card = cipher.card {
                cardholderName = session.decrypt(card.cardholderName) ?? ""
                cardNumber = session.decrypt(card.number) ?? ""
                cardBrand = session.decrypt(card.brand) ?? ""
                cardExpMonth = session.decrypt(card.expMonth) ?? ""
                cardExpYear = session.decrypt(card.expYear) ?? ""
                cardCode = session.decrypt(card.code) ?? ""
            }

        case .identity:
            if let id = cipher.identity {
                idTitle = session.decrypt(id.title) ?? ""
                idFirstName = session.decrypt(id.firstName) ?? ""
                idMiddleName = session.decrypt(id.middleName) ?? ""
                idLastName = session.decrypt(id.lastName) ?? ""
                idUsername = session.decrypt(id.username) ?? ""
                idCompany = session.decrypt(id.company) ?? ""
                idEmail = session.decrypt(id.email) ?? ""
                idPhone = session.decrypt(id.phone) ?? ""
                idAddress1 = session.decrypt(id.address1) ?? ""
                idAddress2 = session.decrypt(id.address2) ?? ""
                idCity = session.decrypt(id.city) ?? ""
                idState = session.decrypt(id.state) ?? ""
                idPostalCode = session.decrypt(id.postalCode) ?? ""
                idCountry = session.decrypt(id.country) ?? ""
            }

        case .sshKey:
            if let ssh = cipher.sshKey {
                sshPublicKey = session.decrypt(ssh.publicKey) ?? ""
                sshPrivateKey = session.decrypt(ssh.privateKey) ?? ""
            }

        case .secureNote:
            break // No additional fields to load
        }

        // Load custom fields
        if let fields = cipher.fields {
            customFields = fields.map { field in
                (
                    name: session.decrypt(field.name) ?? "",
                    value: session.decrypt(field.value) ?? "",
                    type: field.type
                )
            }
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
                    var login = LoginData()
                    login.username = encryptIfPresent(loginUsername)
                    login.password = encryptIfPresent(loginPassword)
                    login.totp = encryptIfPresent(loginTotp)
                    
                    let validUris = loginUris.filter { !$0.isEmpty }
                    if !validUris.isEmpty {
                        login.uris = validUris.compactMap { uri in
                            LoginUri(uri: encryptIfPresent(uri), match: nil)
                        }
                    }
                    cipher.login = login

                case .card:
                    var card = CardData()
                    card.cardholderName = encryptIfPresent(cardholderName)
                    card.number = encryptIfPresent(cardNumber)
                    card.brand = encryptIfPresent(cardBrand)
                    card.expMonth = encryptIfPresent(cardExpMonth)
                    card.expYear = encryptIfPresent(cardExpYear)
                    card.code = encryptIfPresent(cardCode)
                    cipher.card = card

                case .identity:
                    var id = IdentityData()
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
                    cipher.secureNote = SecureNoteData(type: .generic)

                case .sshKey:
                    var ssh = SSHKeyData()
                    ssh.publicKey = encryptIfPresent(sshPublicKey)
                    ssh.privateKey = encryptIfPresent(sshPrivateKey)
                    if let fingerprint = Self.computeSSHFingerprint(sshPublicKey) {
                        ssh.keyFingerprint = encryptIfPresent(fingerprint)
                    }
                    cipher.sshKey = ssh
                }

                let validFields = customFields.filter { !$0.name.isEmpty }
                if !validFields.isEmpty {
                    cipher.fields = validFields.compactMap { field in
                        CustomField(
                            name: encryptIfPresent(field.name),
                            value: encryptIfPresent(field.value),
                            type: field.type
                        )
                    }
                }

                if let engine = try? session.getSyncEngine() {
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
                    
                    // Push to server
                    try await engine.fullSync()
                }
                
                dismiss()
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
                        sshPrivateKey = trimmed
                        
                        // Try to auto-populate public key if not already set
                        if sshPublicKey.isEmpty {
                            // First try the sibling .pub file (may fail in sandbox)
                            let pubURL = url.appendingPathExtension("pub")
                            if let pubData = try? Data(contentsOf: pubURL),
                               let pubText = String(data: pubData, encoding: .utf8) {
                                sshPublicKey = pubText.trimmingCharacters(in: .whitespacesAndNewlines)
                            }
                            // If still empty, extract from the private key itself
                            if sshPublicKey.isEmpty,
                               let extracted = ImportService.extractPublicKeyFromOpenSSHPrivateKey(trimmed) {
                                sshPublicKey = extracted
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
