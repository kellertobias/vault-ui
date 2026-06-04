// MARK: - VaultAppUI/CipherDetailView.swift
// Right column: full cipher detail with type-specific sections

import SwiftUI
import AppKit
import VaultModels
import VaultCrypto
import VaultServices
import VaultAPI
import VaultSync

/// Detail view for a single vault item.
struct CipherDetailView: View {
    let cipherId: String
    var refreshToken: Int = 0
    var onEdit: ((String) -> Void)? = nil
    var onDelete: (() -> Void)? = nil
    var onFavoriteToggled: (() -> Void)? = nil
    @EnvironmentObject var session: SessionManager

    @State private var cipher: Cipher?
    @State private var isLoading = true
    @State private var showDeleteConfirmation = false
    @State private var isTemporaryDraft = false
    @State private var isPromotingTemporaryDraft = false
    @State private var temporaryPromotionError: String?
    @State private var attachmentError: String?
    @State private var downloadingAttachmentId: String?

    private func decrypt(_ encString: EncString?) -> String? {
        session.decrypt(encString, itemKey: cipher?.key)
    }

    var body: some View {
        Group {
            if isLoading {
                ProgressView()
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else if let cipher = cipher {
                ScrollView {
                    VStack(alignment: .leading, spacing: 0) {
                        // Header
                        CipherHeaderView(
                            cipher: cipher,
                            onEdit: { onEdit?(cipherId) },
                            onDelete: { showDeleteConfirmation = true },
                            onFavoriteToggled: { onFavoriteToggled?() }
                        )
                        .id(cipher.id)

                        if isTemporaryDraft {
                            VStack(alignment: .leading, spacing: 8) {
                                HStack(spacing: 8) {
                                    Image(systemName: "clock.badge.exclamationmark")
                                    Text("Temporary credential")
                                    Spacer()
                                    Text("Promotes automatically after a successful form submission.")
                                        .foregroundStyle(.secondary)
                                    Button {
                                        makeTemporaryCredentialPermanent()
                                    } label: {
                                        if isPromotingTemporaryDraft {
                                            ProgressView()
                                                .controlSize(.small)
                                        } else {
                                            Label("Make Permanent", systemImage: "checkmark.seal")
                                        }
                                    }
                                    .buttonStyle(.borderedProminent)
                                    .controlSize(.small)
                                    .disabled(isPromotingTemporaryDraft || session.isOffline)
                                    .help("Save this temporary credential to your vault")
                                }

                                if let temporaryPromotionError {
                                    Text(temporaryPromotionError)
                                        .foregroundStyle(.red)
                                }
                            }
                            .font(.caption)
                            .padding(.horizontal, 24)
                            .padding(.vertical, 10)
                            .background(.orange.opacity(0.12))
                            .foregroundStyle(.orange)
                        }

                        Divider()
                            .padding(.horizontal)

                        let isWifi = cipher.isWifiCredential(decrypt: { session.decrypt($0, itemKey: cipher.key) })

                        // Type-specific content
                        if isWifi {
                            WifiDetailSection(cipher: cipher)
                        } else {
                            switch cipher.type {
                            case .login:
                                LoginDetailSection(login: cipher.login, cipher: cipher, onDeletePasskey: { index in
                                    deletePasskey(at: index)
                                })
                            case .secureNote:
                                SecureNoteDetailSection(cipher: cipher)
                            case .card:
                                CardDetailSection(card: cipher.card, cipher: cipher)
                            case .identity:
                                IdentityDetailSection(identity: cipher.identity, cipher: cipher)
                            case .sshKey:
                                SSHKeyDetailSection(sshKey: cipher.sshKey, cipher: cipher)
                            }
                        }

                        // CLI Slug (if set)
                        if let fields = cipher.fields {
                            CLISlugSection(fields: fields, cipher: cipher)
                        }

                        // Custom Fields (excluding vaultui-slug, and WiFi fields if WiFi)
                        if let fields = cipher.fields {
                            let filtered = fields.filter { field in
                                let name = session.decrypt(field.name, itemKey: cipher.key)
                                if name == VaultUISlug.fieldName { return false }
                                if let name, CertificateMetadata.isCertificateField(name) { return false }
                                if name == "vaultui-temporary" || name == "vaultui-temporary-url" { return false }
                                if isWifi {
                                    let lowerName = name?.lowercased() ?? ""
                                    if lowerName == "netzwerkname" || lowerName == "ssid" || lowerName == "network name" { return false }
                                    if lowerName == "sicherheit" || lowerName == "security" { return false }
                                    if cipher.login?.password == nil && (lowerName == "password" || lowerName == "passwort" || lowerName == "schlüssel" || lowerName == "key") { return false }
                                }
                                return true
                            }
                            if !filtered.isEmpty {
                                CustomFieldsSection(fields: filtered, cipher: cipher)
                            }
                        }

                        // Notes
                        if cipher.notes != nil {
                            NotesSection(notes: cipher.notes, cipher: cipher)
                        }

                        let certificateMetadata = CertificateMetadata.read(
                            fields: cipher.fields,
                            decrypt: { session.decrypt($0, itemKey: cipher.key) }
                        )
                        if certificateMetadata != nil {
                            CertificateDetailSection(metadata: certificateMetadata!)
                        }

                        if let attachments = cipher.attachments, !attachments.isEmpty {
                            AttachmentsSection(
                                attachments: attachments,
                                cipher: cipher,
                                downloadingAttachmentId: downloadingAttachmentId,
                                onDownload: { attachment in
                                    downloadAttachment(attachment)
                                }
                            )
                        }

                        if let attachmentError {
                            Text(attachmentError)
                                .font(.caption)
                                .foregroundStyle(.red)
                                .padding(.horizontal, 20)
                                .padding(.top, 8)
                                .textSelection(.enabled)
                        }

                        // Metadata
                        MetadataSection(cipher: cipher)
                    }
                    .padding(.bottom, 24)
                }
            }
        }
        .task(id: "\(cipherId)-\(refreshToken)") {
            await loadCipher()
        }
        .alert("Move to Trash?", isPresented: $showDeleteConfirmation) {
            Button("Cancel", role: .cancel) {}
            Button("Move to Trash", role: .destructive) {
                performSoftDelete()
            }
        } message: {
            Text("This item will be moved to the trash. You can restore it later.")
        }
    }

    private func loadCipher() async {
        isLoading = true
        defer { isLoading = false }

        guard let engine = try? session.getSyncEngine() else { return }
        guard let ciphers = try? engine.fetchCiphers(includeDeleted: true) else { return }
        guard let persisted = ciphers.first(where: { $0.id == cipherId }) else { return }

        isTemporaryDraft = persisted.syncStatus == .temporaryDraft
        self.cipher = try? persisted.toCipher()
        temporaryPromotionError = nil
    }

    private func performSoftDelete() {
        guard let cipher = cipher else { return }
        guard let engine = try? session.getSyncEngine() else { return }

        do {
            if isTemporaryDraft {
                try engine.deleteLocalCipher(cipher)
            } else {
                try engine.saveCipherLocally(cipher, operation: .softDelete)
            }
            onDelete?()

            // Push to server in background
            if !isTemporaryDraft {
                Task {
                    try? await engine.fullSync()
                }
            }
        } catch {
            // If save failed, don't navigate away
        }
    }

    private func makeTemporaryCredentialPermanent() {
        guard var cipher else { return }
        guard let engine = try? session.getSyncEngine() else { return }

        isPromotingTemporaryDraft = true
        temporaryPromotionError = nil

        Task {
            do {
                cipher.fields = fieldsWithoutTemporaryMarkers(from: cipher)
                try engine.promoteTemporaryCipherLocally(cipher)
                await MainActor.run {
                    self.cipher = cipher
                    self.isTemporaryDraft = false
                    self.isPromotingTemporaryDraft = false
                    onFavoriteToggled?()
                }
                Task {
                    try? await engine.fullSync()
                }
            } catch {
                await MainActor.run {
                    temporaryPromotionError = error.localizedDescription
                    isPromotingTemporaryDraft = false
                }
            }
        }
    }

    private func fieldsWithoutTemporaryMarkers(from cipher: Cipher) -> [CustomField]? {
        guard let fields = cipher.fields else { return nil }
        let filtered = fields.filter { field in
            let name = session.decrypt(field.name, itemKey: cipher.key)
            return name != "vaultui-temporary" && name != "vaultui-temporary-url"
        }
        return filtered.isEmpty ? nil : filtered
    }
    
    private func deletePasskey(at index: Int) {
        guard var updatedCipher = cipher,
              var login = updatedCipher.login,
              var fido2 = login.fido2Credentials else { return }
              
        fido2.remove(at: index)
        login.fido2Credentials = fido2
        updatedCipher.login = login
        self.cipher = updatedCipher // Optimistic update
        
        Task {
            if let engine = try? session.getSyncEngine() {
                try? engine.saveCipherLocally(updatedCipher, operation: .update)
                
                // Push to server in background
                Task {
                    try? await engine.fullSync()
                }
            }
        }
    }

    private func downloadAttachment(_ attachment: Attachment) {
        guard let cipher else { return }
        downloadingAttachmentId = attachment.id
        attachmentError = nil

        Task {
            do {
                let decrypted = try await VaultAttachmentService.downloadAttachment(
                    attachment,
                    from: cipher,
                    session: session
                )

                await MainActor.run {
                    if let id = cipher.id,
                       CertificateMetadata.isCertificateFileName(decrypted.fileName),
                       let password = decrypt(cipher.login?.password),
                       !password.isEmpty {
                        let metadata = CertificateMetadata.read(
                            fields: cipher.fields,
                            decrypt: { session.decrypt($0, itemKey: cipher.key) }
                        )
                        SharedCredentialStore.shared.storeCertificate(
                            id: id,
                            certificate: SharedCertificateData(
                                fileName: decrypted.fileName,
                                dataBase64: decrypted.data.base64EncodedString(),
                                password: password,
                                expiresAt: metadata?.expiresAt
                            )
                        )
                    }

                    let panel = NSSavePanel()
                    panel.nameFieldStringValue = decrypted.fileName
                    panel.canCreateDirectories = true
                    let response = panel.runModal()
                    guard response == .OK, let url = panel.url else {
                        downloadingAttachmentId = nil
                        return
                    }

                    do {
                        try decrypted.data.write(to: url, options: .atomic)
                    } catch {
                        attachmentError = error.localizedDescription
                    }
                    downloadingAttachmentId = nil
                }
            } catch {
                await MainActor.run {
                    attachmentError = error.localizedDescription
                    downloadingAttachmentId = nil
                }
            }
        }
    }
}

/// Cipher header with icon, name, and actions.
struct CipherHeaderView: View {
    let cipher: Cipher
    var onEdit: (() -> Void)? = nil
    var onDelete: (() -> Void)? = nil
    var onFavoriteToggled: (() -> Void)? = nil
    @EnvironmentObject var session: SessionManager

    @State private var isFavorite: Bool = false

    private func decrypt(_ encString: EncString?) -> String? {
        session.decrypt(encString, itemKey: cipher.key)
    }

    var body: some View {
        let isWifi = cipher.isWifiCredential(decrypt: { session.decrypt($0, itemKey: cipher.key) })
        return HStack(spacing: 16) {
            // Icon — use favicon for logins, generic icon for others
            if isWifi {
                typeIcon
            } else if let iconURL = faviconURL {
                CachedAsyncImage(url: iconURL) {
                    typeIcon
                }
                .frame(width: 56, height: 56)
                .background(
                    RoundedRectangle(cornerRadius: 14)
                        .fill(colorFor(cipher.type).opacity(0.1))
                )
                .clipShape(RoundedRectangle(cornerRadius: 14))
                .shadow(color: colorFor(cipher.type).opacity(0.2), radius: 8, y: 4)
            } else {
                typeIcon
            }

            VStack(alignment: .leading, spacing: 4) {
                Text(decrypt(cipher.name) ?? "Unnamed")
                    .font(.title2.bold())

                Text(isWifi ? "WiFi Credential" : cipher.type.displayName)
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }

            Spacer()

            // Favorite toggle
            Button {
                toggleFavorite()
            } label: {
                Image(systemName: isFavorite ? "star.fill" : "star")
                    .font(.system(size: 18))
                    .foregroundStyle(isFavorite ? .yellow : .secondary)
            }
            .buttonStyle(.plain)
            .help(isFavorite ? "Remove from Favorites" : "Add to Favorites")

            // Action buttons
            Button {
                onEdit?()
            } label: {
                Label("Edit", systemImage: "pencil")
                    .font(.system(size: 14))
            }
            .buttonStyle(.bordered)
            .help("Edit Item")
            .disabled(session.isOffline)

            Button(role: .destructive) {
                onDelete?()
            } label: {
                Image(systemName: "trash")
                    .font(.system(size: 14))
            }
            .buttonStyle(.bordered)
            .help("Move to Trash")
            .disabled(session.isOffline)
        }
        .padding(24)
        .onAppear {
            isFavorite = cipher.favorite
        }
        .onChange(of: cipher.id) { _, _ in
            isFavorite = cipher.favorite
        }
        .onChange(of: cipher.favorite) { _, newValue in
            isFavorite = newValue
        }
    }

    /// The generic type icon (fallback for non-login or missing favicon).
    private var typeIcon: some View {
        let isWifi = cipher.isWifiCredential(decrypt: { session.decrypt($0, itemKey: cipher.key) })
        return Image(systemName: isWifi ? "wifi" : cipher.type.iconName)
            .font(.system(size: 28))
            .foregroundStyle(.white)
            .frame(width: 56, height: 56)
            .background(
                RoundedRectangle(cornerRadius: 14)
                    .fill(gradientFor(cipher.type, isWifi: isWifi))
            )
            .shadow(color: colorFor(cipher.type, isWifi: isWifi).opacity(0.3), radius: 8, y: 4)
    }

    /// Compute the favicon URL for login items.
    private var faviconURL: URL? {
        guard cipher.type == .login,
              let uris = cipher.login?.uris,
              let serverBase = session.activeAccount?.serverURL else { return nil }

        for loginUri in uris {
            guard let uriString = decrypt(loginUri.uri),
                  !uriString.isEmpty else { continue }

            let host: String?
            if let url = URL(string: uriString), let h = url.host {
                host = h
            } else if !uriString.contains("://"),
                      let url = URL(string: "https://\(uriString)"),
                      let h = url.host {
                host = h
            } else {
                host = nil
            }

            if let host = host {
                return serverBase.appendingPathComponent("icons/\(host)/icon.png")
            }
        }
        return nil
    }

    private func toggleFavorite() {
        let newValue = !isFavorite
        isFavorite = newValue // Optimistic update

        Task {
            do {
                var updatedCipher = cipher
                updatedCipher.favorite = newValue

                if let engine = try? session.getSyncEngine() {
                    try engine.saveCipherLocally(updatedCipher, operation: .update)
                    Task { @MainActor in
                        onFavoriteToggled?()
                    }
                    Task {
                        try? await engine.fullSync()
                    }
                }
            } catch {
                // Revert on failure
                isFavorite = !newValue
            }
        }
    }

    private func gradientFor(_ type: CipherType, isWifi: Bool = false) -> LinearGradient {
        if isWifi {
            return LinearGradient(colors: [.teal, .cyan], startPoint: .topLeading, endPoint: .bottomTrailing)
        }
        let colors: [Color]
        switch type {
        case .login: colors = [.blue, .cyan]
        case .secureNote: colors = [.green, .mint]
        case .card: colors = [.orange, .yellow]
        case .identity: colors = [.purple, .pink]
        case .sshKey: colors = [.teal, .green]
        }
        return LinearGradient(colors: colors, startPoint: .topLeading, endPoint: .bottomTrailing)
    }

    private func colorFor(_ type: CipherType, isWifi: Bool = false) -> Color {
        if isWifi {
            return .teal
        }
        switch type {
        case .login: return .blue
        case .secureNote: return .green
        case .card: return .orange
        case .identity: return .purple
        case .sshKey: return .teal
        }
    }
}

// MARK: - WiFi Detail

struct WifiDetailSection: View {
    let cipher: Cipher
    @EnvironmentObject var session: SessionManager
    @State private var showPassword = false

    private func decrypt(_ encString: EncString?) -> String? {
        session.decrypt(encString, itemKey: cipher.key)
    }

    var body: some View {
        let details = cipher.wifiDetails(decrypt: { decrypt($0) })
        VStack(alignment: .leading, spacing: 0) {
            // Network Name (SSID)
            if let ssid = details?.ssid {
                CopyableField(
                    label: "Network Name (SSID)",
                    value: ssid,
                    icon: "wifi"
                )
            }

            // Password
            if let password = cipher.login?.password {
                let decrypted = decrypt(password) ?? ""
                CopyableField(
                    label: "Security Key (Password)",
                    value: showPassword ? decrypted : String(repeating: "•", count: 12),
                    icon: "lock.fill",
                    isSecret: true,
                    isRevealed: showPassword,
                    onToggle: { showPassword.toggle() },
                    copyValue: decrypted
                )
            } else if let fields = cipher.fields {
                let fieldPassword = fields.first { field in
                    let name = decrypt(field.name)?.lowercased() ?? ""
                    return name == "password" || name == "passwort" || name == "schlüssel" || name == "key"
                }
                if let fieldPassword = fieldPassword, let decPassword = decrypt(fieldPassword.value) {
                    CopyableField(
                        label: "Security Key (Password)",
                        value: showPassword ? decPassword : String(repeating: "•", count: 12),
                        icon: "lock.fill",
                        isSecret: true,
                        isRevealed: showPassword,
                        onToggle: { showPassword.toggle() },
                        copyValue: decPassword
                    )
                }
            }

            // Security Type
            if let security = details?.security {
                CopyableField(
                    label: "Security Type",
                    value: security,
                    icon: "shield.fill"
                )
            }
        }
    }
}

// MARK: - Login Detail

struct PasskeyWrapper: Identifiable {
    let id = UUID()
    let passkey: Fido2Credential
}

struct LoginDetailSection: View {
    let login: LoginData?
    let cipher: Cipher
    var onDeletePasskey: ((Int) -> Void)?
    @EnvironmentObject var session: SessionManager
    @State private var showPassword = false
    @State private var passkeyToDelete: Int?
    @State private var passkeyToInspect: PasskeyWrapper?

    private func decrypt(_ encString: EncString?) -> String? {
        session.decrypt(encString, itemKey: cipher.key)
    }

    private func hasUnsupportedLegacyCredentialId(_ passkey: Fido2Credential) -> Bool {
        guard let credentialId = decrypt(passkey.credentialId),
              let credentialData = Data(bitwardenFido2CredentialId: credentialId) else {
            return false
        }
        return credentialData.count != 16
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            // Username
            if let username = login?.username {
                CopyableField(
                    label: "Username",
                    value: decrypt(username) ?? "",
                    icon: "person.fill"
                )
            }

            // Password
            if let password = login?.password {
                let decrypted = decrypt(password) ?? ""
                CopyableField(
                    label: "Password",
                    value: showPassword ? decrypted : String(repeating: "•", count: 12),
                    icon: "lock.fill",
                    isSecret: true,
                    isRevealed: showPassword,
                    onToggle: { showPassword.toggle() },
                    copyValue: decrypted
                )
            }

            // TOTP
            if let totp = login?.totp {
                TOTPFieldView(encryptedSecret: totp, itemKey: cipher.key)
                    .id(cipher.id ?? UUID().uuidString)
            }

            // URIs
            if let uris = login?.uris {
                ForEach(Array(uris.enumerated()), id: \.offset) { _, uri in
                    if let encUri = uri.uri, let url = decrypt(encUri) {
                        CopyableField(
                            label: "Website",
                            value: url,
                            icon: "globe"
                        )
                    }
                }
            }
            // Passkeys
            if let fido2 = login?.fido2Credentials, !fido2.isEmpty {
                ForEach(Array(fido2.enumerated()), id: \.offset) { index, passkey in
                    HStack(spacing: 12) {
                        Image(systemName: "person.badge.key.fill")
                            .font(.system(size: 14))
                            .foregroundStyle(.secondary)
                            .frame(width: 20)

                        VStack(alignment: .leading, spacing: 2) {
                            let rpId = decrypt(passkey.rpId) ?? "Unknown Domain"
                            Text("Passkey for \(rpId)")
                                .font(.system(.body, design: .default))
                                .foregroundStyle(.primary)
                            if let created = passkey.creationDate {
                                Text("Created \(created.formatted(date: .abbreviated, time: .shortened))")
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                            }
                        }
                        Spacer()

                        if hasUnsupportedLegacyCredentialId(passkey) {
                            Image(systemName: "exclamationmark.triangle.fill")
                                .font(.system(size: 14))
                                .foregroundStyle(.orange)
                                .help("Legacy passkey credential ID. Re-register this passkey for Bitwarden iOS compatibility.")
                        }
                        
                        Button {
                            passkeyToInspect = PasskeyWrapper(passkey: passkey)
                        } label: {
                            Image(systemName: "info.circle")
                                .font(.system(size: 14))
                                .foregroundStyle(.secondary)
                        }
                        .buttonStyle(.plain)
                        .padding(.trailing, 8)
                        .help("View Passkey Details")
                        
                        Button(role: .destructive) {
                            passkeyToDelete = index
                        } label: {
                            Image(systemName: "trash")
                                .font(.system(size: 14))
                                .foregroundStyle(.red)
                        }
                        .buttonStyle(.plain)
                        .padding(.trailing, 8)
                        .help("Delete Passkey")
                    }
                    .padding(.horizontal, 20)
                    .padding(.vertical, 10)
                }
            }
        }
        .popover(item: $passkeyToInspect) { wrapper in
            PasskeyDebugInfoView(passkey: wrapper.passkey, itemKey: cipher.key)
                .environmentObject(session)
        }
        .confirmationDialog(
            "Delete Passkey?",
            isPresented: Binding(
                get: { passkeyToDelete != nil },
                set: { if !$0 { passkeyToDelete = nil } }
            ),
            titleVisibility: .visible
        ) {
            Button("Delete", role: .destructive) {
                if let index = passkeyToDelete {
                    onDeletePasskey?(index)
                }
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("Are you sure you want to delete this passkey? This action cannot be undone.")
        }
    }
}

// MARK: - Secure Note Detail

struct SecureNoteDetailSection: View {
    let cipher: Cipher
    @EnvironmentObject var session: SessionManager

    private func decrypt(_ encString: EncString?) -> String? {
        session.decrypt(encString, itemKey: cipher.key)
    }

    var body: some View {
        if let notes = cipher.notes, let decrypted = decrypt(notes) {
            VStack(alignment: .leading, spacing: 8) {
                Text(decrypted)
                    .font(.body)
                    .textSelection(.enabled)
                    .padding(20)
            }
        }
    }
}

// MARK: - Card Detail

struct CardDetailSection: View {
    let card: CardData?
    let cipher: Cipher
    @EnvironmentObject var session: SessionManager
    @State private var showNumber = false
    @State private var showCode = false

    private func decrypt(_ encString: EncString?) -> String? {
        session.decrypt(encString, itemKey: cipher.key)
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            if let name = card?.cardholderName {
                CopyableField(label: "Cardholder", value: decrypt(name) ?? "", icon: "person.fill")
            }
            if let number = card?.number {
                let dec = decrypt(number) ?? ""
                CopyableField(
                    label: "Number",
                    value: showNumber ? dec : "•••• •••• •••• \(dec.suffix(4))",
                    icon: "creditcard.fill",
                    isSecret: true,
                    isRevealed: showNumber,
                    onToggle: { showNumber.toggle() },
                    copyValue: dec
                )
            }
            if let brand = card?.brand {
                CopyableField(label: "Brand", value: decrypt(brand) ?? "", icon: "tag.fill")
            }
            HStack(spacing: 16) {
                if let month = card?.expMonth, let year = card?.expYear {
                    let m = decrypt(month) ?? ""
                    let y = decrypt(year) ?? ""
                    CopyableField(label: "Expiry", value: "\(m)/\(y)", icon: "calendar")
                }
            }
            if let code = card?.code {
                let dec = decrypt(code) ?? ""
                CopyableField(
                    label: "CVV",
                    value: showCode ? dec : "•••",
                    icon: "lock.rectangle.fill",
                    isSecret: true,
                    isRevealed: showCode,
                    onToggle: { showCode.toggle() },
                    copyValue: dec
                )
            }
        }
    }
}

// MARK: - Identity Detail

struct IdentityDetailSection: View {
    let identity: IdentityData?
    let cipher: Cipher
    @EnvironmentObject var session: SessionManager

    private func decrypt(_ encString: EncString?) -> String? {
        session.decrypt(encString, itemKey: cipher.key)
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            fieldRow("Title", identity?.title)
            fieldRow("First Name", identity?.firstName)
            fieldRow("Middle Name", identity?.middleName)
            fieldRow("Last Name", identity?.lastName)
            fieldRow("Username", identity?.username)
            fieldRow("Company", identity?.company)
            fieldRow("Email", identity?.email)
            fieldRow("Phone", identity?.phone)
            fieldRow("Address 1", identity?.address1)
            fieldRow("Address 2", identity?.address2)
            fieldRow("City", identity?.city)
            fieldRow("State", identity?.state)
            fieldRow("Postal Code", identity?.postalCode)
            fieldRow("Country", identity?.country)
            fieldRow("SSN", identity?.ssn)
            fieldRow("Passport #", identity?.passportNumber)
            fieldRow("License #", identity?.licenseNumber)
        }
    }

    @ViewBuilder
    private func fieldRow(_ label: String, _ value: EncString?) -> some View {
        if let encValue = value, let decrypted = decrypt(encValue), !decrypted.isEmpty {
            CopyableField(label: label, value: decrypted, icon: "person.text.rectangle")
        }
    }
}

// MARK: - SSH Key Detail

struct SSHKeyDetailSection: View {
    let sshKey: SSHKeyData?
    let cipher: Cipher
    @EnvironmentObject var session: SessionManager
    @State private var showPrivateKey = false

    private func decrypt(_ encString: EncString?) -> String? {
        session.decrypt(encString, itemKey: cipher.key)
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            if let pubKey = sshKey?.publicKey {
                CopyableMultilineField(
                    label: "Public Key",
                    value: decrypt(pubKey) ?? "",
                    icon: "key.fill"
                )
            }
            if let fingerprint = sshKey?.keyFingerprint {
                CopyableField(
                    label: "Fingerprint",
                    value: decrypt(fingerprint) ?? "",
                    icon: "hand.point.up.braille.fill"
                )
            }
            if let privKey = sshKey?.privateKey {
                let dec = decrypt(privKey) ?? ""
                CopyableMultilineField(
                    label: "Private Key",
                    value: showPrivateKey ? dec : String(repeating: "•", count: 40),
                    icon: "lock.fill",
                    isSecret: true,
                    isRevealed: showPrivateKey,
                    onToggle: { showPrivateKey.toggle() },
                    copyValue: dec
                )
            }
        }
    }
}

// MARK: - CLI Slug Section

/// Displays the vaultui-slug custom field as a dedicated CLI Slug row.
struct CLISlugSection: View {
    let fields: [CustomField]
    let cipher: Cipher
    @EnvironmentObject var session: SessionManager

    private func decrypt(_ encString: EncString?) -> String? {
        session.decrypt(encString, itemKey: cipher.key)
    }

    var body: some View {
        let slugValue = fields.compactMap { field -> String? in
            guard let name = decrypt(field.name), name == VaultUISlug.fieldName else { return nil }
            return decrypt(field.value)
        }.first

        if let slug = slugValue, !slug.isEmpty {
            VStack(alignment: .leading, spacing: 0) {
                SectionHeader(title: "CLI Access")
                CopyableField(
                    label: "CLI Slug",
                    value: slug,
                    icon: "terminal.fill"
                )
                HStack(spacing: 4) {
                    Text("vaultui secret get \(slug)")
                        .font(.system(.caption, design: .monospaced))
                        .foregroundStyle(.secondary)
                }
                .padding(.horizontal, 52)
                .padding(.bottom, 8)
            }
        }
    }
}

// MARK: - Custom Fields Section

struct CustomFieldsSection: View {
    let fields: [CustomField]
    let cipher: Cipher
    @EnvironmentObject var session: SessionManager

    private func decrypt(_ encString: EncString?) -> String? {
        session.decrypt(encString, itemKey: cipher.key)
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            SectionHeader(title: "Custom Fields")
            ForEach(Array(fields.enumerated()), id: \.offset) { _, field in
                let name = decrypt(field.name) ?? "Field"
                let value = decrypt(field.value) ?? ""
                CopyableField(label: name, value: value, icon: "textformat")
            }
        }
    }
}

// MARK: - Notes Section

struct NotesSection: View {
    let notes: EncString?
    let cipher: Cipher
    @EnvironmentObject var session: SessionManager

    private func decrypt(_ encString: EncString?) -> String? {
        session.decrypt(encString, itemKey: cipher.key)
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            SectionHeader(title: "Notes")
            if let notes = notes, let text = decrypt(notes) {
                Text(text)
                    .font(.body)
                    .textSelection(.enabled)
                    .padding(.horizontal, 20)
                    .padding(.bottom, 16)
            }
        }
    }
}

// MARK: - Certificate Detail

struct CertificateDetailSection: View {
    let metadata: CertificateMetadata

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            SectionHeader(title: "Certificate")
            if let fileName = metadata.fileName {
                MetadataRow(label: "File", value: fileName)
            }
            if let expiresAt = metadata.expiresAt {
                HStack {
                    Text("Expires")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                    Spacer()
                    Text(expiresAt.formatted(date: .long, time: .omitted))
                        .font(.caption)
                        .foregroundStyle(expiryColor)
                    if metadata.isExpired || metadata.expiresSoon {
                        Text(metadata.isExpired ? "Expired" : "Soon")
                            .font(.caption2.weight(.semibold))
                            .foregroundStyle(expiryColor)
                            .padding(.horizontal, 6)
                            .padding(.vertical, 1)
                            .background(expiryColor.opacity(0.12))
                            .clipShape(Capsule())
                    }
                }
                .padding(.horizontal, 20)
                .padding(.vertical, 6)
            }
            if let subject = metadata.subject {
                MetadataRow(label: "Subject", value: subject)
            }
            if let fingerprint = metadata.fingerprintSHA256 {
                CopyableField(label: "SHA-256", value: fingerprint, icon: "number")
            }
        }
    }

    private var expiryColor: Color {
        if metadata.isExpired { return .red }
        if metadata.expiresSoon { return .orange }
        return .green
    }
}

// MARK: - Attachments Section

struct AttachmentsSection: View {
    let attachments: [Attachment]
    let cipher: Cipher
    let downloadingAttachmentId: String?
    let onDownload: (Attachment) -> Void
    @EnvironmentObject var session: SessionManager

    private func decrypt(_ encString: EncString?) -> String? {
        session.decrypt(encString, itemKey: cipher.key)
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            SectionHeader(title: "Attachments")
            ForEach(Array(attachments.enumerated()), id: \.offset) { _, attachment in
                let fileName = decrypt(attachment.fileName) ?? attachment.id ?? "Attachment"
                HStack(spacing: 12) {
                    Image(systemName: CertificateMetadata.isCertificateFileName(fileName) ? "checkmark.seal.fill" : "paperclip")
                        .font(.system(size: 14))
                        .foregroundStyle(.secondary)
                        .frame(width: 20)

                    VStack(alignment: .leading, spacing: 2) {
                        Text(fileName)
                            .font(.body)
                            .lineLimit(1)
                        if let sizeName = attachment.sizeName ?? attachment.size {
                            Text(sizeName)
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                    }

                    Spacer()

                    Button {
                        onDownload(attachment)
                    } label: {
                        if downloadingAttachmentId == attachment.id {
                            ProgressView()
                                .controlSize(.small)
                        } else {
                            Image(systemName: "arrow.down.circle")
                        }
                    }
                    .buttonStyle(.plain)
                    .help("Download attachment")
                    .disabled(downloadingAttachmentId != nil)
                }
                .padding(.horizontal, 20)
                .padding(.vertical, 8)
            }
        }
    }
}

// MARK: - Metadata Section

struct MetadataSection: View {
    let cipher: Cipher
    @EnvironmentObject var session: SessionManager

    private func decrypt(_ encString: EncString?) -> String? {
        session.decrypt(encString, itemKey: cipher.key)
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            SectionHeader(title: "Info")
            if let created = cipher.creationDate {
                MetadataRow(label: "Created", value: created.formatted(date: .long, time: .shortened))
            }
            if let revised = cipher.revisionDate {
                MetadataRow(label: "Updated", value: revised.formatted(date: .long, time: .shortened))
            }
        }
    }
}

struct MetadataRow: View {
    let label: String
    let value: String

    var body: some View {
        HStack {
            Text(label)
                .font(.caption)
                .foregroundStyle(.secondary)
            Spacer()
            Text(value)
                .font(.caption)
                .foregroundStyle(.tertiary)
        }
        .padding(.horizontal, 20)
        .padding(.vertical, 6)
    }
}

// MARK: - Reusable Components

struct SectionHeader: View {
    let title: String

    var body: some View {
        Text(title.uppercased())
            .font(.caption.bold())
            .foregroundStyle(.secondary)
            .padding(.horizontal, 20)
            .padding(.top, 20)
            .padding(.bottom, 8)
    }
}

/// A field row that copies its value to the clipboard on click.
struct CopyableField: View {
    let label: String
    let value: String
    let icon: String
    var isSecret: Bool = false
    var isRevealed: Bool = false
    var onToggle: (() -> Void)?
    var copyValue: String?

    @State private var copied = false
    @AppStorage("clearClipboard") private var clearClipboard = true
    @AppStorage("clipboardTimeout") private var clipboardTimeout = 30



    var body: some View {
        HStack(spacing: 12) {
            Image(systemName: icon)
                .font(.system(size: 14))
                .foregroundStyle(.secondary)
                .frame(width: 20)

            VStack(alignment: .leading, spacing: 2) {
                Text(label)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                Text(value)
                    .font(.system(.body, design: isSecret ? .monospaced : .default))
                    .textSelection(.enabled)
                    .lineLimit(3)
            }

            Spacer()

            if isSecret, let onToggle = onToggle {
                Button {
                    onToggle()
                } label: {
                    Image(systemName: isRevealed ? "eye.slash" : "eye")
                        .font(.system(size: 13))
                        .foregroundStyle(.secondary)
                }
                .buttonStyle(.plain)
            }

            Button {
                let textToCopy = copyValue ?? value
                ClipboardService.shared.copy(textToCopy, clearAfter: clearClipboard ? clipboardTimeout : 0)
                withAnimation { copied = true }
                DispatchQueue.main.asyncAfter(deadline: .now() + 1.5) {
                    withAnimation { copied = false }
                }
            } label: {
                Image(systemName: copied ? "checkmark" : "doc.on.doc")
                    .font(.system(size: 13))
                    .foregroundStyle(copied ? .green : .secondary)
            }
            .buttonStyle(.plain)
        }
        .padding(.horizontal, 20)
        .padding(.vertical, 10)
    }
}

// MARK: - Passkey Debug Info

struct PasskeyDebugInfoView: View {
    let passkey: Fido2Credential
    let itemKey: EncString?
    @EnvironmentObject var session: SessionManager

    private func decrypt(_ encString: EncString?) -> String? {
        session.decrypt(encString, itemKey: itemKey)
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("Passkey Details")
                .font(.headline)
            
            VStack(alignment: .leading, spacing: 8) {
                detailRow("Relying Party ID", decrypt(passkey.rpId))
                detailRow("Credential ID", decrypt(passkey.credentialId))
                detailRow("User Handle", decrypt(passkey.userHandle))
                detailRow("Private Key", decrypt(passkey.keyValue))
            }
            .font(.system(.caption, design: .monospaced))
        }
        .padding()
        .frame(width: 400)
    }
    
    @ViewBuilder
    private func detailRow(_ label: String, _ value: String?) -> some View {
        if let val = value, !val.isEmpty {
            VStack(alignment: .leading, spacing: 2) {
                Text(label)
                    .foregroundColor(.secondary)
                    .font(.caption2)
                Text(val)
                    .textSelection(.enabled)
                    .lineLimit(5)
            }
        }
    }
}

/// TOTP field with live countdown.
struct TOTPFieldView: View {
    let encryptedSecret: EncString
    let itemKey: EncString?
    @EnvironmentObject var session: SessionManager

    @State private var code: TOTPCode?
    @State private var timer: Timer?
    @State private var copied = false

    private func decrypt(_ encString: EncString?) -> String? {
        session.decrypt(encString, itemKey: itemKey)
    }

    var body: some View {
        Group {
            if let code = code {
                HStack(spacing: 12) {
                    Image(systemName: "clock.badge.checkmark.fill")
                        .font(.system(size: 14))
                        .foregroundStyle(.secondary)
                        .frame(width: 20)

                    VStack(alignment: .leading, spacing: 2) {
                        Text("TOTP")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                        Text(code.formatted)
                            .font(.system(size: 20, weight: .medium, design: .monospaced))
                            .foregroundStyle(.blue)
                    }

                    Spacer()

                    // Countdown ring
                    ZStack {
                        Circle()
                            .stroke(.quaternary, lineWidth: 2)
                        Circle()
                            .trim(from: 0, to: CGFloat(code.remaining) / CGFloat(code.period))
                            .stroke(.blue, lineWidth: 2)
                            .rotationEffect(.degrees(-90))
                    }
                    .frame(width: 24, height: 24)

                    Text("\(code.remaining)s")
                        .font(.caption.monospacedDigit())
                        .foregroundStyle(.secondary)
                        .frame(width: 30)

                    Button {
                        ClipboardService.shared.copy(code.code, clearAfter: 0)
                        withAnimation { copied = true }
                        DispatchQueue.main.asyncAfter(deadline: .now() + 1.5) {
                            withAnimation { copied = false }
                        }
                    } label: {
                        Image(systemName: copied ? "checkmark" : "doc.on.doc")
                            .font(.system(size: 13))
                            .foregroundStyle(copied ? .green : .secondary)
                    }
                    .buttonStyle(.plain)
                }
                .padding(.horizontal, 20)
                .padding(.vertical, 10)
            } else {
                // Placeholder while loading or if generation fails
                HStack(spacing: 12) {
                    Image(systemName: "clock.badge.checkmark.fill")
                        .font(.system(size: 14))
                        .foregroundStyle(.secondary)
                        .frame(width: 20)
                    
                    VStack(alignment: .leading, spacing: 2) {
                        Text("TOTP")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                        Text("------")
                            .font(.system(size: 20, weight: .medium, design: .monospaced))
                            .foregroundStyle(.tertiary)
                    }
                    Spacer()
                }
                .padding(.horizontal, 20)
                .padding(.vertical, 10)
            }
        }
        .onAppear {
            startTimer()
        }
        .onDisappear {
            timer?.invalidate()
            timer = nil
        }
    }
    
    private func updateCode() {
        guard let secret = decrypt(encryptedSecret) else { return }
        self.code = TOTPService.generateCode(from: secret)
    }
    
    private func startTimer() {
        updateCode()
        timer?.invalidate()
        timer = Timer.scheduledTimer(withTimeInterval: 1.0, repeats: true) { _ in
            Task { @MainActor in
                self.updateCode()
            }
        }
    }
}
struct CopyableMultilineField: View {
    let label: String
    let value: String
    let icon: String
    var isSecret: Bool = false
    var isRevealed: Bool = false
    var onToggle: (() -> Void)?
    var copyValue: String?

    @State private var copied = false
    @AppStorage("clearClipboard") private var clearClipboard = true
    @AppStorage("clipboardTimeout") private var clipboardTimeout = 30



    var body: some View {
        HStack(alignment: .top, spacing: 12) {
            Image(systemName: icon)
                .font(.system(size: 14))
                .foregroundStyle(.secondary)
                .frame(width: 20)
                .padding(.top, 4)

            VStack(alignment: .leading, spacing: 4) {
                Text(label)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                Text(value)
                    .font(.system(size: 11, weight: .regular, design: isSecret ? .monospaced : .default))
                    .textSelection(.enabled)
                    .lineLimit(nil)
                    .fixedSize(horizontal: false, vertical: true)
            }

            Spacer()

            HStack(spacing: 8) {
                if isSecret, let onToggle = onToggle {
                    Button(action: onToggle) {
                        Image(systemName: isRevealed ? "eye.slash" : "eye")
                            .foregroundStyle(.secondary)
                    }
                    .buttonStyle(.plain)
                }

                Button {
                    let toCopy = copyValue ?? value
                    ClipboardService.shared.copy(toCopy, clearAfter: clearClipboard ? clipboardTimeout : 0)
                    withAnimation(.spring(response: 0.3, dampingFraction: 0.6)) { copied = true }
                    DispatchQueue.main.asyncAfter(deadline: .now() + 2) {
                        withAnimation { copied = false }
                    }
                } label: {
                    Image(systemName: copied ? "checkmark" : "doc.on.doc")
                        .foregroundStyle(copied ? .green : .secondary)
                }
                .buttonStyle(.plain)
            }
            .padding(.top, 4)
        }
        .padding(.horizontal, 20)
        .padding(.vertical, 8)
    }
}
