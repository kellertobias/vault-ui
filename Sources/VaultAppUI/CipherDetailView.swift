// MARK: - VaultAppUI/CipherDetailView.swift
// Right column: full cipher detail with type-specific sections

import SwiftUI
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

                        Divider()
                            .padding(.horizontal)

                        // Type-specific content
                        switch cipher.type {
                        case .login:
                            LoginDetailSection(login: cipher.login, cipher: cipher)
                        case .secureNote:
                            SecureNoteDetailSection(cipher: cipher)
                        case .card:
                            CardDetailSection(card: cipher.card, cipher: cipher)
                        case .identity:
                            IdentityDetailSection(identity: cipher.identity, cipher: cipher)
                        case .sshKey:
                            SSHKeyDetailSection(sshKey: cipher.sshKey, cipher: cipher)
                        }

                        // Custom Fields
                        if let fields = cipher.fields, !fields.isEmpty {
                            CustomFieldsSection(fields: fields, cipher: cipher)
                        }

                        // Notes
                        if cipher.notes != nil {
                            NotesSection(notes: cipher.notes, cipher: cipher)
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

        self.cipher = try? persisted.toCipher()
    }

    private func performSoftDelete() {
        guard let cipher = cipher else { return }
        guard let engine = try? session.getSyncEngine() else { return }

        do {
            try engine.saveCipherLocally(cipher, operation: .softDelete)
            onDelete?()

            // Push to server in background
            Task {
                try? await engine.fullSync()
            }
        } catch {
            // If save failed, don't navigate away
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
        HStack(spacing: 16) {
            // Icon — use favicon for logins, generic icon for others
            if let iconURL = faviconURL {
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

                Text(cipher.type.displayName)
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

            Button(role: .destructive) {
                onDelete?()
            } label: {
                Image(systemName: "trash")
                    .font(.system(size: 14))
            }
            .buttonStyle(.bordered)
            .help("Move to Trash")
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
        Image(systemName: cipher.type.iconName)
            .font(.system(size: 28))
            .foregroundStyle(.white)
            .frame(width: 56, height: 56)
            .background(
                RoundedRectangle(cornerRadius: 14)
                    .fill(gradientFor(cipher.type))
            )
            .shadow(color: colorFor(cipher.type).opacity(0.3), radius: 8, y: 4)
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
                // Use the full cipher update to reliably toggle favorite
                var updatedCipher = cipher
                updatedCipher.favorite = newValue

                let api = try session.getAPIClient()
                let cipherAPI = CipherAPI(client: api)
                _ = try await cipherAPI.update(updatedCipher)

                if let engine = try? session.getSyncEngine() {
                    try await engine.fullSync()
                }
                onFavoriteToggled?()
            } catch {
                // Revert on failure
                isFavorite = !newValue
            }
        }
    }

    private func gradientFor(_ type: CipherType) -> LinearGradient {
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

    private func colorFor(_ type: CipherType) -> Color {
        switch type {
        case .login: return .blue
        case .secureNote: return .green
        case .card: return .orange
        case .identity: return .purple
        case .sshKey: return .teal
        }
    }
}

// MARK: - Login Detail

struct LoginDetailSection: View {
    let login: LoginData?
    let cipher: Cipher
    @EnvironmentObject var session: SessionManager
    @State private var showPassword = false

    private func decrypt(_ encString: EncString?) -> String? {
        session.decrypt(encString, itemKey: cipher.key)
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

/// TOTP field with live countdown.
struct TOTPFieldView: View {
    let encryptedSecret: EncString
    let itemKey: EncString?
    @EnvironmentObject var session: SessionManager

    @State private var code: TOTPCode?
    @State private var timer: Timer?

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
                    } label: {
                        Image(systemName: "doc.on.doc")
                            .font(.system(size: 13))
                            .foregroundStyle(.secondary)
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
