// MARK: - VaultAppUI/SendView.swift
// Bitwarden Send management view

import AppKit
import SwiftUI
import VaultModels
import VaultCrypto
import VaultServices
import VaultSync
import VaultAPI

/// List, view, create, edit, and delete Bitwarden Send items.
struct SendListView: View {
    @EnvironmentObject var session: SessionManager
    @Binding var searchText: String
    @Binding var selectedSend: SendListItem?
    var refreshToken: Int = 0
    var onCreateSend: (() -> Void)? = nil
    var onEditSend: ((SendListItem) -> Void)? = nil
    var onDeleteSend: (() -> Void)? = nil

    @State private var sends: [SendListItem] = []
    @State private var isLoading = true
    @State private var errorMessage: String?

    var body: some View {
        VStack(spacing: 0) {
            HStack {
                HStack {
                    Image(systemName: "magnifyingglass")
                        .foregroundStyle(.secondary)
                    TextField("Search Sends...", text: $searchText)
                        .textFieldStyle(.plain)
                    Button {
                        searchText = ""
                    } label: {
                        Image(systemName: "xmark.circle.fill")
                            .font(.system(size: 12, weight: .semibold))
                            .foregroundStyle(.secondary)
                            .frame(width: 16, height: 16)
                    }
                    .buttonStyle(.plain)
                    .help("Clear search")
                    .opacity(searchText.isEmpty ? 0 : 1)
                    .disabled(searchText.isEmpty)
                    .accessibilityHidden(searchText.isEmpty)
                }
                .padding(6)
                .background(Color(nsColor: .controlBackgroundColor))
                .clipShape(RoundedRectangle(cornerRadius: 6))
                .overlay(RoundedRectangle(cornerRadius: 6).stroke(Color.secondary.opacity(0.2), lineWidth: 1))

                Button {
                    onCreateSend?()
                } label: {
                    Image(systemName: "plus")
                        .padding(6)
                        .background(Color(nsColor: .controlBackgroundColor))
                        .clipShape(RoundedRectangle(cornerRadius: 6))
                        .overlay(RoundedRectangle(cornerRadius: 6).stroke(Color.secondary.opacity(0.2), lineWidth: 1))
                }
                .buttonStyle(.plain)
                .help("New Send")
                .disabled(session.isOffline)
            }
            .padding()
            .background(.ultraThinMaterial)
            .zIndex(1)

            Group {
                if isLoading {
                    ProgressView()
                        .frame(maxWidth: .infinity, maxHeight: .infinity)
                } else if filteredSends.isEmpty {
                    emptyState
                } else {
                    ScrollViewReader { proxy in
                        List(selection: Binding(
                            get: { selectedSend?.id },
                            set: { id in selectedSend = filteredSends.first { $0.id == id } }
                        )) {
                            ForEach(groupedSends, id: \.0) { letter, letterSends in
                                Section(header: Text(letter).font(.headline)) {
                                    ForEach(letterSends) { send in
                                        SendRowView(item: send)
                                            .id(send.id)
                                            .tag(send.id)
                                            .contextMenu {
                                                Button("Copy Public URL") { copyPublicURL(send) }
                                                Button("Edit") { onEditSend?(send) }
                                                Divider()
                                                Button("Delete", role: .destructive) { deleteSend(send) }
                                            }
                                    }
                                }
                            }
                        }
                        .listStyle(.inset(alternatesRowBackgrounds: true))
                        .onAppear { scrollToSelectedSend(with: proxy) }
                        .onChange(of: selectedSend) { _, _ in scrollToSelectedSend(with: proxy) }
                        .onChange(of: filteredSendIds) { _, _ in scrollToSelectedSend(with: proxy) }
                    }
                }
            }
        }
        .safeAreaInset(edge: .bottom) {
            if let errorMessage {
                Text(errorMessage)
                    .font(.caption)
                    .foregroundStyle(.red)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(10)
                    .background(.bar)
            }
        }
        .navigationTitle("Send")
        .task(id: "\(refreshToken)-\(session.dataUpdateToken)") {
            await loadSends(selecting: selectedSend?.id)
        }
        .onReceive(NotificationCenter.default.publisher(for: Notification.Name("VaultUIDataDidChange"))) { _ in
            Task { await loadSends(selecting: selectedSend?.id) }
        }
    }

    private var filteredSends: [SendListItem] {
        guard !searchText.isEmpty else { return sends }
        let query = searchText.lowercased()
        return sends.filter {
            $0.name.lowercased().contains(query) ||
            $0.notes.lowercased().contains(query) ||
            $0.text.lowercased().contains(query) ||
            $0.fileName.lowercased().contains(query)
        }
    }

    private var filteredSendIds: [String] {
        filteredSends.map(\.id)
    }

    private var groupedSends: [(String, [SendListItem])] {
        let grouped = Dictionary(grouping: filteredSends) { send in
            let firstChar = send.name.first?.uppercased() ?? "#"
            return firstChar.rangeOfCharacter(from: .letters) != nil ? firstChar : "#"
        }
        return grouped.sorted { $0.key < $1.key }
    }

    private var emptyState: some View {
        VStack(spacing: 16) {
            Image(systemName: "paperplane")
                .font(.system(size: 48))
                .foregroundStyle(.quaternary)
            Text(searchText.isEmpty ? "No Sends" : "No results")
                .font(.title3)
                .foregroundStyle(.secondary)
            Text(searchText.isEmpty ? "Use Send to securely share text or files." : "Try a different search term.")
                .font(.caption)
                .foregroundStyle(.tertiary)
            if searchText.isEmpty {
                Button("Create Send") {
                    onCreateSend?()
                }
                .buttonStyle(.borderedProminent)
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    private func scrollToSelectedSend(with proxy: ScrollViewProxy) {
        guard let selectedSend,
              filteredSendIds.contains(selectedSend.id) else { return }

        DispatchQueue.main.async {
            withAnimation(.easeInOut(duration: 0.2)) {
                proxy.scrollTo(selectedSend.id, anchor: .center)
            }
        }
    }

    @MainActor
    private func loadSends(selecting selectedId: String? = nil) async {
        if sends.isEmpty {
            isLoading = true
        }
        defer { isLoading = false }

        guard let engine = try? session.getSyncEngine(),
              let persistedSends = try? engine.fetchSends() else {
            sends = []
            return
        }

        sends = persistedSends.compactMap { persisted -> SendListItem? in
            guard let sendItem = try? persisted.toSendItem() else { return nil }
            return SendListItem(send: sendItem, session: session)
        }
        .filter { send in
            if let deletionDate = send.deletionDate {
                return deletionDate > Date()
            }
            return true
        }
        .sorted { $0.name.localizedCaseInsensitiveCompare($1.name) == .orderedAscending }

        if let selectedId {
            selectedSend = sends.first { $0.id == selectedId }
        } else if let selectedSend, !sends.contains(selectedSend) {
            self.selectedSend = nil
        }
    }

    private func copyPublicURL(_ item: SendListItem) {
        guard let publicURL = item.publicURL else {
            errorMessage = session.hasLegacySendKey(for: item.send)
                ? "This Send uses an old incompatible key. Edit and save text Sends, or recreate file Sends."
                : "This Send is missing the access ID or encryption key."
            return
        }
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(publicURL.absoluteString, forType: .string)
        errorMessage = nil
    }

    private func deleteSend(_ item: SendListItem) {
        Task {
            do {
                let api = try session.getAPIClient()
                try await SendAPI(client: api).delete(id: item.id)
                if let engine = try? session.getSyncEngine() {
                    try? engine.deleteLocalSend(id: item.id)
                }
                await MainActor.run {
                    selectedSend = nil
                    onDeleteSend?()
                }
            } catch {
                await MainActor.run { errorMessage = error.localizedDescription }
            }
        }
    }
}

/// Display item for a Send.
struct SendListItem: Identifiable, Equatable {
    let id: String
    let send: SendItem
    let name: String
    let notes: String
    let text: String
    let fileName: String
    let type: SendType
    let publicURL: URL?
    let expirationDate: Date?
    let deletionDate: Date?
    let accessCount: Int
    let maxAccessCount: Int?
    let isDisabled: Bool
    let hideEmail: Bool
    let textHidden: Bool
    let hasPassword: Bool

    @MainActor
    init?(send: SendItem, session: SessionManager) {
        guard let id = send.id else { return nil }
        self.id = id
        self.send = send
        self.type = send.type
        self.name = session.decryptSend(send.name, send: send) ?? "Unnamed"
        self.notes = session.decryptSend(send.notes, send: send) ?? ""
        self.text = session.decryptSend(send.text?.text, send: send) ?? ""
        self.fileName = session.decryptSend(send.file?.fileName, send: send) ?? ""
        self.expirationDate = send.expirationDate
        self.deletionDate = send.deletionDate
        self.accessCount = send.accessCount ?? 0
        self.maxAccessCount = send.maxAccessCount
        self.isDisabled = send.disabled ?? false
        self.hideEmail = send.hideEmail ?? false
        self.textHidden = send.text?.hidden ?? false
        self.hasPassword = send.password != nil
        self.publicURL = SendURLBuilder.publicURL(for: send, session: session)
    }

    static func == (lhs: Self, rhs: Self) -> Bool {
        lhs.id == rhs.id
    }
}

/// Row in the Send list.
struct SendRowView: View {
    let item: SendListItem

    var body: some View {
        HStack(spacing: 12) {
            Image(systemName: item.type == .text ? "doc.text.fill" : "doc.fill")
                .font(.system(size: 16))
                .foregroundStyle(item.isDisabled ? .gray : .blue)
                .frame(width: 28, height: 28)
                .background(
                    RoundedRectangle(cornerRadius: 6)
                        .fill((item.isDisabled ? Color.gray : Color.blue).opacity(0.12))
                )

            VStack(alignment: .leading, spacing: 3) {
                HStack {
                    Text(item.name)
                        .font(.body)
                        .lineLimit(1)

                    if item.isDisabled {
                        Text("Disabled")
                            .font(.caption2)
                            .foregroundStyle(.white)
                            .padding(.horizontal, 6)
                            .padding(.vertical, 2)
                            .background(Capsule().fill(.gray))
                    }
                }

                HStack(spacing: 10) {
                    Label(item.type == .text ? "Text" : "File", systemImage: item.type == .text ? "text.alignleft" : "paperclip")

                    if let deletionDate = item.deletionDate {
                        Label(deletionDate.formatted(date: .abbreviated, time: .shortened), systemImage: "trash")
                            .foregroundStyle(deletionDate < Date() ? .red : .secondary)
                    }

                    if let max = item.maxAccessCount {
                        Text("\(item.accessCount)/\(max) views")
                    } else {
                        Text("\(item.accessCount) views")
                    }
                }
                .font(.caption)
                .foregroundStyle(.secondary)
            }

            Spacer()
        }
        .padding(.vertical, 4)
    }
}

struct SendDetailView: View {
    let item: SendListItem
    let onEdit: () -> Void
    let onDelete: () -> Void
    @EnvironmentObject var session: SessionManager
    @State private var errorMessage: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack {
                Image(systemName: item.type == .text ? "doc.text.fill" : "doc.fill")
                    .font(.title2)
                    .foregroundStyle(.blue)
                Text(item.name)
                    .font(.title2.bold())
                    .lineLimit(1)
                Spacer()
            }
            .padding(20)

            ScrollView {
                VStack(alignment: .leading, spacing: 16) {
                    if let url = item.publicURL {
                        detailField("Public URL", value: url.absoluteString)
                    }

                    if item.type == .text {
                        detailField("Text", value: item.text.isEmpty ? "No text" : item.text)
                    } else {
                        detailField("File", value: item.fileName.isEmpty ? "Attached file" : item.fileName)
                    }

                    if !item.notes.isEmpty {
                        detailField("Notes", value: item.notes)
                    }

                    Divider()

                    detailField("Access Count", value: item.maxAccessCount.map { "\(item.accessCount) of \($0)" } ?? "\(item.accessCount)")
                    detailField("Deletion Date", value: item.deletionDate?.formatted(date: .abbreviated, time: .shortened) ?? "None")
                    detailField("Expiration Date", value: item.expirationDate?.formatted(date: .abbreviated, time: .shortened) ?? "Never")
                    detailField("Options", value: optionsText)
                }
                .padding(.horizontal, 20)
                .padding(.bottom, 20)
            }

            Divider()
            HStack {
                Button("Delete", role: .destructive) {
                    onDelete()
                }
                Spacer()
                Button("Edit") {
                    onEdit()
                }
                Button("Copy Public URL") {
                    copyPublicURL()
                }
                .buttonStyle(.borderedProminent)
            }
            .padding(20)
        }
        .safeAreaInset(edge: .bottom) {
            if let errorMessage {
                Text(errorMessage)
                    .font(.caption)
                    .foregroundStyle(.red)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(10)
                    .background(.bar)
            }
        }
    }

    private var optionsText: String {
        var parts: [String] = []
        if item.hasPassword { parts.append("Password protected") }
        if item.hideEmail { parts.append("Email hidden") }
        if item.textHidden { parts.append("Text hidden by default") }
        if item.isDisabled { parts.append("Disabled") }
        return parts.isEmpty ? "None" : parts.joined(separator: ", ")
    }

    private func detailField(_ label: String, value: String) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(label)
                .font(.caption)
                .foregroundStyle(.secondary)
            Text(value)
                .textSelection(.enabled)
                .frame(maxWidth: .infinity, alignment: .leading)
        }
    }

    private func copyPublicURL() {
        guard let publicURL = item.publicURL else {
            errorMessage = session.hasLegacySendKey(for: item.send)
                ? "This Send uses an old incompatible key. Edit and save text Sends, or recreate file Sends."
                : "This Send is missing the access ID or encryption key."
            return
        }
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(publicURL.absoluteString, forType: .string)
        errorMessage = nil
    }
}

enum SendEditorMode {
    case create
    case edit(SendItem)
}

/// Create or edit a Send.
struct SendEditorView: View {
    @EnvironmentObject var session: SessionManager
    @Environment(\.dismiss) private var dismiss

    let mode: SendEditorMode
    var onCancel: (() -> Void)? = nil
    var onSaved: ((SendItem) -> Void)? = nil

    @State private var name = ""
    @State private var sendType: SendType = .text
    @State private var textContent = ""
    @State private var hideByDefault = false
    @State private var password = ""
    @State private var removePassword = false
    @State private var maxAccessCount = ""
    @State private var deletionDays = 7
    @State private var expirationDays = 0
    @State private var notes = ""
    @State private var disabled = false
    @State private var hideEmail = false
    @State private var isSaving = false
    @State private var errorMessage: String?
    @State private var selectedFileURL: URL?
    @State private var selectedFileData: Data?
    @State private var selectedFileName: String?

    private var isEditing: Bool {
        if case .edit = mode { return true }
        return false
    }

    var body: some View {
        VStack(spacing: 0) {
            HStack {
                Text(isEditing ? "Edit Send" : "Create Send")
                    .font(.title2.bold())
                Spacer()
            }
            .padding(20)

            ScrollView {
                VStack(alignment: .leading, spacing: 16) {
                    LabeledTextField(label: "Name", text: $name, icon: "textformat")

                    Picker("Type", selection: $sendType) {
                        Text("Text").tag(SendType.text)
                        Text("File").tag(SendType.file)
                    }
                    .pickerStyle(.segmented)
                    .disabled(isEditing)

                    if sendType == .text {
                        GroupBox("Content") {
                            VStack(alignment: .leading, spacing: 8) {
                                TextEditor(text: $textContent)
                                    .font(.body)
                                    .frame(minHeight: 120)
                                Toggle("Hide text by default", isOn: $hideByDefault)
                            }
                            .padding(8)
                        }
                    } else {
                        GroupBox("File") {
                            VStack(spacing: 12) {
                                if let fileName = selectedFileName {
                                    HStack {
                                        Image(systemName: "doc.fill")
                                            .font(.system(size: 24))
                                            .foregroundStyle(.blue)
                                        VStack(alignment: .leading) {
                                            Text(fileName)
                                                .font(.body)
                                            if let size = selectedFileData?.count {
                                                Text(ByteCountFormatter.string(fromByteCount: Int64(size), countStyle: .file))
                                                    .font(.caption)
                                                    .foregroundStyle(.secondary)
                                            }
                                        }
                                        Spacer()
                                        if !isEditing {
                                            Button("Remove") {
                                                selectedFileURL = nil
                                                selectedFileData = nil
                                                selectedFileName = nil
                                            }
                                            .buttonStyle(.plain)
                                            .foregroundStyle(.red)
                                        }
                                    }
                                } else {
                                    Image(systemName: "doc.badge.plus")
                                        .font(.system(size: 32))
                                        .foregroundStyle(.secondary)
                                    Text("Choose a file to share")
                                        .font(.caption)
                                        .foregroundStyle(.secondary)
                                }

                                if !isEditing {
                                    Button(selectedFileURL == nil ? "Choose File..." : "Change File...") {
                                        chooseFile()
                                    }
                                    .buttonStyle(.bordered)
                                }
                            }
                            .frame(maxWidth: .infinity)
                            .padding(16)
                        }
                    }

                    GroupBox("Options") {
                        VStack(spacing: 12) {
                            LabeledTextField(
                                label: isEditing ? "New Password" : "Password",
                                text: $password,
                                icon: "lock.fill",
                                isSecure: true
                            )

                            if isEditing {
                                Toggle("Remove existing password", isOn: $removePassword)
                            }

                            HStack {
                                Text("Max Access Count")
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                                Spacer()
                                TextField("Unlimited", text: $maxAccessCount)
                                    .textFieldStyle(.roundedBorder)
                                    .frame(width: 100)
                            }

                            HStack {
                                Text("Deletion")
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                                Spacer()
                                Picker("", selection: $deletionDays) {
                                    Text("1 day").tag(1)
                                    Text("7 days").tag(7)
                                    Text("14 days").tag(14)
                                    Text("30 days").tag(30)
                                }
                                .frame(width: 120)
                            }

                            HStack {
                                Text("Expiration")
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                                Spacer()
                                Picker("", selection: $expirationDays) {
                                    Text("Never").tag(0)
                                    Text("1 day").tag(1)
                                    Text("7 days").tag(7)
                                    Text("30 days").tag(30)
                                }
                                .frame(width: 120)
                            }

                            Toggle("Hide my email from recipients", isOn: $hideEmail)
                            Toggle("Disable this Send", isOn: $disabled)
                        }
                        .padding(8)
                    }

                    GroupBox("Notes") {
                        TextEditor(text: $notes)
                            .font(.body)
                            .frame(minHeight: 72)
                            .padding(4)
                    }

                    if let error = errorMessage {
                        Text(error)
                            .font(.caption)
                            .foregroundStyle(.red)
                    }
                }
                .padding(20)
            }

            Divider()

            HStack {
                Button("Cancel") {
                    if let onCancel {
                        onCancel()
                    } else {
                        dismiss()
                    }
                }
                    .keyboardShortcut(.cancelAction)
                Spacer()
                Button {
                    saveSend()
                } label: {
                    if isSaving {
                        ProgressView()
                            .controlSize(.small)
                    } else {
                        Text(isEditing ? "Save" : "Create Send")
                    }
                }
                .buttonStyle(.borderedProminent)
                .keyboardShortcut(.defaultAction)
                .disabled(!canSave)
            }
            .padding(20)
        }
        .onAppear(perform: populateFromExistingSend)
    }

    private var canSave: Bool {
        !name.isEmpty && !isSaving && (sendType == .text || isEditing || selectedFileData != nil)
    }

    private func populateFromExistingSend() {
        guard case let .edit(send) = mode else { return }
        sendType = send.type
        name = session.decryptSend(send.name, send: send) ?? ""
        notes = session.decryptSend(send.notes, send: send) ?? ""
        textContent = session.decryptSend(send.text?.text, send: send) ?? ""
        hideByDefault = send.text?.hidden ?? false
        maxAccessCount = send.maxAccessCount.map(String.init) ?? ""
        disabled = send.disabled ?? false
        hideEmail = send.hideEmail ?? false
        selectedFileName = session.decryptSend(send.file?.fileName, send: send)
        deletionDays = days(fromNowTo: send.deletionDate) ?? 7
        expirationDays = days(fromNowTo: send.expirationDate) ?? 0
    }

    private func saveSend() {
        isSaving = true
        errorMessage = nil

        Task {
            do {
                let api = try session.getAPIClient()
                let sendAPI = SendAPI(client: api)
                let saved: SendItem

                switch mode {
                case .create:
                    saved = try await createSend(using: sendAPI)
                case let .edit(existing):
                    saved = try await updateSend(existing, using: sendAPI)
                }

                if let engine = try? session.getSyncEngine() {
                    try? engine.replaceSendFromServer(saved)
                }

                await MainActor.run {
                    onSaved?(saved)
                    if onSaved == nil {
                        dismiss()
                    }
                }
            } catch {
                await MainActor.run {
                    errorMessage = error.localizedDescription
                    isSaving = false
                }
            }
        }
    }

    private func createSend(using sendAPI: SendAPI) async throws -> SendItem {
        let sendKeys = try session.generateSendKey()
        let sendKey = sendKeys.key
        var send = SendItem(type: sendType, name: try session.encrypt(name, using: sendKey))
        send.key = sendKeys.encryptedSecret
        try applyOptions(to: &send, key: sendKey, secret: sendKeys.secret)

        if sendType == .text {
            send.text = SendTextData(
                text: textContent.isEmpty ? nil : try session.encrypt(textContent, using: sendKey),
                hidden: hideByDefault
            )
            var response = try await sendAPI.create(send)
            response.key = response.key ?? send.key
            return response
        }

        guard let fileData = selectedFileData, let fileName = selectedFileName else {
            throw SendEditorError.missingFile
        }

        let encryptedFileName = try session.encrypt(fileName, using: sendKey)
        send.file = SendFileData(fileName: encryptedFileName)
        guard let encryptedPayload = try CipherEncryption.encrypt(data: fileData, key: sendKey)
            .serialized()
            .data(using: .utf8) else {
            throw SendEditorError.invalidEncryptedPayload
        }

        var response = try await sendAPI.createFileSend(
            send,
            fileData: encryptedPayload,
            fileName: encryptedFileName.serialized()
        )
        response.key = response.key ?? send.key
        return response
    }

    private func updateSend(_ existing: SendItem, using sendAPI: SendAPI) async throws -> SendItem {
        var send = existing
        let sendKey: SymmetricCryptoKey
        let sendSecret: Data
        if session.hasLegacySendKey(for: existing) {
            guard existing.type == .text else {
                throw SendEditorError.legacyFileSendRequiresRecreate
            }
            let sendKeys = try session.generateSendKey()
            send.key = sendKeys.encryptedSecret
            sendKey = sendKeys.key
            sendSecret = sendKeys.secret
        } else {
            sendKey = try session.getSendKey(for: existing)
            sendSecret = try session.getSendURLKey(for: existing)
        }
        send.name = try session.encrypt(name, using: sendKey)
        send.notes = notes.isEmpty ? nil : try session.encrypt(notes, using: sendKey)
        send.text = send.type == .text
            ? SendTextData(text: textContent.isEmpty ? nil : try session.encrypt(textContent, using: sendKey), hidden: hideByDefault)
            : send.text
        if send.type == .file, let selectedFileName {
            send.file?.fileName = try session.encrypt(selectedFileName, using: sendKey)
        }
        try applyOptions(to: &send, key: sendKey, secret: sendSecret)

        if removePassword {
            guard let existingId = existing.id else {
                throw SendEditorError.missingSendId
            }
            send.password = nil
            _ = try await sendAPI.removePassword(id: existingId)
        }

        var response = try await sendAPI.update(send)
        response.key = response.key ?? send.key
        return response
    }

    private func applyOptions(to send: inout SendItem, key: SymmetricCryptoKey, secret: Data) throws {
        send.notes = notes.isEmpty ? nil : try session.encrypt(notes, using: key)
        send.password = password.isEmpty ? (isEditing ? send.password : nil) : try SendKeyDerivation.hashPassword(password, secret: secret)
        send.maxAccessCount = Int(maxAccessCount).flatMap { $0 > 0 ? $0 : nil }
        send.deletionDate = Calendar.current.date(byAdding: .day, value: deletionDays, to: Date())
        send.expirationDate = expirationDays > 0
            ? Calendar.current.date(byAdding: .day, value: expirationDays, to: Date())
            : nil
        send.disabled = disabled
        send.hideEmail = hideEmail
    }

    private func chooseFile() {
        let panel = NSOpenPanel()
        panel.allowsMultipleSelection = false
        panel.canChooseDirectories = false
        panel.canChooseFiles = true
        panel.message = "Choose a file to share via Send"

        if panel.runModal() == .OK, let url = panel.url {
            let accessGranted = url.startAccessingSecurityScopedResource()
            defer {
                if accessGranted {
                    url.stopAccessingSecurityScopedResource()
                }
            }

            selectedFileURL = url
            selectedFileName = url.lastPathComponent
            selectedFileData = try? Data(contentsOf: url)
            if name.isEmpty {
                name = url.deletingPathExtension().lastPathComponent
            }
        }
    }

    private func days(fromNowTo date: Date?) -> Int? {
        guard let date else { return nil }
        return max(1, Calendar.current.dateComponents([.day], from: Date(), to: date).day ?? 1)
    }
}

enum SendEditorError: LocalizedError {
    case missingFile
    case missingSendId
    case invalidEncryptedPayload
    case legacyFileSendRequiresRecreate

    var errorDescription: String? {
        switch self {
        case .missingFile:
            return "Choose a file before creating a file Send."
        case .missingSendId:
            return "This Send is missing its server ID."
        case .invalidEncryptedPayload:
            return "The encrypted file payload could not be encoded."
        case .legacyFileSendRequiresRecreate:
            return "This file Send was created with an incompatible key and must be recreated so the file can be re-encrypted."
        }
    }
}

enum SendURLBuilder {
    @MainActor
    static func publicURL(for send: SendItem, session: SessionManager) -> URL? {
        guard let accessId = send.accessId,
              let sendURLKey = try? session.getSendURLKey(for: send) else { return nil }
        let key = sendURLKey.base64URLEncodedString()
        guard let serverURL = session.activeAccount?.serverURL.absoluteString
            .trimmingCharacters(in: CharacterSet(charactersIn: "/")) else {
            return nil
        }
        return URL(string: "\(serverURL)/#/send/\(accessId)/\(key)")
    }
}

private extension Data {
    func base64URLEncodedString() -> String {
        base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}
