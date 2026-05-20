// MARK: - VaultAppUI/SendView.swift
// Bitwarden Send management view

import SwiftUI
import VaultModels
import VaultCrypto
import VaultServices
import VaultSync
import VaultAPI

/// List and create Bitwarden Send items.
struct SendListView: View {
    @EnvironmentObject var session: SessionManager
    @State private var sends: [SendListItem] = []
    @State private var showCreateSheet = false
    @State private var isLoading = true

    var body: some View {
        Group {
            if isLoading {
                ProgressView()
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else if sends.isEmpty {
                VStack(spacing: 16) {
                    Image(systemName: "paperplane")
                        .font(.system(size: 48))
                        .foregroundStyle(.quaternary)
                    Text("No Sends")
                        .font(.title3)
                        .foregroundStyle(.secondary)
                    Text("Use Send to securely share text or files.")
                        .font(.caption)
                        .foregroundStyle(.tertiary)
                    Button("Create Send") {
                        showCreateSheet = true
                    }
                    .buttonStyle(.borderedProminent)
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                List(sends) { send in
                    SendRowView(item: send)
                }
                .listStyle(.inset(alternatesRowBackgrounds: true))
            }
        }
        .navigationTitle("Send")
        .toolbar {
            ToolbarItem(placement: .primaryAction) {
                Button {
                    showCreateSheet = true
                } label: {
                    Image(systemName: "plus")
                }
            }
        }
        .sheet(isPresented: $showCreateSheet) {
            CreateSendView {
                loadSends()
            }
            .frame(minWidth: 450, minHeight: 500)
        }
        .task { loadSends() }
    }

    private func loadSends() {
        isLoading = true
        defer { isLoading = false }

        guard let engine = try? session.getSyncEngine() else { return }
        guard let persistedSends = try? engine.fetchSends() else { return }

        sends = persistedSends.compactMap { persisted -> SendListItem? in
            guard let sendItem = try? persisted.toSendItem() else { return nil }

            let name = session.decrypt(sendItem.name) ?? "Unnamed"
            let sendType: SendListItem.SendType = sendItem.type == .text ? .text : .file

            return SendListItem(
                id: persisted.id,
                name: name,
                type: sendType,
                expirationDate: sendItem.expirationDate,
                accessCount: sendItem.accessCount ?? 0,
                maxAccessCount: sendItem.maxAccessCount,
                isDisabled: sendItem.disabled ?? false
            )
        }
        .sorted { $0.name.localizedCaseInsensitiveCompare($1.name) == .orderedAscending }
    }
}

/// Display item for a Send.
struct SendListItem: Identifiable, Equatable {
    let id: String
    let name: String
    let type: SendType
    let expirationDate: Date?
    let accessCount: Int
    let maxAccessCount: Int?
    let isDisabled: Bool

    enum SendType {
        case text, file
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

            VStack(alignment: .leading, spacing: 2) {
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

                HStack(spacing: 8) {
                    if let expiry = item.expirationDate {
                        Label(
                            expiry.formatted(date: .abbreviated, time: .shortened),
                            systemImage: "clock"
                        )
                        .font(.caption)
                        .foregroundStyle(expiry < Date() ? .red : .secondary)
                    }

                    if let max = item.maxAccessCount {
                        Text("\(item.accessCount)/\(max) views")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    } else {
                        Text("\(item.accessCount) views")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                }
            }

            Spacer()
        }
        .padding(.vertical, 4)
    }
}

/// Create a new Send.
struct CreateSendView: View {
    @EnvironmentObject var session: SessionManager
    @Environment(\.dismiss) private var dismiss
    var onCreated: (() -> Void)? = nil

    @State private var name = ""
    @State private var sendType: SendListItem.SendType = .text
    @State private var textContent = ""
    @State private var hideByDefault = false
    @State private var password = ""
    @State private var maxAccessCount = ""
    @State private var expirationDays = 7
    @State private var notes = ""
    @State private var isSaving = false
    @State private var errorMessage: String?
    @State private var selectedFileURL: URL?
    @State private var selectedFileData: Data?

    var body: some View {
        VStack(spacing: 0) {
            HStack {
                Text("Create Send")
                    .font(.title2.bold())
                Spacer()
            }
            .padding(20)

            ScrollView {
                VStack(alignment: .leading, spacing: 16) {
                    LabeledTextField(label: "Name", text: $name, icon: "textformat")

                    Picker("Type", selection: $sendType) {
                        Text("Text").tag(SendListItem.SendType.text)
                        Text("File").tag(SendListItem.SendType.file)
                    }
                    .pickerStyle(.segmented)

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
                                if let fileURL = selectedFileURL {
                                    HStack {
                                        Image(systemName: "doc.fill")
                                            .font(.system(size: 24))
                                            .foregroundStyle(.blue)
                                        VStack(alignment: .leading) {
                                            Text(fileURL.lastPathComponent)
                                                .font(.body)
                                            if let size = selectedFileData?.count {
                                                Text(ByteCountFormatter.string(fromByteCount: Int64(size), countStyle: .file))
                                                    .font(.caption)
                                                    .foregroundStyle(.secondary)
                                            }
                                        }
                                        Spacer()
                                        Button("Remove") {
                                            selectedFileURL = nil
                                            selectedFileData = nil
                                        }
                                        .buttonStyle(.plain)
                                        .foregroundStyle(.red)
                                    }
                                } else {
                                    Image(systemName: "doc.badge.plus")
                                        .font(.system(size: 32))
                                        .foregroundStyle(.secondary)
                                    Text("Choose a file to share")
                                        .font(.caption)
                                        .foregroundStyle(.secondary)
                                }

                                Button(selectedFileURL == nil ? "Choose File…" : "Change File…") {
                                    chooseFile()
                                }
                                .buttonStyle(.bordered)
                            }
                            .frame(maxWidth: .infinity)
                            .padding(16)
                        }
                    }

                    GroupBox("Options") {
                        VStack(spacing: 12) {
                            LabeledTextField(
                                label: "Password (optional)",
                                text: $password,
                                icon: "lock.fill",
                                isSecure: true
                            )
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
                                Text("Expiration")
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                                Spacer()
                                Picker("", selection: $expirationDays) {
                                    Text("1 day").tag(1)
                                    Text("7 days").tag(7)
                                    Text("30 days").tag(30)
                                    Text("Never").tag(0)
                                }
                                .frame(width: 120)
                            }
                        }
                        .padding(8)
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
                Button("Cancel") { dismiss() }
                    .keyboardShortcut(.cancelAction)
                Spacer()
                Button {
                    createSend()
                } label: {
                    if isSaving {
                        ProgressView()
                            .controlSize(.small)
                    } else {
                        Text("Create Send")
                    }
                }
                .buttonStyle(.borderedProminent)
                .keyboardShortcut(.defaultAction)
                .disabled(name.isEmpty || isSaving || (sendType == .file && selectedFileData == nil))
            }
            .padding(20)
        }
    }

    private func createSend() {
        isSaving = true
        errorMessage = nil

        Task {
            do {
                let encName = try session.encrypt(name)

                var send = SendItem(
                    type: sendType == .text ? .text : .file,
                    name: encName
                )

                if sendType == .text {
                    let encText = textContent.isEmpty ? nil : try session.encrypt(textContent)
                    send.text = SendTextData(text: encText, hidden: hideByDefault)
                }

                if !password.isEmpty {
                    send.password = password
                }

                if let maxCount = Int(maxAccessCount), maxCount > 0 {
                    send.maxAccessCount = maxCount
                }

                // Set deletion date
                if expirationDays > 0 {
                    send.expirationDate = Calendar.current.date(
                        byAdding: .day, value: expirationDays, to: Date()
                    )
                }
                // Bitwarden requires a deletion date — default 7 days if no expiration
                send.deletionDate = Calendar.current.date(
                    byAdding: .day, value: max(expirationDays, 7), to: Date()
                )

                let api = try session.getAPIClient()
                let sendAPI = SendAPI(client: api)

                if sendType == .file, let fileData = selectedFileData, let fileURL = selectedFileURL {
                    _ = try await sendAPI.createFileSend(
                        send,
                        fileData: fileData,
                        fileName: fileURL.lastPathComponent
                    )
                } else {
                    _ = try await sendAPI.create(send)
                }

                // Sync to get the server-assigned ID
                if let engine = try? session.getSyncEngine() {
                    try await engine.fullSync()
                }

                onCreated?()
                dismiss()
            } catch {
                errorMessage = error.localizedDescription
                isSaving = false
            }
        }
    }

    private func chooseFile() {
        let panel = NSOpenPanel()
        panel.allowsMultipleSelection = false
        panel.canChooseDirectories = false
        panel.canChooseFiles = true
        panel.message = "Choose a file to share via Send"

        if panel.runModal() == .OK, let url = panel.url {
            selectedFileURL = url
            selectedFileData = try? Data(contentsOf: url)
            if name.isEmpty {
                name = url.deletingPathExtension().lastPathComponent
            }
        }
    }
}
