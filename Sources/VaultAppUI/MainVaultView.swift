// MARK: - VaultAppUI/MainVaultView.swift
// Main three-column vault layout

import SwiftUI
import VaultModels
import VaultAPI
import VaultServices
import VaultSync

/// Wrapper to make a cipher ID work with sheet(item:).
struct EditSheetItem: Identifiable {
    let id: String
}

/// Wrapper to make a cipher type work with sheet(item:).
struct CreateSheetItem: Identifiable {
    let id = UUID()
    let type: CipherType
}

/// The main vault view with a three-column layout:
/// - Sidebar: folders, types, account switcher
/// - Content: cipher list
/// - Detail: selected cipher details
struct MainVaultView: View {
    @EnvironmentObject var session: SessionManager
    @State private var selectedFilter: SidebarFilter = .allItems
    @State private var selectedCipherIds: Set<String> = []
    @State private var selectedSend: SendListItem?
    @State private var searchText = ""
    @State private var sendSearchText = ""
    @State private var columnVisibility = NavigationSplitViewVisibility.all
    @State private var showPasswordGenerator = false
    @State private var createItemType: CipherType?
    @State private var editItemId: String?
    @State private var isCreatingSend = false
    @State private var editingSend: SendItem?
    @State private var refreshToken = 0

    var body: some View {
        NavigationSplitView(columnVisibility: $columnVisibility) {
            SidebarView(selectedFilter: $selectedFilter, onItemsMoved: {
                refreshToken += 1
            }, onCreateSend: {
                // Switch to the Send section so the editor pane is visible, then start a new Send.
                selectedFilter = .send
                createSend()
            })
        } content: {
            Group {
                if selectedFilter == .send {
                    SendListView(
                        searchText: $sendSearchText,
                        selectedSend: $selectedSend,
                        refreshToken: refreshToken,
                        onCreateSend: { createSend() },
                        onEditSend: { editingSend = $0.send },
                        onDeleteSend: {
                            selectedSend = nil
                            refreshToken += 1
                        }
                    )
                        .navigationSplitViewColumnWidth(min: 300, ideal: 340, max: 500)
                } else {
                    CipherListView(
                        filter: selectedFilter,
                        searchText: $searchText,
                        selectedCipherIds: $selectedCipherIds,
                        refreshToken: refreshToken,
                        onAddCipher: { type in addCipher(type) },
                        onGeneratePassword: { showPasswordGenerator = true },
                        onDeleteSelected: { deleteSelectedCiphers() },
                        onEmptyTrash: { emptyTrash() }
                    )
                    .navigationSplitViewColumnWidth(min: 300, ideal: 340, max: 500)
                }
            }
            .ignoresSafeArea(.container, edges: .top)
        } detail: {
            Group {
                if selectedFilter == .send {
                    if isCreatingSend {
                        SendEditorView(mode: .create, onCancel: {
                            isCreatingSend = false
                        }, onSaved: { send in
                            showSavedSend(send)
                        })
                    } else if let send = editingSend {
                        SendEditorView(mode: .edit(send), onCancel: {
                            editingSend = nil
                        }, onSaved: { send in
                            showSavedSend(send)
                        })
                    } else if let selectedSend {
                        SendDetailView(item: selectedSend, onEdit: {
                            editingSend = selectedSend.send
                        }, onDelete: {
                            deleteSend(selectedSend)
                        })
                    } else {
                        EmptyDetailView()
                    }
                } else if let type = createItemType {
                    CipherEditView(mode: .create(type), onDismiss: {
                        createItemType = nil
                        refreshToken += 1
                    }, onSave: { cipher in
                        showSavedCipher(cipher)
                    })
                } else if let id = editItemId {
                    CipherEditView(mode: .edit(id), onDismiss: {
                        editItemId = nil
                        refreshToken += 1
                    })
                } else if selectedCipherIds.count == 1, let cipherId = selectedCipherIds.first {
                    CipherDetailView(
                        cipherId: cipherId,
                        refreshToken: refreshToken,
                        onEdit: { id in editItemId = id },
                        onDelete: {
                            selectedCipherIds.remove(cipherId)
                            refreshToken += 1
                        },
                        onFavoriteToggled: {
                            refreshToken += 1
                        }
                    )
                } else if selectedCipherIds.count > 1 {
                    MultiSelectMergeView(cipherIds: selectedCipherIds) {
                        selectedCipherIds.removeAll()
                        refreshToken += 1
                        // Push the local merge changes to the server
                        Task {
                            if let engine = try? session.getSyncEngine() {
                                try? await engine.fullSync()
                            }
                        }
                    }
                } else {
                    EmptyDetailView()
                }
            }
            .ignoresSafeArea(.container, edges: .top)
        }
        .sheet(isPresented: $showPasswordGenerator) {
            PasswordGeneratorView()
                .frame(minWidth: 400, minHeight: 500)
        }
        .alert(
            "Weak encryption settings",
            isPresented: Binding(
                get: { session.weakKDFWarning != nil },
                set: { if !$0 { session.weakKDFWarning = nil } }
            )
        ) {
            Button("OK", role: .cancel) { session.weakKDFWarning = nil }
        } message: {
            Text(session.weakKDFWarning ?? "")
        }
        .onChange(of: selectedCipherIds) { _, _ in 
            session.resetLockTimer()
            createItemType = nil
            editItemId = nil
        }
        .onChange(of: selectedFilter) { _, filter in
            session.resetLockTimer()
            if filter == .send {
                selectedCipherIds.removeAll()
                createItemType = nil
                editItemId = nil
            } else {
                selectedSend = nil
                isCreatingSend = false
                editingSend = nil
            }
        }
        .onChange(of: searchText) { _, _ in 
            session.resetLockTimer()
            createItemType = nil
            editItemId = nil
        }
        .onChange(of: sendSearchText) { _, _ in
            session.resetLockTimer()
            isCreatingSend = false
            editingSend = nil
        }
    }

    private func addCipher(_ type: CipherType) {
        createItemType = type
    }

    private func createSend() {
        isCreatingSend = true
        editingSend = nil
        selectedSend = nil
    }

    private func showSavedCipher(_ cipher: Cipher) {
        guard let id = cipher.id else { return }

        createItemType = nil
        editItemId = nil
        searchText = ""

        if selectedFilter != .allItems {
            selectedFilter = .type(cipher.type)
        }

        selectedCipherIds = [id]
        refreshToken += 1
    }

    private func showSavedSend(_ send: SendItem) {
        guard send.id != nil else { return }
        isCreatingSend = false
        editingSend = nil
        sendSearchText = ""
        selectedSend = SendListItem(send: send, session: session)
        refreshToken += 1
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
                    editingSend = nil
                    refreshToken += 1
                }
            } catch {
                // Keep the Send selected so the user can retry from the detail pane.
            }
        }
    }

    private func deleteSelectedCiphers() {
        guard let engine = try? session.getSyncEngine() else { return }
        guard let ciphers = try? engine.fetchCiphers(includeDeleted: false) else { return }
        
        let ciphersToDelete = ciphers.filter { selectedCipherIds.contains($0.id) }
        
        for persisted in ciphersToDelete {
            if let cipher = try? persisted.toCipher() {
                try? engine.saveCipherLocally(cipher, operation: .softDelete)
            }
        }
        
        selectedCipherIds.removeAll()
        refreshToken += 1
        
        Task {
            try? await engine.fullSync()
        }
    }

    private func emptyTrash() {
        guard let engine = try? session.getSyncEngine() else { return }
        guard let ciphers = try? engine.fetchCiphers(includeDeleted: true) else { return }

        let trashedCiphers = ciphers.filter(\.isDeleted)

        for persisted in trashedCiphers {
            if let cipher = try? persisted.toCipher() {
                try? engine.saveCipherLocally(cipher, operation: .delete)
            }
        }

        selectedCipherIds.removeAll()

        Task {
            try? await engine.fullSync()
            await MainActor.run {
                refreshToken += 1
            }
        }
    }
}

/// Empty detail placeholder.
struct EmptyDetailView: View {
    var body: some View {
        VStack(spacing: 16) {
            Image(systemName: "shield.lefthalf.filled")
                .font(.system(size: 64))
                .foregroundStyle(.quaternary)
            Text("Select an item")
                .font(.title3)
                .foregroundStyle(.secondary)
            Text("Choose an item from the list to view its details.")
                .font(.caption)
                .foregroundStyle(.tertiary)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}

/// Small avatar circle with initials, colored per account.
struct AccountAvatarView: View {
    let email: String
    var colorIndex: Int = 0
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
            Text(initials)
                .font(.system(size: size * 0.4, weight: .semibold, design: .rounded))
                .foregroundStyle(.white)
        }
        .frame(width: size, height: size)
    }

    private var initials: String {
        let parts = email.split(separator: "@").first ?? ""
        let first = parts.prefix(1).uppercased()
        return first.isEmpty ? "?" : first
    }
}
