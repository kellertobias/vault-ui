// MARK: - VaultAppUI/MainVaultView.swift
// Main three-column vault layout

import SwiftUI
import VaultModels
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
    @State private var searchText = ""
    @State private var columnVisibility = NavigationSplitViewVisibility.all
    @State private var showPasswordGenerator = false
    @State private var createItemType: CipherType?
    @State private var editItemId: String?
    @State private var refreshToken = 0

    var body: some View {
        NavigationSplitView(columnVisibility: $columnVisibility) {
            SidebarView(selectedFilter: $selectedFilter, onItemsMoved: {
                refreshToken += 1
            })
        } content: {
            Group {
                if selectedFilter == .send {
                    SendListView()
                        .navigationSplitViewColumnWidth(min: 300, ideal: 340, max: 500)
                } else {
                    CipherListView(
                        filter: selectedFilter,
                        searchText: $searchText,
                        selectedCipherIds: $selectedCipherIds,
                        refreshToken: refreshToken,
                        onAddCipher: { type in addCipher(type) },
                        onGeneratePassword: { showPasswordGenerator = true },
                        onDeleteSelected: { deleteSelectedCiphers() }
                    )
                    .navigationSplitViewColumnWidth(min: 300, ideal: 340, max: 500)
                }
            }
            .ignoresSafeArea(.container, edges: .top)
        } detail: {
            Group {
                if let type = createItemType {
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
        .onChange(of: selectedCipherIds) { _, _ in 
            session.resetLockTimer()
            createItemType = nil
            editItemId = nil
        }
        .onChange(of: searchText) { _, _ in 
            session.resetLockTimer()
            createItemType = nil
            editItemId = nil
        }
    }

    private func addCipher(_ type: CipherType) {
        createItemType = type
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

/// Small avatar circle with initials.
struct AccountAvatarView: View {
    let email: String
    let size: CGFloat

    var body: some View {
        ZStack {
            Circle()
                .fill(
                    .linearGradient(
                        colors: [.blue, .purple],
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
