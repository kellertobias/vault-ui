import SwiftUI
import VaultModels
import VaultServices

public struct NativePickerView: View {
    let url: String
    let requestId: String
    let onDismiss: @MainActor () -> Void
    
    @State private var credentials: [SharedCredentialEntry] = []
    
    public init(url: String, requestId: String, onDismiss: @escaping @MainActor () -> Void) {
        self.url = url
        self.requestId = requestId
        self.onDismiss = onDismiss
    }
    
    @State private var lastConfirmedSync: Date?
    @State private var searchText: String = ""
    
    var filteredCredentials: [SharedCredentialEntry] {
        if searchText.isEmpty { return credentials }
        let query = searchText.lowercased()
        return credentials.filter {
            $0.name.lowercased().contains(query)
            || ($0.username?.lowercased().contains(query) ?? false)
            || $0.uris.contains(where: { $0.lowercased().contains(query) })
        }
    }
    
    public var body: some View {
        VStack(spacing: 0) {
            // Header
            HStack {
                Button("Cancel") { cancel() }
                    .keyboardShortcut(.cancelAction)
                Spacer()
                Text("Vault UI — AutoFill")
                    .font(.headline)
                Spacer()
                // Balance the layout
                Button("Cancel") { cancel() }
                    .hidden()
            }
            .padding()
            
            // Search
            TextField("Search credentials…", text: $searchText)
                .textFieldStyle(.roundedBorder)
                .padding(.horizontal)
                .padding(.bottom, 8)
            
            Divider()
            
            // List
            if filteredCredentials.isEmpty {
                VStack(spacing: 12) {
                    Text("No matching credentials")
                        .foregroundStyle(.secondary)
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                List(filteredCredentials, id: \.id) { cred in
                    Button(action: { select(credential: cred) }) {
                        HStack {
                            VStack(alignment: .leading, spacing: 2) {
                                Text(cred.name)
                                    .font(.body)
                                    .fontWeight(.medium)
                                if let username = cred.username, !username.isEmpty {
                                    Text(username)
                                        .font(.caption)
                                        .foregroundStyle(.secondary)
                                }
                                if let uri = cred.uris.first {
                                    Text(uri)
                                        .font(.caption2)
                                        .foregroundStyle(.tertiary)
                                        .lineLimit(1)
                                }
                            }
                            Spacer()
                            Image(systemName: "arrow.right.circle.fill")
                                .foregroundStyle(.blue)
                        }
                        .contentShape(Rectangle())
                        .padding(.vertical, 2)
                    }
                    .buttonStyle(.plain)
                }
                .listStyle(.plain)
            }
            
            if let lastConfirmedSync {
                Divider()
                HStack {
                    Text("Last sync: \(lastConfirmedSync, style: .time)")
                    Spacer()
                }
                .font(.caption2)
                .foregroundColor(.secondary)
                .padding(.horizontal)
                .padding(.vertical, 8)
                .background(Color(NSColor.windowBackgroundColor))
            }
        }
        .frame(width: 300, height: 400)
        .background(Color(NSColor.controlBackgroundColor))
        .onAppear {
            loadCredentials()
            let dates = SharedCredentialStore().fetchSyncDates()
            self.lastConfirmedSync = dates?.lastSyncWithServer
        }
    }
    
    private func loadCredentials() {
        let store = SharedCredentialStore()
        let allEntries = store.fetchCredentials()
        
        let cleanUrl = url.lowercased().replacingOccurrences(of: "https://", with: "").replacingOccurrences(of: "http://", with: "")
        
        var matchedIds = Set<String>()
        for entry in allEntries {
            for uri in entry.uris {
                let cleanUri = uri.lowercased().replacingOccurrences(of: "https://", with: "").replacingOccurrences(of: "http://", with: "")
                if cleanUrl.hasPrefix(cleanUri) || cleanUrl == cleanUri {
                    matchedIds.insert(entry.id)
                    break
                }
            }
        }
        
        self.credentials = allEntries.filter { matchedIds.contains($0.id) }
    }
    
    private func select(credential: SharedCredentialEntry) {
        IPCHelper.saveResponse(requestId: requestId, credentials: [["id": credential.id, "name": credential.name, "username": credential.username ?? ""]], cancelled: false)
        onDismiss()
    }
    
    private func cancel() {
        IPCHelper.saveResponse(requestId: requestId, credentials: [], cancelled: true)
        onDismiss()
    }
}
