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
    
    public var body: some View {
        VStack(spacing: 0) {
            // Header
            HStack {
                Image(systemName: "lock.shield")
                    .foregroundColor(.accentColor)
                Text("Select Credential")
                    .font(.headline)
                Spacer()
                Button(action: cancel) {
                    Image(systemName: "xmark")
                }
                .buttonStyle(.plain)
            }
            .padding()
            .background(Color(NSColor.windowBackgroundColor))
            
            Divider()
            
            // List
            if credentials.isEmpty {
                VStack {
                    Text("No credentials found")
                        .foregroundColor(.secondary)
                        .padding()
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                List(credentials, id: \.id) { cred in
                    Button(action: { select(credential: cred) }) {
                        HStack {
                            VStack(alignment: .leading) {
                                Text(cred.name)
                                    .fontWeight(.medium)
                                if let username = cred.username, !username.isEmpty {
                                    Text(username)
                                        .font(.caption)
                                        .foregroundColor(.secondary)
                                }
                            }
                            Spacer()
                        }
                        .padding(.vertical, 4)
                        .padding(.horizontal, 8)
                        .contentShape(Rectangle())
                    }
                    .buttonStyle(.plain)
                    // Hover effect approximation
                    .onHover { isHovered in
                        if isHovered {
                            NSCursor.pointingHand.push()
                        } else {
                            NSCursor.pop()
                        }
                    }
                }
                .listStyle(.plain)
            }
        }
        .frame(width: 300, height: 400)
        .background(Color(NSColor.controlBackgroundColor))
        .onAppear(perform: loadCredentials)
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
        let sharedDefaults = UserDefaults(suiteName: "group.de.tobisk.apps.vaultui")
        sharedDefaults?.set([
            "id": credential.id,
            "name": credential.name,
            "username": credential.username ?? ""
        ], forKey: "VaultUIPickerResponse-\(requestId)")
        onDismiss()
    }
    
    private func cancel() {
        let sharedDefaults = UserDefaults(suiteName: "group.de.tobisk.apps.vaultui")
        sharedDefaults?.set("true", forKey: "VaultUIPickerCancel-\(requestId)")
        onDismiss()
    }
}
