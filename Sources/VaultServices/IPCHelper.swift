import Foundation
import os.log

public struct IPCRequest: Codable {
    public let id: String
    public let url: String
    public init(id: String, url: String) { self.id = id; self.url = url }
}

public class IPCHelper {
    private static let serviceName = "de.tobisk.apps.vaultui.ipc"
    private static let accountName = "picker-request"
    
    public static func saveRequest(id: String, url: String) {
        let store = SharedCredentialStore()
        let req = IPCRequest(id: id, url: url)
        if let data = try? JSONEncoder().encode(req) {
            try? store.saveToSharedKeychain(data: data, service: serviceName, account: accountName)
        }
    }
    
    public static func fetchAndClearRequest() -> IPCRequest? {
        let store = SharedCredentialStore()
        guard let data = try? store.loadFromSharedKeychain(service: serviceName, account: accountName) else { return nil }
        try? store.deleteFromSharedKeychain(service: serviceName, account: accountName)
        return try? JSONDecoder().decode(IPCRequest.self, from: data)
    }
}

public struct IPCResponse: Codable {
    public let requestId: String
    public let credentials: [[String: String]]
    public let cancelled: Bool
    public init(requestId: String, credentials: [[String: String]], cancelled: Bool) {
        self.requestId = requestId; self.credentials = credentials; self.cancelled = cancelled
    }
}

extension IPCHelper {
    public static func saveResponse(requestId: String, credentials: [[String: String]], cancelled: Bool) {
        let store = SharedCredentialStore()
        let res = IPCResponse(requestId: requestId, credentials: credentials, cancelled: cancelled)
        if let data = try? JSONEncoder().encode(res) {
            try? store.saveToSharedKeychain(data: data, service: serviceName, account: "picker-response-\(requestId)")
        }
    }
    
    public static func fetchAndClearResponse(requestId: String) -> IPCResponse? {
        let store = SharedCredentialStore()
        guard let data = try? store.loadFromSharedKeychain(service: serviceName, account: "picker-response-\(requestId)") else { return nil }
        try? store.deleteFromSharedKeychain(service: serviceName, account: "picker-response-\(requestId)")
        return try? JSONDecoder().decode(IPCResponse.self, from: data)
    }
}
