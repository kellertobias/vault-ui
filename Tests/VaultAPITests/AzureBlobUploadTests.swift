import Foundation
import XCTest
@testable import VaultAPI

final class AzureBlobUploadTests: XCTestCase {

    override func setUp() {
        super.setUp()
        AzureBlobUploadURLProtocol.recorder.reset()
        URLProtocol.registerClass(AzureBlobUploadURLProtocol.self)
    }

    override func tearDown() {
        URLProtocol.unregisterClass(AzureBlobUploadURLProtocol.self)
        AzureBlobUploadURLProtocol.recorder.reset()
        super.tearDown()
    }

    func testPutSendsRawBlobHeadersWithoutAuthorization() async throws {
        let payload = Data("encrypted attachment bytes".utf8)
        let url = URL(string: "https://example.blob.core.windows.net/container/blob?sas=token")!

        try await AzureBlobUpload.put(data: payload, to: url)

        let request = try XCTUnwrap(AzureBlobUploadURLProtocol.recorder.request)
        XCTAssertEqual(request.httpMethod, "PUT")
        XCTAssertEqual(request.url, url)
        XCTAssertEqual(request.value(forHTTPHeaderField: "x-ms-blob-type"), "BlockBlob")
        XCTAssertEqual(request.value(forHTTPHeaderField: "x-ms-version"), "2020-04-08")
        XCTAssertEqual(request.value(forHTTPHeaderField: "Content-Type"), "application/octet-stream")
        XCTAssertEqual(request.value(forHTTPHeaderField: "Content-Length"), "\(payload.count)")
        XCTAssertNil(request.value(forHTTPHeaderField: "Authorization"))
        XCTAssertEqual(AzureBlobUploadURLProtocol.recorder.body, payload)
    }
}

private final class CapturedAzureBlobRequest: @unchecked Sendable {
    private let lock = NSLock()
    private var capturedRequest: URLRequest?
    private var capturedBody: Data?

    var request: URLRequest? {
        lock.lock()
        defer { lock.unlock() }
        return capturedRequest
    }

    var body: Data? {
        lock.lock()
        defer { lock.unlock() }
        return capturedBody
    }

    func capture(_ request: URLRequest) {
        lock.lock()
        capturedRequest = request
        capturedBody = request.httpBody ?? Self.readBodyStream(request.httpBodyStream)
        lock.unlock()
    }

    func reset() {
        lock.lock()
        capturedRequest = nil
        capturedBody = nil
        lock.unlock()
    }

    private static func readBodyStream(_ stream: InputStream?) -> Data? {
        guard let stream else { return nil }
        stream.open()
        defer { stream.close() }

        var data = Data()
        var buffer = [UInt8](repeating: 0, count: 4096)
        while stream.hasBytesAvailable {
            let count = stream.read(&buffer, maxLength: buffer.count)
            if count <= 0 { break }
            data.append(buffer, count: count)
        }
        return data
    }
}

private final class AzureBlobUploadURLProtocol: URLProtocol {
    static let recorder = CapturedAzureBlobRequest()

    override class func canInit(with request: URLRequest) -> Bool {
        request.url?.host == "example.blob.core.windows.net"
    }

    override class func canonicalRequest(for request: URLRequest) -> URLRequest {
        request
    }

    override func startLoading() {
        Self.recorder.capture(request)
        let response = HTTPURLResponse(
            url: request.url!,
            statusCode: 201,
            httpVersion: "HTTP/1.1",
            headerFields: nil
        )!
        client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
        client?.urlProtocolDidFinishLoading(self)
    }

    override func stopLoading() {}
}
