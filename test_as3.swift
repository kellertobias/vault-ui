import AuthenticationServices
@available(macOS 11.0, *)
class MyProvider: ASCredentialProviderViewController {
    override func prepareInterface(for savePasswordRequest: ASSavePasswordRequest) {}
}
