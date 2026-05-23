import AuthenticationServices

class MockContext: ASCredentialProviderExtensionContext {
    func complete(cred: ASPasskeyRegistrationCredential) {
        self.completeRegistrationRequest(using: cred, completionHandler: nil)
    }
}
