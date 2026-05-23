import AuthenticationServices

@available(macOS 14.0, *)
func test(req: ASCredentialRequest) {
    if let p = req as? ASPasswordCredentialRequest {
        print(p.credentialIdentity)
    }
    if let o = req as? ASOneTimeCodeCredentialRequest {
        print(o.credentialIdentity)
    }
}
