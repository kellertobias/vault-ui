import AuthenticationServices

func test(req: ASCredentialRequest) {
    if let pr = req as? ASPasskeyCredentialRequest {
        print(pr.credentialIdentity.relyingPartyIdentifier)
    }
}
