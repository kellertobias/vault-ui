import AuthenticationServices

func test(req: ASCredentialRequest) {
    if let passkeyReq = req as? ASPasskeyRegistrationRequest {
        print(passkeyReq.relyingPartyIdentifier)
        print(passkeyReq.clientDataHash)
    }
}
