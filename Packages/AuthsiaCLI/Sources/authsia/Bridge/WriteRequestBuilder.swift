import Foundation
import AuthenticatorBridge

struct WriteRequestBuilder {
    static func makeRequest(type: BridgeRequestType, query: String, body: Data?, sessionToken: String? = nil) -> BridgeRequest {
        BridgeRequest(
            id: UUID(),
            type: type,
            query: query,
            options: BridgeOptions(field: nil, copy: false),
            context: AuthsiaBridgeClient.currentContext(),
            body: body,
            sessionToken: sessionToken
        )
    }
}
