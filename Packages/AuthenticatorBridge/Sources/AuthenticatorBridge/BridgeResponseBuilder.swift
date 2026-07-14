import Foundation

public enum BridgeResponseBuilder {
    public static func success<T: Codable & Equatable>(id: UUID, payload: T, sessionToken: String? = nil, sessionExpiresAt: Date? = nil) -> BridgeResponse<T> {
        BridgeResponse(id: id, payload: payload, error: nil, sessionToken: sessionToken, sessionExpiresAt: sessionExpiresAt)
    }

    public static func error<T: Codable & Equatable>(id: UUID, code: BridgeErrorCode, message: String) -> BridgeResponse<T> {
        BridgeResponse(id: id, payload: nil, error: BridgeErrorPayload(code: code, message: message))
    }
}
