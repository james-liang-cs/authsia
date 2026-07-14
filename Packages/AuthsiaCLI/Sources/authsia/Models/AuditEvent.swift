import Foundation
import AuthenticatorBridge

struct AuditEvent: Codable, Equatable, Identifiable {
    let version: Int
    let record: BridgeAuditRecord
    let previousHash: String?
    let entryHash: String

    var id: String { entryHash }
}
