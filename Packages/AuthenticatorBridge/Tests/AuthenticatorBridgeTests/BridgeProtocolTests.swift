import XCTest
@testable import AuthenticatorBridge

final class BridgeProtocolTests: XCTestCase {
    func testProtocolSelectorsExist() {
        _ = #selector(AuthsiaBridgeXPCProtocol.status(_:_:))
        _ = #selector(AuthsiaBridgeXPCProtocol.getSSH(_:_:))
        _ = #selector(AuthsiaBridgeXPCProtocol.lock(_:_:))
        _ = #selector(AuthsiaBridgeXPCProtocol.addItem(_:_:))
        _ = #selector(AuthsiaBridgeXPCProtocol.updateItem(_:_:))
        _ = #selector(AuthsiaBridgeXPCProtocol.deleteItem(_:_:))
        _ = #selector(AuthsiaBridgeXPCProtocol.auditVerify(_:_:))
        _ = #selector(AuthsiaBridgeXPCProtocol.exportAccounts(_:_:))
        _ = #selector(AuthsiaBridgeXPCProtocol.agentJITSnapshot(_:_:))
        _ = #selector(AuthsiaBridgeXPCProtocol.revokeAgentJITGrant(_:_:))
        _ = #selector(AuthsiaBridgeXPCProtocol.revokeAllAgentJITGrants(_:_:))
        _ = #selector(AuthsiaBridgeXPCProtocol.renewAgentJITGrant(_:_:))
        _ = #selector(AuthsiaBridgeXPCProtocol.listAccessCredentials(_:_:))
        _ = #selector(AuthsiaBridgeXPCProtocol.revokeAccessCredential(_:_:))
        _ = #selector(AuthsiaBridgeXPCProtocol.validateAccessCredential(_:_:))
        _ = #selector(AuthsiaBridgeXPCProtocol.completeTerminalPairing(_:_:))
    }

    func testPingPayloadKeepsLegacyDecodingAndAddsCLIAccessState() throws {
        let legacy = Data(#"{"protocolVersion":"10"}"#.utf8)
        let decodedLegacy = try JSONDecoder().decode(BridgePingPayload.self, from: legacy)
        XCTAssertNil(decodedLegacy.cliAccessEnabled)
        XCTAssertNil(decodedLegacy.terminalPairing)

        let current = BridgePingPayload(protocolVersion: "10", cliAccessEnabled: false)
        let roundTripped = try JSONDecoder().decode(
            BridgePingPayload.self,
            from: JSONEncoder().encode(current)
        )
        XCTAssertEqual(roundTripped.cliAccessEnabled, false)
    }
}
