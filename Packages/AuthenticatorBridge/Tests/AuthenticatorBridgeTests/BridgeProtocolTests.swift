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
        _ = #selector(AuthsiaBridgeXPCProtocol.listAccessCredentials(_:_:))
        _ = #selector(AuthsiaBridgeXPCProtocol.revokeAccessCredential(_:_:))
        _ = #selector(AuthsiaBridgeXPCProtocol.validateAccessCredential(_:_:))
    }
}
