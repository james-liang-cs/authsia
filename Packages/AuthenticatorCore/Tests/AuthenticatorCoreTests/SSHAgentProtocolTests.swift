import Testing
import Foundation
@testable import AuthenticatorCore

@Suite("SSHAgentMessage")
struct SSHAgentProtocolTests {

    @Test("parse REQUEST_IDENTITIES message")
    func parseRequestIdentities() throws {
        // SSH agent wire: 4-byte length + 1-byte type (11 = REQUEST_IDENTITIES)
        var data = Data()
        let length = UInt32(1).bigEndian
        withUnsafeBytes(of: length) { data.append(contentsOf: $0) }
        data.append(11) // SSH2_AGENTC_REQUEST_IDENTITIES
        let message = try SSHAgentMessage.parse(data)
        #expect(message == .requestIdentities)
    }

    @Test("parse SIGN_REQUEST message extracts key blob and challenge data")
    func parseSignRequest() throws {
        var payload = Data()
        // key blob: 4-byte length + blob
        let keyBlob = Data("fake-key-blob".utf8)
        var keyLen = UInt32(keyBlob.count).bigEndian
        withUnsafeBytes(of: &keyLen) { payload.append(contentsOf: $0) }
        payload.append(keyBlob)
        // data to sign: 4-byte length + data
        let signData = Data("challenge".utf8)
        var signLen = UInt32(signData.count).bigEndian
        withUnsafeBytes(of: &signLen) { payload.append(contentsOf: $0) }
        payload.append(signData)
        // flags: 4 bytes
        var flags = UInt32(0).bigEndian
        withUnsafeBytes(of: &flags) { payload.append(contentsOf: $0) }

        var data = Data()
        let totalLen = UInt32(1 + payload.count).bigEndian
        withUnsafeBytes(of: totalLen) { data.append(contentsOf: $0) }
        data.append(13) // SSH2_AGENTC_SIGN_REQUEST
        data.append(payload)

        let message = try SSHAgentMessage.parse(data)
        guard case .signRequest(let parsedKeyBlob, let parsedData, let parsedFlags) = message else {
            Issue.record("Expected signRequest")
            return
        }
        #expect(parsedKeyBlob == keyBlob)
        #expect(parsedData == signData)
        #expect(parsedFlags == 0)
    }

    @Test("parse ADD_IDENTITY message")
    func parseAddIdentity() throws {
        var data = Data()
        let length = UInt32(1).bigEndian
        withUnsafeBytes(of: length) { data.append(contentsOf: $0) }
        data.append(17) // SSH_AGENTC_ADD_IDENTITY
        let message = try SSHAgentMessage.parse(data)
        #expect(message == .addIdentity)
    }

    @Test("parse REMOVE_IDENTITY message")
    func parseRemoveIdentity() throws {
        var data = Data()
        let length = UInt32(1).bigEndian
        withUnsafeBytes(of: length) { data.append(contentsOf: $0) }
        data.append(18) // SSH_AGENTC_REMOVE_IDENTITY
        let message = try SSHAgentMessage.parse(data)
        #expect(message == .removeIdentity)
    }

    @Test("parse EXTENSION message extracts extension name and payload")
    func parseExtension() throws {
        var payload = Data()
        let name = Data("session-bind@openssh.com".utf8)
        var nameLen = UInt32(name.count).bigEndian
        withUnsafeBytes(of: &nameLen) { payload.append(contentsOf: $0) }
        payload.append(name)
        let extensionPayload = Data("opaque-extension-payload".utf8)
        payload.append(extensionPayload)

        var data = Data()
        let totalLen = UInt32(1 + payload.count).bigEndian
        withUnsafeBytes(of: totalLen) { data.append(contentsOf: $0) }
        data.append(27) // SSH_AGENTC_EXTENSION
        data.append(payload)

        let message = try SSHAgentMessage.parse(data)
        guard case .extensionRequest(let parsedName, let parsedPayload) = message else {
            Issue.record("Expected extensionRequest")
            return
        }
        #expect(parsedName == "session-bind@openssh.com")
        #expect(parsedPayload == extensionPayload)
    }

    @Test("parse unsupported message type")
    func parseUnsupported() throws {
        var data = Data()
        let length = UInt32(1).bigEndian
        withUnsafeBytes(of: length) { data.append(contentsOf: $0) }
        data.append(99) // Unknown type
        let message = try SSHAgentMessage.parse(data)
        #expect(message == .unsupported(type: 99))
    }

    @Test("parse throws on empty data")
    func parseTooShort() {
        #expect(throws: SSHAgentError.messageTooShort) {
            try SSHAgentMessage.parse(Data())
        }
    }

    @Test("parse throws when length exceeds available data")
    func parseLengthMismatch() {
        var data = Data()
        // Claim length of 100 but only provide 1 byte of payload
        let length = UInt32(100).bigEndian
        withUnsafeBytes(of: length) { data.append(contentsOf: $0) }
        data.append(11)
        #expect(throws: SSHAgentError.messageTooShort) {
            try SSHAgentMessage.parse(data)
        }
    }

    @Test("serialize IDENTITIES_ANSWER with no keys")
    func serializeEmptyIdentities() throws {
        let response = SSHAgentResponse.identitiesAnswer(keys: [])
        let data = response.serialize()
        // 4-byte length + 1-byte type (12) + 4-byte count (0)
        #expect(data.count == 9)
        #expect(data[4] == 12) // SSH2_AGENT_IDENTITIES_ANSWER
    }

    @Test("serialize IDENTITIES_ANSWER with one key")
    func serializeOneIdentity() throws {
        let keyBlob = Data("blob".utf8)
        let comment = "test-key"
        let response = SSHAgentResponse.identitiesAnswer(keys: [(keyBlob, comment)])
        let data = response.serialize()
        #expect(data[4] == 12) // SSH2_AGENT_IDENTITIES_ANSWER
        // count should be 1
        let countBytes = data[5..<9]
        let count = countBytes.withUnsafeBytes { $0.loadUnaligned(as: UInt32.self).bigEndian }
        #expect(count == 1)
    }

    @Test("serialize FAILURE response")
    func serializeFailure() throws {
        let response = SSHAgentResponse.failure
        let data = response.serialize()
        // 4-byte length (1) + 1-byte type (5)
        #expect(data.count == 5)
        #expect(data[4] == 5) // SSH_AGENT_FAILURE
    }

    @Test("serialize SUCCESS response")
    func serializeSuccess() throws {
        let response = SSHAgentResponse.success
        let data = response.serialize()
        // 4-byte length (1) + 1-byte type (6)
        #expect(data.count == 5)
        #expect(data[4] == 6) // SSH_AGENT_SUCCESS
    }

    @Test("serialize SIGN_RESPONSE")
    func serializeSignResponse() throws {
        let signature = Data("sig".utf8)
        let response = SSHAgentResponse.signResponse(signature: signature)
        let data = response.serialize()
        #expect(data[4] == 14) // SSH2_AGENT_SIGN_RESPONSE
    }
}
