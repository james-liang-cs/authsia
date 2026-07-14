import Foundation

// MARK: - SSH Agent Messages

public enum SSHAgentMessage: Equatable {
    case requestIdentities                              // type 11
    case signRequest(keyBlob: Data, data: Data, flags: UInt32) // type 13
    case addIdentity                                    // type 17
    case removeIdentity                                 // type 18
    case extensionRequest(name: String, payload: Data)  // type 27
    case unsupported(type: UInt8)

    // MARK: - Parsing

    /// Parses a raw SSH agent wire-protocol message.
    ///
    /// The wire format is: 4-byte big-endian length prefix, followed by
    /// a 1-byte message type and the payload.
    public static func parse(_ data: Data) throws -> SSHAgentMessage {
        guard data.count >= 5 else {
            throw SSHAgentError.messageTooShort
        }
        let length = data.prefix(4).withUnsafeBytes {
            $0.loadUnaligned(as: UInt32.self).bigEndian
        }
        guard data.count >= 4 + Int(length) else {
            throw SSHAgentError.messageTooShort
        }
        let type = data[4]

        switch type {
        case 11:
            return .requestIdentities
        case 13:
            return try parseSignRequest(data.dropFirst(5))
        case 17:
            return .addIdentity
        case 18:
            return .removeIdentity
        case 27:
            return try parseExtensionRequest(data.dropFirst(5))
        default:
            return .unsupported(type: type)
        }
    }

    private static func parseSignRequest(_ payload: Data) throws -> SSHAgentMessage {
        var offset = payload.startIndex

        let keyBlob = try readSSHString(from: payload, at: &offset)
        let signData = try readSSHString(from: payload, at: &offset)

        var flags: UInt32 = 0
        if offset + 4 <= payload.endIndex {
            flags = payload[offset..<offset + 4].withUnsafeBytes {
                $0.loadUnaligned(as: UInt32.self).bigEndian
            }
        }

        return .signRequest(keyBlob: keyBlob, data: signData, flags: flags)
    }

    private static func parseExtensionRequest(_ payload: Data) throws -> SSHAgentMessage {
        var offset = payload.startIndex
        let nameData = try readSSHString(from: payload, at: &offset)
        guard let name = String(data: nameData, encoding: .utf8) else {
            throw SSHAgentError.malformedMessage
        }
        return .extensionRequest(name: name, payload: Data(payload[offset...]))
    }

    private static func readSSHString(
        from data: Data,
        at offset: inout Data.Index
    ) throws -> Data {
        guard offset + 4 <= data.endIndex else {
            throw SSHAgentError.malformedMessage
        }
        let length = Int(data[offset..<offset + 4].withUnsafeBytes {
            $0.loadUnaligned(as: UInt32.self).bigEndian
        })
        offset += 4
        guard offset + length <= data.endIndex else {
            throw SSHAgentError.malformedMessage
        }
        let result = data[offset..<offset + length]
        offset += length
        return Data(result)
    }
}

// MARK: - SSH Agent Responses

public enum SSHAgentResponse {
    case identitiesAnswer(keys: [(blob: Data, comment: String)])  // type 12
    case signResponse(signature: Data)                             // type 14
    case success                                                   // type 6
    case failure                                                   // type 5

    // MARK: - Serialization

    /// Serializes the response into SSH agent wire-protocol format.
    ///
    /// Returns a `Data` value with a 4-byte big-endian length prefix
    /// followed by the message type byte and payload.
    public func serialize() -> Data {
        var body = Data()

        switch self {
        case .identitiesAnswer(let keys):
            body.append(12) // SSH2_AGENT_IDENTITIES_ANSWER
            appendUInt32(&body, UInt32(keys.count))
            for (blob, comment) in keys {
                appendSSHString(&body, blob)
                appendSSHString(&body, Data(comment.utf8))
            }
        case .signResponse(let signature):
            body.append(14) // SSH2_AGENT_SIGN_RESPONSE
            appendSSHString(&body, signature)
        case .success:
            body.append(6)
        case .failure:
            body.append(5)
        }

        var result = Data()
        appendUInt32(&result, UInt32(body.count))
        result.append(body)
        return result
    }

    private func appendUInt32(_ data: inout Data, _ value: UInt32) {
        var bigEndian = value.bigEndian
        withUnsafeBytes(of: &bigEndian) { data.append(contentsOf: $0) }
    }

    private func appendSSHString(_ data: inout Data, _ value: Data) {
        appendUInt32(&data, UInt32(value.count))
        data.append(value)
    }
}

// MARK: - Errors

public enum SSHAgentError: Error, LocalizedError {
    case messageTooShort
    case malformedMessage

    public var errorDescription: String? {
        switch self {
        case .messageTooShort:
            return "SSH agent message is too short to contain a valid header"
        case .malformedMessage:
            return "SSH agent message payload is malformed"
        }
    }
}
