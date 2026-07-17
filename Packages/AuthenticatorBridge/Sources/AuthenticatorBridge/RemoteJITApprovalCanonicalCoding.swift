import CryptoKit
import Foundation

public enum RemoteJITApprovalCanonicalCoding {
    private static let descriptorDomain = Data(
        "Authsia.RemoteJITApproval.Descriptor.V1\0".utf8
    )
    private static let requestEnvelopeDomain = Data(
        "Authsia.RemoteJITApproval.RequestEnvelope.V1\0".utf8
    )
    private static let decisionEnvelopeDomain = Data(
        "Authsia.RemoteJITApproval.DecisionEnvelope.V1\0".utf8
    )
    private static let maximumDescriptorBytes = 1_000_000
    private static let maximumEnvelopeBytes = 1_048_576

    public static func encodeDescriptor(
        _ descriptor: RemoteJITApprovalDescriptor
    ) throws -> Data {
        var writer = CanonicalWriter()
        writer.append(descriptorDomain)
        writer.append(RemoteJITApprovalDescriptor.schemaVersion)
        writer.append(RemoteJITApprovalDescriptor.protocolVersion)
        writer.append(descriptor.approvalID)
        writer.append(descriptor.approvalNonce)
        writer.append(descriptor.bridgeRequestID)
        writer.append(descriptor.pairingGenerationID)
        writer.append(descriptor.macDeviceID)
        writer.append(descriptor.iphoneDeviceID)
        writer.append(descriptor.macSigningKeyFingerprint)
        writer.append(descriptor.iphoneSigningKeyFingerprint)
        writer.append(descriptor.requestIssuedAtMilliseconds)
        writer.append(descriptor.requestExpiresAtMilliseconds)
        try writer.append(descriptor.callerFingerprint)
        writer.append(UInt32(descriptor.capabilities.count))
        for capability in descriptor.capabilities {
            writer.append(capability == .exec ? UInt8(0x01) : UInt8(0x02))
        }
        try writer.append(descriptor.folderScope)
        try writer.append(descriptor.environmentScope)
        writer.append(UInt32(descriptor.requestedItems.count))
        for item in descriptor.requestedItems {
            writer.append(item.kind.rawValue)
            writer.append(item.id)
            try writer.appendOptionalString(item.folderPath)
        }
        writer.append(descriptor.grantIssuedAtMilliseconds)
        writer.append(descriptor.grantExpiresAtMilliseconds)

        guard writer.data.count <= maximumDescriptorBytes else {
            throw RemoteJITApprovalValidationError.oversized
        }
        return writer.data
    }

    public static func decodeDescriptor(
        _ data: Data
    ) throws -> RemoteJITApprovalDescriptor {
        guard data.count <= maximumDescriptorBytes else {
            throw RemoteJITApprovalValidationError.oversized
        }

        var reader = CanonicalReader(data: data)
        guard try reader.readFixedData(count: descriptorDomain.count) == descriptorDomain else {
            throw RemoteJITApprovalValidationError.nonCanonical
        }
        guard try reader.readUInt16() == RemoteJITApprovalDescriptor.schemaVersion,
              try reader.readUInt16() == RemoteJITApprovalDescriptor.protocolVersion else {
            throw RemoteJITApprovalValidationError.unsupportedVersion
        }

        let approvalID = try reader.readUUID()
        let approvalNonce = try reader.readFixedData(count: 32)
        let bridgeRequestID = try reader.readUUID()
        let pairingGenerationID = try reader.readUUID()
        let macDeviceID = try reader.readUUID()
        let iphoneDeviceID = try reader.readUUID()
        let macSigningKeyFingerprint = try reader.readFixedData(count: 32)
        let iphoneSigningKeyFingerprint = try reader.readFixedData(count: 32)
        let requestIssuedAtMilliseconds = try reader.readInt64()
        let requestExpiresAtMilliseconds = try reader.readInt64()

        let callerFingerprint = AgentJITCallerFingerprint(
            processName: try reader.readString(maximumBytes: 255),
            bundleIdentifier: try reader.readOptionalString(maximumBytes: 255),
            signingTeamId: try reader.readOptionalString(maximumBytes: 255),
            signingIdentity: try reader.readOptionalString(maximumBytes: 1_024),
            parentProcessName: try reader.readOptionalString(maximumBytes: 255),
            parentBundleIdentifier: try reader.readOptionalString(maximumBytes: 255),
            hostProcessName: try reader.readOptionalString(maximumBytes: 255),
            hostBundleIdentifier: try reader.readOptionalString(maximumBytes: 255),
            sessionScope: try reader.readString(maximumBytes: 1_024),
            workingDirectory: try reader.readString(maximumBytes: 4_096)
        )

        let capabilities = try reader.readCapabilities()
        let folderScope = try reader.readFolderScope()
        let environmentScope = try reader.readEnvironmentScope()
        let requestedItems = try reader.readItems()
        let grantIssuedAtMilliseconds = try reader.readInt64()
        let grantExpiresAtMilliseconds = try reader.readInt64()
        guard reader.isAtEnd else {
            throw RemoteJITApprovalValidationError.nonCanonical
        }

        let descriptor = try RemoteJITApprovalDescriptor(
            approvalID: approvalID,
            approvalNonce: approvalNonce,
            bridgeRequestID: bridgeRequestID,
            pairingGenerationID: pairingGenerationID,
            macDeviceID: macDeviceID,
            iphoneDeviceID: iphoneDeviceID,
            macSigningKeyFingerprint: macSigningKeyFingerprint,
            iphoneSigningKeyFingerprint: iphoneSigningKeyFingerprint,
            requestIssuedAtMilliseconds: requestIssuedAtMilliseconds,
            requestExpiresAtMilliseconds: requestExpiresAtMilliseconds,
            callerFingerprint: callerFingerprint,
            capabilities: capabilities,
            folderScope: folderScope,
            environmentScope: environmentScope,
            requestedItems: requestedItems,
            grantIssuedAtMilliseconds: grantIssuedAtMilliseconds,
            grantExpiresAtMilliseconds: grantExpiresAtMilliseconds
        )
        guard try encodeDescriptor(descriptor) == data else {
            throw RemoteJITApprovalValidationError.nonCanonical
        }
        return descriptor
    }

    public static func encodeRequest(
        _ request: RemoteJITApprovalRequest
    ) throws -> Data {
        let descriptorBytes = try encodeDescriptor(request.descriptor)
        let digest = descriptorDigest(descriptorBytes)
        guard request.requestDigest == digest else {
            throw RemoteJITApprovalValidationError.inconsistentBinding
        }

        var writer = CanonicalWriter()
        writer.append(requestEnvelopeDomain)
        writer.append(UInt32(descriptorBytes.count))
        writer.append(descriptorBytes)
        writer.append(digest)
        writer.append(request.requestSignature)
        guard writer.data.count <= maximumEnvelopeBytes else {
            throw RemoteJITApprovalValidationError.oversized
        }
        return writer.data
    }

    public static func decodeRequest(
        _ data: Data
    ) throws -> RemoteJITApprovalRequest {
        guard data.count <= maximumEnvelopeBytes else {
            throw RemoteJITApprovalValidationError.oversized
        }

        var reader = CanonicalReader(data: data)
        guard try reader.readFixedData(count: requestEnvelopeDomain.count) == requestEnvelopeDomain else {
            throw RemoteJITApprovalValidationError.nonCanonical
        }
        let descriptorLength = try reader.readBoundedLength(maximum: maximumDescriptorBytes)
        let descriptorBytes = try reader.readFixedData(count: descriptorLength)
        let descriptor = try decodeDescriptor(descriptorBytes)
        let encodedDigest = try reader.readFixedData(count: 32)
        let requestSignature = try reader.readFixedData(count: 64)
        guard reader.isAtEnd else {
            throw RemoteJITApprovalValidationError.nonCanonical
        }
        guard descriptorDigest(descriptorBytes) == encodedDigest else {
            throw RemoteJITApprovalValidationError.inconsistentBinding
        }

        let request = try RemoteJITApprovalRequest(
            descriptor: descriptor,
            requestDigest: encodedDigest,
            requestSignature: requestSignature
        )
        guard try encodeRequest(request) == data else {
            throw RemoteJITApprovalValidationError.nonCanonical
        }
        return request
    }

    public static func encodeDecision(
        _ decision: RemoteJITApprovalDecision
    ) throws -> Data {
        var writer = CanonicalWriter()
        writer.append(decisionEnvelopeDomain)
        writer.append(try unsignedDecisionBytes(decision.payload))
        writer.append(decision.decisionSignature)
        guard writer.data.count <= maximumEnvelopeBytes else {
            throw RemoteJITApprovalValidationError.oversized
        }
        return writer.data
    }

    public static func decodeDecision(
        _ data: Data
    ) throws -> RemoteJITApprovalDecision {
        guard data.count <= maximumEnvelopeBytes else {
            throw RemoteJITApprovalValidationError.oversized
        }

        var reader = CanonicalReader(data: data)
        guard try reader.readFixedData(count: decisionEnvelopeDomain.count) == decisionEnvelopeDomain else {
            throw RemoteJITApprovalValidationError.nonCanonical
        }
        guard try reader.readUInt16() == RemoteJITApprovalDescriptor.schemaVersion,
              try reader.readUInt16() == RemoteJITApprovalDescriptor.protocolVersion else {
            throw RemoteJITApprovalValidationError.unsupportedVersion
        }
        let approvalID = try reader.readUUID()
        let approvalNonce = try reader.readFixedData(count: 32)
        let requestDigest = try reader.readFixedData(count: 32)
        let pairingGenerationID = try reader.readUUID()
        let macDeviceID = try reader.readUUID()
        let iphoneDeviceID = try reader.readUUID()
        guard let value = RemoteJITApprovalDecisionValue(rawValue: try reader.readUInt8()) else {
            throw RemoteJITApprovalValidationError.nonCanonical
        }
        let requestExpiresAtMilliseconds = try reader.readInt64()
        let decisionSignature = try reader.readFixedData(count: 64)
        guard reader.isAtEnd else {
            throw RemoteJITApprovalValidationError.nonCanonical
        }

        let payload = try RemoteJITApprovalDecisionPayload(
            approvalID: approvalID,
            approvalNonce: approvalNonce,
            requestDigest: requestDigest,
            pairingGenerationID: pairingGenerationID,
            macDeviceID: macDeviceID,
            iphoneDeviceID: iphoneDeviceID,
            value: value,
            requestExpiresAtMilliseconds: requestExpiresAtMilliseconds
        )
        let decision = try RemoteJITApprovalDecision(
            payload: payload,
            decisionSignature: decisionSignature
        )
        guard try encodeDecision(decision) == data else {
            throw RemoteJITApprovalValidationError.nonCanonical
        }
        return decision
    }

    public static func unsignedDecisionBytes(
        _ payload: RemoteJITApprovalDecisionPayload
    ) throws -> Data {
        var writer = CanonicalWriter()
        writer.append(RemoteJITApprovalDescriptor.schemaVersion)
        writer.append(RemoteJITApprovalDescriptor.protocolVersion)
        writer.append(payload.approvalID)
        writer.append(payload.approvalNonce)
        writer.append(payload.requestDigest)
        writer.append(payload.pairingGenerationID)
        writer.append(payload.macDeviceID)
        writer.append(payload.iphoneDeviceID)
        writer.append(payload.value.rawValue)
        writer.append(payload.requestExpiresAtMilliseconds)
        return writer.data
    }

    static func requestDigest(
        for descriptor: RemoteJITApprovalDescriptor
    ) throws -> Data {
        descriptorDigest(try encodeDescriptor(descriptor))
    }

    private static func descriptorDigest(_ descriptorBytes: Data) -> Data {
        Data(SHA256.hash(data: descriptorBytes))
    }
}

private struct CanonicalWriter {
    private(set) var data = Data()

    mutating func append(_ value: UInt8) {
        data.append(value)
    }

    mutating func append(_ value: UInt16) {
        data.append(UInt8(truncatingIfNeeded: value >> 8))
        data.append(UInt8(truncatingIfNeeded: value))
    }

    mutating func append(_ value: UInt32) {
        data.append(UInt8(truncatingIfNeeded: value >> 24))
        data.append(UInt8(truncatingIfNeeded: value >> 16))
        data.append(UInt8(truncatingIfNeeded: value >> 8))
        data.append(UInt8(truncatingIfNeeded: value))
    }

    mutating func append(_ value: Int64) {
        let bits = UInt64(bitPattern: value)
        data.append(UInt8(truncatingIfNeeded: bits >> 56))
        data.append(UInt8(truncatingIfNeeded: bits >> 48))
        data.append(UInt8(truncatingIfNeeded: bits >> 40))
        data.append(UInt8(truncatingIfNeeded: bits >> 32))
        data.append(UInt8(truncatingIfNeeded: bits >> 24))
        data.append(UInt8(truncatingIfNeeded: bits >> 16))
        data.append(UInt8(truncatingIfNeeded: bits >> 8))
        data.append(UInt8(truncatingIfNeeded: bits))
    }

    mutating func append(_ value: UUID) {
        let bytes = value.uuid
        data.append(contentsOf: [
            bytes.0, bytes.1, bytes.2, bytes.3,
            bytes.4, bytes.5, bytes.6, bytes.7,
            bytes.8, bytes.9, bytes.10, bytes.11,
            bytes.12, bytes.13, bytes.14, bytes.15,
        ])
    }

    mutating func append(_ value: Data) {
        data.append(value)
    }

    mutating func appendString(_ value: String) throws {
        let bytes = Data(value.utf8)
        guard bytes.count <= Int(UInt32.max) else {
            throw RemoteJITApprovalValidationError.oversized
        }
        append(UInt32(bytes.count))
        append(bytes)
    }

    mutating func appendOptionalString(_ value: String?) throws {
        guard let value else {
            append(UInt8(0))
            return
        }
        append(UInt8(1))
        try appendString(value)
    }

    mutating func append(_ caller: AgentJITCallerFingerprint) throws {
        guard let sessionScope = caller.sessionScope,
              let workingDirectory = caller.workingDirectory else {
            throw RemoteJITApprovalValidationError.inconsistentBinding
        }
        try appendString(caller.processName)
        try appendOptionalString(caller.bundleIdentifier)
        try appendOptionalString(caller.signingTeamId)
        try appendOptionalString(caller.signingIdentity)
        try appendOptionalString(caller.parentProcessName)
        try appendOptionalString(caller.parentBundleIdentifier)
        try appendOptionalString(caller.hostProcessName)
        try appendOptionalString(caller.hostBundleIdentifier)
        try appendString(sessionScope)
        try appendString(workingDirectory)
    }

    mutating func append(_ scope: AgentJITFolderScope) throws {
        switch scope {
        case .root:
            append(UInt8(0))
        case .folder(let path):
            append(UInt8(1))
            try appendString(path)
        }
    }

    mutating func append(_ scope: EnvironmentAccessScope?) throws {
        switch scope {
        case nil:
            append(UInt8(0))
        case .defaultOnly:
            append(UInt8(1))
        case .named(let name):
            append(UInt8(2))
            try appendString(name)
        }
    }
}

private struct CanonicalReader {
    private let data: Data
    private var offset: Int

    init(data: Data) {
        self.data = data
        self.offset = data.startIndex
    }

    var isAtEnd: Bool {
        offset == data.endIndex
    }

    mutating func readUInt8() throws -> UInt8 {
        let bytes = try readBytes(count: 1)
        return bytes[0]
    }

    mutating func readUInt16() throws -> UInt16 {
        let bytes = try readBytes(count: 2)
        return (UInt16(bytes[0]) << 8) | UInt16(bytes[1])
    }

    mutating func readUInt32() throws -> UInt32 {
        let bytes = try readBytes(count: 4)
        return (UInt32(bytes[0]) << 24)
            | (UInt32(bytes[1]) << 16)
            | (UInt32(bytes[2]) << 8)
            | UInt32(bytes[3])
    }

    mutating func readInt64() throws -> Int64 {
        let bytes = try readBytes(count: 8)
        var bits: UInt64 = 0
        for byte in bytes {
            bits = (bits << 8) | UInt64(byte)
        }
        return Int64(bitPattern: bits)
    }

    mutating func readUUID() throws -> UUID {
        let bytes = try readBytes(count: 16)
        return UUID(uuid: (
            bytes[0], bytes[1], bytes[2], bytes[3],
            bytes[4], bytes[5], bytes[6], bytes[7],
            bytes[8], bytes[9], bytes[10], bytes[11],
            bytes[12], bytes[13], bytes[14], bytes[15]
        ))
    }

    mutating func readFixedData(count: Int) throws -> Data {
        Data(try readBytes(count: count))
    }

    mutating func readString(maximumBytes: Int) throws -> String {
        let length = try readBoundedLength(maximum: maximumBytes)
        guard length > 0 else {
            throw RemoteJITApprovalValidationError.invalidString
        }
        let bytes = try readBytes(count: length)
        guard let value = String(bytes: bytes, encoding: .utf8),
              value == value.precomposedStringWithCanonicalMapping,
              value.unicodeScalars.allSatisfy({ scalar in
                  switch scalar.properties.generalCategory {
                  case .control, .format:
                      false
                  default:
                      true
                  }
              }) else {
            throw RemoteJITApprovalValidationError.invalidString
        }
        return value
    }

    mutating func readOptionalString(maximumBytes: Int) throws -> String? {
        switch try readUInt8() {
        case 0:
            return nil
        case 1:
            return try readString(maximumBytes: maximumBytes)
        default:
            throw RemoteJITApprovalValidationError.nonCanonical
        }
    }

    mutating func readCapabilities() throws -> [AgentJITCapability] {
        let count = try readBoundedCount(maximum: 2)
        let capabilities: [AgentJITCapability] = try (0..<count).map { _ in
            switch try readUInt8() {
            case 0x01: .exec
            case 0x02: .list
            default: throw RemoteJITApprovalValidationError.nonCanonical
            }
        }
        guard capabilities == [.list] || capabilities == [.exec, .list] else {
            throw RemoteJITApprovalValidationError.nonCanonical
        }
        return capabilities
    }

    mutating func readFolderScope() throws -> AgentJITFolderScope {
        switch try readUInt8() {
        case 0:
            return .root
        case 1:
            return .folder(try readString(maximumBytes: 4_096))
        default:
            throw RemoteJITApprovalValidationError.nonCanonical
        }
    }

    mutating func readEnvironmentScope() throws -> EnvironmentAccessScope? {
        switch try readUInt8() {
        case 0:
            return nil
        case 1:
            return .defaultOnly
        case 2:
            return .named(try readString(maximumBytes: 255))
        default:
            throw RemoteJITApprovalValidationError.nonCanonical
        }
    }

    mutating func readItems() throws -> [RemoteJITApprovalItemReference] {
        let count = try readBoundedCount(maximum: 1_024)
        guard count > 0 else {
            throw RemoteJITApprovalValidationError.invalidItems
        }
        var items: [RemoteJITApprovalItemReference] = []
        items.reserveCapacity(count)
        var itemIDs = Set<UUID>()
        var previousSortKey: [UInt8]?
        for _ in 0..<count {
            guard let kind = RemoteJITApprovalItemKind(rawValue: try readUInt8()) else {
                throw RemoteJITApprovalValidationError.nonCanonical
            }
            let id = try readUUID()
            let folderMarker = try readUInt8()
            let folderPath: String?
            switch folderMarker {
            case 0:
                folderPath = nil
            case 1:
                folderPath = try readString(maximumBytes: 4_096)
            default:
                throw RemoteJITApprovalValidationError.nonCanonical
            }

            guard itemIDs.insert(id).inserted else {
                throw RemoteJITApprovalValidationError.duplicateItem
            }
            let sortKey = [kind.rawValue]
                + uuidBytes(id)
                + [folderMarker]
                + (folderPath.map { Array($0.utf8) } ?? [])
            if let previousSortKey,
               !previousSortKey.lexicographicallyPrecedes(sortKey) {
                throw RemoteJITApprovalValidationError.nonCanonical
            }
            previousSortKey = sortKey
            items.append(try RemoteJITApprovalItemReference(
                id: id,
                kind: kind,
                folderPath: folderPath
            ))
        }
        return items
    }

    mutating func readBoundedLength(maximum: Int) throws -> Int {
        let encoded = try readUInt32()
        guard encoded <= UInt32(maximum) else {
            throw RemoteJITApprovalValidationError.oversized
        }
        return Int(encoded)
    }

    private mutating func readBoundedCount(maximum: Int) throws -> Int {
        let encoded = try readUInt32()
        guard encoded <= UInt32(maximum) else {
            throw RemoteJITApprovalValidationError.oversized
        }
        return Int(encoded)
    }

    private mutating func readBytes(count: Int) throws -> [UInt8] {
        guard count >= 0, count <= data.endIndex - offset else {
            throw RemoteJITApprovalValidationError.invalidLength
        }
        let end = offset + count
        let bytes = Array(data[offset..<end])
        offset = end
        return bytes
    }

    private func uuidBytes(_ value: UUID) -> [UInt8] {
        let bytes = value.uuid
        return [
            bytes.0, bytes.1, bytes.2, bytes.3,
            bytes.4, bytes.5, bytes.6, bytes.7,
            bytes.8, bytes.9, bytes.10, bytes.11,
            bytes.12, bytes.13, bytes.14, bytes.15,
        ]
    }
}
