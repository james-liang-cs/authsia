import Foundation

public enum RemoteJITApprovalValidationError: Error, Equatable, Sendable {
    case unsupportedVersion
    case invalidLength
    case invalidString
    case invalidPath
    case invalidTime
    case invalidCapabilities
    case invalidScope
    case invalidEnvironment
    case invalidItems
    case duplicateItem
    case inconsistentBinding
    case oversized
    case nonCanonical
}

public enum RemoteJITApprovalItemKind: UInt8, CaseIterable, Sendable {
    case password = 0x01
    case apiKey = 0x02
    case certificate = 0x03
    case note = 0x04
    case ssh = 0x05
}

public struct RemoteJITApprovalItemReference: Equatable, Sendable {
    public let id: UUID
    public let kind: RemoteJITApprovalItemKind
    public let folderPath: String?

    public init(
        id: UUID,
        kind: RemoteJITApprovalItemKind,
        folderPath: String?
    ) throws {
        let normalizedFolder: String?
        if let folderPath {
            guard let value = try normalizedRemoteFolderPath(folderPath) else {
                throw RemoteJITApprovalValidationError.invalidPath
            }
            normalizedFolder = value
        } else {
            normalizedFolder = nil
        }

        self.id = id
        self.kind = kind
        self.folderPath = normalizedFolder
    }
}

public enum RemoteJITApprovalDecisionValue: UInt8, Sendable {
    case approve = 0x01
    case deny = 0x02
}

public struct RemoteJITApprovalPairingBinding: Equatable, Sendable {
    public let pairingGenerationID: UUID
    public let macDeviceID: UUID
    public let iphoneDeviceID: UUID
    public let macSigningKeyFingerprint: Data
    public let iphoneSigningKeyFingerprint: Data

    public init(
        pairingGenerationID: UUID,
        macDeviceID: UUID,
        iphoneDeviceID: UUID,
        macSigningKeyFingerprint: Data,
        iphoneSigningKeyFingerprint: Data
    ) throws {
        guard macSigningKeyFingerprint.count == 32,
              iphoneSigningKeyFingerprint.count == 32 else {
            throw RemoteJITApprovalValidationError.invalidLength
        }
        self.pairingGenerationID = pairingGenerationID
        self.macDeviceID = macDeviceID
        self.iphoneDeviceID = iphoneDeviceID
        self.macSigningKeyFingerprint = macSigningKeyFingerprint
        self.iphoneSigningKeyFingerprint = iphoneSigningKeyFingerprint
    }
}

public struct RemoteJITApprovalPairedIPhoneSource: Equatable, Sendable {
    public let pairingGenerationID: UUID
    public let signingKeyFingerprint: Data

    public init(
        pairingGenerationID: UUID,
        signingKeyFingerprint: Data
    ) throws {
        guard signingKeyFingerprint.count == 32 else {
            throw RemoteJITApprovalValidationError.invalidLength
        }
        self.pairingGenerationID = pairingGenerationID
        self.signingKeyFingerprint = signingKeyFingerprint
    }
}

public enum RemoteJITApprovalSource: Equatable, Sendable {
    case macBiometric
    case macPanel
    case pairedIPhone(RemoteJITApprovalPairedIPhoneSource)
}

public enum RemoteJITApprovalOutcome: Equatable, Sendable {
    case approved(source: RemoteJITApprovalSource)
    case denied(source: RemoteJITApprovalSource)
    case superseded
    case timedOut
}

public struct RemoteJITApprovalDescriptor: Equatable, Sendable {
    public static let schemaVersion: UInt16 = 1
    public static let protocolVersion: UInt16 = 1
    public static let requestLifetimeMilliseconds: Int64 = 90_000

    public let approvalID: UUID
    public let approvalNonce: Data
    public let bridgeRequestID: UUID
    public let pairingGenerationID: UUID
    public let macDeviceID: UUID
    public let iphoneDeviceID: UUID
    public let macSigningKeyFingerprint: Data
    public let iphoneSigningKeyFingerprint: Data
    public let requestIssuedAtMilliseconds: Int64
    public let requestExpiresAtMilliseconds: Int64
    public let callerFingerprint: AgentJITCallerFingerprint
    public let capabilities: [AgentJITCapability]
    public let folderScope: AgentJITFolderScope
    public let environmentScope: EnvironmentAccessScope?
    public let requestedItems: [RemoteJITApprovalItemReference]
    public let grantIssuedAtMilliseconds: Int64
    public let grantExpiresAtMilliseconds: Int64

    public init(
        approvalID: UUID,
        approvalNonce: Data,
        bridgeRequestID: UUID,
        pairingGenerationID: UUID,
        macDeviceID: UUID,
        iphoneDeviceID: UUID,
        macSigningKeyFingerprint: Data,
        iphoneSigningKeyFingerprint: Data,
        requestIssuedAtMilliseconds: Int64,
        requestExpiresAtMilliseconds: Int64,
        callerFingerprint: AgentJITCallerFingerprint,
        capabilities: [AgentJITCapability],
        folderScope: AgentJITFolderScope,
        environmentScope: EnvironmentAccessScope?,
        requestedItems: [RemoteJITApprovalItemReference],
        grantIssuedAtMilliseconds: Int64,
        grantExpiresAtMilliseconds: Int64
    ) throws {
        guard approvalNonce.count == 32,
              macSigningKeyFingerprint.count == 32,
              iphoneSigningKeyFingerprint.count == 32 else {
            throw RemoteJITApprovalValidationError.invalidLength
        }
        try validateDescriptorTimes(
            requestIssuedAtMilliseconds: requestIssuedAtMilliseconds,
            requestExpiresAtMilliseconds: requestExpiresAtMilliseconds,
            grantIssuedAtMilliseconds: grantIssuedAtMilliseconds,
            grantExpiresAtMilliseconds: grantExpiresAtMilliseconds
        )

        let normalizedCaller = try normalizedRemoteCallerFingerprint(callerFingerprint)
        let normalizedCapabilities = try normalizedRemoteCapabilities(capabilities)
        let normalizedFolderScope = try normalizedRemoteFolderScope(folderScope)
        let normalizedEnvironmentScope = try normalizedRemoteEnvironmentScope(environmentScope)
        let normalizedItems = try normalizedRemoteItems(
            requestedItems,
            folderScope: normalizedFolderScope,
            capabilities: normalizedCapabilities
        )

        self.approvalID = approvalID
        self.approvalNonce = approvalNonce
        self.bridgeRequestID = bridgeRequestID
        self.pairingGenerationID = pairingGenerationID
        self.macDeviceID = macDeviceID
        self.iphoneDeviceID = iphoneDeviceID
        self.macSigningKeyFingerprint = macSigningKeyFingerprint
        self.iphoneSigningKeyFingerprint = iphoneSigningKeyFingerprint
        self.requestIssuedAtMilliseconds = requestIssuedAtMilliseconds
        self.requestExpiresAtMilliseconds = requestExpiresAtMilliseconds
        self.callerFingerprint = normalizedCaller
        self.capabilities = normalizedCapabilities
        self.folderScope = normalizedFolderScope
        self.environmentScope = normalizedEnvironmentScope
        self.requestedItems = normalizedItems
        self.grantIssuedAtMilliseconds = grantIssuedAtMilliseconds
        self.grantExpiresAtMilliseconds = grantExpiresAtMilliseconds
    }

    var workspaceLabel: String {
        guard let path = callerFingerprint.workingDirectory, path != "/" else {
            return "/"
        }
        return String(path.split(separator: "/").last ?? "/")
    }
}

public struct RemoteJITApprovalRequest: Equatable, Sendable {
    public let descriptor: RemoteJITApprovalDescriptor
    public let requestDigest: Data
    public let requestSignature: Data

    public init(
        descriptor: RemoteJITApprovalDescriptor,
        requestDigest: Data,
        requestSignature: Data
    ) throws {
        guard requestDigest.count == 32, requestSignature.count == 64 else {
            throw RemoteJITApprovalValidationError.invalidLength
        }
        self.descriptor = descriptor
        self.requestDigest = requestDigest
        self.requestSignature = requestSignature
    }
}

public struct RemoteJITApprovalDecisionPayload: Equatable, Sendable {
    public let approvalID: UUID
    public let approvalNonce: Data
    public let requestDigest: Data
    public let pairingGenerationID: UUID
    public let macDeviceID: UUID
    public let iphoneDeviceID: UUID
    public let value: RemoteJITApprovalDecisionValue
    public let requestExpiresAtMilliseconds: Int64

    public init(
        approvalID: UUID,
        approvalNonce: Data,
        requestDigest: Data,
        pairingGenerationID: UUID,
        macDeviceID: UUID,
        iphoneDeviceID: UUID,
        value: RemoteJITApprovalDecisionValue,
        requestExpiresAtMilliseconds: Int64
    ) throws {
        guard approvalNonce.count == 32, requestDigest.count == 32 else {
            throw RemoteJITApprovalValidationError.invalidLength
        }
        try validateRemoteTime(requestExpiresAtMilliseconds)
        self.approvalID = approvalID
        self.approvalNonce = approvalNonce
        self.requestDigest = requestDigest
        self.pairingGenerationID = pairingGenerationID
        self.macDeviceID = macDeviceID
        self.iphoneDeviceID = iphoneDeviceID
        self.value = value
        self.requestExpiresAtMilliseconds = requestExpiresAtMilliseconds
    }
}

public struct RemoteJITApprovalDecision: Equatable, Sendable {
    public let payload: RemoteJITApprovalDecisionPayload
    public let decisionSignature: Data

    public init(
        payload: RemoteJITApprovalDecisionPayload,
        decisionSignature: Data
    ) throws {
        guard decisionSignature.count == 64 else {
            throw RemoteJITApprovalValidationError.invalidLength
        }
        self.payload = payload
        self.decisionSignature = decisionSignature
    }
}

private let maximumRemoteTimestamp: Int64 = 253_402_300_799_999
private let maximumRemoteGrantLifetime: Int64 = 86_400_000
private let maximumRemoteItemCount = 1_024
private let maximumRemoteRawStringBytes = 1_048_576

private func validateDescriptorTimes(
    requestIssuedAtMilliseconds: Int64,
    requestExpiresAtMilliseconds: Int64,
    grantIssuedAtMilliseconds: Int64,
    grantExpiresAtMilliseconds: Int64
) throws {
    try validateRemoteTime(requestIssuedAtMilliseconds)
    try validateRemoteTime(requestExpiresAtMilliseconds)
    try validateRemoteTime(grantIssuedAtMilliseconds)
    try validateRemoteTime(grantExpiresAtMilliseconds)

    let (expectedRequestExpiry, requestOverflow) = requestIssuedAtMilliseconds.addingReportingOverflow(
        RemoteJITApprovalDescriptor.requestLifetimeMilliseconds
    )
    let (grantLifetime, grantOverflow) = grantExpiresAtMilliseconds.subtractingReportingOverflow(
        grantIssuedAtMilliseconds
    )
    guard !requestOverflow,
          !grantOverflow,
          requestExpiresAtMilliseconds == expectedRequestExpiry,
          grantIssuedAtMilliseconds == requestIssuedAtMilliseconds,
          (1...maximumRemoteGrantLifetime).contains(grantLifetime) else {
        throw RemoteJITApprovalValidationError.invalidTime
    }
}

private func validateRemoteTime(_ value: Int64) throws {
    guard (0...maximumRemoteTimestamp).contains(value) else {
        throw RemoteJITApprovalValidationError.invalidTime
    }
}

private func normalizedRemoteCallerFingerprint(
    _ caller: AgentJITCallerFingerprint
) throws -> AgentJITCallerFingerprint {
    let processName = try normalizedRemoteString(caller.processName, maximumBytes: 255)
    let bundleIdentifier = try normalizedRemoteOptionalString(caller.bundleIdentifier, maximumBytes: 255)
    let signingTeamID = try normalizedRemoteOptionalString(caller.signingTeamId, maximumBytes: 255)
    let signingIdentity = try normalizedRemoteOptionalString(caller.signingIdentity, maximumBytes: 1_024)
    let parentProcessName = try normalizedRemoteOptionalString(caller.parentProcessName, maximumBytes: 255)
    let parentBundleIdentifier = try normalizedRemoteOptionalString(caller.parentBundleIdentifier, maximumBytes: 255)
    let hostProcessName = try normalizedRemoteOptionalString(caller.hostProcessName, maximumBytes: 255)
    let hostBundleIdentifier = try normalizedRemoteOptionalString(caller.hostBundleIdentifier, maximumBytes: 255)
    guard let sessionScope = caller.sessionScope else {
        throw RemoteJITApprovalValidationError.invalidString
    }
    guard let workingDirectory = caller.workingDirectory else {
        throw RemoteJITApprovalValidationError.invalidPath
    }

    return AgentJITCallerFingerprint(
        processName: processName,
        bundleIdentifier: bundleIdentifier,
        signingTeamId: signingTeamID,
        signingIdentity: signingIdentity,
        parentProcessName: parentProcessName,
        parentBundleIdentifier: parentBundleIdentifier,
        hostProcessName: hostProcessName,
        hostBundleIdentifier: hostBundleIdentifier,
        sessionScope: try normalizedRemoteString(sessionScope, maximumBytes: 1_024),
        workingDirectory: try normalizedRemoteWorkingDirectory(workingDirectory)
    )
}

private func normalizedRemoteString(_ value: String, maximumBytes: Int) throws -> String {
    try validateRemoteRawStringInput(value)
    let normalized = value.precomposedStringWithCanonicalMapping
    guard !normalized.isEmpty, isSafeRemoteString(normalized) else {
        throw RemoteJITApprovalValidationError.invalidString
    }
    guard normalized.utf8.count <= maximumBytes else {
        throw RemoteJITApprovalValidationError.oversized
    }
    return normalized
}

private func normalizedRemoteOptionalString(
    _ value: String?,
    maximumBytes: Int
) throws -> String? {
    guard let value else { return nil }
    return try normalizedRemoteString(value, maximumBytes: maximumBytes)
}

private func isSafeRemoteString(_ value: String) -> Bool {
    value.unicodeScalars.allSatisfy { scalar in
        switch scalar.properties.generalCategory {
        case .control, .format:
            false
        default:
            true
        }
    }
}

func normalizedRemoteEnvironmentName(_ value: String) throws -> String {
    try validateRemoteRawStringInput(value)
    let trimmed = stringByTrimmingScalars(value, where: isASCIIWhitespace)
        .precomposedStringWithCanonicalMapping
    guard !trimmed.isEmpty, isSafeRemoteString(trimmed) else {
        throw RemoteJITApprovalValidationError.invalidEnvironment
    }
    guard trimmed.utf8.count <= 255 else {
        throw RemoteJITApprovalValidationError.oversized
    }
    return trimmed
}

private func normalizedRemoteEnvironmentScope(
    _ scope: EnvironmentAccessScope?
) throws -> EnvironmentAccessScope? {
    switch scope {
    case nil:
        return nil
    case .defaultOnly:
        return .defaultOnly
    case .named(let name):
        return .named(try normalizedRemoteEnvironmentName(name))
    }
}

private func normalizedRemoteFolderScope(
    _ scope: AgentJITFolderScope
) throws -> AgentJITFolderScope {
    switch scope {
    case .root:
        return .root
    case .folder(let path):
        guard let normalized = try normalizedRemoteFolderPath(path) else {
            throw RemoteJITApprovalValidationError.invalidScope
        }
        return .folder(normalized)
    }
}

private func normalizedRemoteCapabilities(
    _ capabilities: [AgentJITCapability]
) throws -> [AgentJITCapability] {
    guard capabilities.count <= 2 else {
        throw RemoteJITApprovalValidationError.invalidCapabilities
    }
    guard Set(capabilities).count == capabilities.count else {
        throw RemoteJITApprovalValidationError.invalidCapabilities
    }
    let values = Set(capabilities)
    guard values == [.list] || values == [.exec, .list] else {
        throw RemoteJITApprovalValidationError.invalidCapabilities
    }
    return capabilities.sorted { capabilityTag($0) < capabilityTag($1) }
}

private func capabilityTag(_ capability: AgentJITCapability) -> UInt8 {
    switch capability {
    case .exec: 0x01
    case .list: 0x02
    }
}

private func normalizedRemoteItems(
    _ items: [RemoteJITApprovalItemReference],
    folderScope: AgentJITFolderScope,
    capabilities: [AgentJITCapability]
) throws -> [RemoteJITApprovalItemReference] {
    guard !items.isEmpty else {
        throw RemoteJITApprovalValidationError.invalidItems
    }
    guard items.count <= maximumRemoteItemCount else {
        throw RemoteJITApprovalValidationError.oversized
    }

    var itemIDs = Set<UUID>()
    for item in items {
        guard itemIDs.insert(item.id).inserted else {
            throw RemoteJITApprovalValidationError.duplicateItem
        }
        guard remoteFolderScope(folderScope, contains: item.folderPath) else {
            throw RemoteJITApprovalValidationError.invalidItems
        }
        if item.kind == .ssh, capabilities.contains(.exec) {
            throw RemoteJITApprovalValidationError.invalidItems
        }
    }

    return items.sorted(by: remoteItemPrecedes)
}

private func remoteFolderScope(
    _ scope: AgentJITFolderScope,
    contains itemFolderPath: String?
) -> Bool {
    switch scope {
    case .root:
        return itemFolderPath == nil
    case .folder(let path):
        guard let itemFolderPath else { return false }
        return itemFolderPath == path || itemFolderPath.hasPrefix(path + "/")
    }
}

private func remoteItemPrecedes(
    _ lhs: RemoteJITApprovalItemReference,
    _ rhs: RemoteJITApprovalItemReference
) -> Bool {
    if lhs.kind.rawValue != rhs.kind.rawValue {
        return lhs.kind.rawValue < rhs.kind.rawValue
    }
    let lhsUUID = remoteUUIDBytes(lhs.id)
    let rhsUUID = remoteUUIDBytes(rhs.id)
    if lhsUUID != rhsUUID {
        return lhsUUID.lexicographicallyPrecedes(rhsUUID)
    }
    let lhsFolder = remoteOptionalFolderBytes(lhs.folderPath)
    let rhsFolder = remoteOptionalFolderBytes(rhs.folderPath)
    return lhsFolder.lexicographicallyPrecedes(rhsFolder)
}

private func remoteUUIDBytes(_ value: UUID) -> [UInt8] {
    let uuid = value.uuid
    return [
        uuid.0, uuid.1, uuid.2, uuid.3,
        uuid.4, uuid.5, uuid.6, uuid.7,
        uuid.8, uuid.9, uuid.10, uuid.11,
        uuid.12, uuid.13, uuid.14, uuid.15,
    ]
}

private func remoteOptionalFolderBytes(_ value: String?) -> [UInt8] {
    guard let value else { return [0] }
    return [1] + Array(value.utf8)
}

private func normalizedRemoteFolderPath(_ value: String) throws -> String? {
    try validateRemoteRawStringInput(value)
    var components: [String] = []
    for rawComponent in value.split(separator: "/", omittingEmptySubsequences: false) {
        let trimmed = stringByTrimmingScalars(String(rawComponent), where: isFolderTrimScalar)
        guard !trimmed.isEmpty else { continue }
        let normalized = trimmed.precomposedStringWithCanonicalMapping
        guard isSafeRemoteString(normalized) else {
            throw RemoteJITApprovalValidationError.invalidPath
        }
        components.append(normalized)
    }
    guard !components.isEmpty else { return nil }
    let normalized = components.joined(separator: "/")
    guard normalized.utf8.count <= 4_096 else {
        throw RemoteJITApprovalValidationError.oversized
    }
    return normalized
}

private func normalizedRemoteWorkingDirectory(_ value: String) throws -> String {
    try validateRemoteRawStringInput(value)
    guard value.hasPrefix("/") else {
        throw RemoteJITApprovalValidationError.invalidPath
    }
    var components: [String] = []
    for rawComponent in value.split(separator: "/", omittingEmptySubsequences: false) {
        switch rawComponent {
        case "", ".":
            continue
        case "..":
            guard !components.isEmpty else {
                throw RemoteJITApprovalValidationError.invalidPath
            }
            components.removeLast()
        default:
            let normalized = String(rawComponent).precomposedStringWithCanonicalMapping
            guard isSafeRemoteString(normalized) else {
                throw RemoteJITApprovalValidationError.invalidPath
            }
            components.append(normalized)
        }
    }
    let normalized = components.isEmpty ? "/" : "/" + components.joined(separator: "/")
    guard normalized.utf8.count <= 4_096 else {
        throw RemoteJITApprovalValidationError.oversized
    }
    return normalized
}

private func validateRemoteRawStringInput(_ value: String) throws {
    var byteCount = 0
    for _ in value.utf8 {
        byteCount += 1
        guard byteCount <= maximumRemoteRawStringBytes else {
            throw RemoteJITApprovalValidationError.oversized
        }
    }
}

private func stringByTrimmingScalars(
    _ value: String,
    where shouldTrim: (Unicode.Scalar) -> Bool
) -> String {
    let scalars = Array(value.unicodeScalars)
    var lowerBound = scalars.startIndex
    var upperBound = scalars.endIndex
    while lowerBound < upperBound, shouldTrim(scalars[lowerBound]) {
        lowerBound += 1
    }
    while upperBound > lowerBound, shouldTrim(scalars[upperBound - 1]) {
        upperBound -= 1
    }
    var result = String.UnicodeScalarView()
    result.append(contentsOf: scalars[lowerBound..<upperBound])
    return String(result)
}

private func isASCIIWhitespace(_ scalar: Unicode.Scalar) -> Bool {
    scalar.value == 0x20 || (0x09...0x0D).contains(scalar.value)
}

private func isFolderTrimScalar(_ scalar: Unicode.Scalar) -> Bool {
    switch scalar.value {
    case 0x0009...0x000D,
         0x0020,
         0x0085,
         0x00A0,
         0x1680,
         0x2000...0x200B,
         0x2028,
         0x2029,
         0x202F,
         0x205F,
         0x3000:
        true
    default:
        false
    }
}
