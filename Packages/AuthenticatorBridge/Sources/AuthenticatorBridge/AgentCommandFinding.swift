import Foundation

public enum AgentCommandFindingSeverity: String, Codable, CaseIterable, Equatable, Sendable {
    case info
    case review
    case warning
}

public enum AgentCommandFindingType: String, Codable, Equatable, Hashable, Sendable {
    case commandAfterGrantEnded
    case processOnlyCapture
    case deniedDirectSecretRead
    case possibleEnvironmentExposure
    case processFallbackUsed
    case injectedTreeCapture
    case sensitiveFileActivity
    case outsideWorkspaceFileActivity
    case secretFileScrubbed
    case secretDetectedInFile
    case secretFileInspectionIncomplete
    case secretFileCleanupIncomplete
    case mediatedResponse
    case networkAfterGrantEnded
    case networkDescendantSurvived
    case networkInspectionUnavailable
    case networkInspectionPartial
    case potentialCleartextNetwork
}

public struct AgentCommandFinding: Codable, Equatable, Identifiable, Sendable {
    public let id: String
    public let severity: AgentCommandFindingSeverity
    public let type: AgentCommandFindingType
    public let agentJITGrantID: UUID?
    public let evidenceEventIDs: [UUID]
    public let fileEvidenceEventIDs: [UUID]
    public let networkEvidenceRecordIDs: [UUID]
    public let recordedAt: Date
    public let title: String
    public let detail: String
    public let recommendedAction: String

    public init(
        id: String? = nil,
        severity: AgentCommandFindingSeverity,
        type: AgentCommandFindingType,
        agentJITGrantID: UUID?,
        evidenceEventIDs: [UUID],
        fileEvidenceEventIDs: [UUID] = [],
        networkEvidenceRecordIDs: [UUID] = [],
        recordedAt: Date,
        title: String,
        detail: String,
        recommendedAction: String
    ) {
        self.severity = severity
        self.type = type
        self.agentJITGrantID = agentJITGrantID
        self.evidenceEventIDs = evidenceEventIDs
        self.fileEvidenceEventIDs = fileEvidenceEventIDs
        self.networkEvidenceRecordIDs = networkEvidenceRecordIDs
        self.recordedAt = recordedAt
        self.title = title
        self.detail = detail
        self.recommendedAction = recommendedAction
        self.id = id ?? Self.makeID(
            type: type,
            agentJITGrantID: agentJITGrantID,
            evidenceEventIDs: evidenceEventIDs,
            fileEvidenceEventIDs: fileEvidenceEventIDs,
            networkEvidenceRecordIDs: networkEvidenceRecordIDs,
            recordedAt: recordedAt
        )
    }

    private enum CodingKeys: String, CodingKey {
        case id
        case severity
        case type
        case agentJITGrantID
        case evidenceEventIDs
        case fileEvidenceEventIDs
        case networkEvidenceRecordIDs
        case recordedAt
        case title
        case detail
        case recommendedAction
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.id = try container.decode(String.self, forKey: .id)
        self.severity = try container.decode(AgentCommandFindingSeverity.self, forKey: .severity)
        self.type = try container.decode(AgentCommandFindingType.self, forKey: .type)
        self.agentJITGrantID = try container.decodeIfPresent(UUID.self, forKey: .agentJITGrantID)
        self.evidenceEventIDs = try container.decode([UUID].self, forKey: .evidenceEventIDs)
        self.fileEvidenceEventIDs = try container.decodeIfPresent([UUID].self, forKey: .fileEvidenceEventIDs) ?? []
        self.networkEvidenceRecordIDs = try container.decodeIfPresent(
            [UUID].self,
            forKey: .networkEvidenceRecordIDs
        ) ?? []
        self.recordedAt = try container.decode(Date.self, forKey: .recordedAt)
        self.title = try container.decode(String.self, forKey: .title)
        self.detail = try container.decode(String.self, forKey: .detail)
        self.recommendedAction = try container.decode(String.self, forKey: .recommendedAction)
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(id, forKey: .id)
        try container.encode(severity, forKey: .severity)
        try container.encode(type, forKey: .type)
        try container.encodeIfPresent(agentJITGrantID, forKey: .agentJITGrantID)
        try container.encode(evidenceEventIDs, forKey: .evidenceEventIDs)
        try container.encode(fileEvidenceEventIDs, forKey: .fileEvidenceEventIDs)
        try container.encode(networkEvidenceRecordIDs, forKey: .networkEvidenceRecordIDs)
        try container.encode(recordedAt, forKey: .recordedAt)
        try container.encode(title, forKey: .title)
        try container.encode(detail, forKey: .detail)
        try container.encode(recommendedAction, forKey: .recommendedAction)
    }

    private static func makeID(
        type: AgentCommandFindingType,
        agentJITGrantID: UUID?,
        evidenceEventIDs: [UUID],
        fileEvidenceEventIDs: [UUID],
        networkEvidenceRecordIDs: [UUID],
        recordedAt: Date
    ) -> String {
        let selectedIDs = evidenceEventIDs.isEmpty
            ? (fileEvidenceEventIDs.isEmpty ? networkEvidenceRecordIDs : fileEvidenceEventIDs)
            : evidenceEventIDs
        let eventIDs = selectedIDs
            .map(\.uuidString)
            .joined(separator: ",")
        return [
            type.rawValue,
            agentJITGrantID?.uuidString ?? "no-grant",
            eventIDs,
            String(Int(recordedAt.timeIntervalSince1970.rounded())),
        ].joined(separator: ":")
    }
}

public struct AgentCommandFindingSummary: Codable, Equatable, Sendable {
    public let infoCount: Int
    public let reviewCount: Int
    public let warningCount: Int
    public let totalCount: Int

    public init(findings: [AgentCommandFinding]) {
        self.infoCount = findings.filter { $0.severity == .info }.count
        self.reviewCount = findings.filter { $0.severity == .review }.count
        self.warningCount = findings.filter { $0.severity == .warning }.count
        self.totalCount = findings.count
    }
}

public struct AgentCommandHistoryExport: Codable, Equatable, Sendable {
    public let events: [AgentCommandEvent]
    public let findings: [AgentCommandFinding]
    public let summary: AgentCommandFindingSummary

    public init(events: [AgentCommandEvent], findings: [AgentCommandFinding]) {
        self.events = events.sorted { $0.recordedAt < $1.recordedAt }
        self.findings = findings.sorted { lhs, rhs in
            if lhs.recordedAt == rhs.recordedAt {
                return lhs.id < rhs.id
            }
            return lhs.recordedAt < rhs.recordedAt
        }
        self.summary = AgentCommandFindingSummary(findings: self.findings)
    }
}

public struct AgentNetworkActivityCoverageExport: Codable, Equatable, Sendable {
    public let runID: UUID
    public let grantIDs: [UUID]
    public let coverage: AgentNetworkCaptureCoverage
    public let updatedAt: Date
    public let endedAt: Date?
    public let survivingDescendantIdentityKeys: [String]

    public init(snapshot: AgentNetworkActivityRunSnapshot) {
        self.runID = snapshot.runID
        self.grantIDs = snapshot.grantIDs
        self.coverage = snapshot.coverage
        self.updatedAt = snapshot.updatedAt
        self.endedAt = snapshot.endedAt
        self.survivingDescendantIdentityKeys = snapshot.survivingDescendantIdentityKeys
    }
}

public struct AgentSessionActivityExport: Codable, Equatable, Sendable {
    public let commands: [AgentCommandEvent]
    public let files: [AgentFileActivityExportEvent]
    public let processTrees: [InjectedProcessTreeRun]
    public let network: [AgentNetworkActivityRecord]
    public let networkDomains: [AgentNetworkDomainEvidence]?
    public let networkCoverage: [AgentNetworkActivityCoverageExport]
    public let findings: [AgentCommandFinding]
    public let summary: AgentCommandFindingSummary

    public init(
        commands: [AgentCommandEvent],
        files: [AgentFileActivityEvent],
        processTrees: [InjectedProcessTreeRun] = [],
        networkSnapshots: [AgentNetworkActivityRunSnapshot] = [],
        findings: [AgentCommandFinding]
    ) {
        self.commands = commands.sorted { lhs, rhs in
            if lhs.recordedAt == rhs.recordedAt {
                return lhs.id.uuidString < rhs.id.uuidString
            }
            return lhs.recordedAt < rhs.recordedAt
        }
        self.files = files
            .sorted { lhs, rhs in
                if lhs.recordedAt == rhs.recordedAt {
                    return lhs.id.uuidString < rhs.id.uuidString
                }
                return lhs.recordedAt < rhs.recordedAt
            }
            .map(AgentFileActivityExportEvent.init(event:))
        self.processTrees = processTrees.sorted { lhs, rhs in
            if lhs.startedAt == rhs.startedAt {
                return lhs.id.uuidString < rhs.id.uuidString
            }
            return lhs.startedAt < rhs.startedAt
        }
        self.network = networkSnapshots
            .flatMap(\.records)
            .sorted { lhs, rhs in
                if lhs.lastSeenAt == rhs.lastSeenAt {
                    return lhs.id.uuidString < rhs.id.uuidString
                }
                return lhs.lastSeenAt < rhs.lastSeenAt
            }
        self.networkDomains = networkSnapshots
            .flatMap(\.domainEvidence)
            .sorted { lhs, rhs in
                if lhs.lastSeenAt == rhs.lastSeenAt {
                    return lhs.id.uuidString < rhs.id.uuidString
                }
                return lhs.lastSeenAt < rhs.lastSeenAt
            }
        self.networkCoverage = networkSnapshots
            .sorted { lhs, rhs in
                if lhs.updatedAt == rhs.updatedAt {
                    return lhs.runID.uuidString < rhs.runID.uuidString
                }
                return lhs.updatedAt < rhs.updatedAt
            }
            .map(AgentNetworkActivityCoverageExport.init(snapshot:))
        self.findings = findings.sorted { lhs, rhs in
            if lhs.recordedAt == rhs.recordedAt {
                return lhs.id < rhs.id
            }
            return lhs.recordedAt < rhs.recordedAt
        }
        self.summary = AgentCommandFindingSummary(findings: findings)
    }
}

public enum AgentCommandFindingDetector {
    private static let hookMatchWindow: TimeInterval = 10
    private static let directSecretReadCommands: Set<String> = ["get", "read", "load", "inject"]
    private static let environmentExecutables: Set<String> = ["env", "printenv"]
    private static let environmentFileReadExecutables: Set<String> = [
        "bat", "cat", "head", "less", "more", "source", "tail", "type",
    ]

    public static func findings(
        for grants: [AgentJITGrant],
        events: [AgentCommandEvent],
        auditRecords: [BridgeAuditRecord]
    ) -> [AgentCommandFinding] {
        findings(for: grants, events: events, fileEvents: [], auditRecords: auditRecords)
    }

    public static func findings(
        for grants: [AgentJITGrant],
        events: [AgentCommandEvent],
        fileEvents: [AgentFileActivityEvent],
        auditRecords: [BridgeAuditRecord]
    ) -> [AgentCommandFinding] {
        findings(
            for: grants,
            events: events,
            fileEvents: fileEvents,
            networkSnapshots: [],
            auditRecords: auditRecords
        )
    }

    public static func findings(
        for grants: [AgentJITGrant],
        events: [AgentCommandEvent],
        fileEvents: [AgentFileActivityEvent],
        networkSnapshots: [AgentNetworkActivityRunSnapshot],
        auditRecords: [BridgeAuditRecord]
    ) -> [AgentCommandFinding] {
        grants
            .flatMap { grant in
                findings(
                    for: grant,
                    events: events,
                    fileEvents: fileEvents,
                    networkSnapshots: networkSnapshots,
                    auditRecords: auditRecords
                )
            }
            .sorted { lhs, rhs in
                if lhs.recordedAt == rhs.recordedAt {
                    return lhs.id < rhs.id
                }
                return lhs.recordedAt < rhs.recordedAt
            }
    }

    public static func findings(
        for grant: AgentJITGrant,
        events: [AgentCommandEvent],
        auditRecords: [BridgeAuditRecord]
    ) -> [AgentCommandFinding] {
        findings(for: grant, events: events, fileEvents: [], auditRecords: auditRecords)
    }

    public static func findings(
        for grant: AgentJITGrant,
        events: [AgentCommandEvent],
        fileEvents: [AgentFileActivityEvent],
        auditRecords: [BridgeAuditRecord]
    ) -> [AgentCommandFinding] {
        findings(
            for: grant,
            events: events,
            fileEvents: fileEvents,
            networkSnapshots: [],
            auditRecords: auditRecords
        )
    }

    public static func findings(
        for grant: AgentJITGrant,
        events: [AgentCommandEvent],
        fileEvents: [AgentFileActivityEvent],
        networkSnapshots: [AgentNetworkActivityRunSnapshot],
        auditRecords: [BridgeAuditRecord]
    ) -> [AgentCommandFinding] {
        let grantEvents = events
            .filter { matchesGrantOrScope(event: $0, grant: grant) }
            .sorted { $0.recordedAt < $1.recordedAt }
        let grantFileEvents = AgentFileActivityQuery.events(for: grant, from: fileEvents)
        var findings: [AgentCommandFinding] = []

        for event in grantEvents {
            if grantEndedBefore(event.recordedAt, grant: grant) {
                findings.append(commandAfterGrantEndedFinding(for: event, grant: grant))
            }

            if event.captureSource == .process {
                if isHookCapable(event: event, grant: grant) {
                    if !hasMatchingHookEvent(for: event, grant: grant, events: events) {
                        findings.append(processOnlyCaptureFinding(for: event, grant: grant))
                    }
                } else {
                    findings.append(processFallbackUsedFinding(for: event, grant: grant))
                }
            }

            if event.captureSource == .injectedTree {
                findings.append(injectedTreeCaptureFinding(for: event, grant: grant))
            }

            if isDeniedDirectSecretRead(event) {
                findings.append(deniedDirectSecretReadFinding(for: event, grant: grant))
            }

            if isPossibleEnvironmentExposure(event), grant.status(asOf: event.recordedAt) == .active {
                findings.append(possibleEnvironmentExposureFinding(for: event, grant: grant))
            }

            if let responseOutcome = event.responseOutcome, responseOutcome != .allow {
                findings.append(mediatedResponseFinding(for: event, grant: grant))
            }
        }

        for record in auditRecords where record.agentJITGrantID == grant.id && isDeniedDirectSecretRead(record) {
            findings.append(deniedDirectSecretReadFinding(for: record, grant: grant))
        }

        for fileEvent in grantFileEvents {
            if fileEvent.captureSource == .injectedExec {
                if fileEvent.detail == InjectedSecretFileActivityDetail.scrubbed {
                    findings.append(secretFileScrubbedFinding(for: fileEvent, grant: grant))
                } else if fileEvent.detail == InjectedSecretFileActivityDetail.secretDetected {
                    findings.append(secretDetectedInFileFinding(for: fileEvent, grant: grant))
                } else if fileEvent.detail == InjectedSecretFileActivityDetail.inspectionFailed {
                    findings.append(
                        secretFileInspectionIncompleteFinding(for: fileEvent, grant: grant)
                    )
                } else if fileEvent.detail == InjectedSecretFileActivityDetail.verificationFailed
                    || fileEvent.detail == InjectedSecretFileActivityDetail.remediationFailed {
                    findings.append(secretFileCleanupIncompleteFinding(for: fileEvent, grant: grant))
                }
                continue
            }

            if isSensitiveFileActivity(fileEvent) {
                findings.append(sensitiveFileActivityFinding(for: fileEvent, grant: grant))
            }

            if isOutsideWorkspaceFileActivity(fileEvent) {
                findings.append(outsideWorkspaceFileActivityFinding(for: fileEvent, grant: grant))
            }
        }

        for snapshot in AgentNetworkActivityQuery.snapshots(
            for: grant,
            from: networkSnapshots
        ) {
            switch snapshot.coverage {
            case .unavailable:
                findings.append(networkInspectionUnavailableFinding(for: snapshot, grant: grant))
            case .partial:
                findings.append(networkInspectionPartialFinding(for: snapshot, grant: grant))
            case .observed:
                break
            }

            if !snapshot.survivingDescendantIdentityKeys.isEmpty {
                findings.append(networkDescendantSurvivedFinding(for: snapshot, grant: grant))
            }

            for record in snapshot.records {
                if grantEndedBefore(record.lastSeenAt, grant: grant) {
                    findings.append(networkAfterGrantEndedFinding(for: record, grant: grant))
                }
                if isPotentialCleartextNetwork(record) {
                    findings.append(potentialCleartextNetworkFinding(for: record, grant: grant))
                }
            }
        }

        return findings.sorted { lhs, rhs in
            if lhs.recordedAt == rhs.recordedAt {
                return lhs.id < rhs.id
            }
            return lhs.recordedAt < rhs.recordedAt
        }
    }

    private static func networkAfterGrantEndedFinding(
        for record: AgentNetworkActivityRecord,
        grant: AgentJITGrant
    ) -> AgentCommandFinding {
        AgentCommandFinding(
            severity: .review,
            type: .networkAfterGrantEnded,
            agentJITGrantID: grant.id,
            evidenceEventIDs: [],
            networkEvidenceRecordIDs: [record.id],
            recordedAt: record.lastSeenAt,
            title: "Network activity after access ended",
            detail: "A process in the mediated run contacted an endpoint after the matching access was no longer active.",
            recommendedAction: "Compare the endpoint time with the grant expiration or revocation time."
        )
    }

    private static func networkDescendantSurvivedFinding(
        for snapshot: AgentNetworkActivityRunSnapshot,
        grant: AgentJITGrant
    ) -> AgentCommandFinding {
        AgentCommandFinding(
            severity: .review,
            type: .networkDescendantSurvived,
            agentJITGrantID: grant.id,
            evidenceEventIDs: [],
            networkEvidenceRecordIDs: snapshot.records.map(\.id),
            recordedAt: snapshot.endedAt ?? snapshot.updatedAt,
            title: "Network-capable descendant survived",
            detail: "One or more observed descendants were still running when the mediated root process exited.",
            recommendedAction: "Review the Process Tree and confirm the surviving processes were expected."
        )
    }

    private static func networkInspectionUnavailableFinding(
        for snapshot: AgentNetworkActivityRunSnapshot,
        grant: AgentJITGrant
    ) -> AgentCommandFinding {
        AgentCommandFinding(
            severity: .review,
            type: .networkInspectionUnavailable,
            agentJITGrantID: grant.id,
            evidenceEventIDs: [],
            networkEvidenceRecordIDs: snapshot.records.map(\.id),
            recordedAt: snapshot.updatedAt,
            title: "Network observation unavailable",
            detail: "Authsia could not inspect network activity for this mediated run.",
            recommendedAction: "Treat the run as incomplete evidence and review its commands and Process Tree."
        )
    }

    private static func networkInspectionPartialFinding(
        for snapshot: AgentNetworkActivityRunSnapshot,
        grant: AgentJITGrant
    ) -> AgentCommandFinding {
        AgentCommandFinding(
            severity: .info,
            type: .networkInspectionPartial,
            agentJITGrantID: grant.id,
            evidenceEventIDs: [],
            networkEvidenceRecordIDs: snapshot.records.map(\.id),
            recordedAt: snapshot.updatedAt,
            title: "Partial network observation",
            detail: "Some processes or socket descriptors could not be inspected within the bounded capture limits.",
            recommendedAction: "Use the observed endpoints as supporting evidence, not a complete network trace."
        )
    }

    private static func potentialCleartextNetworkFinding(
        for record: AgentNetworkActivityRecord,
        grant: AgentJITGrant
    ) -> AgentCommandFinding {
        AgentCommandFinding(
            severity: .review,
            type: .potentialCleartextNetwork,
            agentJITGrantID: grant.id,
            evidenceEventIDs: [],
            networkEvidenceRecordIDs: [record.id],
            recordedAt: record.lastSeenAt,
            title: "Potential cleartext network service",
            detail: "A non-loopback endpoint used a port commonly associated with a cleartext service.",
            recommendedAction: "Confirm the endpoint and transport were appropriate for the approved task."
        )
    }

    private static func commandAfterGrantEndedFinding(
        for event: AgentCommandEvent,
        grant: AgentJITGrant
    ) -> AgentCommandFinding {
        AgentCommandFinding(
            severity: .warning,
            type: .commandAfterGrantEnded,
            agentJITGrantID: grant.id,
            evidenceEventIDs: [event.id],
            recordedAt: event.recordedAt,
            title: "Command after access ended",
            detail: "This command was recorded after the matching agent access was no longer active.",
            recommendedAction: "Compare the command time with the grant expiration or revocation time."
        )
    }

    private static func processOnlyCaptureFinding(
        for event: AgentCommandEvent,
        grant: AgentJITGrant
    ) -> AgentCommandFinding {
        AgentCommandFinding(
            severity: .info,
            type: .processOnlyCapture,
            agentJITGrantID: grant.id,
            evidenceEventIDs: [event.id],
            recordedAt: event.recordedAt,
            title: "Process-only capture",
            detail: "Authsia saw this command through local process monitoring without a matching hook event.",
            recommendedAction: "Review the command context if a hook event was expected."
        )
    }

    private static func deniedDirectSecretReadFinding(
        for event: AgentCommandEvent,
        grant: AgentJITGrant
    ) -> AgentCommandFinding {
        AgentCommandFinding(
            severity: .review,
            type: .deniedDirectSecretRead,
            agentJITGrantID: grant.id,
            evidenceEventIDs: [event.id],
            recordedAt: event.recordedAt,
            title: "Direct secret-read command",
            detail: "A direct Authsia secret-read command was recorded for this agent access.",
            recommendedAction: "Check whether this command matched the access workflow you intended."
        )
    }

    private static func deniedDirectSecretReadFinding(
        for record: BridgeAuditRecord,
        grant: AgentJITGrant
    ) -> AgentCommandFinding {
        AgentCommandFinding(
            severity: .review,
            type: .deniedDirectSecretRead,
            agentJITGrantID: grant.id,
            evidenceEventIDs: [],
            recordedAt: record.timestamp,
            title: "Direct secret-read command",
            detail: "An audit record shows a direct Authsia secret-read command for this agent access.",
            recommendedAction: "Check whether this command matched the access workflow you intended."
        )
    }

    private static func possibleEnvironmentExposureFinding(
        for event: AgentCommandEvent,
        grant: AgentJITGrant
    ) -> AgentCommandFinding {
        AgentCommandFinding(
            severity: .review,
            type: .possibleEnvironmentExposure,
            agentJITGrantID: grant.id,
            evidenceEventIDs: [event.id],
            recordedAt: event.recordedAt,
            title: "Possible environment exposure",
            detail: "This command can print environment values or read local environment files during active access.",
            recommendedAction: "Review whether the command needed access to environment data."
        )
    }

    private static func processFallbackUsedFinding(
        for event: AgentCommandEvent,
        grant: AgentJITGrant
    ) -> AgentCommandFinding {
        AgentCommandFinding(
            severity: .info,
            type: .processFallbackUsed,
            agentJITGrantID: grant.id,
            evidenceEventIDs: [event.id],
            recordedAt: event.recordedAt,
            title: "Process fallback used",
            detail: "Authsia recorded this command through local process monitoring.",
            recommendedAction: "Use this as supporting evidence when hook capture is unavailable."
        )
    }

    private static func injectedTreeCaptureFinding(
        for event: AgentCommandEvent,
        grant: AgentJITGrant
    ) -> AgentCommandFinding {
        AgentCommandFinding(
            severity: .info,
            type: .injectedTreeCapture,
            agentJITGrantID: grant.id,
            evidenceEventIDs: [event.id],
            recordedAt: event.recordedAt,
            title: "Injected process tree capture",
            detail: "Authsia recorded this process while observing the secret-injected child tree.",
            recommendedAction: "Use the Process Tree view to review descendants launched after secret release."
        )
    }

    private static func mediatedResponseFinding(
        for event: AgentCommandEvent,
        grant: AgentJITGrant
    ) -> AgentCommandFinding {
        let prevented = event.responsePreventedAction == true
        let outcome = event.responseOutcome ?? .warn
        return AgentCommandFinding(
            severity: outcome == .warn ? .review : .warning,
            type: .mediatedResponse,
            agentJITGrantID: grant.id,
            evidenceEventIDs: [event.id],
            recordedAt: event.recordedAt,
            title: prevented ? "Mediated tool action stopped" : "Mediated tool risk observed",
            detail: prevented
                ? "Authsia's pre-tool hook stopped or held a matching action before it ran."
                : "Authsia recorded a matching action without claiming it was prevented.",
            recommendedAction: outcome == .revokeAndDeny
                ? "Review the incident before creating new agent authority."
                : "Review the tool action and workspace response mode."
        )
    }

    private static func sensitiveFileActivityFinding(
        for event: AgentFileActivityEvent,
        grant: AgentJITGrant
    ) -> AgentCommandFinding {
        AgentCommandFinding(
            severity: .review,
            type: .sensitiveFileActivity,
            agentJITGrantID: grant.id,
            evidenceEventIDs: [],
            fileEvidenceEventIDs: [event.id],
            recordedAt: event.recordedAt,
            title: "Sensitive file activity",
            detail: "Agent file activity touched a path that looks like a secret-bearing file.",
            recommendedAction: "Review whether the file access matched the agent task you approved."
        )
    }

    private static func secretFileScrubbedFinding(
        for event: AgentFileActivityEvent,
        grant: AgentJITGrant
    ) -> AgentCommandFinding {
        AgentCommandFinding(
            severity: .info,
            type: .secretFileScrubbed,
            agentJITGrantID: grant.id,
            evidenceEventIDs: [],
            fileEvidenceEventIDs: [event.id],
            recordedAt: event.recordedAt,
            title: "Secret scrubbed from file",
            detail: "A known injected secret was replaced with a concealment placeholder in an "
                + "observed candidate file after the mediated child exited.",
            recommendedAction: "Confirm the child should not have written vault secrets to disk."
        )
    }

    private static func secretDetectedInFileFinding(
        for event: AgentFileActivityEvent,
        grant: AgentJITGrant
    ) -> AgentCommandFinding {
        AgentCommandFinding(
            severity: .review,
            type: .secretDetectedInFile,
            agentJITGrantID: grant.id,
            evidenceEventIDs: [],
            fileEvidenceEventIDs: [event.id],
            recordedAt: event.recordedAt,
            title: "Secret detected in file",
            detail: "A known injected secret was confirmed in an observed candidate file and "
                + "intentionally left unchanged because secret-file cleanup was not enabled for "
                + "this run.",
            recommendedAction: "Review the file and remove or rotate the exposed secret if needed."
        )
    }

    private static func secretFileCleanupIncompleteFinding(
        for event: AgentFileActivityEvent,
        grant: AgentJITGrant
    ) -> AgentCommandFinding {
        AgentCommandFinding(
            severity: .review,
            type: .secretFileCleanupIncomplete,
            agentJITGrantID: grant.id,
            evidenceEventIDs: [],
            fileEvidenceEventIDs: [event.id],
            recordedAt: event.recordedAt,
            title: "Secret-file cleanup incomplete",
            detail: "Authsia could not verify that a known injected secret was removed from a touched file.",
            recommendedAction: "Review the affected file activity and remove or rotate any exposed secret if needed."
        )
    }

    private static func secretFileInspectionIncompleteFinding(
        for event: AgentFileActivityEvent,
        grant: AgentJITGrant
    ) -> AgentCommandFinding {
        AgentCommandFinding(
            severity: .review,
            type: .secretFileInspectionIncomplete,
            agentJITGrantID: grant.id,
            evidenceEventIDs: [],
            fileEvidenceEventIDs: [event.id],
            recordedAt: event.recordedAt,
            title: "Secret-file inspection incomplete",
            detail: "Bounded post-exit inspection could not complete, so secret presence in the "
                + "touched file was not confirmed.",
            recommendedAction: "Review the affected file activity and inspect the file if needed."
        )
    }

    private static func outsideWorkspaceFileActivityFinding(
        for event: AgentFileActivityEvent,
        grant: AgentJITGrant
    ) -> AgentCommandFinding {
        AgentCommandFinding(
            severity: .info,
            type: .outsideWorkspaceFileActivity,
            agentJITGrantID: grant.id,
            evidenceEventIDs: [],
            fileEvidenceEventIDs: [event.id],
            recordedAt: event.recordedAt,
            title: "Outside-workspace file activity",
            detail: "Agent file activity touched a path outside the recorded workspace root.",
            recommendedAction: "Confirm whether this file access was expected for the approved workspace."
        )
    }

    private static func grantEndedBefore(_ date: Date, grant: AgentJITGrant) -> Bool {
        if let revokedAt = grant.revokedAt, date >= revokedAt {
            return true
        }
        return date >= grant.expiresAt
    }

    private static func hasMatchingHookEvent(
        for event: AgentCommandEvent,
        grant: AgentJITGrant,
        events: [AgentCommandEvent]
    ) -> Bool {
        events.contains { candidate in
            guard candidate.captureSource == .hook else { return false }
            guard matchesGrantOrScope(event: candidate, grant: grant) else { return false }
            guard commandsMatch(event, candidate) else { return false }
            return abs(candidate.recordedAt.timeIntervalSince(event.recordedAt)) <= hookMatchWindow
        }
    }

    private static func commandsMatch(_ lhs: AgentCommandEvent, _ rhs: AgentCommandEvent) -> Bool {
        if let lhsCommand = normalized(lhs.command),
           let rhsCommand = normalized(rhs.command),
           lhsCommand == rhsCommand {
            return true
        }
        return normalized(lhs.executable) == normalized(rhs.executable)
            && lhs.arguments.map(normalizedToken) == rhs.arguments.map(normalizedToken)
    }

    private static func matchesGrantOrScope(event: AgentCommandEvent, grant: AgentJITGrant) -> Bool {
        event.agentJITGrantID == grant.id
            || matchesRuntimeContext(event: event, grant: grant)
            || matchesTerminalScope(event: event, grant: grant)
    }

    private static func matchesRuntimeContext(event: AgentCommandEvent, grant: AgentJITGrant) -> Bool {
        guard let context = grant.agentRuntimeContext else { return false }
        guard let eventPlatform = normalizedPlatform(event.agentPlatform),
              let contextPlatform = normalizedPlatform(context.platform),
              eventPlatform == contextPlatform else {
            return false
        }

        let comparisons = [
            (event.sessionID, context.sessionID),
            (event.turnID, context.turnID),
            (event.agentID, context.agentID),
            (event.toolUseID, context.toolUseID),
        ]
        var hasMatchingIdentifier = false
        for (lhs, rhs) in comparisons {
            guard let lhs = normalized(lhs), let rhs = normalized(rhs) else { continue }
            guard lhs == rhs else { return false }
            hasMatchingIdentifier = true
        }
        return hasMatchingIdentifier
    }

    private static func matchesTerminalScope(event: AgentCommandEvent, grant: AgentJITGrant) -> Bool {
        guard let eventScope = normalized(event.terminalSessionScope),
              let grantScope = normalized(grant.callerFingerprint.sessionScope),
              eventScope == grantScope else {
            return false
        }
        guard let eventWorkingDirectory = normalizedPath(event.workingDirectory),
              let grantWorkingDirectory = normalizedPath(grant.callerFingerprint.workingDirectory) else {
            return true
        }
        return WorkspaceAuthority.matchesWorkingDirectory(
            eventWorkingDirectory,
            authorityPath: grantWorkingDirectory
        )
    }

    private static func isHookCapable(event: AgentCommandEvent, grant: AgentJITGrant) -> Bool {
        let platform = normalizedPlatform(event.agentPlatform)
            ?? normalizedPlatform(grant.agentRuntimeContext?.platform)
            ?? normalizedPlatform(grant.agentName)
            ?? normalizedPlatform(grant.callerFingerprint.parentProcessName)
        return platform == "claude-code" || platform == "copilot"
    }

    private static func isDeniedDirectSecretRead(_ event: AgentCommandEvent) -> Bool {
        let tokens = commandTokens(event)
        guard let first = executableName(tokens.first) else { return false }

        if first == "authsia", tokens.count > 1 {
            return directSecretReadCommands.contains(tokens[1].lowercased())
        }
        if executableName(event.executable) == "authsia", let command = tokens.dropFirst().first {
            return directSecretReadCommands.contains(command.lowercased())
        }
        return false
    }

    private static func isDeniedDirectSecretRead(_ record: BridgeAuditRecord) -> Bool {
        if let requestedCommand = normalized(record.requestedCommand)?.lowercased(),
           directSecretReadCommands.contains(requestedCommand) {
            return true
        }
        guard let fullCommand = record.fullCommand else { return false }
        let tokens = splitCommand(fullCommand)
        guard let first = executableName(tokens.first), first == "authsia", tokens.count > 1 else {
            return false
        }
        return directSecretReadCommands.contains(tokens[1].lowercased())
    }

    private static func isPossibleEnvironmentExposure(_ event: AgentCommandEvent) -> Bool {
        if let executable = executableName(event.executable), environmentExecutables.contains(executable) {
            return true
        }

        let tokens = commandTokens(event).map { normalizedToken($0).lowercased() }
        if let first = tokens.first,
           let firstExecutable = executableName(first),
           environmentExecutables.contains(firstExecutable) {
            return true
        }

        guard let first = tokens.first,
              let firstExecutable = executableName(first),
              environmentFileReadExecutables.contains(firstExecutable) || firstExecutable == "." else {
            return false
        }

        return tokens.dropFirst().contains(where: AgentSecretPathPolicy.isHighSignalDotEnvPath)
    }

    private static func isSensitiveFileActivity(_ event: AgentFileActivityEvent) -> Bool {
        AgentSecretPathPolicy.isHighSignalSecretPath(event.path)
    }

    private static func isOutsideWorkspaceFileActivity(_ event: AgentFileActivityEvent) -> Bool {
        guard let workspaceRoot = normalizedPath(event.workspaceRoot) else { return false }
        guard let path = normalizedPath(event.path, relativeTo: event.workspaceRoot ?? event.workingDirectory) else {
            return true
        }
        return !isEqualOrDescendant(path: path, root: workspaceRoot)
    }

    private static func isPotentialCleartextNetwork(
        _ record: AgentNetworkActivityRecord
    ) -> Bool {
        guard record.destinationZone != .loopback else { return false }
        return [20, 21, 23, 80, 110, 143, 389].contains(record.remotePort)
    }

    private static func isEqualOrDescendant(path: String, root: String) -> Bool {
        let pathComponents = URL(fileURLWithPath: path).standardizedFileURL.pathComponents
        let rootComponents = URL(fileURLWithPath: root).standardizedFileURL.pathComponents
        guard pathComponents.count >= rootComponents.count else { return false }
        return Array(pathComponents.prefix(rootComponents.count)) == rootComponents
    }

    private static func commandTokens(_ event: AgentCommandEvent) -> [String] {
        if !event.arguments.isEmpty {
            return event.arguments.map(normalizedToken)
        }
        if let command = event.command {
            return splitCommand(command)
        }
        if let executable = event.executable {
            return [executable]
        }
        return []
    }

    private static func splitCommand(_ command: String) -> [String] {
        command
            .split { $0 == " " || $0 == "\t" || $0 == "\n" }
            .map { normalizedToken(String($0)) }
            .filter { !$0.isEmpty }
    }

    private static func normalizedPlatform(_ value: String?) -> String? {
        switch normalized(value)?.lowercased() {
        case "claude", "claude-code", "claude code":
            return "claude-code"
        case "codex":
            return "codex"
        case "copilot", "github-copilot", "github copilot":
            return "copilot"
        case let value?:
            return value
        case nil:
            return nil
        }
    }

    private static func normalizedPath(_ value: String?) -> String? {
        guard let value = normalized(value) else { return nil }
        return URL(fileURLWithPath: value).standardizedFileURL.path
    }

    private static func normalizedPath(_ value: String?, relativeTo base: String?) -> String? {
        guard let value = normalized(value) else { return nil }
        guard !value.hasPrefix("/") else {
            return URL(fileURLWithPath: value).standardizedFileURL.path
        }
        guard let basePath = normalizedPath(base) else {
            return URL(fileURLWithPath: value).standardizedFileURL.path
        }
        return URL(
            fileURLWithPath: value,
            relativeTo: URL(fileURLWithPath: basePath, isDirectory: true)
        ).standardizedFileURL.path
    }

    private static func normalized(_ value: String?) -> String? {
        guard let value else { return nil }
        let trimmed = normalizedToken(value)
        return trimmed.isEmpty ? nil : trimmed
    }

    private static func executableName(_ value: String?) -> String? {
        guard let value = normalized(value) else { return nil }
        return URL(fileURLWithPath: value).lastPathComponent.lowercased()
    }

    private static func normalizedToken(_ value: String) -> String {
        value.trimmingCharacters(in: CharacterSet.whitespacesAndNewlines.union(CharacterSet(charactersIn: "\"'")))
    }
}
