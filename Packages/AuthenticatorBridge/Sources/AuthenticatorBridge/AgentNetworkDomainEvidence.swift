import Foundation

public enum AgentNetworkDomainEvidenceSource: String, Codable, CaseIterable, Equatable, Sendable {
    case commandArgument
}

public enum AgentNetworkEvidenceConfidence: String, Codable, CaseIterable, Equatable, Sendable {
    case observed
    case inferred
}

struct AgentNetworkDomainObservation: Equatable, Sendable {
    let observedAt: Date
    let pid: Int32
    let processStartTime: UInt64
    let executable: String?
    let hostname: String
    let source: AgentNetworkDomainEvidenceSource
    let confidence: AgentNetworkEvidenceConfidence

    init(
        observedAt: Date,
        pid: Int32,
        processStartTime: UInt64,
        executable: String?,
        hostname: String,
        source: AgentNetworkDomainEvidenceSource,
        confidence: AgentNetworkEvidenceConfidence
    ) {
        self.observedAt = observedAt
        self.pid = pid
        self.processStartTime = processStartTime
        self.executable = AgentCommandRedactor.sanitized(executable, maxLength: 1_024)
        self.hostname = hostname
        self.source = source
        self.confidence = confidence
    }
}

public struct AgentNetworkDomainEvidence: Codable, Equatable, Identifiable, Sendable {
    public let id: UUID
    public let runID: UUID
    public let grantIDs: [UUID]
    public let pid: Int32
    public let processStartTime: UInt64
    public let executable: String?
    public let hostname: String
    public let source: AgentNetworkDomainEvidenceSource
    public let confidence: AgentNetworkEvidenceConfidence
    public private(set) var firstSeenAt: Date
    public private(set) var lastSeenAt: Date
    public private(set) var observationCount: Int

    init(
        id: UUID = UUID(),
        runID: UUID,
        grantIDs: [UUID],
        observation: AgentNetworkDomainObservation
    ) {
        self.id = id
        self.runID = runID
        self.grantIDs = Array(Set(grantIDs)).sorted { $0.uuidString < $1.uuidString }
        self.pid = observation.pid
        self.processStartTime = observation.processStartTime
        self.executable = observation.executable
        self.hostname = observation.hostname
        self.source = observation.source
        self.confidence = observation.confidence
        self.firstSeenAt = observation.observedAt
        self.lastSeenAt = observation.observedAt
        self.observationCount = 1
    }

    mutating func apply(_ observation: AgentNetworkDomainObservation) {
        firstSeenAt = min(firstSeenAt, observation.observedAt)
        lastSeenAt = max(lastSeenAt, observation.observedAt)
        observationCount += 1
    }
}

enum AgentNetworkDomainExtractor {
    private static let urlSchemes = [
        "https://",
        "http://",
        "wss://",
        "ws://",
        "ftp://",
        "ssh://",
        "git://",
    ]
    private static let bareHostExecutables: Set<String> = [
        "curl",
        "wget",
        "ping",
        "nc",
        "netcat",
        "ssh",
    ]

    static func evidence(
        from samples: [InjectedProcessTreeSample],
        observedAt: Date
    ) -> [AgentNetworkDomainObservation] {
        var observationsByKey: [String: AgentNetworkDomainObservation] = [:]
        for sample in samples {
            let executable = URL(fileURLWithPath: sample.executable)
                .lastPathComponent
                .lowercased()
            let arguments = AgentCommandRedactor.redactedArguments(sample.arguments)
            for (index, argument) in arguments.enumerated() {
                let previousArgument = index > 0 ? arguments[index - 1] : nil
                guard !isSensitiveOptionValue(
                    argument,
                    previousArgument: previousArgument
                ) else {
                    continue
                }
                for hostname in hostnames(
                    in: argument,
                    acceptsBareHostname: index > 0
                        && bareHostExecutables.contains(executable)
                ) {
                    let observation = AgentNetworkDomainObservation(
                        observedAt: observedAt,
                        pid: sample.pid,
                        processStartTime: sample.startTime,
                        executable: sample.executable,
                        hostname: hostname,
                        source: .commandArgument,
                        confidence: .inferred
                    )
                    let key = [
                        sample.identityKey,
                        hostname,
                        observation.source.rawValue,
                    ].joined(separator: ":")
                    observationsByKey[key] = observation
                }
            }
        }
        return observationsByKey.values.sorted {
            if $0.pid == $1.pid {
                return $0.hostname < $1.hostname
            }
            return $0.pid < $1.pid
        }
    }

    private static func hostnames(
        in argument: String,
        acceptsBareHostname: Bool
    ) -> Set<String> {
        guard !isEnvironmentAssignment(argument) else { return [] }
        var hostnames: Set<String> = []
        let tokens = argument.components(separatedBy: tokenSeparators)
            .map { $0.trimmingCharacters(in: tokenTrimCharacters) }
            .filter { !$0.isEmpty }

        for token in tokens {
            if let hostname = hostnameFromURLToken(token) {
                hostnames.insert(hostname)
            }
            if let hostname = hostnameFromGitRemote(token) {
                hostnames.insert(hostname)
            }
            if acceptsBareHostname,
               !token.hasPrefix("-"),
               let hostname = normalizedHostname(token) {
                hostnames.insert(hostname)
            }
        }
        return hostnames
    }

    private static func hostnameFromURLToken(_ token: String) -> String? {
        let lowercased = token.lowercased()
        for scheme in urlSchemes {
            guard let range = lowercased.range(of: scheme) else { continue }
            let urlText = String(token[range.lowerBound...])
            guard let host = URLComponents(string: urlText)?.host else { continue }
            return normalizedHostname(host)
        }
        return nil
    }

    private static func hostnameFromGitRemote(_ token: String) -> String? {
        guard !token.contains("://"),
              let at = token.firstIndex(of: "@"),
              let colon = token[at...].firstIndex(of: ":"),
              at < colon else {
            return nil
        }
        let hostStart = token.index(after: at)
        return normalizedHostname(String(token[hostStart..<colon]))
    }

    private static func normalizedHostname(_ rawValue: String) -> String? {
        let withoutPort: String
        if let colon = rawValue.firstIndex(of: ":") {
            withoutPort = String(rawValue[..<colon])
        } else {
            withoutPort = rawValue
        }
        let hostname = withoutPort
            .trimmingCharacters(in: CharacterSet(charactersIn: "."))
            .lowercased()
        guard hostname.count <= 253,
              hostname.contains("."),
              !hostname.contains(":") else {
            return nil
        }
        let labels = hostname.split(separator: ".", omittingEmptySubsequences: false)
        guard labels.count >= 2,
              labels.allSatisfy({ label in
                  !label.isEmpty
                      && label.count <= 63
                      && label.first != "-"
                      && label.last != "-"
                      && label.allSatisfy {
                          $0.isASCII && ($0.isLetter || $0.isNumber || $0 == "-")
                      }
              }),
              labels.last?.contains(where: \.isLetter) == true else {
            return nil
        }
        return hostname
    }

    private static func isEnvironmentAssignment(_ argument: String) -> Bool {
        guard let equals = argument.firstIndex(of: "=") else { return false }
        let name = argument[..<equals]
        return !name.hasPrefix("-")
            && !name.isEmpty
            && name.allSatisfy { $0.isLetter || $0.isNumber || $0 == "_" }
    }

    private static func isSensitiveOptionValue(
        _ argument: String,
        previousArgument: String?
    ) -> Bool {
        if let previousArgument,
           sensitiveOptionNames.contains(optionName(previousArgument)) {
            return true
        }
        guard argument.hasPrefix("-"), argument.contains("=") else {
            return false
        }
        return sensitiveOptionNames.contains(optionName(argument))
    }

    private static func optionName(_ argument: String) -> String {
        let name = argument.split(separator: "=", maxSplits: 1).first ?? ""
        return name.drop(while: { $0 == "-" }).lowercased()
    }

    private static let sensitiveOptionNames: Set<String> = [
        "authorization",
        "cookie",
        "data",
        "data-ascii",
        "data-binary",
        "data-raw",
        "data-urlencode",
        "form",
        "form-string",
        "h",
        "header",
        "pass",
        "password",
        "secret",
        "token",
        "u",
        "user",
    ]
    private static let tokenSeparators = CharacterSet.whitespacesAndNewlines
        .union(CharacterSet(charactersIn: "'\"()[]{};,"))
    private static let tokenTrimCharacters = CharacterSet(
        charactersIn: "'\"()[]{};,<>"
    )
}
