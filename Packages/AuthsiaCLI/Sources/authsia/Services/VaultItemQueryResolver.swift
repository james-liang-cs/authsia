import AuthenticatorBridge
import AuthenticatorCore
import Foundation

enum VaultItemQueryType: String {
    case password
    case apiKey = "api-key"
    case certificate
    case note
    case ssh
}

enum VaultItemQueryResolver {
    struct Candidate: Equatable {
        let id: UUID
        let name: String
        let folderPath: String?
        let environments: [String]
    }

    static func resolve(
        type: VaultItemQueryType,
        query: String,
        environment: String?,
        folder: String? = nil,
        payload: BridgeListPayload
    ) throws -> UUID {
        try resolveCandidate(
            type: type,
            query: query,
            environment: environment,
            folder: folder,
            payload: payload
        ).id
    }

    static func resolveCandidate(
        type: VaultItemQueryType,
        query: String,
        environment: String?,
        folder: String? = nil,
        payload: BridgeListPayload
    ) throws -> Candidate {
        let normalizedFolder = normalizeFolderPath(folder)
        var candidates = candidates(type: type, payload: payload).filter { candidate in
            let environmentMatches = environment.map {
                candidate.environments.isEmpty || VaultEnvironmentTags.contains($0, in: candidate.environments)
            } ?? true
            let folderMatches = normalizedFolder.map { candidate.folderPath == $0 } ?? true
            return environmentMatches && folderMatches
        }
        if environment != nil {
            let exactTaggedNames: Set<String> = Set(candidates.compactMap { candidate -> String? in
                guard !candidate.environments.isEmpty,
                      candidate.name.caseInsensitiveCompare(query) == .orderedSame else { return nil }
                return candidate.name.lowercased()
            })
            if !exactTaggedNames.isEmpty {
                candidates.removeAll {
                    $0.environments.isEmpty && exactTaggedNames.contains($0.name.lowercased())
                }
            }
        }

        return try MatchHelper.findSingle(
            query: query,
            items: candidates,
            kind: type.rawValue,
            id: { $0.id.uuidString },
            searchable: { [$0.name] },
            display: {
                CLIError.MatchDescriptor(
                    name: $0.name,
                    id: $0.id.uuidString,
                    context: environmentDisplay($0.environments)
                )
            }
        )
    }

    static func matchingCandidates(
        type: VaultItemQueryType,
        query: String,
        folder: String? = nil,
        payload: BridgeListPayload
    ) -> [Candidate] {
        let normalizedFolder = normalizeFolderPath(folder)
        let scoped = candidates(type: type, payload: payload).filter { candidate in
            normalizedFolder.map { candidate.folderPath == $0 } ?? true
        }
        let trimmed = query.trimmingCharacters(in: .whitespacesAndNewlines)
        if let idMatch = scoped.first(where: { $0.id.uuidString.caseInsensitiveCompare(trimmed) == .orderedSame }) {
            return [idMatch]
        }
        let exactCaseMatches = scoped.filter { $0.name == trimmed }
        if !exactCaseMatches.isEmpty { return exactCaseMatches }
        let exactMatches = scoped.filter { $0.name.caseInsensitiveCompare(trimmed) == .orderedSame }
        if !exactMatches.isEmpty { return exactMatches }
        let lowered = trimmed.lowercased()
        return scoped.filter { $0.name.lowercased().contains(lowered) }
    }

    private static func candidates(type: VaultItemQueryType, payload: BridgeListPayload) -> [Candidate] {
        switch type {
        case .password:
            return payload.passwords.map { Candidate(id: $0.id, name: $0.name, folderPath: $0.folderPath, environments: $0.environments) }
        case .apiKey:
            return payload.apiKeys.map { Candidate(id: $0.id, name: $0.name, folderPath: $0.folderPath, environments: $0.environments) }
        case .certificate:
            return payload.certificates.map { Candidate(id: $0.id, name: $0.name, folderPath: $0.folderPath, environments: $0.environments) }
        case .note:
            return payload.notes.map { Candidate(id: $0.id, name: $0.title, folderPath: $0.folderPath, environments: $0.environments) }
        case .ssh:
            return payload.sshKeys.map { Candidate(id: $0.id, name: $0.name, folderPath: $0.folderPath, environments: $0.environments) }
        }
    }

    private static func environmentDisplay(_ environments: [String]) -> String {
        environments.isEmpty ? "Default environment" : environments.joined(separator: ", ")
    }
}
