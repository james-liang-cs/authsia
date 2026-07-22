import AuthenticatorBridge
import AuthenticatorCore
import Foundation

enum WorkspaceEnvironmentSuggestion {
    static func from(path: String) -> String? {
        let name = URL(fileURLWithPath: path).lastPathComponent.lowercased()
        let markers: [(String, String)] = [
            ("production", "Production"),
            ("development", "Development"),
            ("staging", "Staging"),
            ("testing", "Testing"),
            ("test", "Test"),
        ]
        return markers.first(where: { name.split(separator: ".").contains(Substring($0.0)) })?.1
    }
}

struct WorkspaceEnvironmentEvaluation {
    let resolution: WorkspaceEnvironmentResolution
    let environmentOverrides: [String: String]

    static func evaluate(
        config: WorkspaceConfig,
        payload: BridgeListPayload,
        selection: WorkspaceEnvironmentSelection
    ) -> WorkspaceEnvironmentEvaluation {
        let configured = configuredCandidates(config: config, payload: payload)
        return resolved(
            candidates: configured.candidates,
            valueByCandidateID: configured.values,
            selection: selection
        )
    }

    static func evaluate(
        config: WorkspaceConfig,
        envFiles: [String],
        explicitEnvFiles: [String] = [],
        workspaceEnvFiles: [String]? = nil,
        payload: BridgeListPayload,
        selection: WorkspaceEnvironmentSelection
    ) throws -> WorkspaceEnvironmentEvaluation {
        let configured = configuredCandidates(config: config, payload: payload)
        var valueByCandidateID = configured.values
        var allCandidates = configured.candidates

        for (fileIndex, path) in envFiles.enumerated() {
            for (entryIndex, entry) in try EnvFileParser.parse(contentsOf: path).enumerated() {
                let candidateID = "file-\(fileIndex)-\(entryIndex)"
                for candidate in candidates(
                    id: candidateID,
                    name: entry.key,
                    value: entry.value,
                    sourceTier: .configured,
                    sourceScopePath: URL(fileURLWithPath: path)
                        .deletingLastPathComponent()
                        .standardizedFileURL.path,
                    payload: payload
                ) {
                    valueByCandidateID[candidate.id] = (entry.key, entry.value)
                    allCandidates.append(candidate)
                }
            }
        }

        for (fileIndex, path) in explicitEnvFiles.enumerated() {
            for (entryIndex, entry) in try EnvFileParser.parse(contentsOf: path).enumerated() {
                let candidateID = "explicit-file-\(fileIndex)-\(entryIndex)"
                for candidate in candidates(
                    id: candidateID,
                    name: entry.key,
                    value: entry.value,
                    sourceTier: .explicitOneRun,
                    payload: payload
                ) {
                    valueByCandidateID[candidate.id] = (entry.key, entry.value)
                    allCandidates.append(candidate)
                }
            }
        }

        let workspaceAvailableEnvironments: [String]?
        if let workspaceEnvFiles {
            var availabilityCandidates = configured.candidates
            for (fileIndex, path) in workspaceEnvFiles.enumerated() {
                for (entryIndex, entry) in try EnvFileParser.parse(contentsOf: path).enumerated() {
                    availabilityCandidates.append(contentsOf: candidates(
                        id: "workspace-file-\(fileIndex)-\(entryIndex)",
                        name: entry.key,
                        value: entry.value,
                        sourceTier: .configured,
                        sourceScopePath: URL(fileURLWithPath: path)
                            .deletingLastPathComponent()
                            .standardizedFileURL.path,
                        payload: payload
                    ))
                }
            }
            workspaceAvailableEnvironments = VaultEnvironmentTags.normalize(
                (availabilityCandidates + allCandidates).flatMap(\.environments)
            )
        } else {
            workspaceAvailableEnvironments = nil
        }

        return resolved(
            candidates: allCandidates,
            valueByCandidateID: valueByCandidateID,
            selection: selection,
            availableEnvironments: workspaceAvailableEnvironments
        )
    }

    private static func configuredCandidates(
        config: WorkspaceConfig,
        payload: BridgeListPayload
    ) -> (candidates: [WorkspaceEnvironmentCandidate], values: [String: (name: String, value: String)]) {
        var values: [String: (name: String, value: String)] = [:]
        var resolvedCandidates: [WorkspaceEnvironmentCandidate] = []
        for (index, binding) in config.envBindings.enumerated() {
            let candidateID = "binding-\(index)"
            for candidate in candidates(
                id: candidateID,
                name: binding.name,
                value: binding.reference,
                sourceTier: .configured,
                payload: payload
            ) {
                values[candidate.id] = (binding.name, binding.reference)
                resolvedCandidates.append(candidate)
            }
        }
        return (resolvedCandidates, values)
    }

    private static func resolved(
        candidates: [WorkspaceEnvironmentCandidate],
        valueByCandidateID: [String: (name: String, value: String)],
        selection: WorkspaceEnvironmentSelection,
        availableEnvironments: [String]? = nil
    ) -> WorkspaceEnvironmentEvaluation {
        let resolution = WorkspaceEnvironmentResolver.resolve(
            candidates: candidates,
            selection: selection,
            availableEnvironments: availableEnvironments
        )
        let overrides = Dictionary(uniqueKeysWithValues: resolution.effective.compactMap { candidate in
            valueByCandidateID[candidate.id].map {
                ($0.name, runtimeValue(for: candidate, configuredValue: $0.value))
            }
        })
        return WorkspaceEnvironmentEvaluation(resolution: resolution, environmentOverrides: overrides)
    }

    private static func runtimeValue(
        for candidate: WorkspaceEnvironmentCandidate,
        configuredValue: String
    ) -> String {
        guard let reference = try? SecretReference.parse(configuredValue),
              let itemID = candidate.itemID else {
            return configuredValue
        }
        let field = reference.field.map { "/\($0)" } ?? ""
        return "authsia://\(reference.type.rawValue)/\(itemID.uuidString)\(field)"
    }

    private static func candidates(
        id: String,
        name: String,
        value: String,
        sourceTier: WorkspaceCandidateSourceTier,
        sourceScopePath: String? = nil,
        payload: BridgeListPayload
    ) -> [WorkspaceEnvironmentCandidate] {
        guard SecretReference.isSecretReference(value) else {
            return [WorkspaceEnvironmentCandidate(
                id: id,
                variableName: name,
                sourceTier: sourceTier,
                referenceField: nil,
                itemID: nil,
                itemType: nil,
                itemName: nil,
                folderPath: nil,
                sourceScopePath: sourceScopePath,
                environments: [],
                isCLIEnabled: true,
                isLiteral: true
            )]
        }
        guard let reference = try? SecretReference.parse(value),
              let type = queryType(reference.type) else {
            return [WorkspaceEnvironmentCandidate(
                id: id,
                variableName: name,
                sourceTier: sourceTier,
                referenceField: nil,
                itemID: nil,
                itemType: nil,
                itemName: nil,
                folderPath: nil,
                sourceScopePath: sourceScopePath,
                environments: [],
                isCLIEnabled: true,
                isLiteral: false
            )]
        }
        let matches = VaultItemQueryResolver.matchingCandidates(
            type: type,
            query: reference.item,
            folder: reference.folder,
            payload: payload
        )
        guard !matches.isEmpty else {
            return [WorkspaceEnvironmentCandidate(
                id: id,
                variableName: name,
                sourceTier: sourceTier,
                referenceField: nil,
                itemID: nil,
                itemType: nil,
                itemName: nil,
                folderPath: nil,
                sourceScopePath: sourceScopePath,
                environments: [],
                isCLIEnabled: true,
                isLiteral: false
            )]
        }
        return matches.map { metadata in
            WorkspaceEnvironmentCandidate(
                id: "\(id)#\(metadata.id.uuidString.lowercased())",
                variableName: name,
                sourceTier: sourceTier,
                referenceField: reference.resolvedField,
                itemID: metadata.id,
                itemType: reference.type.rawValue,
                itemName: metadata.name,
                folderPath: metadata.folderPath,
                sourceScopePath: sourceScopePath,
                environments: metadata.environments,
                isCLIEnabled: isCLIEnabled(type: type, id: metadata.id, payload: payload),
                isLiteral: false
            )
        }
    }

    private static func queryType(_ type: SecretReference.ItemType) -> VaultItemQueryType? {
        switch type {
        case .password: return .password
        case .apiKey: return .apiKey
        case .cert: return .certificate
        case .note: return .note
        case .ssh: return .ssh
        case .otp: return nil
        }
    }

    private static func isCLIEnabled(
        type: VaultItemQueryType,
        id: UUID,
        payload: BridgeListPayload
    ) -> Bool {
        switch type {
        case .password: return payload.passwords.first(where: { $0.id == id })?.isCliEnabled ?? false
        case .apiKey: return payload.apiKeys.first(where: { $0.id == id })?.isCliEnabled ?? false
        case .certificate: return payload.certificates.first(where: { $0.id == id })?.isCliEnabled ?? false
        case .note: return payload.notes.first(where: { $0.id == id })?.isCliEnabled ?? false
        case .ssh: return payload.sshKeys.first(where: { $0.id == id })?.isCliEnabled ?? false
        }
    }
}
