import Foundation

public enum WorkspaceEnvironmentSelection: Equatable, Sendable {
    case defaultOnly
    case named(String)
}

public enum WorkspaceCandidateSourceTier: Int, Comparable, Sendable {
    case configured = 0
    case explicitOneRun = 1

    public static func < (lhs: WorkspaceCandidateSourceTier, rhs: WorkspaceCandidateSourceTier) -> Bool {
        lhs.rawValue < rhs.rawValue
    }
}

public struct WorkspaceEnvironmentCandidate: Equatable, Identifiable, Sendable {
    public let id: String
    public let variableName: String
    public let sourceTier: WorkspaceCandidateSourceTier
    public let referenceField: String?
    public let itemID: UUID?
    public let itemType: String?
    public let itemName: String?
    public let folderPath: String?
    public let sourceScopePath: String?
    public let environments: [String]
    public let isCLIEnabled: Bool
    public let isLiteral: Bool

    public init(
        id: String,
        variableName: String,
        sourceTier: WorkspaceCandidateSourceTier,
        referenceField: String?,
        itemID: UUID?,
        itemType: String?,
        itemName: String?,
        folderPath: String?,
        sourceScopePath: String? = nil,
        environments: [String],
        isCLIEnabled: Bool,
        isLiteral: Bool
    ) {
        self.id = id
        self.variableName = variableName
        self.sourceTier = sourceTier
        self.referenceField = referenceField
        self.itemID = itemID
        self.itemType = itemType
        self.itemName = itemName
        self.folderPath = folderPath
        self.sourceScopePath = sourceScopePath
        self.environments = VaultEnvironmentTags.normalize(environments)
        self.isCLIEnabled = isCLIEnabled
        self.isLiteral = isLiteral
    }
}

public struct WorkspaceEnvironmentIssue: Equatable, Sendable {
    public enum Kind: String, Equatable, Sendable {
        case staleSelection
        case conflict
        case cliDisabled
        case missingReference
    }

    public let kind: Kind
    public let variableName: String?
    public let candidateIDs: [String]

    public init(kind: Kind, variableName: String?, candidateIDs: [String]) {
        self.kind = kind
        self.variableName = variableName
        self.candidateIDs = candidateIDs
    }
}

public struct WorkspaceEnvironmentResolution: Equatable, Sendable {
    public let selection: WorkspaceEnvironmentSelection
    public let availableEnvironments: [String]
    public let effective: [WorkspaceEnvironmentCandidate]
    public let overridden: [WorkspaceEnvironmentCandidate]
    public let inactive: [WorkspaceEnvironmentCandidate]
    public let issues: [WorkspaceEnvironmentIssue]

    public init(
        selection: WorkspaceEnvironmentSelection,
        availableEnvironments: [String],
        effective: [WorkspaceEnvironmentCandidate],
        overridden: [WorkspaceEnvironmentCandidate],
        inactive: [WorkspaceEnvironmentCandidate],
        issues: [WorkspaceEnvironmentIssue]
    ) {
        self.selection = selection
        self.availableEnvironments = availableEnvironments
        self.effective = effective
        self.overridden = overridden
        self.inactive = inactive
        self.issues = issues
    }
}

public enum WorkspaceEnvironmentResolver {
    public static func resolve(
        candidates: [WorkspaceEnvironmentCandidate],
        selection: WorkspaceEnvironmentSelection
    ) -> WorkspaceEnvironmentResolution {
        let normalizedSelection = normalize(selection)
        let available = VaultEnvironmentTags.normalize(candidates.flatMap(\.environments))
        let isStaleSelection: Bool
        if case .named(let name) = normalizedSelection {
            isStaleSelection = !VaultEnvironmentTags.contains(name, in: available)
        } else {
            isStaleSelection = false
        }

        var effective: [WorkspaceEnvironmentCandidate] = []
        var overridden: [WorkspaceEnvironmentCandidate] = []
        var inactive: [WorkspaceEnvironmentCandidate] = []
        var issues: [WorkspaceEnvironmentIssue] = []

        let grouped = Dictionary(grouping: candidates) { $0.variableName.uppercased() }
        for key in grouped.keys.sorted() {
            let group = grouped[key] ?? []
            let eligible = group.filter { allows($0, selection: normalizedSelection) }
            inactive.append(contentsOf: group.filter { !allows($0, selection: normalizedSelection) })
            guard let highestTier = eligible.map(\.sourceTier).max() else { continue }

            let tierCandidates = eligible.filter { $0.sourceTier == highestTier }
            overridden.append(contentsOf: eligible.filter { $0.sourceTier < highestTier })

            let environmentSpecific: [WorkspaceEnvironmentCandidate]
            if case .named(let name) = normalizedSelection {
                let tagged = tierCandidates.filter { VaultEnvironmentTags.contains(name, in: $0.environments) }
                if tagged.isEmpty {
                    environmentSpecific = tierCandidates.filter(\.environments.isEmpty)
                } else {
                    environmentSpecific = tagged
                    overridden.append(contentsOf: tierCandidates.filter(\.environments.isEmpty))
                }
            } else {
                environmentSpecific = tierCandidates.filter(\.environments.isEmpty)
            }

            let scopeSpecific = mostSpecificSourceScopeCandidates(environmentSpecific)
            let scopeSpecificIDs = Set(scopeSpecific.map(\.id))
            overridden.append(contentsOf: environmentSpecific.filter { !scopeSpecificIDs.contains($0.id) })

            let folderSpecific = mostSpecificFolderCandidates(scopeSpecific)
            let folderSpecificIDs = Set(folderSpecific.map(\.id))
            overridden.append(contentsOf: scopeSpecific.filter { !folderSpecificIDs.contains($0.id) })

            var valid: [WorkspaceEnvironmentCandidate] = []
            for candidate in folderSpecific {
                if !candidate.isCLIEnabled {
                    issues.append(issue(.cliDisabled, candidate: candidate))
                    continue
                }
                if !candidate.isLiteral && candidate.referenceField == nil {
                    issues.append(issue(.missingReference, candidate: candidate))
                    continue
                }
                valid.append(candidate)
            }

            let unique = deduplicated(valid)
            if unique.count > 1 {
                issues.append(
                    WorkspaceEnvironmentIssue(
                        kind: .conflict,
                        variableName: unique.first?.variableName,
                        candidateIDs: unique.map(\.id).sorted()
                    )
                )
            } else {
                effective.append(contentsOf: unique)
            }
        }

        if isStaleSelection {
            issues.append(WorkspaceEnvironmentIssue(kind: .staleSelection, variableName: nil, candidateIDs: []))
        }

        return WorkspaceEnvironmentResolution(
            selection: normalizedSelection,
            availableEnvironments: available,
            effective: sorted(effective),
            overridden: sorted(overridden),
            inactive: sorted(inactive),
            issues: issues.sorted { lhs, rhs in
                (lhs.variableName ?? "", lhs.kind.rawValue, lhs.candidateIDs.joined()) <
                    (rhs.variableName ?? "", rhs.kind.rawValue, rhs.candidateIDs.joined())
            }
        )
    }

    private static func normalize(_ selection: WorkspaceEnvironmentSelection) -> WorkspaceEnvironmentSelection {
        switch selection {
        case .defaultOnly:
            return .defaultOnly
        case .named(let name):
            return .named(VaultEnvironmentTags.normalize([name]).first ?? "")
        }
    }

    private static func allows(
        _ candidate: WorkspaceEnvironmentCandidate,
        selection: WorkspaceEnvironmentSelection
    ) -> Bool {
        switch selection {
        case .defaultOnly:
            return candidate.environments.isEmpty
        case .named(let name):
            return candidate.environments.isEmpty || VaultEnvironmentTags.contains(name, in: candidate.environments)
        }
    }

    private static func deduplicated(
        _ candidates: [WorkspaceEnvironmentCandidate]
    ) -> [WorkspaceEnvironmentCandidate] {
        var seen = Set<String>()
        return candidates.filter { seen.insert(identity($0)).inserted }
    }

    private static func mostSpecificFolderCandidates(
        _ candidates: [WorkspaceEnvironmentCandidate]
    ) -> [WorkspaceEnvironmentCandidate] {
        guard candidates.count > 1,
              candidates.allSatisfy({ normalizeFolderPath($0.folderPath) != nil }) else {
            return candidates
        }

        let nested = candidates.filter { candidate in
            guard let folder = normalizeFolderPath(candidate.folderPath) else { return false }
            return candidates.allSatisfy { other in
                guard let otherFolder = normalizeFolderPath(other.folderPath) else { return false }
                return folder == otherFolder || folder.hasPrefix(otherFolder + "/")
            }
        }
        return nested.isEmpty ? candidates : nested
    }

    private static func mostSpecificSourceScopeCandidates(
        _ candidates: [WorkspaceEnvironmentCandidate]
    ) -> [WorkspaceEnvironmentCandidate] {
        guard candidates.count > 1 else { return candidates }
        let scopes = Dictionary(uniqueKeysWithValues: candidates.compactMap { candidate in
            normalizedSourceScopePath(candidate.sourceScopePath).map { (candidate.id, $0) }
        })
        guard scopes.count == candidates.count else { return candidates }

        let nested = candidates.filter { candidate in
            guard let scope = scopes[candidate.id] else { return false }
            return candidates.allSatisfy { other in
                guard let otherScope = scopes[other.id], scope.count >= otherScope.count else { return false }
                return Array(scope.prefix(otherScope.count)) == otherScope
            }
        }
        return nested.isEmpty ? candidates : nested
    }

    private static func identity(_ candidate: WorkspaceEnvironmentCandidate) -> String {
        let item = candidate.itemID?.uuidString ?? candidate.id
        let field = candidate.referenceField ?? "literal"
        return "\(item.lowercased())|\(field.lowercased())"
    }

    private static func issue(
        _ kind: WorkspaceEnvironmentIssue.Kind,
        candidate: WorkspaceEnvironmentCandidate
    ) -> WorkspaceEnvironmentIssue {
        WorkspaceEnvironmentIssue(kind: kind, variableName: candidate.variableName, candidateIDs: [candidate.id])
    }

    private static func sorted(
        _ candidates: [WorkspaceEnvironmentCandidate]
    ) -> [WorkspaceEnvironmentCandidate] {
        candidates.sorted {
            ($0.variableName.uppercased(), $0.id) < ($1.variableName.uppercased(), $1.id)
        }
    }

    private static func normalizeFolderPath(_ path: String?) -> String? {
        guard let path else { return nil }
        let segments = path
            .split(separator: "/")
            .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
            .filter { !$0.isEmpty }
        guard !segments.isEmpty else { return nil }
        return segments.joined(separator: "/")
    }

    private static func normalizedSourceScopePath(_ path: String?) -> [String]? {
        guard let path, !path.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            return nil
        }
        return path
            .split(separator: "/")
            .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
            .filter { !$0.isEmpty && $0 != "." }
    }
}
