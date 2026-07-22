import AuthenticatorCore
import Foundation
import Testing
@testable import authsia

@Suite("Workspace environment resolver")
struct WorkspaceEnvironmentResolverTests {
    private let defaultEnvironmentID = UUID(uuidString: "11111111-1111-1111-1111-111111111111")!
    private let developmentID = UUID(uuidString: "22222222-2222-2222-2222-222222222222")!
    private let productionID = UUID(uuidString: "33333333-3333-3333-3333-333333333333")!

    @Test("Default-environment and named selections stay isolated")
    func selectionsApplyPrecedence() {
        let candidates = [
            candidate(id: defaultEnvironmentID, environments: []),
            candidate(id: developmentID, environments: ["Development"]),
            candidate(id: productionID, environments: ["Production"]),
        ]

        let `default` = WorkspaceEnvironmentResolver.resolve(candidates: candidates, selection: .defaultOnly)
        let development = WorkspaceEnvironmentResolver.resolve(candidates: candidates, selection: .named("Development"))
        let production = WorkspaceEnvironmentResolver.resolve(candidates: candidates, selection: .named("Production"))

        #expect(`default`.effective.map(\.itemID) == [defaultEnvironmentID])
        #expect(development.effective.map(\.itemID) == [developmentID])
        #expect(production.effective.map(\.itemID) == [productionID])
        #expect(production.overridden.isEmpty)
        #expect(production.inactive.map(\.itemID) == [defaultEnvironmentID, developmentID])
        #expect(production.issues.isEmpty)
    }

    @Test("explicit source tier wins and same-tier active duplicates conflict")
    func sourceTierAndConflicts() {
        let configured = candidate(id: productionID, environments: ["Production"])
        let explicitID = UUID(uuidString: "44444444-4444-4444-4444-444444444444")!
        let explicit = candidate(id: explicitID, environments: ["Production"], sourceTier: .explicitOneRun)
        let winning = WorkspaceEnvironmentResolver.resolve(
            candidates: [configured, explicit],
            selection: .named("Production")
        )
        let conflict = WorkspaceEnvironmentResolver.resolve(
            candidates: [configured, candidate(id: explicitID, environments: ["Production"])],
            selection: .named("Production")
        )

        #expect(winning.effective.map(\.itemID) == [explicitID])
        #expect(winning.overridden.map(\.itemID) == [productionID])
        #expect(conflict.effective.isEmpty)
        #expect(conflict.issues.map(\.kind) == [.conflict])
    }

    @Test("duplicate item reference is deduplicated")
    func duplicateReferenceIsDeduplicated() {
        let duplicate = candidate(id: productionID, environments: ["Development", "Production"])
        let result = WorkspaceEnvironmentResolver.resolve(
            candidates: [duplicate, duplicate],
            selection: .named("Production")
        )

        #expect(result.effective.count == 1)
        #expect(result.issues.isEmpty)
    }

    @Test("active environment leaves a default item in a deeper folder inactive")
    func activeEnvironmentLeavesDeeperDefaultItemInactive() {
        let parent = candidate(
            id: productionID,
            environments: ["Production"],
            folder: "Workspaces/api"
        )
        let childID = UUID(uuidString: "44444444-4444-4444-4444-444444444444")!
        let child = candidate(
            id: childID,
            environments: [],
            folder: "Workspaces/api/services/payments"
        )

        let result = WorkspaceEnvironmentResolver.resolve(
            candidates: [parent, child],
            selection: .named("Production")
        )

        #expect(result.effective.map(\.itemID) == [productionID])
        #expect(result.inactive.map(\.itemID) == [childID])
        #expect(result.issues.isEmpty)
    }

    @Test("nested vault folder wins within the active environment tier")
    func nestedFolderWinsWithinActiveEnvironmentTier() {
        let parent = candidate(
            id: productionID,
            environments: ["Production"],
            folder: "Workspaces/api"
        )
        let childID = UUID(uuidString: "44444444-4444-4444-4444-444444444444")!
        let child = candidate(
            id: childID,
            environments: ["Production"],
            folder: "Workspaces/api/services/payments"
        )

        let result = WorkspaceEnvironmentResolver.resolve(
            candidates: [parent, child],
            selection: .named("Production")
        )

        #expect(result.effective.map(\.itemID) == [childID])
        #expect(result.overridden.map(\.itemID) == [productionID])
        #expect(result.issues.isEmpty)
    }

    @Test("unrelated folders remain a conflict")
    func unrelatedFoldersRemainConflict() {
        let siblingID = UUID(uuidString: "55555555-5555-5555-5555-555555555555")!
        let result = WorkspaceEnvironmentResolver.resolve(
            candidates: [
                candidate(id: productionID, environments: ["Production"], folder: "Workspaces/api/services"),
                candidate(id: siblingID, environments: ["Production"], folder: "Workspaces/api/workers"),
            ],
            selection: .named("Production")
        )

        #expect(result.effective.isEmpty)
        #expect(result.issues.map(\.kind) == [.conflict])
    }

    @Test("active environment leaves a default item in an unrelated folder inactive")
    func activeEnvironmentLeavesUnrelatedDefaultItemInactive() {
        let siblingID = UUID(uuidString: "88888888-8888-8888-8888-888888888888")!
        let result = WorkspaceEnvironmentResolver.resolve(
            candidates: [
                candidate(id: productionID, environments: ["Production"], folder: "Workspaces/api/services"),
                candidate(id: siblingID, environments: [], folder: "Workspaces/api/workers"),
            ],
            selection: .named("Production")
        )

        #expect(result.effective.map(\.itemID) == [productionID])
        #expect(result.inactive.map(\.itemID) == [siblingID])
        #expect(result.issues.isEmpty)
    }

    @Test("stale selection and disabled metadata produce redacted issues")
    func staleAndDisabledProduceIssues() {
        let disabled = candidate(id: productionID, environments: ["Production"], isCLIEnabled: false)
        let stale = WorkspaceEnvironmentResolver.resolve(candidates: [disabled], selection: .named("Staging"))
        let staleWithDefaultEnvironment = WorkspaceEnvironmentResolver.resolve(
            candidates: [candidate(id: defaultEnvironmentID, environments: []), disabled],
            selection: .named("Staging")
        )
        let selected = WorkspaceEnvironmentResolver.resolve(candidates: [disabled], selection: .named("Production"))

        #expect(stale.issues.map(\.kind) == [.staleSelection])
        #expect(staleWithDefaultEnvironment.issues.map(\.kind) == [.staleSelection])
        #expect(staleWithDefaultEnvironment.effective.isEmpty)
        #expect(staleWithDefaultEnvironment.inactive.map(\.itemID) == [defaultEnvironmentID, productionID])
        #expect(selected.issues.map(\.kind) == [.cliDisabled])
        #expect(selected.effective.isEmpty)
    }

    private func candidate(
        id: UUID,
        environments: [String],
        sourceTier: WorkspaceCandidateSourceTier = .configured,
        isCLIEnabled: Bool = true,
        folder: String? = nil
    ) -> WorkspaceEnvironmentCandidate {
        WorkspaceEnvironmentCandidate(
            id: id.uuidString,
            variableName: "DATABASE_URL",
            sourceTier: sourceTier,
            referenceField: "key",
            itemID: id,
            itemType: "api-key",
            itemName: "DATABASE_URL",
            folderPath: folder,
            environments: environments,
            isCLIEnabled: isCLIEnabled,
            isLiteral: false
        )
    }
}
