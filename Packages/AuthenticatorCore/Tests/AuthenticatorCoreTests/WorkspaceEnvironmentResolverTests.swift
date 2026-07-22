import Foundation
import XCTest
@testable import AuthenticatorCore

final class WorkspaceEnvironmentResolverTests: XCTestCase {
    func testActiveEnvironmentLeavesDeeperDefaultCandidateInactive() {
        let productionID = UUID(uuidString: "11111111-1111-1111-1111-111111111111")!
        let defaultID = UUID(uuidString: "22222222-2222-2222-2222-222222222222")!

        let resolution = WorkspaceEnvironmentResolver.resolve(
            candidates: [
                candidate(
                    id: productionID,
                    folderPath: "Workspaces/api",
                    environments: ["Production"]
                ),
                candidate(
                    id: defaultID,
                    folderPath: "Workspaces/api/services",
                    environments: []
                ),
            ],
            selection: .named("Production")
        )

        XCTAssertEqual(resolution.effective.map(\.itemID), [productionID])
        XCTAssertEqual(resolution.inactive.map(\.itemID), [defaultID])
        XCTAssertTrue(resolution.issues.isEmpty)
    }

    func testNearestSourceScopeWinsWithinActiveEnvironment() {
        let rootID = UUID(uuidString: "33333333-3333-3333-3333-333333333333")!
        let nestedID = UUID(uuidString: "44444444-4444-4444-4444-444444444444")!

        let resolution = WorkspaceEnvironmentResolver.resolve(
            candidates: [
                candidate(
                    id: rootID,
                    folderPath: "Workspaces/api",
                    sourceScopePath: "/workspace",
                    environments: ["Production"]
                ),
                candidate(
                    id: nestedID,
                    folderPath: "Workspaces/api",
                    sourceScopePath: "/workspace/nested",
                    environments: ["Production"]
                ),
            ],
            selection: .named("Production")
        )

        XCTAssertEqual(resolution.effective.map(\.itemID), [nestedID])
        XCTAssertEqual(resolution.overridden.map(\.itemID), [rootID])
        XCTAssertTrue(resolution.issues.isEmpty)
    }

    func testActiveEnvironmentLeavesNearerDefaultSourceScopeInactive() {
        let productionID = UUID(uuidString: "55555555-5555-5555-5555-555555555555")!
        let nestedDefaultID = UUID(uuidString: "66666666-6666-6666-6666-666666666666")!

        let resolution = WorkspaceEnvironmentResolver.resolve(
            candidates: [
                candidate(
                    id: productionID,
                    folderPath: "Workspaces/api",
                    sourceScopePath: "/workspace",
                    environments: ["Production"]
                ),
                candidate(
                    id: nestedDefaultID,
                    folderPath: "Workspaces/api",
                    sourceScopePath: "/workspace/nested",
                    environments: []
                ),
            ],
            selection: .named("Production")
        )

        XCTAssertEqual(resolution.effective.map(\.itemID), [productionID])
        XCTAssertEqual(resolution.inactive.map(\.itemID), [nestedDefaultID])
        XCTAssertTrue(resolution.issues.isEmpty)
    }

    func testWorkspaceWideAvailabilityKeepsScopeLocalDefaultFallbackHealthy() {
        let defaultID = UUID(uuidString: "77777777-7777-7777-7777-777777777777")!

        let resolution = WorkspaceEnvironmentResolver.resolve(
            candidates: [
                candidate(
                    id: defaultID,
                    folderPath: "Workspaces/api",
                    sourceScopePath: "/workspace",
                    environments: [],
                    isLiteral: true
                ),
            ],
            selection: .named("Production"),
            availableEnvironments: ["Production"]
        )

        XCTAssertEqual(resolution.effective.map(\.itemID), [defaultID])
        XCTAssertTrue(resolution.issues.isEmpty)
    }

    func testNamedEnvironmentBlocksDefaultSecretFallback() {
        let defaultID = UUID(uuidString: "88888888-8888-8888-8888-888888888888")!

        let resolution = WorkspaceEnvironmentResolver.resolve(
            candidates: [
                candidate(
                    id: defaultID,
                    folderPath: "Workspaces/api",
                    environments: []
                ),
            ],
            selection: .named("Production"),
            availableEnvironments: ["Production"]
        )

        XCTAssertTrue(resolution.effective.isEmpty)
        XCTAssertEqual(resolution.inactive.map(\.itemID), [defaultID])
        XCTAssertEqual(resolution.issues.map(\.kind), [.missingEnvironmentValue])
    }

    func testAllIsGlobalFallbackWhileExactEnvironmentWins() {
        let defaultID = UUID(uuidString: "99999999-9999-9999-9999-999999999999")!
        let allID = UUID(uuidString: "AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA")!
        let productionID = UUID(uuidString: "BBBBBBBB-BBBB-BBBB-BBBB-BBBBBBBBBBBB")!
        let candidates = [
            candidate(id: defaultID, folderPath: "Workspaces/api", environments: []),
            candidate(id: allID, folderPath: "Workspaces/api", environments: ["All"]),
            candidate(id: productionID, folderPath: "Workspaces/api", environments: ["Production"]),
        ]

        let `default` = WorkspaceEnvironmentResolver.resolve(
            candidates: candidates,
            selection: .defaultOnly,
            availableEnvironments: ["All", "Production", "Staging"]
        )
        let staging = WorkspaceEnvironmentResolver.resolve(
            candidates: candidates,
            selection: .named("Staging"),
            availableEnvironments: ["All", "Production", "Staging"]
        )
        let production = WorkspaceEnvironmentResolver.resolve(
            candidates: candidates,
            selection: .named("Production"),
            availableEnvironments: ["All", "Production", "Staging"]
        )

        XCTAssertEqual(`default`.effective.map(\.itemID), [defaultID])
        XCTAssertEqual(staging.effective.map(\.itemID), [allID])
        XCTAssertEqual(production.effective.map(\.itemID), [productionID])
        XCTAssertEqual(production.overridden.map(\.itemID), [allID])
        XCTAssertEqual(production.availableEnvironments, ["Production", "Staging"])
    }

    private func candidate(
        id: UUID,
        folderPath: String,
        sourceScopePath: String? = nil,
        environments: [String],
        isLiteral: Bool = false
    ) -> WorkspaceEnvironmentCandidate {
        WorkspaceEnvironmentCandidate(
            id: id.uuidString,
            variableName: "DATABASE_URL",
            sourceTier: .configured,
            referenceField: isLiteral ? nil : "key",
            itemID: id,
            itemType: "api-key",
            itemName: "DATABASE_URL",
            folderPath: folderPath,
            sourceScopePath: sourceScopePath,
            environments: environments,
            isCLIEnabled: true,
            isLiteral: isLiteral
        )
    }
}
