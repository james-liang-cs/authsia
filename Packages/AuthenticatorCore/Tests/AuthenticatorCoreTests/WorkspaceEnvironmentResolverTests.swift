import Foundation
import XCTest
@testable import AuthenticatorCore

final class WorkspaceEnvironmentResolverTests: XCTestCase {
    func testActiveEnvironmentOverridesDeeperDefaultCandidate() {
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
        XCTAssertEqual(resolution.overridden.map(\.itemID), [defaultID])
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

    func testActiveEnvironmentOverridesNearerDefaultSourceScope() {
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
        XCTAssertEqual(resolution.overridden.map(\.itemID), [nestedDefaultID])
        XCTAssertTrue(resolution.issues.isEmpty)
    }

    private func candidate(
        id: UUID,
        folderPath: String,
        sourceScopePath: String? = nil,
        environments: [String]
    ) -> WorkspaceEnvironmentCandidate {
        WorkspaceEnvironmentCandidate(
            id: id.uuidString,
            variableName: "DATABASE_URL",
            sourceTier: .configured,
            referenceField: "key",
            itemID: id,
            itemType: "api-key",
            itemName: "DATABASE_URL",
            folderPath: folderPath,
            sourceScopePath: sourceScopePath,
            environments: environments,
            isCLIEnabled: true,
            isLiteral: false
        )
    }
}
