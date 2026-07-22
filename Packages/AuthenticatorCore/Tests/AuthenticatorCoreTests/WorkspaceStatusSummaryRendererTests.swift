import XCTest
@testable import AuthenticatorCore

final class WorkspaceStatusSummaryRendererTests: XCTestCase {
    func testRendersWorkspaceStatusSummaryWithoutSecretValues() {
        let summary = WorkspaceStatusSummaryRenderer.render(
            managedEnvFiles: [
                WorkspaceStatusManagedEnvFile(relativePath: ".env", isMissing: false, authsiaReferenceCount: 2),
                WorkspaceStatusManagedEnvFile(relativePath: ".env.local", isMissing: true, authsiaReferenceCount: 0),
            ],
            agentRules: [
                WorkspaceStatusAgentRule(title: "Codex", isInstalled: true),
                WorkspaceStatusAgentRule(title: "Claude Code", isInstalled: false),
            ]
        )

        XCTAssertEqual(summary.managedEnvFilesText, ".env, .env.local")
        XCTAssertEqual(summary.agentRulesText, "Codex installed, Claude Code missing")
        XCTAssertEqual(summary.healthSummary, "Needs attention")
        XCTAssertEqual(summary.healthDetail, "1 missing env file - 1 missing agent rule - 2 authsia:// refs")
        XCTAssertFalse(String(describing: summary).contains("sk_live"))
        XCTAssertFalse(String(describing: summary).contains("authsia://password"))
    }

    func testRendersReadyWorkspaceWithEmptyLists() {
        let summary = WorkspaceStatusSummaryRenderer.render(managedEnvFiles: [], agentRules: [])

        XCTAssertEqual(summary.managedEnvFilesText, "none")
        XCTAssertEqual(summary.envBindingsText, "none")
        XCTAssertEqual(summary.agentRulesText, "none")
        XCTAssertEqual(summary.healthSummary, "Ready")
        XCTAssertEqual(summary.healthDetail, "0 authsia:// refs")
    }

    func testRendersWorkspaceEnvBindingsAsAuthsiaRefsWithoutSecretValues() {
        let summary = WorkspaceStatusSummaryRenderer.render(
            managedEnvFiles: [],
            envBindings: [
                WorkspaceStatusEnvBinding(name: "API_KEY"),
                WorkspaceStatusEnvBinding(name: "HF_TOKEN"),
            ],
            agentRules: []
        )

        XCTAssertEqual(summary.managedEnvFilesText, "none")
        XCTAssertEqual(summary.envBindingsText, "API_KEY, HF_TOKEN")
        XCTAssertEqual(summary.healthSummary, "Ready")
        XCTAssertEqual(summary.healthDetail, "2 authsia:// refs")
        XCTAssertFalse(String(describing: summary).contains("authsia://password"))
    }

    func testMissingReferencesAndFolderNeedAttention() {
        let summary = WorkspaceStatusSummaryRenderer.render(
            managedEnvFiles: [
                WorkspaceStatusManagedEnvFile(relativePath: ".env", isMissing: false, authsiaReferenceCount: 1),
            ],
            agentRules: [],
            missingReferenceCount: 1,
            workspaceFolder: WorkspaceStatusWorkspaceFolder(isMissing: true)
        )

        XCTAssertEqual(summary.healthSummary, "Needs attention")
        XCTAssertEqual(summary.healthDetail, "1 missing Authsia reference - missing Authsia folder - 1 authsia:// ref")
    }

    func testEnvironmentResolutionIssuesNeedAttention() {
        let summary = WorkspaceStatusSummaryRenderer.render(
            managedEnvFiles: [],
            agentRules: [],
            environmentIssueCount: 2
        )

        XCTAssertEqual(summary.healthSummary, "Needs attention")
        XCTAssertEqual(summary.healthDetail, "2 environment resolution issues - 0 authsia:// refs")
    }
}
