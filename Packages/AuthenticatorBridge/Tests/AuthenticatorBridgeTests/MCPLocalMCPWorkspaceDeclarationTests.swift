import XCTest
@testable import AuthenticatorBridge

final class MCPLocalMCPWorkspaceDeclarationTests: XCTestCase {
    func testDeclareAppendsCredentialLessUpstreamAndLeavesClientFilesUntouched() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let authsia = root.appendingPathComponent(".authsia")
        try FileManager.default.createDirectory(at: authsia, withIntermediateDirectories: true)
        let config = authsia.appendingPathComponent("workspace.json")
        let client = root.appendingPathComponent("mcp.json")
        try writeJSON([
            "schemaVersion": 2,
            "workspace": ["name": "Demo", "authsiaFolder": "Demo"],
            "mcpUpstreams": [
                ["name": "echo", "command": "tools/echo-mcp", "env": [:] as [String: String]],
            ],
        ], to: config)
        try writeJSON(["mcpServers": ["playwright": ["command": "npx"]]], to: client)
        let originalClient = try Data(contentsOf: client)

        let outcome = try MCPLocalMCPWorkspaceDeclaration.declare(
            finding: wrapFinding(),
            workspaceRoot: root
        )

        XCTAssertEqual(outcome, .declared)
        let loaded = try JSONSerialization.jsonObject(with: Data(contentsOf: config)) as? [String: Any]
        let upstreams = loaded?["mcpUpstreams"] as? [[String: Any]]
        XCTAssertEqual(upstreams?.count, 2)
        XCTAssertEqual(upstreams?.last?["name"] as? String, "playwright")
        XCTAssertEqual(upstreams?.last?["command"] as? String, "npx")
        XCTAssertEqual(upstreams?.last?["args"] as? [String], ["-y", "@playwright/mcp"])
        XCTAssertEqual((loaded?["workspace"] as? [String: Any])?["name"] as? String, "Demo")
        XCTAssertEqual(try Data(contentsOf: client), originalClient)
        let text = String(decoding: try Data(contentsOf: config), as: UTF8.self)
        XCTAssertFalse(text.contains("TOKEN"))
        XCTAssertFalse(text.contains("authsia://"))
    }

    func testDeclareIsIdempotentForTheSameCommandAndRejectsNameCollision() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        try FileManager.default.createDirectory(
            at: root.appendingPathComponent(".authsia"),
            withIntermediateDirectories: true
        )
        let config = root.appendingPathComponent(".authsia/workspace.json")
        try writeJSON([
            "schemaVersion": 2,
            "workspace": ["name": "Demo", "authsiaFolder": "Demo"],
        ], to: config)

        XCTAssertEqual(
            try MCPLocalMCPWorkspaceDeclaration.declare(finding: wrapFinding(), workspaceRoot: root),
            .declared
        )
        XCTAssertEqual(
            try MCPLocalMCPWorkspaceDeclaration.declare(finding: wrapFinding(), workspaceRoot: root),
            .alreadyDeclared
        )

        var collision = wrapFinding()
        collision = MCPClientServerFinding(
            source: .codex,
            serverName: "playwright",
            commandLabel: "uvx",
            status: .unadmitted,
            declaredUpstreamName: nil,
            configPathLabel: "~/.codex/config.toml",
            wrapCommand: "uvx",
            wrapArguments: ["playwright"],
            isWrapEligible: true
        )
        XCTAssertThrowsError(
            try MCPLocalMCPWorkspaceDeclaration.declare(finding: collision, workspaceRoot: root)
        ) { error in
            XCTAssertEqual(
                error as? MCPLocalMCPWorkspaceDeclaration.DeclarationError,
                .duplicateName("playwright")
            )
        }
    }

    func testDeclareDoesNotCreateAWorkspaceAndSkipsIneligibleFindings() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)

        XCTAssertThrowsError(
            try MCPLocalMCPWorkspaceDeclaration.declare(finding: wrapFinding(), workspaceRoot: root)
        ) { error in
            XCTAssertEqual(
                error as? MCPLocalMCPWorkspaceDeclaration.DeclarationError,
                .missingConfig
            )
        }
        XCTAssertFalse(
            FileManager.default.fileExists(atPath: root.appendingPathComponent(".authsia/workspace.json").path)
        )

        XCTAssertNil(MCPLocalMCPWorkspaceDeclaration.candidateWorkspaceRoot(
            knownRoots: [root.path],
            grantWorkingDirectories: []
        ))

        let wrapped = MCPClientServerFinding(
            source: .codex,
            serverName: "jira",
            commandLabel: "authsia",
            status: .admittedWrapped,
            declaredUpstreamName: "jira",
            configPathLabel: "~/.codex/config.toml"
        )
        XCTAssertThrowsError(
            try MCPLocalMCPWorkspaceDeclaration.declare(finding: wrapped, workspaceRoot: root)
        ) { error in
            XCTAssertEqual(
                error as? MCPLocalMCPWorkspaceDeclaration.DeclarationError,
                .notWrapEligible
            )
        }
    }

    func testCandidateWorkspaceRootWalksFromAGrantWorkingDirectory() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let nested = root.appendingPathComponent("Sources/Feature")
        try FileManager.default.createDirectory(
            at: root.appendingPathComponent(".authsia"),
            withIntermediateDirectories: true
        )
        try FileManager.default.createDirectory(at: nested, withIntermediateDirectories: true)
        try Data("{}".utf8).write(to: root.appendingPathComponent(".authsia/workspace.json"))

        XCTAssertEqual(
            MCPLocalMCPWorkspaceDeclaration.candidateWorkspaceRoot(
                knownRoots: [],
                grantWorkingDirectories: [nested.path]
            )?.path,
            root.standardizedFileURL.path
        )
    }

    func testCandidateWorkspacesPrefersGrantMatchesAndPreselectsThem() throws {
        let grantRoot = try makeWorkspace(name: "Grant")
        let knownRoot = try makeWorkspace(name: "Known")
        defer {
            try? FileManager.default.removeItem(at: grantRoot)
            try? FileManager.default.removeItem(at: knownRoot)
        }
        let nested = grantRoot.appendingPathComponent("Sources/Feature")
        try FileManager.default.createDirectory(at: nested, withIntermediateDirectories: true)

        let candidates = MCPLocalMCPWorkspaceDeclaration.candidateWorkspaces(
            knownRoots: [knownRoot.path, grantRoot.path],
            grantWorkingDirectories: [nested.path]
        )

        XCTAssertEqual(candidates.map(\.displayName), ["Grant", "Known"])
        XCTAssertEqual(candidates.map(\.isPreferred), [true, false])
        XCTAssertEqual(
            candidates.map(\.root.path),
            [grantRoot.standardizedFileURL.path, knownRoot.standardizedFileURL.path]
        )
        XCTAssertEqual(
            MCPLocalMCPWorkspaceDeclaration.preselectedRootPaths(in: candidates),
            [grantRoot.standardizedFileURL.path]
        )
        XCTAssertEqual(
            MCPLocalMCPWorkspaceDeclaration.candidateWorkspaceRoot(
                knownRoots: [knownRoot.path],
                grantWorkingDirectories: [nested.path]
            )?.path,
            grantRoot.standardizedFileURL.path
        )
    }

    func testPreselectedRootPathsUsesFirstKnownWorkspaceWhenNoGrantMatch() throws {
        let recent = try makeWorkspace(name: "Recent")
        let older = try makeWorkspace(name: "Older")
        defer {
            try? FileManager.default.removeItem(at: recent)
            try? FileManager.default.removeItem(at: older)
        }

        let candidates = MCPLocalMCPWorkspaceDeclaration.candidateWorkspaces(
            knownRoots: [recent.path, older.path],
            grantWorkingDirectories: []
        )

        XCTAssertEqual(candidates.map(\.displayName), ["Recent", "Older"])
        XCTAssertEqual(candidates.map(\.isPreferred), [false, false])
        XCTAssertEqual(
            MCPLocalMCPWorkspaceDeclaration.preselectedRootPaths(in: candidates),
            [recent.standardizedFileURL.path]
        )
    }

    func testDeclareWritesSelectedWorkspacesIndependentlyAndDedupesRoots() throws {
        let first = try makeWorkspace(name: "One")
        let second = try makeWorkspace(name: "Two")
        defer {
            try? FileManager.default.removeItem(at: first)
            try? FileManager.default.removeItem(at: second)
        }

        let results = MCPLocalMCPWorkspaceDeclaration.declare(
            finding: wrapFinding(),
            workspaceRoots: [first, second, first]
        )

        XCTAssertEqual(results.count, 2)
        XCTAssertEqual(
            results.map { try? $0.outcome.get() },
            [.declared, .declared]
        )

        let already = MCPLocalMCPWorkspaceDeclaration.declare(
            finding: wrapFinding(),
            workspaceRoots: [first]
        )
        XCTAssertEqual(already.map { try? $0.outcome.get() }, [.alreadyDeclared])

        let collision = MCPClientServerFinding(
            source: .codex,
            serverName: "playwright",
            commandLabel: "uvx",
            status: .unadmitted,
            declaredUpstreamName: nil,
            configPathLabel: "~/.codex/config.toml",
            wrapCommand: "uvx",
            wrapArguments: ["playwright"],
            isWrapEligible: true
        )
        let mixed = MCPLocalMCPWorkspaceDeclaration.declare(
            finding: collision,
            workspaceRoots: [first, FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)]
        )
        XCTAssertEqual(mixed[0].outcome, .failure(.duplicateName("playwright")))
        XCTAssertEqual(mixed[1].outcome, .failure(.missingConfig))

        let loaded = try JSONSerialization.jsonObject(
            with: Data(contentsOf: second.appendingPathComponent(".authsia/workspace.json"))
        ) as? [String: Any]
        let upstreams = loaded?["mcpUpstreams"] as? [[String: Any]]
        XCTAssertEqual(upstreams?.last?["name"] as? String, "playwright")
        XCTAssertEqual((loaded?["workspace"] as? [String: Any])?["name"] as? String, "Two")
    }

    private func makeWorkspace(name: String) throws -> URL {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(
            at: root.appendingPathComponent(".authsia"),
            withIntermediateDirectories: true
        )
        try writeJSON(
            [
                "schemaVersion": 2,
                "workspace": ["name": name, "authsiaFolder": name],
            ],
            to: root.appendingPathComponent(".authsia/workspace.json")
        )
        return root
    }

    private func wrapFinding() -> MCPClientServerFinding {
        MCPClientServerFinding(
            source: .codex,
            serverName: "playwright",
            commandLabel: "npx",
            status: .unadmitted,
            declaredUpstreamName: nil,
            configPathLabel: "~/.codex/config.toml",
            wrapCommand: "npx",
            wrapArguments: ["-y", "@playwright/mcp"],
            isWrapEligible: true
        )
    }

    private func writeJSON(_ object: [String: Any], to url: URL) throws {
        try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys]).write(to: url)
    }
}
