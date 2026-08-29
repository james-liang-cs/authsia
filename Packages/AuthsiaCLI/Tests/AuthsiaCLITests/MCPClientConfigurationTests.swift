import Foundation
import ArgumentParser
import AuthenticatorBridge
import Testing
@testable import authsia

@Suite("MCP client configuration")
struct MCPClientConfigurationTests {
    @Test("all supported clients receive deterministic global configuration")
    func supportedClients() throws {
        let fixture = try makeFixture()
        defer { try? FileManager.default.removeItem(at: fixture.root) }

        for client in MCPClient.allCases {
            let first = try MCPClientConfiguration.render(
                client: client,
                executableURL: fixture.binary
            )
            let second = try MCPClientConfiguration.render(
                client: client,
                executableURL: fixture.binary
            )

            #expect(first == second)
            #expect(first.contains(fixture.binary.path))
            #expect(!first.contains("cwd"))
            #expect(first.contains("mcp"))
            #expect(first.contains("serve"))
            #expect(first.contains("Machine-specific absolute path"))
            #expect(first.contains("The server can start from any directory"))
            #expect(first.contains("accepts an optional workspaceRoot tool argument"))
            #expect(first.contains("workspace tools remain unavailable"))
            #expect(first.contains("user-global"))
            #expect(!first.contains("AUTHSIA_ACCESS_CREDENTIAL"))
            #expect(!first.lowercased().contains("bearer"))
            #expect(!first.contains("sh -c"))
            #expect(!first.contains("bash -c"))
            #expect(first.contains("Proxy blocks appear here when mcpUpstreams are declared"))
        }
    }

    @Test("declared upstreams receive client-native proxy configuration")
    func declaredUpstreamConfiguration() throws {
        let fixture = try makeFixture()
        defer { try? FileManager.default.removeItem(at: fixture.root) }

        for client in MCPClient.allCases {
            let output = try MCPClientConfiguration.render(
                client: client,
                executableURL: fixture.binary,
                upstreamNames: ["jira"]
            )
            #expect(output.contains("mcp"))
            #expect(output.contains("proxy"))
            #expect(!output.contains("--upstream"))
            #expect(output.contains("AUTHSIA_MCP_UPSTREAM"))
            #expect(output.contains("jira"))
            #expect(!output.contains("--workspace"))
            #expect(!output.contains("authsia://"))
            #expect(!output.contains("synthetic-token"))
            #expect(!output.contains("Proxy blocks appear here"))
        }

        let codex = try MCPClientConfiguration.render(
            client: .codex,
            executableURL: fixture.binary,
            upstreamNames: ["jira"]
        )
        #expect(codex.contains("codex mcp add jira --"))
        #expect(codex.contains("--env AUTHSIA_MCP_UPSTREAM=jira"))
        #expect(codex.contains("[mcp_servers.jira]"))
        #expect(codex.contains("args = [\"mcp\", \"proxy\"]"))
        #expect(codex.contains("env_vars = [\"NODE_EXTRA_CA_CERTS\", \"REQUESTS_CA_BUNDLE\", \"SSL_CERT_FILE\"]"))
        #expect(codex.contains("AUTHSIA_MCP_UPSTREAM = \"jira\""))
        #expect(!codex.contains("--upstream"))

        let claude = try MCPClientConfiguration.render(
            client: .claude,
            executableURL: fixture.binary,
            upstreamNames: ["jira"]
        )
        // The name precedes the variadic `--env`; the other order makes
        // `claude mcp add` read the server name as another KEY=value.
        #expect(claude.contains("claude mcp add --scope user jira --env AUTHSIA_MCP_UPSTREAM=jira --"))
        #expect(claude.contains("\"jira\""))
        #expect(claude.contains("\"AUTHSIA_MCP_UPSTREAM\""))

        let cursor = try MCPClientConfiguration.render(
            client: .cursor,
            executableURL: fixture.binary,
            upstreamNames: ["jira"]
        )
        #expect(cursor.contains("\"authsia\""))
        #expect(cursor.contains("\"jira\""))

        let vscode = try MCPClientConfiguration.render(
            client: .vscode,
            executableURL: fixture.binary,
            upstreamNames: ["jira"]
        )
        #expect(vscode.contains("\"name\":\"jira\""))
        #expect(vscode.contains("\"jira\""))
        #expect(vscode.contains("\"type\":\"stdio\""))
    }

    @Test("configure discovers upstreams from the client workspace")
    func configureWorkspaceDiscovery() throws {
        let root = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        try WorkspaceConfigStore.write(
            WorkspaceConfig(
                workspace: .init(name: "client", authsiaFolder: "Workspaces/client"),
                managedEnvFiles: [],
                agents: nil,
                mcpUpstreams: [
                    MCPUpstreamConfig(
                        name: "jira",
                        command: "mcp-atlassian",
                        tools: MCPUpstreamToolPolicy(allow: ["jira_get_issue"])
                    )
                ]
            ),
            toWorkspaceRoot: root
        )
        let nested = root.appendingPathComponent("Sources/Feature", isDirectory: true)
        try FileManager.default.createDirectory(at: nested, withIntermediateDirectories: true)

        #expect(MCPCommand.Configure.upstreamNames(
            environment: ["WORKSPACE_FOLDER_PATHS": nested.path],
            currentDirectoryPath: "/tmp/fallback"
        ) == ["jira"])

        let empty = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: empty) }
        #expect(MCPCommand.Configure.upstreamNames(
            environment: [:],
            currentDirectoryPath: empty.path
        ).isEmpty)
    }

    @Test("scanner report states wrapped, bypass, and detective-only boundaries")
    func scannerReport() throws {
        let findings = [
            MCPClientServerFinding(
                source: .codex,
                serverName: "jira",
                commandLabel: "authsia",
                status: .admittedWrapped,
                declaredUpstreamName: "jira",
                configPathLabel: "~/.codex/config.toml",
                configScope: .userGlobal,
                precedence: .effective,
                workspacePathLabel: "~/repo"
            ),
            MCPClientServerFinding(
                source: .cursor,
                serverName: "filesystem",
                commandLabel: "npx",
                status: .directBypass,
                declaredUpstreamName: "filesystem",
                configPathLabel: "~/.cursor/mcp.json",
                configScope: .userGlobal,
                precedence: .conditional,
                workspacePathLabel: nil
            ),
            MCPClientServerFinding(
                source: .vscode,
                serverName: "rogue",
                commandLabel: "node",
                status: .unadmitted,
                declaredUpstreamName: nil,
                configPathLabel: "VS Code user mcp.json",
                configScope: .project,
                precedence: .overridden,
                workspacePathLabel: "~/repo"
            ),
        ]

        let report = try #require(MCPClientConfiguration.scanReport(findings))

        #expect(report.contains("wrapped and declared"))
        #expect(report.contains("approval is required before discovery or first call"))
        #expect(report.contains("bypasses admission"))
        #expect(report.contains("not on the current workspace allowlist"))
        #expect(report.contains("visibility only"))
        #expect(report.contains("does not edit client files or block them"))
        #expect(report.contains("User-global / Effective / ~/repo / ~/.codex/config.toml"))
        #expect(report.contains("Project / Overridden / ~/repo / VS Code user mcp.json"))
        #expect(MCPClientConfiguration.scanReport([]) == nil)
    }

    @Test("client shapes match their documented configuration surfaces")
    func clientShapes() throws {
        let fixture = try makeFixture()
        defer { try? FileManager.default.removeItem(at: fixture.root) }

        let codex = try render(.codex, fixture: fixture)
        #expect(codex.contains("codex mcp add authsia --"))
        #expect(codex.contains("~/.codex/config.toml"))
        #expect(codex.contains("[mcp_servers.authsia]"))
        #expect(codex.contains("args = [\"mcp\", \"serve\"]"))
        #expect(codex.contains("env_vars = [\"NODE_EXTRA_CA_CERTS\", \"REQUESTS_CA_BUNDLE\", \"SSL_CERT_FILE\"]"))
        #expect(codex.contains("For a custom TLS CA, use the manual configuration below."))
        #expect(!codex.contains("cwd ="))

        let claude = try render(.claude, fixture: fixture)
        #expect(claude.contains("claude mcp add --scope user authsia --"))
        #expect(claude.contains("~/.claude.json"))
        #expect(claude.contains("\"mcpServers\""))

        let cursor = try render(.cursor, fixture: fixture)
        #expect(!cursor.contains("Configure directly:"))
        #expect(cursor.contains("~/.cursor/mcp.json"))
        #expect(cursor.contains("\"mcpServers\""))
        #expect(!cursor.contains("\"--workspace\""))
        #expect(!cursor.contains("${workspaceFolder}"))

        let devin = try render(.devin, fixture: fixture)
        #expect(!devin.contains("Configure directly:"))
        #expect(devin.contains("~/.config/devin/mcp_config.json"))
        #expect(devin.contains("\"mcpServers\""))

        let vscode = try render(.vscode, fixture: fixture)
        #expect(vscode.contains("code --add-mcp"))
        #expect(vscode.contains("MCP: Open User Configuration"))
        #expect(vscode.contains("\"servers\""))
        #expect(vscode.contains("\"type" + "\" : \"stdio\""))
        #expect(!vscode.contains("\"cwd\""))
    }

    @Test("serve discovers one client workspace without fixed configuration")
    func serveWorkspaceDiscovery() throws {
        let fallback = "/tmp/fallback"

        #expect(MCPCommand.Serve.startingDirectory(
            workspace: "/tmp/explicit",
            environment: ["WORKSPACE_FOLDER_PATHS": "/tmp/client"],
            currentDirectoryPath: fallback
        ).path == "/tmp/explicit")
        #expect(MCPCommand.Serve.startingDirectory(
            workspace: nil,
            environment: ["WORKSPACE_FOLDER_PATHS": "/tmp/client"],
            currentDirectoryPath: fallback
        ).path == "/tmp/client")
        #expect(MCPCommand.Serve.startingDirectory(
            workspace: nil,
            environment: ["WORKSPACE_FOLDER_PATHS": "/tmp/one,/tmp/two"],
            currentDirectoryPath: fallback
        ).path == fallback)
        #expect(MCPCommand.Serve.startingDirectory(
            workspace: nil,
            environment: [:],
            currentDirectoryPath: fallback
        ).path == fallback)

        let root = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        try WorkspaceConfigStore.write(
            WorkspaceConfig(
                workspace: .init(name: "cursor", authsiaFolder: "Workspaces/cursor"),
                managedEnvFiles: [],
                agents: nil
            ),
            toWorkspaceRoot: root
        )
        let selected = MCPCommand.Serve.startingDirectory(
            workspace: nil,
            environment: ["WORKSPACE_FOLDER_PATHS": root.path],
            currentDirectoryPath: fallback
        )
        let runtime = MCPRuntimeContext(startingDirectory: selected)
        #expect(runtime.workspaceName == "cursor")
        #expect(runtime.workspaceRoot?.path == root.resolvingSymlinksInPath().path)
    }

    @Test("direct commands shell-quote machine-specific paths")
    func directCommandEscaping() throws {
        let binary = URL(fileURLWithPath: "/Applications/Authsia's App/authsia")

        let codex = try MCPClientConfiguration.render(client: .codex, executableURL: binary)
        #expect(codex.contains("'/Applications/Authsia'\\''s App/authsia'"))

        let vscode = try MCPClientConfiguration.render(client: .vscode, executableURL: binary)
        #expect(vscode.contains("Authsia'\\''s App"))
    }

    @Test("global configuration needs no workspace and unsafe values fail closed")
    func invalidInputs() throws {
        let safeBinary = URL(fileURLWithPath: "/Applications/Authsia.app/Contents/Helpers/authsia")

        let global = try MCPClientConfiguration.render(
            client: .codex,
            executableURL: safeBinary
        )
        #expect(global.contains("~/.codex/config.toml"))
        #expect(throws: MCPClientConfigurationError.self) {
            try MCPClientConfiguration.render(
                clientName: "codex\nmalicious",
                executableURL: safeBinary
            )
        }
        #expect(throws: MCPClientConfigurationError.self) {
            try MCPClientConfiguration.render(
                clientName: "unsupported",
                executableURL: safeBinary
            )
        }
        #expect(throws: MCPClientConfigurationError.self) {
            try MCPClientConfiguration.render(
                client: .codex,
                executableURL: safeBinary,
                upstreamNames: ["jira.injected"]
            )
        }
    }

    @Test("configure, serve, proxy, and doctor commands are visible")
    func commandRegistration() throws {
        #expect(MCPCommand.Configure.configuration.shouldDisplay)
        #expect(MCPCommand.Serve.configuration.shouldDisplay)
        #expect(MCPCommand.Proxy.configuration.shouldDisplay)
        #expect(MCPCommand.Doctor.configuration.shouldDisplay)
        _ = try Authsia.parseAsRoot(["mcp", "configure", "--client", "codex"])
        _ = try Authsia.parseAsRoot(["mcp", "configure", "--client", "devin"])
        _ = try Authsia.parseAsRoot(["mcp", "configure", "--client", "windsurf"])
        _ = try Authsia.parseAsRoot(["mcp", "serve", "--workspace", "/tmp/project"])
        _ = try Authsia.parseAsRoot(["mcp", "proxy", "--upstream", "jira"])
        _ = try Authsia.parseAsRoot(["mcp", "doctor", "--json"])
        _ = try Authsia.parseAsRoot(["mcp", "doctor", "--workspace", "/tmp/project", "--client", "cursor"])
    }

    @Test("proxy selects upstream from --upstream or AUTHSIA_MCP_UPSTREAM")
    func proxyUpstreamSelection() throws {
        #expect(try MCPCommand.Proxy.resolveUpstreamName(flag: "jira", environment: [:]) == "jira")
        #expect(
            try MCPCommand.Proxy.resolveUpstreamName(
                flag: nil,
                environment: ["AUTHSIA_MCP_UPSTREAM": "jira"]
            ) == "jira"
        )
        #expect(
            try MCPCommand.Proxy.resolveUpstreamName(
                flag: "jira",
                environment: ["AUTHSIA_MCP_UPSTREAM": "jira"]
            ) == "jira"
        )
        #expect(throws: (any Error).self) {
            try MCPCommand.Proxy.resolveUpstreamName(flag: nil, environment: [:])
        }
        #expect(throws: (any Error).self) {
            try MCPCommand.Proxy.resolveUpstreamName(
                flag: "jira",
                environment: ["AUTHSIA_MCP_UPSTREAM": "other"]
            )
        }
        #expect(throws: (any Error).self) {
            try MCPCommand.Proxy.resolveUpstreamName(flag: "jira.injected", environment: [:])
        }
    }

    @Test("doctor fails a user-global bypass when no workspace is bound")
    func doctorFailsConditionalFleetScan() throws {
        let fixture = try makeDoctorFixture()
        defer { fixture.tearDown() }

        let result = try runDoctor(
            arguments: ["--json"],
            home: fixture.home,
            currentDirectory: fixture.unrelated
        )
        #expect(result.code == 2)

        let report = try JSONDecoder().decode(MCPDoctorReport.self, from: Data(result.output.utf8))
        #expect(report.schemaVersion == 1)
        #expect(report.workspaceRoots.isEmpty)
        #expect(report.violationCount == 2)
        #expect(report.findings.map(\.id) == [
            ":claude:filesystem:~/.claude.json",
            ":cursor:jira:~/.cursor/mcp.json",
        ])
        let filesystem = try #require(report.findings.first { $0.serverName == "filesystem" })
        #expect(filesystem.precedence == .conditional)
        #expect(filesystem.status == .unadmitted)
        #expect(!result.output.contains("synthetic-token"))
        #expect(!result.output.lowercased().contains("bearer"))
    }

    @Test("doctor exits 0 when every finding is admitted-wrapped")
    func doctorPassesWrappedEntries() throws {
        let fixture = try makeDoctorFixture()
        defer { fixture.tearDown() }

        let result = try runDoctor(
            arguments: ["--client", "cursor", "--workspace", fixture.workspace.path],
            home: fixture.home,
            currentDirectory: fixture.unrelated
        )
        #expect(result.code == 0)
    }

    @Test("doctor fails an effective direct-bypass when a workspace is supplied")
    func doctorFailsEffectiveDirectBypass() throws {
        let fixture = try makeDoctorFixture()
        defer { fixture.tearDown() }

        let result = try runDoctor(
            arguments: ["--client", "claude", "--workspace", fixture.workspace.path],
            home: fixture.home,
            currentDirectory: fixture.unrelated
        )
        #expect(result.code == 2)
    }

    @Test("doctor does not fail an overridden user-global bypass")
    func doctorIgnoresOverriddenBypass() throws {
        let fixture = try makeDoctorFixture()
        defer { fixture.tearDown() }
        try writeDoctorJSON([
            "mcpServers": [
                "filesystem": [
                    "command": "/Applications/Authsia.app/Contents/Helpers/authsia",
                    "args": ["mcp", "proxy"],
                    "env": ["AUTHSIA_MCP_UPSTREAM": "filesystem"],
                ]
            ]
        ], to: fixture.workspace.appendingPathComponent(".mcp.json"))

        let result = try runDoctor(
            arguments: ["--client", "claude", "--workspace", fixture.workspace.path],
            home: fixture.home,
            currentDirectory: fixture.unrelated
        )
        #expect(result.code == 0)
    }

    private func render(
        _ client: MCPClient,
        fixture: (root: URL, binary: URL)
    ) throws -> String {
        try MCPClientConfiguration.render(
            client: client,
            executableURL: fixture.binary
        )
    }

    private func makeFixture() throws -> (root: URL, binary: URL) {
        let root = try makeWorkspaceRoot()
        let binary = root.appendingPathComponent("bin/authsia")
        try FileManager.default.createDirectory(
            at: binary.deletingLastPathComponent(),
            withIntermediateDirectories: true
        )
        return (root, binary)
    }
}

private struct DoctorFixture {
    let home: URL
    let workspace: URL
    let unrelated: URL

    func tearDown() {
        try? FileManager.default.removeItem(at: home)
        try? FileManager.default.removeItem(at: workspace)
        try? FileManager.default.removeItem(at: unrelated)
    }
}

private func makeDoctorFixture() throws -> DoctorFixture {
    let home = FileManager.default.temporaryDirectory.appendingPathComponent(
        "authsia-doctor-home-\(UUID().uuidString)",
        isDirectory: true
    )
    try FileManager.default.createDirectory(at: home, withIntermediateDirectories: true)
    let workspace = try makeWorkspaceRoot()
    try WorkspaceConfigStore.write(
        WorkspaceConfig(
            workspace: .init(name: "doctor", authsiaFolder: "Workspaces/doctor"),
            managedEnvFiles: [],
            agents: nil,
            mcpUpstreams: [
                MCPUpstreamConfig(
                    name: "jira",
                    command: "mcp-atlassian",
                    tools: MCPUpstreamToolPolicy(allow: ["jira_get_issue"])
                ),
                MCPUpstreamConfig(
                    name: "filesystem",
                    command: "npx",
                    args: ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"],
                    tools: MCPUpstreamToolPolicy(allow: ["read_file"])
                ),
            ]
        ),
        toWorkspaceRoot: workspace
    )
    try writeDoctorJSON([
        "mcpServers": [
            "jira": [
                "command": "/Applications/Authsia.app/Contents/Helpers/authsia",
                "args": ["mcp", "proxy"],
                "env": ["AUTHSIA_MCP_UPSTREAM": "jira"],
            ]
        ]
    ], to: home.appendingPathComponent(".cursor/mcp.json"))
    try writeDoctorJSON([
        "mcpServers": [
            "filesystem": [
                "command": "npx",
                "args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"],
            ]
        ]
    ], to: home.appendingPathComponent(".claude.json"))
    return DoctorFixture(
        home: home,
        workspace: workspace,
        unrelated: try makeWorkspaceRoot()
    )
}

private func writeDoctorJSON(_ object: [String: Any], to url: URL) throws {
    try FileManager.default.createDirectory(
        at: url.deletingLastPathComponent(),
        withIntermediateDirectories: true
    )
    try JSONSerialization.data(
        withJSONObject: object,
        options: [.prettyPrinted, .sortedKeys]
    ).write(to: url)
}

private func runDoctor(
    arguments: [String],
    home: URL,
    currentDirectory: URL,
    environment: [String: String] = [:]
) throws -> (code: Int32, output: String) {
    var doctor = try MCPCommand.Doctor.parse(arguments)
    doctor.homeDirectory = home
    doctor.currentDirectoryPath = currentDirectory.path
    doctor.environment = environment
    var output = ""
    do {
        try doctor.run { output = $0 }
        return (0, output)
    } catch let code as ExitCode {
        return (code.rawValue, output)
    }
}
