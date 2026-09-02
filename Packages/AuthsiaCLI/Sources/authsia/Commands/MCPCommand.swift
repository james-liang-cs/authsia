import ArgumentParser
import AuthenticatorBridge
import Foundation
import MCP

struct MCPCommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "mcp",
        abstract: "Connect local AI clients to Authsia",
        discussion: """
            Print client configuration or run Authsia's local stdio MCP server.
            Most users should configure a supported client, which launches the server
            automatically and supplies its active workspace when supported.
            Enable MCP Integrations in Authsia Settings > Developer Access first.
            `mcp proxy` wraps one named workspace upstream as a separate stdio
            process; it does not add tools to `mcp serve`. Clients launch a stable
            `mcp proxy` argv and set AUTHSIA_MCP_UPSTREAM; `--upstream` is optional
            for terminal use.

            Examples:
              authsia mcp configure --client codex
              authsia mcp wrap --write --server filesystem
              authsia mcp catalog --server filesystem --write
              authsia mcp serve --workspace /path/to/repository
              authsia mcp proxy --upstream jira
              authsia mcp doctor --json
            """,
        subcommands: [Configure.self, Wrap.self, Catalog.self, Serve.self, Proxy.self, Doctor.self]
    )

    static func startingDirectory(
        workspace: String?,
        environment: [String: String],
        currentDirectoryPath: String
    ) -> URL {
        let clientWorkspacePath: String?
        if let value = environment[MCPProxyClientLaunch.workspaceEnvironmentKey] {
            let paths = value.split(separator: ",", omittingEmptySubsequences: false)
            let path = paths.count == 1 ? String(paths[0]) : ""
            clientWorkspacePath = path.hasPrefix("/") && path.unicodeScalars.allSatisfy {
                !CharacterSet.controlCharacters.contains($0)
            } ? path : nil
        } else {
            clientWorkspacePath = nil
        }
        return URL(
            fileURLWithPath: workspace ?? clientWorkspacePath ?? currentDirectoryPath,
            isDirectory: true
        )
    }

    struct Configure: ParsableCommand {
        static let configuration = CommandConfiguration(
            abstract: "Print a user-global MCP fallback and a table of current launches"
        )

        @Option(help: "Client: codex, claude, cursor, devin, or vscode")
        var client: MCPClient

        var homeDirectory = FileManager.default.homeDirectoryForCurrentUser
        var currentDirectoryPath = FileManager.default.currentDirectoryPath
        var environment = ProcessInfo.processInfo.environment
        var executableURL = Authsia.currentExecutableURL()

        func run() throws {
            try run { print($0) }
        }

        func run(output: (String) -> Void) throws {
            let upstreams = Self.upstreams(
                environment: environment,
                currentDirectoryPath: currentDirectoryPath
            )
            let recipe = try MCPClientConfiguration.render(
                client: client,
                executableURL: executableURL,
                upstreamNames: upstreams.map(\.name)
            )
            let workspaceRoot = Self.boundWorkspaceRoot(
                environment: environment,
                currentDirectoryPath: currentDirectoryPath
            )
            let declared = Self.declaredServers(
                from: upstreams,
                workspaceRoot: workspaceRoot
            )
            // The bound workspace's project config outranks the user-global one
            // this command prints, so report it too.
            let locations = MCPClientConfigLocation.knownLocations(
                homeDirectory: homeDirectory
            ) + MCPClientConfigLocation.projectLocations(
                workspaceRoots: workspaceRoot.map { [$0] } ?? [],
                homeDirectory: homeDirectory
            )
            let findings = MCPClientConfigScanner().scan(
                declaredServers: declared,
                locations: locations
            )
            .filter { $0.source.rawValue == client.rawValue }
            .sorted { $0.id < $1.id }
            let table = MCPClientConfiguration.scanTable(
                workspaceRoots: workspaceRoot.map { [$0.path] } ?? [],
                findings: findings,
                unboundHint: "No managed workspace is bound from this directory. User-global entries stay conditional."
            )
            output(recipe + "\n\n" + table)
        }

        static func upstreamNames(
            environment: [String: String],
            currentDirectoryPath: String
        ) -> [String] {
            upstreams(
                environment: environment,
                currentDirectoryPath: currentDirectoryPath
            ).map(\.name)
        }

        static func boundWorkspaceRoot(
            environment: [String: String],
            currentDirectoryPath: String
        ) -> URL? {
            MCPRuntimeContext(
                startingDirectory: Serve.startingDirectory(
                    workspace: nil,
                    environment: environment,
                    currentDirectoryPath: currentDirectoryPath
                )
            ).workspaceRoot
        }

        static func declaredServers(
            from upstreams: [MCPUpstreamConfig],
            workspaceRoot: URL?
        ) -> [MCPDeclaredLocalServer] {
            upstreams.compactMap { upstream -> MCPDeclaredLocalServer? in
                guard upstream.transport == .stdio, let command = upstream.command else { return nil }
                return MCPDeclaredLocalServer(
                    name: upstream.name,
                    command: command,
                    arguments: upstream.args,
                    workspaceRoot: workspaceRoot,
                    hasAdvertisedCatalog: !upstream.tools.allow.isEmpty
                        || !upstream.tools.approve.isEmpty,
                    canRecordCatalog: upstream.requiresStdioPolicy && upstream.env.isEmpty
                )
            }
        }

        static func upstreams(
            environment: [String: String],
            currentDirectoryPath: String
        ) -> [MCPUpstreamConfig] {
            guard let root = boundWorkspaceRoot(
                environment: environment,
                currentDirectoryPath: currentDirectoryPath
            ),
                  let config = try? WorkspaceConfigStore.read(fromWorkspaceRoot: root) else {
                return []
            }
            return config.mcpUpstreams
        }
    }

    struct Catalog: AsyncParsableCommand {
        static let configuration = CommandConfiguration(
            abstract: "Record what a declared local MCP server advertises into workspace policy",
            discussion: """
                Starts the declared child once behind local MCP admission, reads its
                tool list, then stops it. With --write the names and schemas land in
                .authsia/workspace.json, so opening the workspace never starts the
                child and the admission prompt falls on the first tool call instead.

                Examples:
                  authsia mcp catalog --server codegraph
                  authsia mcp catalog --server codegraph --write
                """
        )

        @Option(help: "Named workspace MCP upstream to probe")
        var server: String

        @Option(help: "Explicit workspace binding (otherwise uses launch context)")
        var workspace: String?

        @Flag(name: .customLong("write"), help: "Record the probed catalog in .authsia/workspace.json")
        var write = false

        mutating func run() async throws {
            try await run { print($0) }
        }

        func run(output: (String) -> Void) async throws {
            guard WorkspaceConfigStore.isValidMCPUpstreamName(server) else {
                throw ValidationError("Upstream name must match [A-Za-z][A-Za-z0-9_-]{0,31}.")
            }
            let runtimeContext = MCPRuntimeContext(
                startingDirectory: MCPCommand.startingDirectory(
                    workspace: workspace,
                    environment: ProcessInfo.processInfo.environment,
                    currentDirectoryPath: FileManager.default.currentDirectoryPath
                )
            )
            guard let workspaceRoot = runtimeContext.workspaceRoot else {
                throw ValidationError(runtimeContext.workspaceUnavailableMessage)
            }
            let proxy = AuthsiaMCPProxy(
                version: Authsia.version(),
                upstreamName: server,
                runtimeContext: runtimeContext,
                mcpAccessEnabled: { MCPAccessSettings.isEnabled() }
            )
            let tools: [Tool]
            switch await proxy.captureCatalog() {
            case .success(let discovered):
                tools = discovered
            case .failure(let failure):
                throw ValidationError(failure.message)
            }
            guard !tools.isEmpty else {
                throw ValidationError(
                    "'\(server)' advertised no tools. Admission may have been declined."
                )
            }
            output("\(server) advertises \(Self.toolCount(tools.count)):")
            for tool in tools {
                output("  \(tool.name)")
            }
            guard write else {
                output(
                    "\nRe-run with --write to record this catalog in "
                        + WorkspaceConfigStore.relativeConfigPath + "."
                )
                return
            }
            let outcome = try MCPCatalogCapture.apply(
                tools: tools,
                upstreamName: server,
                workspaceRoot: workspaceRoot
            )
            output(
                "\nRecorded \(Self.toolCount(outcome.advertised.count)) in "
                    + WorkspaceConfigStore.relativeConfigPath + "."
            )
            if !outcome.wroteDescriptors {
                output("Descriptions and schemas exceeded the committed catalog bound and were omitted.")
            }
        }

        static func toolCount(_ count: Int) -> String {
            "\(count) tool" + (count == 1 ? "" : "s")
        }
    }

    struct Serve: AsyncParsableCommand {
        static let configuration = CommandConfiguration(
            abstract: "Serve Authsia tools over local stdio"
        )

        @Option(help: "Explicit workspace binding (otherwise uses tool input or launch context)")
        var workspace: String?

        mutating func run() async throws {
            let startingDirectory = MCPCommand.startingDirectory(
                workspace: workspace,
                environment: ProcessInfo.processInfo.environment,
                currentDirectoryPath: FileManager.default.currentDirectoryPath
            )
            let server = AuthsiaMCPServer(
                version: Authsia.version(),
                runtimeContext: MCPRuntimeContext(startingDirectory: startingDirectory),
                acceptsToolWorkspace: workspace == nil,
                mcpAccessEnabled: { MCPAccessSettings.isEnabled() }
            )
            try await server.runStdio()
        }

        static func startingDirectory(
            workspace: String?,
            environment: [String: String],
            currentDirectoryPath: String
        ) -> URL {
            MCPCommand.startingDirectory(
                workspace: workspace,
                environment: environment,
                currentDirectoryPath: currentDirectoryPath
            )
        }
    }

    struct Proxy: AsyncParsableCommand {
        static let configuration = CommandConfiguration(
            abstract: "Proxy a named workspace upstream over local stdio"
        )

        @Option(help: "Named workspace MCP upstream (or AUTHSIA_MCP_UPSTREAM)")
        var upstream: String?

        @Option(help: "Explicit workspace binding (otherwise uses tool input or launch context)")
        var workspace: String?

        mutating func validate() throws {
            _ = try Self.resolveUpstreamName(
                flag: upstream,
                environment: ProcessInfo.processInfo.environment
            )
        }

        mutating func run() async throws {
            let environment = ProcessInfo.processInfo.environment
            let upstreamName = try Self.resolveUpstreamName(
                flag: upstream,
                environment: environment
            )
            let startingDirectory = MCPCommand.startingDirectory(
                workspace: workspace,
                environment: environment,
                currentDirectoryPath: FileManager.default.currentDirectoryPath
            )
            let proxy = AuthsiaMCPProxy(
                version: Authsia.version(),
                upstreamName: upstreamName,
                runtimeContext: MCPRuntimeContext(startingDirectory: startingDirectory),
                mcpAccessEnabled: { MCPAccessSettings.isEnabled() }
            )
            try await proxy.runStdio()
        }

        static func resolveUpstreamName(
            flag: String?,
            environment: [String: String]
        ) throws -> String {
            let fromFlag = trimmed(flag)
            let fromEnv = trimmed(environment[MCPProxyClientLaunch.environmentKey])
            if let fromFlag, let fromEnv, fromFlag != fromEnv {
                throw ValidationError(
                    "--upstream and AUTHSIA_MCP_UPSTREAM must name the same upstream."
                )
            }
            let name = fromFlag ?? fromEnv
            guard let name else {
                throw ValidationError(
                    "Pass --upstream or set AUTHSIA_MCP_UPSTREAM to a workspace mcpUpstreams name."
                )
            }
            guard WorkspaceConfigStore.isValidMCPUpstreamName(name) else {
                throw ValidationError(
                    "Upstream name must match [A-Za-z][A-Za-z0-9_-]{0,31}."
                )
            }
            return name
        }

        private static func trimmed(_ value: String?) -> String? {
            guard let value else { return nil }
            let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
            return trimmed.isEmpty ? nil : trimmed
        }
    }

    struct Doctor: ParsableCommand {
        static let configuration = CommandConfiguration(
            abstract: "Report whether known MCP client configs comply with the Authsia allowlist",
            discussion: """
                Scan user-global and project MCP client files and exit 2 when an
                effective or conditional entry bypasses Authsia or is unadmitted.
                Overridden entries are reported and do not fail. Default output is
                a table; --json is the machine verdict. Pass --workspace to resolve
                user-global fallbacks as effective or overridden.

                Examples:
                  authsia mcp doctor
                  authsia mcp doctor --json
                  authsia mcp doctor --workspace /path/to/repository --json
                """
        )

        @Option(help: "Client: codex, claude, cursor, devin, or vscode")
        var client: MCPClient?

        @Option(help: "Workspace root used to resolve effective vs overridden findings. Repeatable.")
        var workspace: [String] = []

        @Flag(name: .customLong("json"), help: "Print a machine-readable compliance verdict")
        var json = false

        var homeDirectory = FileManager.default.homeDirectoryForCurrentUser
        var currentDirectoryPath = FileManager.default.currentDirectoryPath
        var environment = ProcessInfo.processInfo.environment

        func run() throws {
            try run { print($0) }
        }

        func run(output: (String) -> Void) throws {
            let report = try makeReport()
            if json {
                let encoder = JSONEncoder()
                encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
                let data = try encoder.encode(report)
                output(String(decoding: data, as: UTF8.self))
            } else {
                output(
                    MCPClientConfiguration.doctorTable(
                        workspaceRoots: report.workspaceRoots,
                        violationCount: report.violationCount,
                        findings: report.findings
                    )
                )
            }
            if report.violationCount > 0 {
                throw ExitCode(2)
            }
        }

        func makeReport() throws -> MCPDoctorReport {
            let workspaceRoots = resolvedWorkspaceRoots()
            var locations = MCPClientConfigLocation.knownLocations(
                homeDirectory: homeDirectory
            ) + MCPClientConfigLocation.projectLocations(
                workspaceRoots: workspaceRoots,
                homeDirectory: homeDirectory
            )
            if let client {
                locations = locations.filter { $0.source.rawValue == client.rawValue }
            }
            let findings = MCPClientConfigScanner().scan(
                declaredServers: declaredServers(workspaceRoots: workspaceRoots),
                locations: locations
            ).sorted { $0.id < $1.id }
            return MCPDoctorReport(
                schemaVersion: 1,
                workspaceRoots: workspaceRoots.map(\.path).sorted(),
                violationCount: findings.filter(Self.isFailingViolation).count,
                findings: findings
            )
        }

        private func resolvedWorkspaceRoots() -> [URL] {
            if !workspace.isEmpty {
                return workspace.map { path in
                    let url = URL(fileURLWithPath: path, isDirectory: true)
                    return MCPRuntimeContext(startingDirectory: url).workspaceRoot
                        ?? url.standardizedFileURL
                }
            }
            if let root = Configure.boundWorkspaceRoot(
                environment: environment,
                currentDirectoryPath: currentDirectoryPath
            ) {
                return [root]
            }
            return []
        }

        private func declaredServers(workspaceRoots: [URL]) -> [MCPDeclaredLocalServer] {
            return workspaceRoots.flatMap { root in
                let upstreams = (try? WorkspaceConfigStore.read(fromWorkspaceRoot: root))?.mcpUpstreams ?? []
                return Configure.declaredServers(from: upstreams, workspaceRoot: root)
            }
        }

        static func isFailingViolation(_ finding: MCPClientServerFinding) -> Bool {
            // A client with no repository of its own cannot be brought into
            // compliance per pilot repository, so failing every machine that
            // has it installed would report a gap nobody can close here.
            guard finding.source.hasWorkspaceOfItsOwn else { return false }
            switch finding.status {
            case .admittedWrapped:
                return false
            case .directBypass, .unadmitted:
                return finding.precedence != .overridden
            }
        }
    }

    struct Wrap: ParsableCommand {
        static let configuration = CommandConfiguration(
            abstract: "Replace a scanned client MCP launch with Authsia mcp proxy after confirmation",
            discussion: """
                Writes the scanned client file only. Re-run with --yes after reviewing
                the replacement. Project scope wins over user-global. Authsia never
                rewrites the file if the checksum no longer matches.

                Examples:
                  authsia mcp wrap --write --server filesystem
                  authsia mcp wrap --write --server filesystem --yes
                """
        )

        @Flag(name: .customLong("write"), help: "Replace the scanned client launch with mcp proxy")
        var write = false

        @Option(help: "Upstream / client server name to wrap")
        var server: String

        @Option(help: "Client: codex, claude, cursor, devin, or vscode")
        var client: MCPClient?

        @Flag(name: .customLong("yes"), help: "Write the replacement after printing the plan")
        var yes = false

        @Option(help: "Workspace root used to resolve effective vs overridden findings. Repeatable.")
        var workspace: [String] = []

        var homeDirectory = FileManager.default.homeDirectoryForCurrentUser
        var currentDirectoryPath = FileManager.default.currentDirectoryPath
        var environment = ProcessInfo.processInfo.environment

        func run() throws {
            try run { print($0) }
        }

        func run(output: (String) -> Void) throws {
            guard write else {
                throw ValidationError("Pass --write to replace a scanned client launch.")
            }
            guard MCPProxyClientLaunch.validUpstreamName(server) != nil else {
                throw ValidationError("Server name must match [A-Za-z][A-Za-z0-9_-]{0,31}.")
            }
            var doctor = Doctor()
            doctor.client = client
            doctor.workspace = workspace
            doctor.homeDirectory = homeDirectory
            doctor.currentDirectoryPath = currentDirectoryPath
            doctor.environment = environment
            let report = try doctor.makeReport()
            let findings = report.findings
            let workspaceRoots = report.workspaceRoots.map {
                URL(fileURLWithPath: $0, isDirectory: true)
            }
            guard !workspaceRoots.isEmpty else {
                throw ValidationError(
                    "No managed workspace resolved from this directory. Pass --workspace "
                        + "<root> so the upstream can be declared alongside the client write."
                )
            }
            guard let finding = MCPLocalMCPClientWrap.preferredFinding(named: server, in: findings) else {
                throw ValidationError(
                    "No wrap-eligible \(server) launch won in the scanned client files."
                )
            }
            let plan = try MCPLocalMCPClientWrap.plan(
                finding: finding,
                authsiaCommand: Authsia.currentExecutableURL().path,
                homeDirectory: homeDirectory
            )
            let message = """
                Replace \(finding.source.displayName) \(finding.serverName) in \(finding.configPathLabel)
                Checksum \(plan.checksum)

                Current:
                \(plan.existingSnippet)

                Replacement:
                \(plan.replacementSnippet)
                """
            guard yes else {
                output(message + "\n\nRe-run with --yes to write this replacement.")
                throw ExitCode(2)
            }
            // Pointing a client at `mcp proxy` without a matching
            // `mcpUpstreams` entry leaves a launch that cannot resolve, so the
            // declaration is part of the wrap rather than a step left to the
            // reader. An already-declared upstream reports `alreadyDeclared`.
            let declarations = MCPLocalMCPWorkspaceDeclaration.declare(
                finding: finding,
                workspaceRoots: workspaceRoots
            )
            var declareNotes: [String] = []
            for declaration in declarations {
                guard case .failure(let error) = declaration.outcome else { continue }
                // A name already declared with a different body still resolves,
                // so the wrap is safe; the human just needs to know the proxy
                // will run the declared child and not the scanned one.
                guard case .duplicateName = error else {
                    throw ValidationError(
                        "Could not declare \(finding.serverName) in "
                            + "\(declaration.workspaceRoot.path): "
                            + (error.errorDescription ?? "Could not declare.")
                    )
                }
                declareNotes.append(
                    "\(declaration.workspaceRoot.path) already declares \(finding.serverName) "
                        + "differently; the proxy runs the declared child."
                )
            }
            try MCPLocalMCPClientWrap.apply(
                plan,
                authsiaCommand: Authsia.currentExecutableURL().path
            )
            let declared = declarations.compactMap { declaration -> String? in
                guard case .success(.declared) = declaration.outcome else { return nil }
                return declaration.workspaceRoot.path
            }
            var written = ["Wrote \(finding.configPathLabel)."]
            if !declared.isEmpty {
                written.append("Declared \(finding.serverName) in \(declared.joined(separator: ", ")).")
            }
            written.append(contentsOf: declareNotes)
            // The proxy answers tools/list from workspace policy, so a wrapped
            // server the workspace has no catalog for lists nothing until
            // capture runs.
            output(
                message + "\n\n" + written.joined(separator: "\n")
                    + "\nNext: authsia mcp catalog --server \(finding.serverName) --write "
                    + "records what that server advertises."
            )
        }
    }
}

struct MCPDoctorReport: Codable, Equatable, Sendable {
    let schemaVersion: Int
    let workspaceRoots: [String]
    let violationCount: Int
    let findings: [MCPClientServerFinding]
}
