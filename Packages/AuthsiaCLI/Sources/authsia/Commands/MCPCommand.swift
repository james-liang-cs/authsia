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
              authsia mcp unwrap --write --server filesystem
              authsia mcp declare --server codegraph --command codegraph --arg serve
              authsia mcp catalog --server filesystem --write
              authsia mcp serve --workspace /path/to/repository
              authsia mcp proxy --upstream jira
              authsia mcp doctor --json
              authsia mcp activity export --json --unowned
            """,
        subcommands: [
            Configure.self, Wrap.self, Unwrap.self, Declare.self, Catalog.self, Serve.self, Proxy.self,
            Doctor.self, Activity.self,
        ]
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
                mcpAccessEnabled: { MCPAccessSettings.isEnabled() },
                toolCallRecorder: LiveMCPProxyToolCallRecorder()
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
                mcpAccessEnabled: { MCPAccessSettings.isEnabled() },
                toolCallRecorder: LiveMCPProxyToolCallRecorder()
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
                user-global fallbacks as effective or overridden. Pass --home or set
                AUTHSIA_MCP_SCAN_HOME to scan a different home directory.

                Examples:
                  authsia mcp doctor
                  authsia mcp doctor --json
                  authsia mcp doctor --workspace /path/to/repository --json
                  authsia mcp doctor --home /tmp/fleet-home --json
                """
        )

        @Option(help: "Client: codex, claude, cursor, devin, or vscode")
        var client: MCPClient? = nil

        @Option(help: "Workspace root used to resolve effective vs overridden findings. Repeatable.")
        var workspace: [String] = []

        @Option(name: .customLong("home"), help: "Home directory to scan instead of the current user")
        var home: String? = nil

        @Flag(name: .customLong("json"), help: "Print a machine-readable compliance verdict")
        var json = false

        var homeDirectory = FileManager.default.homeDirectoryForCurrentUser
        var currentDirectoryPath = FileManager.default.currentDirectoryPath
        var environment = ProcessInfo.processInfo.environment

        func run() throws {
            try run { print($0) }
        }

        func run(output: (String) -> Void) throws {
            try run(output: output, auditIntegrity: nil)
        }

        func run(output: (String) -> Void, auditIntegrity: AuditChainIntegrity?) throws {
            let integrity = auditIntegrity ?? AuditChainIntegrity.from(
                verify: { try AuthsiaBridgeClient(timeout: 2).auditVerify() }
            )
            let report = try makeReport(auditIntegrity: integrity)
            if json {
                let encoder = JSONEncoder()
                encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
                encoder.dateEncodingStrategy = .iso8601
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

        func makeReport(auditIntegrity: AuditChainIntegrity = .unavailable) throws -> MCPDoctorReport {
            let scanHome = resolvedHomeDirectory()
            let workspaceRoots = resolvedWorkspaceRoots()
            var locations = MCPClientConfigLocation.knownLocations(
                homeDirectory: scanHome
            ) + MCPClientConfigLocation.projectLocations(
                workspaceRoots: workspaceRoots,
                homeDirectory: scanHome
            )
            if let client {
                locations = locations.filter { $0.source.rawValue == client.rawValue }
            }
            let findings = MCPClientConfigScanner().scan(
                declaredServers: declaredServers(workspaceRoots: workspaceRoots),
                locations: locations
            ).sorted { $0.id < $1.id }
            return MCPDoctorReport(
                schemaVersion: 2,
                generatedAt: ISO8601DateFormatter().string(from: Date()),
                hostname: ProcessInfo.processInfo.hostName,
                user: NSUserName(),
                authsiaVersion: Authsia.version(),
                mcpIntegrationsEnabled: MCPAccessSettings.isEnabled(),
                auditIntegrity: auditIntegrity,
                workspaceRoots: workspaceRoots.map(\.path).sorted(),
                violationCount: findings.filter(Self.isFailingViolation).count,
                findings: findings
            )
        }

        private func resolvedHomeDirectory() -> URL {
            if let home {
                let trimmed = home.trimmingCharacters(in: .whitespacesAndNewlines)
                if !trimmed.isEmpty {
                    return URL(fileURLWithPath: trimmed, isDirectory: true)
                }
            }
            if let env = environment["AUTHSIA_MCP_SCAN_HOME"] {
                let trimmed = env.trimmingCharacters(in: .whitespacesAndNewlines)
                if !trimmed.isEmpty {
                    return URL(fileURLWithPath: trimmed, isDirectory: true)
                }
            }
            return homeDirectory
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
            case .admittedWrapped, .skipped:
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
        var client: MCPClient? = nil

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
            var doctor = try Doctor.parse([])
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
            // capture runs. A scanned child env means the declaration wrote
            // empty env and probing would record the wrong catalog.
            let next = finding.childEnvironmentCount > 0
                ? "\nNext: name tools under mcpUpstreams.tools.allow; Authsia will not start this child to read a catalog."
                : "\nNext: authsia mcp catalog --server \(finding.serverName) --write "
                    + "records what that server advertises."
            output(
                message + "\n\n" + written.joined(separator: "\n")
                    + next
            )
        }
    }

    struct Unwrap: ParsableCommand {
        static let configuration = CommandConfiguration(
            abstract: "Restore a wrapped client MCP launch to the child workspace policy declares",
            discussion: """
                Writes the scanned client file only, and leaves the mcpUpstreams entry
                declared so the launch can be protected again. Re-run with --yes after
                reviewing the restore. Project scope wins over user-global. Authsia
                never rewrites the file if the checksum no longer matches.

                Examples:
                  authsia mcp unwrap --write --server filesystem
                  authsia mcp unwrap --write --server filesystem --yes
                """
        )

        @Flag(name: .customLong("write"), help: "Restore the wrapped client launch")
        var write = false

        @Option(help: "Upstream / client server name to restore")
        var server: String

        @Option(help: "Client: codex, claude, cursor, devin, or vscode")
        var client: MCPClient? = nil

        @Flag(name: .customLong("yes"), help: "Write the restore after printing the plan")
        var yes = false

        @Option(help: "Workspace root that declares the upstream. Repeatable.")
        var workspace: [String] = []

        var homeDirectory = FileManager.default.homeDirectoryForCurrentUser
        var currentDirectoryPath = FileManager.default.currentDirectoryPath
        var environment = ProcessInfo.processInfo.environment

        func run() throws {
            try run { print($0) }
        }

        func run(output: (String) -> Void) throws {
            guard write else {
                throw ValidationError("Pass --write to restore a wrapped client launch.")
            }
            guard MCPProxyClientLaunch.validUpstreamName(server) != nil else {
                throw ValidationError("Server name must match [A-Za-z][A-Za-z0-9_-]{0,31}.")
            }
            var doctor = try Doctor.parse([])
            doctor.client = client
            doctor.workspace = workspace
            doctor.homeDirectory = homeDirectory
            doctor.currentDirectoryPath = currentDirectoryPath
            doctor.environment = environment
            let report = try doctor.makeReport()
            guard let finding = MCPLocalMCPClientUnwrap.preferredFinding(
                named: server,
                in: report.findings
            ) else {
                throw ValidationError(
                    "No protected \(server) launch won in the scanned client files."
                )
            }
            // The child argv survives a wrap only in workspace policy, so the
            // restore reads the same roots the scan resolved.
            let plan = try MCPLocalMCPClientUnwrap.plan(
                finding: finding,
                workspaceRoots: report.workspaceRoots.map {
                    URL(fileURLWithPath: $0, isDirectory: true)
                },
                homeDirectory: homeDirectory
            )
            var message = """
                Restore \(finding.source.displayName) \(finding.serverName) in \(finding.configPathLabel)
                Declared by \(plan.workspaceRoot.path)
                Checksum \(plan.checksum)

                Current:
                \(plan.existingSnippet)

                Restored:
                \(plan.replacementSnippet)
                """
            message += """


                Any environment values the client entry used before protection were not retained by
                Authsia and cannot be restored automatically. Add any values the child still needs
                to the client file.
                """
            if plan.declaredEnvironmentCount > 0 {
                message += "\n\nWorkspace policy sets \(plan.declaredEnvironmentCount) environment "
                    + "value\(plan.declaredEnvironmentCount == 1 ? "" : "s") for this child. Authsia "
                    + "does not copy them into the restored launch. This includes any authsia:// references, "
                    + "which only the proxy resolves."
            } else {
                message += """


                    Authsia does not copy workspace environment values into a restored client launch.
                    Any authsia:// references stay in policy because only the proxy resolves them.
                    """
            }
            guard yes else {
                output(message + "\n\nRe-run with --yes to write this restore.")
                throw ExitCode(2)
            }
            // Even an explicitly confirmed invocation shows the exact plan
            // before the mutation it authorizes.
            output(message)
            try MCPLocalMCPClientUnwrap.apply(plan)
            output(
                "Wrote \(finding.configPathLabel). \(finding.serverName) now starts "
                    + "directly: its calls are no longer admitted, audited, or revocable by Authsia. "
                    + "\(plan.workspaceRoot.path) still declares the upstream, so "
                    + "authsia mcp wrap --write --server \(finding.serverName) protects it again. "
                    + "Reopen the client."
            )
        }
    }

    struct Declare: ParsableCommand {
        static let configuration = CommandConfiguration(
            abstract: "Declare a child command for a proxy launch that has no workspace policy",
            discussion: """
                Write command and argv into mcpUpstreams when the client already
                launches authsia mcp proxy. Wrap cannot infer that child from the
                proxy entry. Without --yes this prints the plan and exits 2.

                Examples:
                  authsia mcp declare --server codegraph --command codegraph --arg serve
                  authsia mcp declare --server codegraph --command codegraph --arg serve --yes
                """
        )

        @Option(help: "Upstream / client server name to declare")
        var server: String

        @Option(help: "Child executable stored in workspace policy")
        var command: String

        @Option(name: .customLong("arg"), help: "Child argument. Repeatable.")
        var arg: [String] = []

        @Flag(name: .customLong("yes"), help: "Write the declaration after printing the plan")
        var yes = false

        @Option(help: "Workspace root to declare in. Repeatable.")
        var workspace: [String] = []

        var homeDirectory = FileManager.default.homeDirectoryForCurrentUser
        var currentDirectoryPath = FileManager.default.currentDirectoryPath
        var environment = ProcessInfo.processInfo.environment

        func run() throws {
            try run { print($0) }
        }

        func run(output: (String) -> Void) throws {
            guard MCPProxyClientLaunch.validUpstreamName(server) != nil else {
                throw ValidationError("Server name must match [A-Za-z][A-Za-z0-9_-]{0,31}.")
            }
            guard let policyCommand = MCPUpstreamCommandRules.policyCommand(fromScanned: command) else {
                throw ValidationError(
                    "Command must be a PATH basename or workspace-relative executable."
                )
            }
            var doctor = try Doctor.parse([])
            doctor.workspace = workspace
            doctor.homeDirectory = homeDirectory
            doctor.currentDirectoryPath = currentDirectoryPath
            doctor.environment = environment
            let report = try doctor.makeReport()
            let roots = report.workspaceRoots.map {
                URL(fileURLWithPath: $0, isDirectory: true)
            }
            guard !roots.isEmpty else {
                throw ValidationError(
                    "No managed workspace resolved from this directory. Pass --workspace "
                        + "<root> so the child can be declared."
                )
            }
            var message = "Declare \(server) as \(policyCommand)"
            if !arg.isEmpty {
                message += " \(arg.joined(separator: " "))"
            }
            message += " in:"
            for root in roots {
                message += "\n  \(root.path)/\(MCPLocalMCPWorkspaceDeclaration.relativeConfigPath)"
            }
            guard yes else {
                output(message + "\n\nRe-run with --yes to write this declaration.")
                throw ExitCode(2)
            }
            output(message)
            for root in roots {
                let outcome = try MCPLocalMCPWorkspaceDeclaration.declare(
                    name: server,
                    command: policyCommand,
                    arguments: arg,
                    workspaceRoot: root
                )
                switch outcome {
                case .declared:
                    output("Declared \(server) in \(root.path).")
                case .alreadyDeclared:
                    output("\(server) is already declared in \(root.path).")
                }
            }
        }
    }

    struct Activity: ParsableCommand {
        static let configuration = CommandConfiguration(
            commandName: "activity",
            abstract: "Export redacted MCP proxy command history",
            subcommands: [Export.self]
        )

        struct Export: ParsableCommand {
            static let configuration = CommandConfiguration(
                commandName: "export",
                abstract: "Export MCP proxy activity from the local command history",
                discussion: """
                    Writes redacted `.mcpProxy` command-history rows. Arguments,
                    results, JSON-RPC, and child stderr are never stored.

                    Examples:
                      authsia mcp activity export --json
                      authsia mcp activity export --json --unowned
                      authsia mcp activity export --json --upstream jira --workspace /path/to/repo
                    """
            )

            @Flag(name: .customLong("json"), help: "Print JSON (the only export format)")
            var json = false

            @Option(name: .long, help: "Include events at or after this ISO-8601 timestamp")
            var since: String? = nil

            @Option(name: .long, help: "Filter by upstream name or executable")
            var upstream: String? = nil

            @Option(name: .long, help: "Filter by workspace path")
            var workspace: String? = nil

            @Flag(name: .customLong("unowned"), help: "Only events with no grant ID")
            var unowned = false

            func run() throws {
                try run { print($0) }
            }

            func run(output: (String) -> Void) throws {
                let events = try filteredEvents()
                let encoder = JSONEncoder()
                encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
                encoder.dateEncodingStrategy = .iso8601
                let data = try encoder.encode(MCPActivityExport(events: events))
                output(String(decoding: data, as: UTF8.self))
            }

            func filteredEvents(historyFile: String? = nil) throws -> [AgentCommandEvent] {
                let store: AgentCommandHistoryStore
                if let historyFile {
                    store = AgentCommandHistoryStore(fileURL: URL(fileURLWithPath: historyFile))
                } else {
                    store = AgentCommandHistoryStore()
                }
                var events = try store.loadAll().filter { $0.captureSource == .mcpProxy }
                if let since {
                    let parsed = try Self.parseSince(since)
                    events = events.filter { $0.recordedAt >= parsed }
                }
                if let upstream {
                    let needle = upstream.trimmingCharacters(in: .whitespacesAndNewlines)
                    events = events.filter { event in
                        if event.agentID == "proxy:\(needle)" { return true }
                        if event.executable == needle { return true }
                        if let executable = event.executable,
                           URL(fileURLWithPath: executable).lastPathComponent == needle {
                            return true
                        }
                        return false
                    }
                }
                if let workspace {
                    let path = URL(fileURLWithPath: workspace, isDirectory: true)
                        .standardizedFileURL.path
                    events = events.filter { event in
                        guard let workingDirectory = event.workingDirectory else { return false }
                        return URL(fileURLWithPath: workingDirectory, isDirectory: true)
                            .standardizedFileURL.path == path
                    }
                }
                if unowned {
                    events = events.filter { $0.agentJITGrantID == nil }
                }
                return events.sorted { lhs, rhs in
                    if lhs.recordedAt == rhs.recordedAt {
                        return lhs.id.uuidString < rhs.id.uuidString
                    }
                    return lhs.recordedAt < rhs.recordedAt
                }
            }

            private static func parseSince(_ raw: String) throws -> Date {
                let formatter = ISO8601DateFormatter()
                formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
                if let date = formatter.date(from: raw) {
                    return date
                }
                formatter.formatOptions = [.withInternetDateTime]
                if let date = formatter.date(from: raw) {
                    return date
                }
                throw ValidationError("--since must be an ISO-8601 timestamp.")
            }
        }
    }
}

struct MCPDoctorReport: Codable, Equatable, Sendable {
    let schemaVersion: Int
    let generatedAt: String
    let hostname: String
    let user: String
    let authsiaVersion: String
    let mcpIntegrationsEnabled: Bool
    let auditIntegrity: AuditChainIntegrity
    let workspaceRoots: [String]
    let violationCount: Int
    let findings: [MCPClientServerFinding]
}

struct MCPActivityExport: Codable, Equatable, Sendable {
    let events: [AgentCommandEvent]
}
