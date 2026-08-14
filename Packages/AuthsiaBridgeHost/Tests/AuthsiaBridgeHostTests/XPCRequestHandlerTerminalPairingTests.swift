#if os(macOS)
import CryptoKit
import Darwin
import XCTest
import AuthenticatorBridge
@testable import AuthsiaBridgeHost

@MainActor
final class XPCRequestHandlerTerminalPairingTests: XCTestCase {
    func testDirectGetInUnmanagedVSCodeDirectoryRequestsPairing() throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("authsia-terminal-pairing-unmanaged-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }

        let caller = try makeIDECaller(
            terminal: "ttys-unmanaged-\(UUID().uuidString)",
            command: "/usr/local/bin/authsia get password test"
        )
        let handler = XPCRequestHandler(
            approver: TerminalPairingApprovalTracker(),
            terminalPairingStore: TerminalPairingStore(
                fileURL: directory.appendingPathComponent("terminal-pairings.json")
            ),
            callerIdentityProvider: { caller }
        )
        let request = BridgeRequest(
            id: UUID(),
            type: .getPassword,
            query: "test",
            options: BridgeOptions(field: nil, copy: false),
            context: BridgeContext(
                isTTY: true,
                isPiped: false,
                isSSH: false,
                isCI: false,
                timestamp: Date(),
                requestedCommand: "get",
                sessionScope: "tty:/dev/\(caller.controllingTerminal!):sid:\(getpid())",
                workingDirectory: directory.path,
                workspaceAuthorityPath: nil
            )
        )

        XCTAssertEqual(
            handler.secretReadApprovalDecision(
                itemFolderPath: nil,
                itemEnvironments: [],
                request: request,
                bypassApproval: false,
                callerIdentity: caller
            ),
            .needsPairing
        )
    }

    func testDirectListInUnmanagedVSCodeDirectoryRequestsPairing() async throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("authsia-terminal-pairing-direct-list-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }

        let caller = try makeIDECaller(
            terminal: "ttys-direct-list-\(UUID().uuidString)",
            command: "/usr/local/bin/authsia list passwords"
        )
        let approver = TerminalPairingApprovalTracker()
        let handler = XPCRequestHandler(
            approver: approver,
            terminalPairingStore: TerminalPairingStore(
                fileURL: directory.appendingPathComponent("terminal-pairings.json")
            ),
            callerIdentityProvider: { caller }
        )
        let request = BridgeRequest(
            id: UUID(),
            type: .list,
            query: "",
            options: BridgeOptions(field: nil, copy: false),
            context: BridgeContext(
                isTTY: true,
                isPiped: false,
                isSSH: false,
                isCI: false,
                timestamp: Date(),
                requestedCommand: "list",
                sessionScope: "tty:/dev/\(caller.controllingTerminal!):sid:\(getpid())",
                workingDirectory: directory.path,
                workspaceAuthorityPath: directory.path
            )
        )
        let replyExpectation = expectation(description: "direct list pairing reply")
        var responseData: Data?

        handler.list(try BridgeCoder.encode(request)) { data, _ in
            responseData = data
            replyExpectation.fulfill()
        }
        await fulfillment(of: [replyExpectation], timeout: 2)

        let response = try BridgeCoder.decode(
            BridgeResponse<String>.self,
            from: try XCTUnwrap(responseData)
        )
        XCTAssertEqual(response.error?.code, .requiresPairing)
        XCTAssertEqual(response.error?.pairingRequestID, approver.pairingRequest?.id)
        XCTAssertEqual(approver.regularApprovalCount, 0)
        XCTAssertFalse(approver.regularApprovalCommands.contains(.agentJITPreflight))
    }

    func testEditListBootstrapRequestsPairingBeforeReturningMetadata() async throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("authsia-terminal-pairing-list-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }

        let caller = try makeIDECaller(
            terminal: "ttys-list-\(UUID().uuidString)",
            command: "/usr/local/bin/authsia edit password deploy --username user"
        )
        let approver = TerminalPairingApprovalTracker()
        let handler = XPCRequestHandler(
            approver: approver,
            terminalPairingStore: TerminalPairingStore(
                fileURL: directory.appendingPathComponent("terminal-pairings.json")
            ),
            callerIdentityProvider: { caller }
        )
        let request = BridgeRequest(
            id: UUID(),
            type: .list,
            query: "",
            options: BridgeOptions(field: nil, copy: false),
            context: BridgeContext(
                isTTY: true,
                isPiped: false,
                isSSH: false,
                isCI: false,
                timestamp: Date(),
                requestedCommand: "edit",
                sessionScope: "tty:/dev/\(caller.controllingTerminal!):sid:\(getpid())",
                workingDirectory: directory.path,
                workspaceAuthorityPath: directory.path
            )
        )
        let replyExpectation = expectation(description: "edit bootstrap pairing reply")
        var responseData: Data?

        handler.list(try BridgeCoder.encode(request)) { data, _ in
            responseData = data
            replyExpectation.fulfill()
        }
        await fulfillment(of: [replyExpectation], timeout: 2)

        let response = try BridgeCoder.decode(
            BridgeResponse<String>.self,
            from: try XCTUnwrap(responseData)
        )
        XCTAssertEqual(response.error?.code, .requiresPairing)
        XCTAssertEqual(response.error?.pairingRequestID, approver.pairingRequest?.id)
        XCTAssertEqual(approver.regularApprovalCount, 0)
    }

    func testApprovedPairingCreatesConfiguredSessionAndSecondReadNeedsNoPrompt() async throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("authsia-terminal-pairing-handler-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }

        let shellPID = getpid()
        let terminal = "ttys-pairing-\(UUID().uuidString)"
        let scope = "tty:/dev/\(terminal):sid:\(shellPID)"
        defer { _ = BridgeSessionManager.shared.invalidate(scope: scope) }

        let caller = try makeIDECaller(
            terminal: terminal,
            command: "/usr/local/bin/authsia get password deploy"
        )
        let approver = TerminalPairingApprovalTracker()
        let pairingStore = TerminalPairingStore(
            fileURL: directory.appendingPathComponent("terminal-pairings.json")
        )
        let handler = XPCRequestHandler(
            approver: approver,
            terminalPairingStore: pairingStore,
            callerIdentityProvider: { caller },
            auditLogger: BridgeAuditLogger(
                fileURL: directory.appendingPathComponent("bridge-audit.log"),
                hmacKeyProvider: { SymmetricKey(data: Data(repeating: 0xA5, count: 32)) }
            )
        )
        let context = BridgeContext(
            isTTY: true,
            isPiped: false,
            isSSH: false,
            isCI: false,
            timestamp: Date(),
            requestedCommand: "get",
            sessionScope: scope,
            workingDirectory: directory.path,
            workspaceAuthorityPath: nil
        )
        let initialRequest = BridgeRequest(
            id: UUID(),
            type: .getPassword,
            query: "deploy",
            options: BridgeOptions(field: nil, copy: false),
            context: context
        )

        var initialResponseData: Data?
        await handler.requestTerminalPairing(
            request: initialRequest,
            callerIdentity: caller,
            reply: XPCReply { data, _ in initialResponseData = data }
        )
        let initialResponse = try BridgeCoder.decode(
            BridgeResponse<String>.self,
            from: try XCTUnwrap(initialResponseData)
        )
        let approvalRequest = try XCTUnwrap(approver.pairingRequest)
        XCTAssertEqual(initialResponse.error?.code, .requiresPairing)
        XCTAssertEqual(initialResponse.error?.pairingRequestID, approvalRequest.id)

        let completionRequest = BridgeRequest(
            id: UUID(),
            type: .terminalPairingComplete,
            query: "",
            options: BridgeOptions(field: nil, copy: false),
            context: context,
            body: try BridgeCoder.encode(TerminalPairingCompletionRequest(
                pairingRequestID: approvalRequest.id,
                code: approvalRequest.code
            ))
        )
        let completionExpectation = expectation(description: "terminal pairing completion")
        var completionResponseData: Data?
        handler.completeTerminalPairing(try BridgeCoder.encode(completionRequest)) { data, _ in
            completionResponseData = data
            completionExpectation.fulfill()
        }
        await fulfillment(of: [completionExpectation], timeout: 2)

        let completionResponse = try BridgeCoder.decode(
            BridgeResponse<TerminalPairingSessionPayload>.self,
            from: try XCTUnwrap(completionResponseData)
        )
        let session = try XCTUnwrap(completionResponse.payload)
        XCTAssertEqual(session.ttlSeconds, Int(XPCRequestHandler.configuredSessionTTL))
        XCTAssertEqual(completionResponse.sessionToken, session.sessionToken)
        XCTAssertEqual(try pairingStore.loadAll().map(\.id), [session.pairingID])
        XCTAssertEqual(approver.finishedPairingIDs, [approvalRequest.id])

        let secondRequest = BridgeRequest(
            id: UUID(),
            type: .getPassword,
            query: "deploy",
            options: BridgeOptions(field: nil, copy: false),
            context: context,
            sessionToken: session.sessionToken
        )
        XCTAssertEqual(
            handler.secretReadApprovalDecision(
                itemFolderPath: nil,
                itemEnvironments: [],
                request: secondRequest,
                bypassApproval: false,
                callerIdentity: caller
            ),
            .allowed(approvedBy: "paired-human", needsApproval: false, agentJITGrantID: nil)
        )
        XCTAssertEqual(approver.regularApprovalCount, 0)

        let otherDirectory = directory.appendingPathComponent("other", isDirectory: true)
        try FileManager.default.createDirectory(at: otherDirectory, withIntermediateDirectories: true)
        let otherDirectoryRequest = BridgeRequest(
            id: UUID(),
            type: .getPassword,
            query: "deploy",
            options: BridgeOptions(field: nil, copy: false),
            context: BridgeContext(
                isTTY: true,
                isPiped: false,
                isSSH: false,
                isCI: false,
                timestamp: Date(),
                requestedCommand: "get",
                sessionScope: scope,
                workingDirectory: otherDirectory.path,
                workspaceAuthorityPath: nil
            ),
            sessionToken: session.sessionToken
        )
        XCTAssertEqual(
            handler.secretReadApprovalDecision(
                itemFolderPath: nil,
                itemEnvironments: [],
                request: otherDirectoryRequest,
                bypassApproval: false,
                callerIdentity: caller
            ),
            .needsPairing
        )

        let statusExpectation = expectation(description: "status includes terminal pairing")
        var statusResponseData: Data?
        let statusRequest = BridgeRequest(
            id: UUID(),
            type: .status,
            query: "",
            options: BridgeOptions(field: nil, copy: false),
            context: context,
            sessionToken: session.sessionToken
        )
        handler.status(try BridgeCoder.encode(statusRequest)) { data, _ in
            statusResponseData = data
            statusExpectation.fulfill()
        }
        await fulfillment(of: [statusExpectation], timeout: 2)
        let statusResponse = try BridgeCoder.decode(
            BridgeResponse<BridgePingPayload>.self,
            from: try XCTUnwrap(statusResponseData)
        )
        XCTAssertEqual(statusResponse.payload?.terminalPairing?.id, session.pairingID)

        let lockExpectation = expectation(description: "lock revokes terminal pairing")
        let lockContext = BridgeContext(
            isTTY: true,
            isPiped: false,
            isSSH: false,
            isCI: false,
            timestamp: Date(),
            requestedCommand: "lock",
            sessionScope: scope,
            workingDirectory: nil,
            workspaceAuthorityPath: nil
        )
        let lockRequest = BridgeRequest(
            id: UUID(),
            type: .lock,
            query: "",
            options: BridgeOptions(field: nil, copy: false),
            context: lockContext,
            sessionToken: session.sessionToken
        )
        handler.lock(try BridgeCoder.encode(lockRequest)) { _, _ in
            lockExpectation.fulfill()
        }
        await fulfillment(of: [lockExpectation], timeout: 2)
        XCTAssertTrue(try pairingStore.loadAll().isEmpty)
    }

    func testPairedIDEListPreflightReturnsEmptyGrantsWithoutApprovalOrAudit() async throws {
        let fixture = try makePairedIDEFixture(command: "/usr/local/bin/authsia list passwords")
        defer { fixture.tearDown() }

        let response: BridgeResponse<AgentJITPreflightResultPayload> = try await invoke(
            fixture.handler.addItem,
            request: fixture.request(
                type: BridgeRequestType.agentJITPreflight,
                requestedCommand: "list",
                body: try BridgeCoder.encode(AgentJITPreflightPayload(
                    requestedCommand: "list",
                    references: [
                        AgentJITPreflightReference(
                            type: "password",
                            query: "",
                            folderPath: nil,
                            isFolderScoped: false
                        ),
                    ]
                ))
            ),
            description: "paired list preflight"
        )

        XCTAssertNil(response.error)
        XCTAssertEqual(response.payload?.grantIDs, [])
        XCTAssertEqual(fixture.approver.regularApprovalCommands, [])
        XCTAssertFalse(try fixture.auditText().contains("agentJITPreflight"))
    }

    func testPairedIDEListDoesNotRequireJITGrant() async throws {
        let fixture = try makePairedIDEFixture(command: "/usr/local/bin/authsia list passwords")
        defer { fixture.tearDown() }

        let response: BridgeResponse<BridgeListPayload> = try await invoke(
            fixture.handler.list,
            request: fixture.request(type: BridgeRequestType.list, requestedCommand: "list"),
            description: "paired list"
        )

        XCTAssertNil(response.error)
        XCTAssertNotNil(response.payload)
        XCTAssertFalse(fixture.approver.regularApprovalCommands.contains(.agentJITPreflight))
        XCTAssertFalse(try fixture.auditText().contains("agentJITPreflight"))
    }

    func testAgentRuntimeContextStillRequiresListJITDespitePairing() async throws {
        let fixture = try makePairedIDEFixture(
            command: "/usr/local/bin/authsia list passwords",
            listPayload: BridgeListPayload(
                accounts: [],
                passwords: [
                    BridgePassword(
                        id: UUID(),
                        name: "API",
                        username: "user",
                        website: nil,
                        folderPath: nil,
                        isFavorite: false,
                        isCliEnabled: true,
                        isScraped: false,
                        createdAt: Date(),
                        updatedAt: Date()
                    ),
                ],
                certificates: [],
                notes: [],
                sshKeys: []
            )
        )
        defer { fixture.tearDown() }

        let response: BridgeResponse<AgentJITPreflightResultPayload> = try await invoke(
            fixture.handler.addItem,
            request: fixture.request(
                type: BridgeRequestType.agentJITPreflight,
                requestedCommand: "list",
                agentRuntimeContext: AgentRuntimeContext(platform: "copilot", sessionID: "session-1"),
                body: try BridgeCoder.encode(AgentJITPreflightPayload(
                    requestedCommand: "list",
                    references: [
                        AgentJITPreflightReference(
                            type: "password",
                            query: "",
                            folderPath: nil,
                            isFolderScoped: false
                        ),
                    ]
                ))
            ),
            description: "agent list preflight"
        )

        XCTAssertEqual(
            fixture.approver.regularApprovalCommands,
            [BridgeRequestType.agentJITPreflight]
        )
        XCTAssertNotEqual(response.error?.code, .invalidRequest)
    }

    func testPairedIDEUnlockRequestsLocalApprovalAndReturnsSession() async throws {
        let fixture = try makePairedIDEFixture(command: "/usr/local/bin/authsia unlock")
        defer { fixture.tearDown() }

        let response: BridgeResponse<UnlockPayload> = try await invoke(
            fixture.handler.unlock,
            request: fixture.request(type: BridgeRequestType.unlock, requestedCommand: nil),
            description: "paired unlock"
        )

        XCTAssertNil(response.error)
        XCTAssertNotNil(response.payload?.sessionToken)
        XCTAssertEqual(fixture.approver.regularApprovalCommands, [.unlock])
    }

    private func makePairedIDEFixture(
        command: String,
        listPayload: BridgeListPayload = BridgeListPayload(
            accounts: [],
            passwords: [],
            certificates: [],
            notes: [],
            sshKeys: []
        )
    ) throws -> PairedIDEFixture {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("authsia-terminal-pairing-runtime-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let workspaceRoot = try XCTUnwrap(
            WorkspaceAuthority.validatedRootPath(directory.path, containing: directory.path)
        )
        let terminal = "ttys-runtime-\(UUID().uuidString)"
        let caller = try makeIDECaller(terminal: terminal, command: command)
        let shell = try XCTUnwrap(caller.shellAncestryPrefix?.first)
        let startTime = try XCTUnwrap(shell.startTimeSeconds)
        let pairingStore = TerminalPairingStore(
            fileURL: directory.appendingPathComponent("terminal-pairings.json")
        )
        try pairingStore.save(
            TerminalPairing(
                id: UUID(),
                controllingTerminal: terminal,
                anchorShellPID: shell.pid,
                anchorShellStartTime: startTime,
                workspaceRoot: workspaceRoot,
                createdAt: Date(),
                expiresAt: Date().addingTimeInterval(3_600)
            )
        )
        let approver = TerminalPairingApprovalTracker()
        let auditURL = directory.appendingPathComponent("bridge-audit.log")
        let handler = XPCRequestHandler(
            listProvider: { listPayload },
            approver: approver,
            terminalPairingStore: pairingStore,
            callerIdentityProvider: { caller },
            callerIdentityRevalidationProvider: { _ in caller },
            auditLogger: BridgeAuditLogger(
                fileURL: auditURL,
                hmacKeyProvider: { SymmetricKey(data: Data(repeating: 0xA5, count: 32)) }
            )
        )
        return PairedIDEFixture(
            directory: directory,
            caller: caller,
            approver: approver,
            handler: handler,
            auditURL: auditURL,
            workingDirectory: directory.path,
            sessionScope: "tty:/dev/\(terminal):sid:\(shell.pid)"
        )
    }

    private func invoke<T: Codable & Equatable>(
        _ action: (Data, @escaping (Data?, NSError?) -> Void) -> Void,
        request: BridgeRequest,
        description: String
    ) async throws -> BridgeResponse<T> {
        let expectation = expectation(description: description)
        var responseData: Data?
        action(try BridgeCoder.encode(request)) { data, _ in
            responseData = data
            expectation.fulfill()
        }
        await fulfillment(of: [expectation], timeout: 2)
        return try BridgeCoder.decode(
            BridgeResponse<T>.self,
            from: try XCTUnwrap(responseData)
        )
    }

    private func makeIDECaller(terminal: String, command: String) throws -> CallerIdentity {
        let shellPID = getpid()
        let shellStart = try XCTUnwrap(TerminalSessionScope.startTimeSeconds(pid: shellPID))
        let shell = ParentProcessInfo(
            pid: shellPID,
            processName: "zsh",
            bundleIdentifier: nil,
            startTimeSeconds: shellStart
        )
        return CallerIdentity(
            pid: shellPID,
            processName: "authsia",
            bundleIdentifier: "app.authsia.cli",
            signingTeamId: "TEAM",
            signingIdentity: "Developer ID Application",
            parentProcess: shell,
            hostProcess: ParentProcessInfo(
                pid: shellPID,
                processName: "Code Helper",
                bundleIdentifier: "com.microsoft.VSCode"
            ),
            controllingTerminal: terminal,
            shellAncestryPrefix: [shell],
            hostCommand: command
        )
    }
}

@MainActor
private final class TerminalPairingApprovalTracker: TerminalPairingApproving {
    private(set) var pairingRequest: TerminalPairingApprovalRequest?
    private(set) var finishedPairingIDs: [UUID] = []
    private(set) var regularApprovalCount = 0
    private(set) var regularApprovalCommands: [BridgeRequestType] = []

    func requestTerminalPairingApproval(_ request: TerminalPairingApprovalRequest) async -> Bool {
        pairingRequest = request
        return true
    }

    func finishTerminalPairing(id: UUID) {
        finishedPairingIDs.append(id)
    }

    func requestApproval(
        prompt: String,
        command: BridgeRequestType,
        itemLabel: String?,
        field: String?,
        callback: AuthsiaBridgeApprovalCallbackProtocol?,
        remoteRequests: [RemoteJITApprovalRequest]
    ) async -> RemoteJITApprovalOutcome {
        regularApprovalCount += 1
        regularApprovalCommands.append(command)
        return .approved(source: .macBiometric)
    }
}

private struct PairedIDEFixture {
    let directory: URL
    let caller: CallerIdentity
    let approver: TerminalPairingApprovalTracker
    let handler: XPCRequestHandler
    let auditURL: URL
    let workingDirectory: String
    let sessionScope: String

    func request(
        type: BridgeRequestType,
        requestedCommand: String?,
        agentRuntimeContext: AgentRuntimeContext? = nil,
        body: Data? = nil,
        sessionToken: String? = nil
    ) -> BridgeRequest {
        BridgeRequest(
            id: UUID(),
            type: type,
            query: "",
            options: BridgeOptions(field: nil, copy: false),
            context: BridgeContext(
                isTTY: true,
                isPiped: false,
                isSSH: false,
                isCI: false,
                timestamp: Date(),
                requestedCommand: requestedCommand,
                sessionScope: sessionScope,
                workingDirectory: workingDirectory,
                workspaceAuthorityPath: workingDirectory,
                agentRuntimeContext: agentRuntimeContext
            ),
            body: body,
            sessionToken: sessionToken
        )
    }

    func auditText() throws -> String {
        guard FileManager.default.fileExists(atPath: auditURL.path) else { return "" }
        return try String(contentsOf: auditURL, encoding: .utf8)
    }

    func tearDown() {
        _ = BridgeSessionManager.shared.invalidate(scope: sessionScope)
        try? FileManager.default.removeItem(at: directory)
    }
}
#endif
