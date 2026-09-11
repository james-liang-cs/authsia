import XCTest
import AuthenticatorBridge
import NIOCore
import NIOHTTP1
import NIOPosix
@testable import AuthsiaBridgeHost

final class MCPHTTPProxyServerTests: XCTestCase {
    func testStartupGETDoesNotRequestAdmissionOrContactUpstream() async throws {
        let fixture = try await HTTPMCPFixture.start()
        addTeardownBlock { try await fixture.stop() }
        let authorizations = HTTPAuthorizationCollector()
        let router = HTTPRouterHarness(port: fixture.port).router(authorizations: authorizations)
        addTeardownBlock { await router.shutdown() }
        let sid = try await initialize(router)
        let call = request(method: "tools/call", session: sid, tool: "read")
        let get = await router.handle(.init(method: "GET", uri: call.uri, headers: call.headers, body: Data()))
        XCTAssertEqual(get.status, 405)
        let startupTools = await authorizations.tools
        XCTAssertTrue(startupTools.isEmpty, "Opening the optional stream must not request a grant or credentials")
        XCTAssertEqual(fixture.requestCount, 0)
        let listed = await router.handle(request(method: "tools/list", session: sid))
        XCTAssertEqual(listed.status, 200)
        let result = await router.handle(call)
        let output = try await collect(result)
        XCTAssertTrue(String(decoding: output, as: UTF8.self).contains("fixture-ok"))
        let calledTools = await authorizations.tools
        XCTAssertEqual(calledTools, ["read"], "The first tool call must name the actual tool at admission")
    }

    func testHTTPVersionNegotiatesSupportedFallbackAndBindsLaterRequests() async throws {
        let router = HTTPRouterHarness(port: 19001).router()
        addTeardownBlock { await router.shutdown() }
        for offered in ["2025-03-26", "2025-06-18", "2025-11-25", "2099-01-01"] {
            let response = await router.handle(request(method: "initialize", version: offered))
            XCTAssertEqual(response.status, 200)
            let object = try JSONSerialization.jsonObject(with: response.body) as? [String: Any]
            let selected = offered == "2099-01-01" ? "2025-11-25" : offered
            XCTAssertEqual((object?["result"] as? [String: Any])?["protocolVersion"] as? String, selected)
            let sid = try XCTUnwrap(response.headers.first(name: "MCP-Session-Id"))
            let call = request(method: "tools/list", session: sid, version: selected)
            var headers = call.headers
            headers.remove(name: "MCP-Protocol-Version")
            let legacy = await router.handle(.init(method: "POST", uri: call.uri, headers: headers, body: call.body))
            XCTAssertEqual(legacy.status, 200, "The session identifies the negotiated version for older clients")
            headers.add(name: "MCP-Protocol-Version", value: selected)
            headers.add(name: "MCP-Protocol-Version", value: "unsupported")
            let duplicate = await router.handle(.init(method: "POST", uri: call.uri, headers: headers, body: call.body))
            XCTAssertEqual(duplicate.status, 400)
            let mismatch = await router.handle(request(method: "tools/list", session: sid, version: "unsupported"))
            XCTAssertEqual(mismatch.status, 400)
        }
    }

    func testOptionalGETRejectionPreservesToolsAndSession() async throws {
        let fixture = try await HTTPMCPFixture.start(rejectGET: true)
        addTeardownBlock { try await fixture.stop() }
        let router = HTTPRouterHarness(port: fixture.port).router()
        addTeardownBlock { await router.shutdown() }
        let sid = try await initialize(router)
        let call = request(method: "tools/call", session: sid, tool: "read")
        let get = await router.handle(.init(method: "GET", uri: call.uri, headers: call.headers, body: Data()))
        XCTAssertEqual(get.status, 405)
        let result = await router.handle(call)
        XCTAssertEqual(result.status, 200)
        let output = try await collect(result)
        XCTAssertTrue(String(decoding: output, as: UTF8.self).contains("fixture-ok"))
        XCTAssertFalse(String(decoding: output, as: UTF8.self).contains("synthetic-upstream"))
        let admittedGET = await router.handle(.init(method: "GET", uri: call.uri, headers: call.headers, body: Data()))
        XCTAssertEqual(admittedGET.status, 405)
        let nextCall = await router.handle(call)
        XCTAssertEqual(nextCall.status, 200)
    }

    func testSSEInitializationAndCatalogWithBOMAndCRLineEndings() async throws {
        let fixture = try await HTTPMCPFixture.start(sseInitialization: true)
        addTeardownBlock { try await fixture.stop() }
        let catalog = try await MCPHTTPCatalogCapture.run(endpoint: "http://127.0.0.1:\(fixture.port)/mcp", headers: [:])
        XCTAssertFalse(catalog.isEmpty)
        let router = HTTPRouterHarness(port: fixture.port).router()
        addTeardownBlock { await router.shutdown() }
        let sid = try await initialize(router)
        let result = await router.handle(request(method: "tools/call", session: sid, tool: "read"))
        XCTAssertEqual(result.status, 200)
        let output = try await collect(result)
        XCTAssertTrue(String(decoding: output, as: UTF8.self).contains("fixture-ok"))
    }

    func testUpstreamNegotiationUsesSelectedVersionForCatalogAndCalls() async throws {
        for version in ["2025-03-26", "2025-06-18", "2025-11-25"] {
            let fixture = try await HTTPMCPFixture.start(negotiatedVersion: version)
            addTeardownBlock { try await fixture.stop() }
            let catalog = try await MCPHTTPCatalogCapture.run(endpoint: "http://127.0.0.1:\(fixture.port)/mcp", headers: [:])
            XCTAssertEqual(catalog.map(\.name), ["read"])
            let router = HTTPRouterHarness(port: fixture.port).router()
            addTeardownBlock { await router.shutdown() }
            let sid = try await initialize(router)
            let result = await router.handle(request(method: "tools/call", session: sid, tool: "read"))
            XCTAssertEqual(result.status, 200)
            let output = try await collect(result)
            XCTAssertTrue(String(decoding: output, as: UTF8.self).contains("fixture-ok"))
            let listed = await router.handle(request(method: "tools/list", session: sid))
            XCTAssertEqual(listed.status, 200, "Upstream negotiation must not change the client-facing session version")
        }
    }

    func testUnsupportedUpstreamVersionStopsBeforeCatalogOrToolDispatch() async throws {
        let fixture = try await HTTPMCPFixture.start(negotiatedVersion: "unsupported")
        addTeardownBlock { try await fixture.stop() }
        do {
            _ = try await MCPHTTPCatalogCapture.run(endpoint: "http://127.0.0.1:\(fixture.port)/mcp", headers: [:])
            XCTFail("Must reject unsupported negotiation")
        } catch { XCTAssertEqual(error as? MCPManagementError, .catalogStartupFailed) }
        XCTAssertEqual(fixture.requestCount, 1)
        let router = HTTPRouterHarness(port: fixture.port).router()
        addTeardownBlock { await router.shutdown() }
        let sid = try await initialize(router)
        let result = await router.handle(request(method: "tools/call", session: sid, tool: "read"))
        let error = try JSONSerialization.jsonObject(with: result.body) as? [String: Any]
        XCTAssertEqual((error?["error"] as? [String: Any])?["code"] as? Int, -32020)
        XCTAssertEqual(fixture.requestCount, 2, "Only the two initialization requests may reach the upstream")
    }

    func testSSEDecoderKeepsSizeAndCompleteEventBoundaries() throws {
        var parser = MCPHTTPSSEDecoder()
        for byte in Data("data: {\"result\":{}}\r".utf8) { XCTAssertNil(try parser.append(byte)) }
        XCTAssertNotNil(try parser.append(13))
        var oversized = MCPHTTPSSEDecoder()
        for _ in 0..<(4 * 1_024 * 1_024) { _ = try oversized.append(65) }
        XCTAssertThrowsError(try oversized.append(65)) { XCTAssertEqual($0 as? MCPManagementError, .busy) }
    }

    func testSSEFramingAcceptsAllLineEndingsAndOnlyStripsLeadingBOM() throws {
        for separator in ["\n", "\r\n", "\r"] {
            var parser = MCPHTTPSSEDecoder()
            let raw = "\u{FEFF}data: {" + separator + "data: \"text\":\"\u{FEFF}synthetic-upstream\"}" + separator + separator
            var messages: [Data] = []
            for byte in raw.utf8 { if let value = try parser.append(byte), !value.isEmpty { messages.append(value) } }
            XCTAssertEqual(messages.count, 1)
            let json = try XCTUnwrap(messages.first)
            XCTAssertNotNil(json.range(of: Data("\u{FEFF}synthetic-upstream".utf8)))
            let masked = try MCPHTTPMessageMasker(secrets: ["synthetic-upstream"]).mask(json)
            XCTAssertFalse(String(decoding: masked, as: UTF8.self).contains("synthetic-upstream"))
        }
    }

    func testCancellationBeforeResponseHeadersPreservesSession() async throws {
        let received = expectation(description: "upstream received call")
        let fixture = try await HTTPMCPFixture.start(holdCallHeaders: true, callReceived: { received.fulfill() })
        addTeardownBlock { try await fixture.stop() }
        let router = HTTPRouterHarness(port: fixture.port).router()
        addTeardownBlock { await router.shutdown() }
        let sid = try await initialize(router)
        let call = request(method: "tools/call", session: sid, tool: "read")
        let pending = Task { await router.handle(call) }
        await fulfillment(of: [received], timeout: 5)
        let cancel = MCPHTTPRequest(method: "POST", uri: call.uri, headers: call.headers,
            body: Data(#"{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":1}}"#.utf8))
        _ = await router.handle(cancel)
        _ = await pending.value
        let listed = await router.handle(request(method: "tools/list", session: sid))
        XCTAssertEqual(listed.status, 200)
    }
    func testFailedInitializationRecordsTerminalOutcome() async throws {
        let fixture = try await HTTPMCPFixture.start()
        let port = fixture.port
        try await fixture.stop()
        let events = HTTPActivityCollector()
        let router = HTTPRouterHarness(port: port).router(events: events)
        addTeardownBlock { await router.shutdown() }
        let sid = try await initialize(router)
        _ = await router.handle(request(method: "tools/call", session: sid, tool: "read"))
        let recorded = await events.events
        XCTAssertEqual(recorded.map(\.outcome), [.started, .upstreamUnavailable])
        XCTAssertEqual(recorded.first?.id, recorded.last?.id)
    }
    func testDisconnectBeforeBodyRecordsCancellationAndPreservesSession() async throws {
        let fixture = try await HTTPMCPFixture.start()
        addTeardownBlock { try await fixture.stop() }
        let events = HTTPActivityCollector()
        let router = HTTPRouterHarness(port: fixture.port).router(events: events)
        addTeardownBlock { await router.shutdown() }
        let sid = try await initialize(router)
        let response = await router.handle(request(method: "tools/call", session: sid, tool: "read"))
        await response.disconnect?()
        let recorded = await events.events
        XCTAssertEqual(recorded.map(\.outcome), [.started, .cancelled])
        let listed = await router.handle(request(method: "tools/list", session: sid))
        XCTAssertEqual(listed.status, 200)
    }
    func testOwnedSessionPolicyMaskingAndAuditGate() async throws {
        let fixture = try await HTTPMCPFixture.start()
        addTeardownBlock { try await fixture.stop() }
        let harness = HTTPRouterHarness(port: fixture.port)
        let router = harness.router()
        addTeardownBlock { await router.shutdown() }
        let sid = try await initialize(router)
        let listed = await router.handle(request(method:"tools/list", session:sid))
        XCTAssertEqual(listed.status, 200)
        XCTAssertEqual(fixture.requestCount, 0)
        let response = await router.handle(request(method:"tools/call", session:sid, tool:"read"))
        let output = try await collect(response)
        XCTAssertTrue(String(decoding:output,as:UTF8.self).contains("fixture-ok"))
        XCTAssertFalse(String(decoding:output,as:UTF8.self).contains("synthetic-upstream"))
        XCTAssertEqual(fixture.lastAPIKey, "synthetic-upstream")
        let count = fixture.requestCount
        _ = await router.handle(request(method:"tools/call", session:sid, tool:"delete"))
        XCTAssertEqual(fixture.requestCount, count)
    }
    func testSSEProgressIsDeliveredBeforeUpstreamCompletes() async throws {
        let fixture = try await HTTPMCPFixture.start(streaming: true)
        addTeardownBlock { try await fixture.stop() }
        let router = HTTPRouterHarness(port: fixture.port).router()
        addTeardownBlock { await router.shutdown() }
        let sid = try await initialize(router)
        let response = await router.handle(request(method:"tools/call", session:sid, tool:"read"))
        let stream = try XCTUnwrap(response.stream)
        let counter = HTTPDataCollector()
        let timeout = Task { try await Task.sleep(for: .seconds(5)); await router.shutdown() }
        defer { timeout.cancel() }
        try await stream { data in
            let text = String(decoding:data, as:UTF8.self)
            XCTAssertFalse(text.contains("synthetic-upstream"))
            await counter.append(data)
            let event = try JSONSerialization.jsonObject(with: Data(data.dropFirst(6))) as? [String: Any]
            if event?["method"] as? String == "notifications/progress" { fixture.releaseFinal() }
        }
        let data = await counter.data
        XCTAssertTrue(String(decoding:data,as:UTF8.self).contains("fixture-ok"))
    }

    func testOtherAssociationCannotUseOrDeleteSession() async throws {
        let harness = HTTPRouterHarness(port:9000)
        let router = harness.router()
        addTeardownBlock { await router.shutdown() }
        let sid = try await initialize(router)
        let denied = await router.handle(request(method:"tools/list", session:sid, token:"other"))
        XCTAssertEqual(denied.status,404)
        var headers = request(method:"tools/list", session:sid, token:"other").headers
        headers.replaceOrAdd(name:"MCP-Session-Id",value:sid)
        let deletion = await router.handle(.init(method:"DELETE",uri:"/mcp/fixture-server",headers:headers,body:Data()))
        XCTAssertEqual(deletion.status,404)
        let stillOwned = await router.handle(request(method:"tools/list", session:sid))
        XCTAssertEqual(stillOwned.status,200)
    }
    func testDeniedToolCallRecordsActivityWithoutUpstream() async throws {
        let fixture = try await HTTPMCPFixture.start()
        addTeardownBlock { try await fixture.stop() }
        let events = HTTPActivityCollector()
        let router = HTTPRouterHarness(port: fixture.port).router(events: events)
        addTeardownBlock { await router.shutdown() }
        let sid = try await initialize(router)
        let before = fixture.requestCount
        _ = await router.handle(request(method: "tools/call", session: sid, tool: "delete"))
        XCTAssertEqual(fixture.requestCount, before)
        let recorded = await events.events
        XCTAssertEqual(recorded.map(\.outcome), [.denied])
        XCTAssertEqual(recorded.first?.toolName, "delete")
        XCTAssertEqual(recorded.first?.reasonCode, "policy")
    }

    func testBusyToolCallRecordsActivityWithoutASecondDispatch() async throws {
        let received = expectation(description: "first call held")
        received.expectedFulfillmentCount = 1
        let fixture = try await HTTPMCPFixture.start(holdCallHeaders: true, callReceived: { received.fulfill() })
        addTeardownBlock { try await fixture.stop() }
        let events = HTTPActivityCollector()
        let router = HTTPRouterHarness(port: fixture.port).router(events: events)
        addTeardownBlock { await router.shutdown() }
        let sid = try await initialize(router)
        let first = request(method: "tools/call", session: sid, tool: "read")
        let pending = Task { await router.handle(first) }
        await fulfillment(of: [received], timeout: 5)
        _ = await router.handle(first)
        let recorded = await events.events
        XCTAssertTrue(recorded.contains { $0.outcome == .busy })
        pending.cancel()
    }

    func testNativeDenialIsRecordedAsDeniedWithoutDispatch() async throws {
        let fixture = try await HTTPMCPFixture.start()
        addTeardownBlock { try await fixture.stop() }
        let events = HTTPActivityCollector()
        let router = HTTPRouterHarness(port: fixture.port).router(events: events, denyAdmission: true)
        addTeardownBlock { await router.shutdown() }
        let sid = try await initialize(router)
        let response = await router.handle(request(method: "tools/call", session: sid, tool: "read"))
        XCTAssertTrue(String(decoding: response.body, as: UTF8.self).contains("-32010"))
        XCTAssertEqual(fixture.requestCount, 0)
        let recorded = await events.events
        XCTAssertEqual(recorded.map(\.outcome), [.denied])
    }

    func testTerminalAuditRetryPreservesDeliveredSuccess() async throws {
        let fixture = try await HTTPMCPFixture.start()
        addTeardownBlock { try await fixture.stop() }
        let events = HTTPActivityCollector()
        let router = HTTPRouterHarness(port: fixture.port).router(events: events, failFirstTerminal: true)
        addTeardownBlock { await router.shutdown() }
        let sid = try await initialize(router)
        let response = await router.handle(request(method: "tools/call", session: sid, tool: "read"))
        let body = try await collect(response)
        XCTAssertTrue(String(decoding: body, as: UTF8.self).contains("fixture-ok"))
        let recorded = await events.events
        XCTAssertEqual(recorded.map(\.outcome), [.started, .succeeded])
    }

    func testHTTPResponseCompletesWhileTerminalEvidenceWriterIsSuspended() async throws {
        let fixture = try await HTTPMCPFixture.start()
        addTeardownBlock { try await fixture.stop() }
        let gate = HTTPTerminalGate()
        let router = HTTPRouterHarness(port: fixture.port).router(terminalGate: gate)
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        let server = try await ServerBootstrap(group: group).childChannelInitializer { channel in
            channel.pipeline.configureHTTPServerPipeline().flatMap {
                channel.pipeline.addHandlers(MCPHTTPRequestDeadline(), MCPHTTPHandler(router: router))
            }
        }.bind(host: "127.0.0.1", port: 0).get()
        addTeardownBlock {
            await gate.release()
            await router.shutdown()
            try await server.close().get()
            try await group.shutdownGracefully()
        }
        let sid = try await initialize(router)
        let call = request(method: "tools/call", session: sid, tool: "read")
        let port = try XCTUnwrap(server.localAddress?.port)
        var request = URLRequest(url: URL(string: "http://127.0.0.1:\(port)/mcp/fixture-server")!, timeoutInterval: 3)
        request.httpMethod = "POST"; request.httpBody = call.body
        for (name, value) in call.headers { request.setValue(value, forHTTPHeaderField: name) }
        let session = URLSession(configuration: .ephemeral)
        defer { session.invalidateAndCancel() }
        let (data, response) = try await session.data(for: request)
        XCTAssertEqual((response as? HTTPURLResponse)?.statusCode, 200)
        XCTAssertTrue(String(decoding: data, as: UTF8.self).contains("fixture-ok"))
        // The HTTP body, including its terminating chunk, arrived before release.
        await gate.release()
    }

    func testPersistentTerminalAuditFailureDoesNotFailAnAlreadyDeliveredCall() async throws {
        let fixture = try await HTTPMCPFixture.start()
        addTeardownBlock { try await fixture.stop() }
        let events = HTTPActivityCollector()
        let router = HTTPRouterHarness(port: fixture.port).router(events: events, failEveryTerminal: true)
        addTeardownBlock { await router.shutdown() }
        let sid = try await initialize(router)
        let response = await router.handle(request(method: "tools/call", session: sid, tool: "read"))
        let body = try await collect(response)
        XCTAssertTrue(String(decoding: body, as: UTF8.self).contains("fixture-ok"))
        let attempts = await events.attempts
        XCTAssertEqual(attempts, [.started, .succeeded, .succeeded])
    }

    func testHTTPCatalogCaptureListsToolsWithoutCallingThem() async throws {
        let fixture = try await HTTPMCPFixture.start()
        addTeardownBlock { try await fixture.stop() }
        let tools = try await MCPHTTPCatalogCapture.run(endpoint: "http://127.0.0.1:\(fixture.port)/mcp", headers: [:])
        XCTAssertEqual(tools.map(\.name), ["read"])
        XCTAssertEqual(fixture.requestCount, 3) // initialize, initialized, tools/list
    }

    func testHTTPCatalogCaptureFollowsBoundedListCursors() async throws {
        let fixture = try await HTTPMCPFixture.start(paginatedList: true)
        addTeardownBlock { try await fixture.stop() }
        let tools = try await MCPHTTPCatalogCapture.run(endpoint: "http://127.0.0.1:\(fixture.port)/mcp", headers: [:])
        XCTAssertEqual(tools.map(\.name), ["read", "write"])
        XCTAssertEqual(fixture.requestCount, 4)
    }

    func testHTTPCatalogCaptureRevalidatesAfterListResponse() async throws {
        let fixture = try await HTTPMCPFixture.start()
        addTeardownBlock { try await fixture.stop() }
        final class Remaining: @unchecked Sendable { var value = 1 }
        let remaining = Remaining()
        do {
            _ = try await MCPHTTPCatalogCapture.run(
                endpoint: "http://127.0.0.1:\(fixture.port)/mcp",
                headers: [:],
                validate: {
                    remaining.value -= 1
                    if remaining.value < 0 { throw MCPManagementError.denied }
                }
            )
            XCTFail("revocation after tools/list must deny publication")
        } catch {
            XCTAssertEqual(error as? MCPManagementError, .denied)
        }
        XCTAssertEqual(remaining.value, -1)
    }

    func testHTTPCatalogCaptureRejectsAnUnboundedList() async throws {
        let fixture = try await HTTPMCPFixture.start(endlessList: true)
        addTeardownBlock { try await fixture.stop() }
        do {
            _ = try await MCPHTTPCatalogCapture.run(endpoint: "http://127.0.0.1:\(fixture.port)/mcp", headers: [:])
            XCTFail("incomplete catalogs must not succeed")
        } catch {
            XCTAssertEqual(error as? MCPManagementError, .catalogIncomplete)
        }
    }

    func testAuditFailurePreventsToolDispatch() async throws {
        let fixture = try await HTTPMCPFixture.start()
        addTeardownBlock { try await fixture.stop() }
        let router = HTTPRouterHarness(port:fixture.port).router(failAudit:true)
        addTeardownBlock { await router.shutdown() }
        let sid = try await initialize(router)
        let response = await router.handle(request(method:"tools/call",session:sid,tool:"read"))
        XCTAssertTrue(String(decoding:response.body,as:UTF8.self).contains("-32030"))
        XCTAssertEqual(fixture.requestCount,0) // Audit is required even before credentialed initialization.
    }
    func testSplitSSESecretsAreMaskedOnlyAfterCompleteEvent() throws {
        var parser = MCPHTTPSSEDecoder()
        let raw = Data("data: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"text\":\"synthetic-upstream\"}}\n\n".utf8)
        var messages:[Data] = []
        for byte in raw { if let message = try parser.append(byte) { messages.append(message) } }
        XCTAssertEqual(messages.count,1)
        let output = try MCPHTTPMessageMasker(secrets:["synthetic-upstream"]).mask(messages[0])
        XCTAssertFalse(String(decoding:output,as:UTF8.self).contains("synthetic-upstream"))
    }
    private func initialize(_ router:MCPHTTPRouter) async throws -> String {
        let response = await router.handle(request(method:"initialize"))
        XCTAssertEqual(response.status,200)
        return try XCTUnwrap(response.headers.first(name:"MCP-Session-Id"))
    }
    private func request(method:String,session:String?=nil,tool:String?=nil,token:String="primary",version:String="2025-11-25") -> MCPHTTPRequest {
        var headers = HTTPHeaders([("Host","127.0.0.1:8788"),("Authorization","Bearer "+token),("MCP-Protocol-Version",version)])
        if let session { headers.add(name:"MCP-Session-Id",value:session) }
        let params:[String:Any] = method == "initialize" ? ["protocolVersion":version,"capabilities":[:],"clientInfo":["name":"test","version":"1"]] : ["name":tool ?? "","arguments":[:]]
        let body = try! JSONSerialization.data(withJSONObject:["jsonrpc":"2.0","id":1,"method":method,"params":params])
        return MCPHTTPRequest(method:"POST",uri:"/mcp/fixture-server",headers:headers,body:body)
    }
    private func collect(_ response:MCPHTTPResponse) async throws -> Data {
        let collector = HTTPDataCollector()
        if let stream=response.stream {
            let delivered = try await stream { await collector.append($0) }
            await delivered?()
            return await collector.data
        }
        return response.body
    }
}
private actor HTTPTerminalGate {
    private var released = false
    private var waiter: CheckedContinuation<Void, Never>?
    func wait() async {
        if released { return }
        await withCheckedContinuation { waiter = $0 }
    }
    func release() { released = true; waiter?.resume(); waiter = nil }
}
private actor HTTPDataCollector { var data=Data();func append(_ chunk:Data){data.append(chunk)} }
private actor HTTPAuthorizationCollector {
    var tools: [String] = []
    func append(_ tool: String) { tools.append(tool) }
}
private actor HTTPActivityCollector {
    var events: [MCPHTTPActivityEvent] = []
    var attempts: [MCPHTTPActivityOutcome] = []
    private var rejectedTerminal = false
    func append(_ event: MCPHTTPActivityEvent, failFirstTerminal: Bool = false, failEveryTerminal: Bool = false) throws {
        attempts.append(event.outcome)
        if failEveryTerminal, event.outcome != .started { throw MCPManagementError.auditUnavailable }
        if failFirstTerminal, event.outcome != .started, !rejectedTerminal {
            rejectedTerminal = true
            throw MCPManagementError.auditUnavailable
        }
        events.append(event)
    }
}
private struct HTTPRouterHarness: Sendable {
    let port:Int
    let identity = MCPServerIdentity(workspacePath:"/tmp/fixture",upstreamName:"internal")
    let primary = UUID(), secondary = UUID(), generation = UUID()
    func router(failAudit:Bool=false, events: HTTPActivityCollector? = nil, denyAdmission: Bool = false, failFirstTerminal: Bool = false, failEveryTerminal: Bool = false, terminalGate: HTTPTerminalGate? = nil, authorizations: HTTPAuthorizationCollector? = nil) -> MCPHTTPRouter {
        let server=MCPServerSnapshot(id:"fixture-server",identity:identity,displayName:"Internal",transport:.streamableHTTP,
            endpointLabel:"http://127.0.0.1:\(port)/mcp",policy:.init(allow:["read"],deny:["delete"]),catalog:[.init(name:"read")],authorizationRevision:"revision")
        return MCPHTTPRouter(dependencies:.init(registrySnapshot:{.init(revision:"revision",servers:[server])},portalDocument:{"<html/>"},mcpAccessEnabled:{true},
            httpAuthority:{ command in
                switch command {
                case .authenticate(_,let token):
                    return .init(principal:.init(id:token == "primary" ? primary : secondary,binding:.init(serverID:"fixture-server",identity:identity,client:.codex),generation:generation))
                case .authorize(let principal,let session,let revision,let tool),
                     .authorizeExisting(let principal,let session,let revision,let tool):
                    await authorizations?.append(tool)
                    if denyAdmission { throw MCPManagementError.denied }
                    return .init(lease:.init(grant:.init(id:UUID(),principal:principal,sessionID:session,revision:revision,expiresAt:Date().addingTimeInterval(60),credentialLabels:[]),
                        headers:["X-API-Key":"synthetic-upstream"],secrets:["synthetic-upstream"]))
                case .validate:return .init(valid:true)
                default:return .init()
                }
            },recordHTTPActivity:{ event in
                if failAudit { throw MCPManagementError.auditUnavailable }
                if event.outcome == .succeeded { await terminalGate?.wait() }
                try await events?.append(event, failFirstTerminal: failFirstTerminal, failEveryTerminal: failEveryTerminal)
            }))
    }
}

private final class HTTPMCPFixture: @unchecked Sendable {
    let port: Int
    private let group: MultiThreadedEventLoopGroup
    private let channel: Channel
    private let box: FixtureBox
    private let lock = NSLock()
    private var storedRequestCount = 0
    private var storedLastAPIKey: String?

    var requestCount: Int {
        lock.withLock { storedRequestCount }
    }

    var lastAPIKey: String? {
        lock.withLock { storedLastAPIKey }
    }

    private init(port: Int, group: MultiThreadedEventLoopGroup, channel: Channel, box: FixtureBox) {
        self.box = box
        self.port = port
        self.group = group
        self.channel = channel
    }

    static func start(streaming: Bool = false, holdCallHeaders: Bool = false,
                      rejectGET: Bool = false, sseInitialization: Bool = false, negotiatedVersion: String? = nil,
                      paginatedList: Bool = false, endlessList: Bool = false,
                      callReceived: @escaping @Sendable () -> Void = {}) async throws -> HTTPMCPFixture {
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        let box = FixtureBox()
        box.streaming = streaming
        box.rejectGET = rejectGET
        box.sseInitialization = sseInitialization
        box.negotiatedVersion = negotiatedVersion
        box.holdCallHeaders = holdCallHeaders
        box.paginatedList = paginatedList
        box.endlessList = endlessList
        box.callReceived = callReceived
        let channel = try await ServerBootstrap(group: group)
            .childChannelInitializer { channel in
                channel.pipeline.configureHTTPServerPipeline().flatMap {
                    channel.pipeline.addHandler(HTTPMCPFixtureHandler(box: box))
                }
            }
            .bind(host: "127.0.0.1", port: 0)
            .get()
        let port = try XCTUnwrap(channel.localAddress?.port)
        let fixture = HTTPMCPFixture(port: port, group: group, channel: channel, box: box)
        box.observe = { [weak fixture] headers in
            fixture?.lock.withLock {
                fixture?.storedRequestCount += 1
                fixture?.storedLastAPIKey = headers.first(name: "X-API-Key")
            }
        }
        return fixture
    }

    func releaseFinal() { box.release() }

    func stop() async throws {
        try await channel.close().get()
        try await group.shutdownGracefully()
    }
}

private final class FixtureBox: @unchecked Sendable {
    let lock = NSLock()
    var streaming = false
    var rejectGET = false
    var sseInitialization = false
    var negotiatedVersion: String?
    var holdCallHeaders = false
    var paginatedList = false
    var endlessList = false
    var callReceived: @Sendable () -> Void = {}
    private var finish: (@Sendable () -> Void)?
    func setFinish(_ value: @escaping @Sendable () -> Void) { lock.withLock { finish = value } }
    func release() { let action = lock.withLock { let action = finish; finish = nil; return action }; action?() }
    var observe: @Sendable (HTTPHeaders) -> Void = { _ in }
}

private final class HTTPMCPFixtureHandler: ChannelInboundHandler, @unchecked Sendable {
    typealias InboundIn = HTTPServerRequestPart
    typealias OutboundOut = HTTPServerResponsePart
    private let box: FixtureBox
    private var body = ByteBuffer()
    private var headers = HTTPHeaders()
    private var method = HTTPMethod.POST

    init(box: FixtureBox) { self.box = box }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        switch unwrapInboundIn(data) {
        case .head(let head):
            body.clear()
            headers = head.headers
            method = head.method
        case .body(var value):
            body.writeBuffer(&value)
        case .end:
            box.observe(headers)
            if method == .GET, box.rejectGET {
                context.write(wrapOutboundOut(.head(.init(version: .http1_1, status: .methodNotAllowed,
                    headers: HTTPHeaders([("Content-Length", "0")])))), promise: nil)
                context.writeAndFlush(wrapOutboundOut(.end(nil)), promise: nil)
                return
            }
            let request = (try? JSONSerialization.jsonObject(
                with: Data(body.readBytes(length: body.readableBytes) ?? [])
            ) as? [String: Any]) ?? [:]
            if let version = box.negotiatedVersion, request["method"] as? String != "initialize",
               headers.first(name: "MCP-Protocol-Version") != version {
                context.write(wrapOutboundOut(.head(.init(version: .http1_1, status: .badRequest,
                    headers: HTTPHeaders([("Content-Length", "0")])))), promise: nil)
                context.writeAndFlush(wrapOutboundOut(.end(nil)), promise: nil)
                return
            }
            var response: [String: Any] = [
                "jsonrpc": "2.0",
                "id": request["id"] ?? NSNull(),
                "result": ["content": [["type": "text", "text": "fixture-ok"]]],
            ]
            if request["method"] as? String == "initialize" {
                response["result"] = ["protocolVersion":box.negotiatedVersion ?? "2025-11-25", "capabilities":["tools":[:]], "serverInfo":["name":"fixture","version":"1"]]
            }
            if request["method"] as? String == "tools/list" {
                let params = request["params"] as? [String: Any]
                let cursor = params?["cursor"] as? String
                if box.endlessList {
                    response["result"] = [
                        "tools": [["name": "read", "description": "Read fixture data.", "inputSchema": ["type": "object"]]],
                        "nextCursor": "more",
                    ]
                } else if box.paginatedList {
                    if cursor == "page-2" {
                        response["result"] = ["tools": [["name": "write", "description": "Write fixture data.", "inputSchema": ["type": "object"]]]]
                    } else {
                        response["result"] = [
                            "tools": [["name": "read", "description": "Read fixture data.", "inputSchema": ["type": "object"]]],
                            "nextCursor": "page-2",
                        ]
                    }
                } else {
                    response["result"] = ["tools": [["name": "read", "description": "Read fixture data.", "inputSchema": ["type": "object"]]]]
                }
            }
            if request["method"] as? String == "tools/call" {
                box.callReceived()
                if box.holdCallHeaders { return }
                response["result"] = ["content":[["type":"text","text":"fixture-ok synthetic-upstream"]]]
            }
            var data = try! JSONSerialization.data(withJSONObject: response)
            let sseInit = box.sseInitialization && request["method"] as? String == "initialize"
            if sseInit { data = Data("\u{FEFF}data: ".utf8) + data + Data("\r\r".utf8) }
            if box.streaming, request["method"] as? String == "tools/call" {
                let channel = context.channel
                let finalData = Data("data: ".utf8) + data + Data("\n\n".utf8)
                box.setFinish {
                    var buffer = channel.allocator.buffer(capacity:finalData.count)
                    buffer.writeBytes(finalData)
                    channel.writeAndFlush(HTTPServerResponsePart.body(.byteBuffer(buffer)),promise:nil)
                    channel.writeAndFlush(HTTPServerResponsePart.end(nil),promise:nil)
                }
                context.write(wrapOutboundOut(.head(.init(version:.http1_1,status:.ok,
                    headers:HTTPHeaders([("Content-Type","text/event-stream"),("Transfer-Encoding","chunked")])))),promise:nil)
                let progress = Data("data: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\",\"params\":{\"progressToken\":\"x\",\"progress\":0,\"message\":\"synthetic-upstream\"}}\n\n".utf8)
                for chunk in [progress.prefix(progress.count-10), progress.suffix(10)] {
                    var buffer = channel.allocator.buffer(capacity:chunk.count); buffer.writeBytes(chunk)
                    context.writeAndFlush(wrapOutboundOut(.body(.byteBuffer(buffer))),promise:nil)
                }
                return
            }
            var headers = HTTPHeaders()
            headers.add(name: "Content-Type", value: sseInit ? "text/event-stream; charset=utf-8" : "application/json")
            headers.add(name: "Content-Length", value: String(data.count))
            context.write(wrapOutboundOut(.head(HTTPResponseHead(
                version: .http1_1,
                status: .ok,
                headers: headers
            ))), promise: nil)
            var buffer = context.channel.allocator.buffer(capacity: data.count)
            buffer.writeBytes(data)
            context.write(wrapOutboundOut(.body(.byteBuffer(buffer))), promise: nil)
            context.writeAndFlush(wrapOutboundOut(.end(nil)), promise: nil)
        }
    }
}
