import XCTest
import AuthenticatorBridge
@testable import AuthsiaBridgeHost

final class MCPManagerRuntimeTests: XCTestCase {
    func testConcurrentStartsJoinOneListenerAndOrderedStopWins() async throws {
        let runtime = MCPManagerRuntime(dependencies: .init(registrySnapshot: { .init(revision: "fixture", servers: []) },
                                                           portalDocument: { "<html/>" }, mcpAccessEnabled: { true }))
        addTeardownBlock { await runtime.stop() }
        try await withThrowingTaskGroup(of: URL.self) { group in
            for _ in 0..<12 { group.addTask { try await runtime.start() } }
            for try await url in group { XCTAssertEqual(url.port, 8787) }
        }
        await runtime.stop()
        let status = await runtime.status()
        XCTAssertEqual(status.state, .stopped)
        // A subsequent start must be able to bind the same ports.
        _ = try await runtime.start()
    }
    func testBootstrapAuthenticatesStatusAndRegistryThenCannotReplay() async throws {
        let registry = MCPRegistrySnapshot(revision: "fixture", servers: [])
        let runtime = MCPManagerRuntime(dependencies: MCPManagerRuntimeDependencies(
            registrySnapshot: { registry },
            portalDocument: { "<html><body>Authsia MCP</body></html>" },
            mcpAccessEnabled: { true }
        ))
        let session = URLSession(configuration: .ephemeral)
        let bootstrapURL = try await runtime.start()
        addTeardownBlock { await runtime.stop(); session.invalidateAndCancel() }

        let documentURL = try XCTUnwrap(URL(string: MCPManagerRuntime.portalURL + "/"))
        let (document, documentResponse) = try await session.data(from: documentURL)
        XCTAssertEqual((documentResponse as? HTTPURLResponse)?.statusCode, 200)
        XCTAssertTrue(String(decoding: document, as: UTF8.self).contains("Authsia MCP"))

        let capability = try XCTUnwrap(
            URLComponents(url: bootstrapURL, resolvingAgainstBaseURL: false)?
                .fragment?
                .split(separator: "=", maxSplits: 1)
                .last
                .map(String.init)
        )
        let exchange = try await exchangeCapability(capability, session: session)
        XCTAssertEqual(exchange.status, 200)

        let status = try await authenticatedGET(
            "/api/v1/status",
            cookie: exchange.cookie,
            proof: exchange.proof,
            session: session
        )
        XCTAssertEqual(status.status, 200)
        XCTAssertEqual(status.json["state"] as? String, "running")
        XCTAssertEqual(status.json["mcpAccessEnabled"] as? Bool, true)

        let registryResponse = try await authenticatedGET(
            "/api/v1/registry",
            cookie: exchange.cookie,
            proof: exchange.proof,
            session: session
        )
        XCTAssertEqual(registryResponse.status, 200)
        XCTAssertEqual(registryResponse.json["revision"] as? String, "fixture")

        let replay = try await exchangeCapability(capability, session: session)
        XCTAssertEqual(replay.status, 401)
        await runtime.stop()
        let stoppedStatus = await runtime.status()
        XCTAssertEqual(stoppedStatus.state, .stopped)
    }

    func testCookieWithoutMemoryProofIsRejected() async throws {
        let runtime = MCPManagerRuntime(dependencies: MCPManagerRuntimeDependencies(
            registrySnapshot: { MCPRegistrySnapshot(revision: "fixture", servers: []) },
            portalDocument: { "<html></html>" },
            mcpAccessEnabled: { true }
        ))
        let session = URLSession(configuration: .ephemeral)
        let bootstrapURL = try await runtime.start()
        addTeardownBlock { await runtime.stop(); session.invalidateAndCancel() }
        let capability = try XCTUnwrap(
            URLComponents(url: bootstrapURL, resolvingAgainstBaseURL: false)?.fragment?
                .split(separator: "=", maxSplits: 1).last.map(String.init)
        )
        let exchange = try await exchangeCapability(capability, session: session)

        var request = URLRequest(url: URL(string: MCPManagerRuntime.portalURL + "/api/v1/status")!)
        request.setValue(MCPManagerRuntime.portalURL + "/", forHTTPHeaderField: "Referer")
        request.setValue(exchange.cookie, forHTTPHeaderField: "Cookie")
        let (_, response) = try await session.data(for: request)
        XCTAssertEqual((response as? HTTPURLResponse)?.statusCode, 401)
    }

    func testAuthenticatedEnrollmentDelegatesWithoutReturningToken() async throws {
        let runtime = MCPManagerRuntime(dependencies: MCPManagerRuntimeDependencies(
            registrySnapshot: { MCPRegistrySnapshot(revision: "fixture", servers: []) },
            portalDocument: { "<html></html>" },
            mcpAccessEnabled: { true },
            prepareOperation: { _ in MCPPreparedManagementChange(preview: "Enroll Codex", validate: {}, apply: { "Done" }) },
            confirmOperation: { _ in true }
        ))
        let session = URLSession(configuration: .ephemeral)
        let bootstrapURL = try await runtime.start()
        addTeardownBlock { await runtime.stop(); session.invalidateAndCancel() }
        let capability = try XCTUnwrap(
            URLComponents(url: bootstrapURL, resolvingAgainstBaseURL: false)?.fragment?
                .split(separator: "=", maxSplits: 1).last.map(String.init)
        )
        let exchange = try await exchangeCapability(capability, session: session)
        var request = URLRequest(
            url: URL(string: MCPManagerRuntime.portalURL + "/api/v1/operations")!
        )
        request.httpMethod = "POST"
        request.setValue(MCPManagerRuntime.portalURL, forHTTPHeaderField: "Origin")
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue(exchange.cookie, forHTTPHeaderField: "Cookie")
        request.setValue(exchange.proof, forHTTPHeaderField: "X-Authsia-Proof")
        request.httpBody = try JSONEncoder().encode(MCPManagementOperationRequest(kind: .enrollHTTP, serverID: "server-fixture"))

        let (data, response) = try await session.data(for: request)
        XCTAssertEqual((response as? HTTPURLResponse)?.statusCode, 200)
        let result = try JSONDecoder().decode(MCPManagementOperationView.self, from: data)
        XCTAssertEqual(result.state, .prepared)
        XCTAssertFalse(String(decoding: data, as: UTF8.self).localizedCaseInsensitiveContains("token"))
    }

    private func exchangeCapability(
        _ capability: String,
        session: URLSession
    ) async throws -> (status: Int, cookie: String, proof: String) {
        var request = URLRequest(
            url: URL(string: MCPManagerRuntime.portalURL + "/api/v1/session/exchange")!
        )
        request.httpMethod = "POST"
        request.setValue(MCPManagerRuntime.portalURL, forHTTPHeaderField: "Origin")
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = try JSONSerialization.data(withJSONObject: ["capability": capability])
        let (data, response) = try await session.data(for: request)
        let http = try XCTUnwrap(response as? HTTPURLResponse)
        let object = (try? JSONSerialization.jsonObject(with: data) as? [String: Any]) ?? [:]
        let setCookie = http.value(forHTTPHeaderField: "Set-Cookie") ?? ""
        let cookie = setCookie.split(separator: ";", maxSplits: 1).first.map(String.init) ?? ""
        return (http.statusCode, cookie, object["proof"] as? String ?? "")
    }

    private func authenticatedGET(
        _ path: String,
        cookie: String,
        proof: String,
        session: URLSession
    ) async throws -> (status: Int, json: [String: Any]) {
        var request = URLRequest(url: URL(string: MCPManagerRuntime.portalURL + path)!)
        // Same-origin browser GET under Referrer-Policy: no-referrer sends
        // neither Origin nor Referer. Authentication must not require them.
        request.setValue(cookie, forHTTPHeaderField: "Cookie")
        request.setValue(proof, forHTTPHeaderField: "X-Authsia-Proof")
        let (data, response) = try await session.data(for: request)
        let http = try XCTUnwrap(response as? HTTPURLResponse)
        let object = (try? JSONSerialization.jsonObject(with: data) as? [String: Any]) ?? [:]
        return (http.statusCode, object)
    }
}
