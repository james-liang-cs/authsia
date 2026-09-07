import XCTest
import AuthenticatorBridge
@testable import AuthsiaBridgeHost

final class MCPManagerEndpointRegistryTests: XCTestCase {
    func testOnlyAppMayRegisterAndClearEndpoint() throws {
        let registry = MCPManagerEndpointRegistry()
        let listener = NSXPCListener.anonymous()
        let app = identity(pid: 41, bundleIdentifier: "app.authsia")
        let cli = identity(pid: 42, bundleIdentifier: "authsia")

        XCTAssertThrowsError(try registry.register(endpoint: listener.endpoint, caller: cli, connectionID: ObjectIdentifier(listener))) {
            XCTAssertEqual($0 as? MCPManagerEndpointRegistryError, .unauthorized)
        }

        try registry.register(endpoint: listener.endpoint, caller: app, connectionID: ObjectIdentifier(listener))
        XCTAssertNoThrow(try registry.endpoint(caller: cli, cliAccessEnabled: true))
        XCTAssertThrowsError(try registry.clear(caller: cli, connectionID: ObjectIdentifier(listener)))
        try registry.clear(caller: app, connectionID: ObjectIdentifier(listener))
        XCTAssertThrowsError(try registry.endpoint(caller: cli, cliAccessEnabled: true)) {
            XCTAssertEqual($0 as? MCPManagerEndpointRegistryError, .unavailable)
        }
    }

    func testCLIRetrievalRequiresCLISetting() throws {
        let registry = MCPManagerEndpointRegistry()
        let listener = NSXPCListener.anonymous()
        try registry.register(
            endpoint: listener.endpoint,
            caller: identity(pid: 41, bundleIdentifier: "app.authsia"),
            connectionID: ObjectIdentifier(listener)
        )

        XCTAssertThrowsError(
            try registry.endpoint(
                caller: identity(pid: 42, bundleIdentifier: "authsia"),
                cliAccessEnabled: false
            )
        ) { error in
            XCTAssertEqual(error as? MCPManagerEndpointRegistryError, .unauthorized)
        }
    }

    func testInvalidatingOldOwnerDoesNotClearReplacement() throws {
        let registry = MCPManagerEndpointRegistry()
        let first = NSXPCListener.anonymous()
        let replacement = NSXPCListener.anonymous()
        try registry.register(
            endpoint: first.endpoint,
            caller: identity(pid: 41, bundleIdentifier: "app.authsia"),
            connectionID: ObjectIdentifier(first)
        )
        try registry.register(
            endpoint: replacement.endpoint,
            caller: identity(pid: 41, bundleIdentifier: "app.authsia"),
            connectionID: ObjectIdentifier(replacement)
        )

        registry.clear(connectionID: ObjectIdentifier(first))

        XCTAssertNoThrow(
            try registry.endpoint(
                caller: identity(pid: 42, bundleIdentifier: "authsia"),
                cliAccessEnabled: true
            )
        )
    }

    private func identity(pid: Int32, bundleIdentifier: String) -> CallerIdentity {
        CallerIdentity(
            pid: pid,
            processName: bundleIdentifier,
            bundleIdentifier: bundleIdentifier,
            signingTeamId: "SYNTHETIC",
            signingIdentity: "synthetic"
        )
    }
}
