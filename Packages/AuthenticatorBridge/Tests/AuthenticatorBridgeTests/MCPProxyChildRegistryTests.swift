#if os(macOS)
import XCTest
@testable import AuthenticatorBridge

final class MCPProxyChildRegistryTests: XCTestCase {
    func testRegisterReplaceAndUnregisterByGrant() throws {
        let fileURL = FileManager.default.temporaryDirectory
            .appendingPathComponent("mcp-proxy-children-\(UUID().uuidString).json")
        defer { try? FileManager.default.removeItem(at: fileURL) }
        let grant = UUID(uuidString: "11111111-1111-1111-1111-111111111111")!

        MCPProxyChildRegistry.register(
            grantIDs: [grant],
            processGroupID: 4242,
            childProcessID: 4242,
            proxyProcessID: 4243,
            fileURL: fileURL
        )
        MCPProxyChildRegistry.register(
            grantIDs: [grant],
            processGroupID: 5252,
            childProcessID: 5252,
            proxyProcessID: 5253,
            fileURL: fileURL
        )
        let loaded = MCPProxyChildRegistry.load(fileURL: fileURL)
        XCTAssertEqual(loaded.map(\.processGroupID), [5252])
        XCTAssertEqual(loaded.map(\.proxyProcessID), [5253])

        MCPProxyChildRegistry.unregister(grantIDs: [grant], fileURL: fileURL)
        XCTAssertTrue(MCPProxyChildRegistry.load(fileURL: fileURL).isEmpty)
    }

    func testReapOrphansKillsDeadProxyRowsAndLeavesLiveOnes() throws {
        let fileURL = FileManager.default.temporaryDirectory
            .appendingPathComponent("mcp-proxy-children-\(UUID().uuidString).json")
        defer { try? FileManager.default.removeItem(at: fileURL) }
        let liveGrant = UUID(uuidString: "22222222-2222-2222-2222-222222222222")!
        let deadGrant = UUID(uuidString: "33333333-3333-3333-3333-333333333333")!
        MCPProxyChildRegistry.register(
            grantIDs: [liveGrant],
            processGroupID: 62_001,
            childProcessID: 62_001,
            proxyProcessID: 7_001,
            fileURL: fileURL
        )
        MCPProxyChildRegistry.register(
            grantIDs: [deadGrant],
            processGroupID: 62_002,
            childProcessID: 62_002,
            proxyProcessID: 7_002,
            fileURL: fileURL
        )

        MCPProxyChildRegistry.reapOrphans(
            fileURL: fileURL,
            isProcessAlive: { $0 == 7_001 },
            graceSeconds: 0
        )

        let remaining = MCPProxyChildRegistry.load(fileURL: fileURL)
        XCTAssertEqual(remaining.map(\.grantID), [liveGrant])
        XCTAssertEqual(remaining.map(\.proxyProcessID), [7_001])
    }

    func testEmptyGrantIDsStillRecordARowKeyedByProcessGroup() throws {
        let fileURL = FileManager.default.temporaryDirectory
            .appendingPathComponent("mcp-proxy-children-\(UUID().uuidString).json")
        defer { try? FileManager.default.removeItem(at: fileURL) }
        MCPProxyChildRegistry.register(
            grantIDs: [],
            processGroupID: 62_010,
            childProcessID: 62_011,
            proxyProcessID: 7_010,
            fileURL: fileURL
        )
        let loaded = MCPProxyChildRegistry.load(fileURL: fileURL)
        XCTAssertEqual(loaded.count, 1)
        XCTAssertEqual(loaded.first?.processGroupID, 62_010)
        XCTAssertEqual(loaded.first?.childProcessID, 62_011)

        MCPProxyChildRegistry.unregister(processGroupID: 62_010, fileURL: fileURL)
        XCTAssertTrue(MCPProxyChildRegistry.load(fileURL: fileURL).isEmpty)
    }

    func testTerminateIfCurrentSkipsWhenChildDoesNotOwnGroup() {
        MCPProxyChildRegistry.terminateIfCurrent(
            childProcessID: 1,
            processGroupID: 99_999,
            graceSeconds: 0
        )
    }

    func testTerminateProcessGroupIgnoresInitAndKernelPids() {
        MCPProxyChildRegistry.terminateProcessGroup(0, graceSeconds: 0)
        MCPProxyChildRegistry.terminateProcessGroup(1, graceSeconds: 0)
    }
}
#endif
