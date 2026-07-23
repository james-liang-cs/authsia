import Foundation
import XCTest
import AuthenticatorBridge
@testable import authsia

final class AgentLeakBoundaryContractTests: XCTestCase {
    func testAutomationCredentialIsDiscoverableInCurrentLocalStore() throws {
        let (store, directory) = try AccessCredentialStoreFixture.make(prefix: "agent-leak-contract")
        defer { try? FileManager.default.removeItem(at: directory) }
        let credential = AccessCredential(
            id: UUID(uuidString: "00000000-0000-0000-0000-000000000002")!,
            name: "synthetic automation",
            scope: "Team/API",
            createdAt: Date(timeIntervalSince1970: 1_700_000_000),
            expiresAt: Date(timeIntervalSince1970: 1_700_000_300),
            revokedAt: nil,
            machineId: "synthetic-machine",
            machineName: "Synthetic Host",
            allowedCommands: [.exec]
        )
        try store.save(credential)

        let onDiskData = try Data(contentsOf: store.fileURL)
        let decoded = try JSONDecoder.authsiaISO8601.decode([AccessCredential].self, from: onDiskData)

        XCTAssertEqual(decoded, [credential])
    }

    func testNonUTF8OutputPassesThroughStreamingMasker() {
        let masker = OutputMasker(secrets: ["synthetic-secret"])
        var stream = masker.makeStream()
        let binary = Data([0xff, 0xfe, 0x00, 0x80])

        let output = stream.mask(binary) + stream.flush()

        XCTAssertEqual(output, binary)
    }
}

private extension JSONDecoder {
    static var authsiaISO8601: JSONDecoder {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return decoder
    }
}
