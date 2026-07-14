import XCTest
@testable import AuthsiaBridgeHost

final class BridgeScrapeProvenanceTests: XCTestCase {
    func testNormalizedClearsMachineDetailsWhenNotScraped() {
        let provenance = BridgeScrapeProvenance.normalized(
            isScraped: false,
            machineName: "Laptop",
            machineId: "machine-1"
        )

        XCTAssertEqual(provenance, BridgeScrapeProvenance(isScraped: false, machineName: nil, machineId: nil))
    }

    func testNormalizedKeepsMachineDetailsWhenScraped() {
        let provenance = BridgeScrapeProvenance.normalized(
            isScraped: true,
            machineName: "Laptop",
            machineId: "machine-1"
        )

        XCTAssertEqual(provenance, BridgeScrapeProvenance(isScraped: true, machineName: "Laptop", machineId: "machine-1"))
    }

    func testResolvedInheritsExistingStateWhenPayloadOmitsScrapeFields() {
        let provenance = BridgeScrapeProvenance.resolved(
            payloadIsScraped: nil,
            payloadMachineName: nil,
            payloadMachineId: nil,
            existingIsScraped: true,
            existingMachineName: "Old Laptop",
            existingMachineId: "old-machine"
        )

        XCTAssertEqual(
            provenance,
            BridgeScrapeProvenance(isScraped: true, machineName: "Old Laptop", machineId: "old-machine")
        )
    }

    func testResolvedClearsMachineDetailsWhenPayloadDisablesScrapedState() {
        let provenance = BridgeScrapeProvenance.resolved(
            payloadIsScraped: false,
            payloadMachineName: "Laptop",
            payloadMachineId: "machine-1",
            existingIsScraped: true,
            existingMachineName: "Old Laptop",
            existingMachineId: "old-machine"
        )

        XCTAssertEqual(provenance, BridgeScrapeProvenance(isScraped: false, machineName: nil, machineId: nil))
    }
}
