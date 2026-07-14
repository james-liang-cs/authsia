#if os(macOS)
public struct BridgeScrapeProvenance: Equatable {
    public let isScraped: Bool
    public let machineName: String?
    public let machineId: String?

    public init(isScraped: Bool, machineName: String?, machineId: String?) {
        self.isScraped = isScraped
        self.machineName = machineName
        self.machineId = machineId
    }

    public static func normalized(
        isScraped: Bool,
        machineName: String?,
        machineId: String?
    ) -> BridgeScrapeProvenance {
        guard isScraped else {
            return BridgeScrapeProvenance(isScraped: false, machineName: nil, machineId: nil)
        }
        return BridgeScrapeProvenance(isScraped: true, machineName: machineName, machineId: machineId)
    }

    public static func resolved(
        payloadIsScraped: Bool?,
        payloadMachineName: String?,
        payloadMachineId: String?,
        existingIsScraped: Bool,
        existingMachineName: String?,
        existingMachineId: String?
    ) -> BridgeScrapeProvenance {
        let isScraped = payloadIsScraped ?? existingIsScraped
        guard isScraped else {
            return BridgeScrapeProvenance(isScraped: false, machineName: nil, machineId: nil)
        }
        return BridgeScrapeProvenance(
            isScraped: isScraped,
            machineName: payloadMachineName ?? existingMachineName,
            machineId: payloadMachineId ?? existingMachineId
        )
    }
}
#endif
