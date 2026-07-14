import Foundation

enum ScrapedItemMachineSupport {
    static func shouldInclude(
        isScraped: Bool,
        scrapeMachineName: String? = nil,
        scrapeMachineId: String?,
        currentMachineId: String,
        currentMachineName: String? = nil,
        allMachines: Bool
    ) -> Bool {
        guard isScraped else { return true }
        guard !allMachines else { return true }
        guard let scrapeMachineId, !scrapeMachineId.isEmpty else { return true }
        if scrapeMachineId == currentMachineId { return true }
        guard let scrapeMachineName = normalizedMachineName(scrapeMachineName),
              let currentMachineName = normalizedMachineName(currentMachineName) else {
            return false
        }
        return scrapeMachineName == currentMachineName
    }

    static func displayMachine(
        isScraped: Bool,
        scrapeMachineName: String?,
        scrapeMachineId: String?
    ) -> String {
        guard isScraped else { return "-" }
        if let scrapeMachineName,
           !scrapeMachineName.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            return scrapeMachineName
        }
        return scrapeMachineId == nil ? "legacy scrape" : "unknown machine"
    }

    private static func normalizedMachineName(_ name: String?) -> String? {
        guard var value = name?.trimmingCharacters(in: .whitespacesAndNewlines),
              !value.isEmpty else {
            return nil
        }
        if value.hasSuffix(".local") {
            value.removeLast(".local".count)
        }
        return value.lowercased()
    }
}
