import Foundation

enum ScrapedItemMachineSupport {
    struct Partition<Item> {
        let included: [Item]
        let omittedCount: Int
        let omittedMachineLabels: [String]
    }

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

    static func partition<Item>(
        _ items: [Item],
        allMachines: Bool,
        currentMachineId: String,
        currentMachineName: String?,
        isScraped: KeyPath<Item, Bool>,
        scrapeMachineName: KeyPath<Item, String?>,
        scrapeMachineId: KeyPath<Item, String?>
    ) -> Partition<Item> {
        var included: [Item] = []
        var omittedLabels: [String] = []
        for item in items {
            if shouldInclude(
                isScraped: item[keyPath: isScraped],
                scrapeMachineName: item[keyPath: scrapeMachineName],
                scrapeMachineId: item[keyPath: scrapeMachineId],
                currentMachineId: currentMachineId,
                currentMachineName: currentMachineName,
                allMachines: allMachines
            ) {
                included.append(item)
            } else {
                omittedLabels.append(
                    displayMachine(
                        isScraped: true,
                        scrapeMachineName: item[keyPath: scrapeMachineName],
                        scrapeMachineId: item[keyPath: scrapeMachineId]
                    )
                )
            }
        }
        return Partition(
            included: included,
            omittedCount: omittedLabels.count,
            omittedMachineLabels: Array(Set(omittedLabels)).sorted()
        )
    }

    static func omissionWarning(omittedCount: Int, machineLabels: [String]) -> String? {
        guard omittedCount > 0 else { return nil }
        let noun = omittedCount == 1 ? "item" : "items"
        let labels = machineLabels.filter { !$0.isEmpty && $0 != "-" }
        let origin = labels.isEmpty ? "" : " (\(labels.joined(separator: ", ")))"
        return "warning: omitted \(omittedCount) scraped \(noun) not from this machine\(origin); pass --all-machines to include them"
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
