import Foundation

struct MachineIdentity: Codable, Sendable {
    let machineId: String
    let hostname: String

    /// Hostname with `.local` suffix stripped for clean display.
    var displayName: String {
        hostname.hasSuffix(".local")
            ? String(hostname.dropLast(".local".count))
            : hostname
    }

    /// Load from disk (or create and persist if absent).
    static func load(from directory: URL = defaultDirectory) -> MachineIdentity {
        let fileURL = directory.appendingPathComponent("machine.json")
        let fm = FileManager.default

        if fm.fileExists(atPath: fileURL.path),
           let data = try? Data(contentsOf: fileURL),
           let existing = try? JSONDecoder().decode(MachineIdentity.self, from: data) {
            // Repair permissions on read path in case they were changed externally
            try? fm.setAttributes([.posixPermissions: 0o600], ofItemAtPath: fileURL.path)
            return existing
        }

        let identity = MachineIdentity(
            machineId: UUID().uuidString,
            hostname: ProcessInfo.processInfo.hostName
        )

        try? fm.createDirectory(at: directory, withIntermediateDirectories: true)
        if let data = try? JSONEncoder().encode(identity) {
            // Use .withoutOverwriting so a concurrent first write doesn't clobber
            try? data.write(to: fileURL, options: [.withoutOverwriting])
            try? fm.setAttributes([.posixPermissions: 0o600], ofItemAtPath: fileURL.path)
        }

        // If write failed due to a racing writer, read back what was written
        if let raceData = try? Data(contentsOf: fileURL),
           let raceIdentity = try? JSONDecoder().decode(MachineIdentity.self, from: raceData) {
            return raceIdentity
        }

        // Verify the file was actually persisted; warn if not
        if fm.fileExists(atPath: fileURL.path) == false {
            fputs("warning: authsia could not persist machine identity to \(fileURL.path) — machine ID will not be stable across sessions\n", stderr)
        }

        return identity
    }

    private static var defaultDirectory: URL {
        FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent(".authsia")
    }
}
