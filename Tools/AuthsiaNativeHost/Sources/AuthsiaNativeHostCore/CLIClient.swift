import Foundation

public enum CLIClientError: Error, Equatable {
    case emptyOutput
    case nonZeroExit(status: Int32, stderr: String)
    case invalidUTF8
}

public enum CLICommand: Equatable {
    case listOTPJSON
    case listPasswordsJSON
    case getPasswordJSON(id: UUID)
    case getOTPJSON(id: UUID)
    case getChromePasswordJSON(id: UUID)
    case getChromeOTPJSON(id: UUID)

    var arguments: [String] {
        switch self {
        case .listOTPJSON:
            return ["authsia", "list", "otp", "--format", "json"]
        case .listPasswordsJSON:
            return ["authsia", "list", "passwords", "--format", "json"]
        case .getPasswordJSON(let id):
            return ["authsia", "get", "password", id.uuidString, "--format", "json"]
        case .getOTPJSON(let id):
            return ["authsia", "get", "otp", id.uuidString, "--format", "json"]
        case .getChromePasswordJSON(let id):
            return ["authsia", "get", "password", id.uuidString, "--format", "json", "--chrome-native-host"]
        case .getChromeOTPJSON(let id):
            return ["authsia", "get", "otp", id.uuidString, "--format", "json", "--chrome-native-host"]
        }
    }
}

public struct CLIListAccount: Codable, Equatable {
    public let id: UUID
    public let issuer: String
    public let label: String
    public let hosts: [String]?
    public let isFavorite: Bool
    public let isCliEnabled: Bool
    public let isScraped: Bool
    public let createdAt: Date
    public let updatedAt: Date

    public init(
        id: UUID,
        issuer: String,
        label: String,
        hosts: [String]? = nil,
        isFavorite: Bool,
        isCliEnabled: Bool,
        isScraped: Bool,
        createdAt: Date,
        updatedAt: Date
    ) {
        self.id = id
        self.issuer = issuer
        self.label = label
        self.hosts = hosts
        self.isFavorite = isFavorite
        self.isCliEnabled = isCliEnabled
        self.isScraped = isScraped
        self.createdAt = createdAt
        self.updatedAt = updatedAt
    }
}

public struct CLIListPassword: Codable, Equatable {
    public let id: UUID
    public let name: String
    public let username: String
    public let website: String?
    public let isFavorite: Bool
    public let isCliEnabled: Bool

    public init(
        id: UUID,
        name: String,
        username: String,
        website: String?,
        isFavorite: Bool,
        isCliEnabled: Bool
    ) {
        self.id = id
        self.name = name
        self.username = username
        self.website = website
        self.isFavorite = isFavorite
        self.isCliEnabled = isCliEnabled
    }
}

fileprivate struct CLIPasswordItem: Codable {
    let id: String
    let name: String
    let username: String
    let website: String?
    let isFavorite: Bool
    let isCliEnabled: Bool
}

public struct CLIGetPasswordResult: Codable, Equatable {
    public let id: String
    public let name: String
    public let username: String
    public let password: String
    public let website: String?

    public init(id: String, name: String, username: String, password: String, website: String?) {
        self.id = id
        self.name = name
        self.username = username
        self.password = password
        self.website = website
    }
}

public struct CLIGetOTPResult: Codable, Equatable {
    public let id: String
    public let issuer: String
    public let label: String
    public let code: String
    public let remaining: Int
    public let expiresAt: Date
    public let isFavorite: Bool
}

public struct CLIClient {
    public typealias Runner = (CLICommand) throws -> Data

    private let runner: Runner
    private let decoder: JSONDecoder

    public init(runner: @escaping Runner = CLIClient.processRunner) {
        self.runner = runner
        self.decoder = JSONDecoder()
        self.decoder.dateDecodingStrategy = .iso8601
    }

    public func listPasswords() throws -> [CLIListPassword] {
        let data = try runner(.listPasswordsJSON)
        guard !data.isEmpty else {
            throw CLIClientError.emptyOutput
        }

        let response = try decoder.decode([CLIPasswordItem].self, from: data)
        return response.compactMap { item in
            guard let uuid = UUID(uuidString: item.id) else { return nil }
            return CLIListPassword(
                id: uuid,
                name: item.name,
                username: item.username,
                website: item.website,
                isFavorite: item.isFavorite,
                isCliEnabled: item.isCliEnabled
            )
        }
    }

    public func listAccounts() throws -> [CLIListAccount] {
        let data = try runner(.listOTPJSON)
        guard !data.isEmpty else {
            throw CLIClientError.emptyOutput
        }

        return try decoder.decode([CLIListAccount].self, from: data)
    }

    public func getPassword(id: UUID) throws -> CLIGetPasswordResult {
        let data = try runner(.getChromePasswordJSON(id: id))
        guard !data.isEmpty else {
            throw CLIClientError.emptyOutput
        }
        return try decoder.decode(CLIGetPasswordResult.self, from: data)
    }

    public func getOTP(id: UUID) throws -> CLIGetOTPResult {
        let data = try runner(.getChromeOTPJSON(id: id))
        guard !data.isEmpty else {
            throw CLIClientError.emptyOutput
        }
        return try decoder.decode(CLIGetOTPResult.self, from: data)
    }

    private static let candidatePaths: [String] = {
        var paths = [
            "/usr/local/bin/authsia",
            "/opt/homebrew/bin/authsia",
        ]
        // Also check ~/.local/bin (common user-local install path)
        if let home = ProcessInfo.processInfo.environment["HOME"] ?? homeDirectoryFallback() {
            paths.append(home + "/.local/bin/authsia")
        }
        // Check inside the app bundle (symlink target)
        paths.append("/Applications/Authsia.app/Contents/Helpers/authsia")
        return paths
    }()

    private static func homeDirectoryFallback() -> String? {
        let pw = getpwuid(getuid())
        guard let dir = pw?.pointee.pw_dir else { return nil }
        return String(cString: dir)
    }

    private static func resolveExecutablePath() -> URL? {
        for path in candidatePaths {
            if FileManager.default.isExecutableFile(atPath: path) {
                return URL(fileURLWithPath: path)
            }
        }
        // Fallback: check PATH via /usr/bin/which
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/which")
        process.arguments = ["authsia"]
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = FileHandle.nullDevice
        do {
            try process.run()
            process.waitUntilExit()
            let data = pipe.fileHandleForReading.readDataToEndOfFile()
            let path = String(data: data, encoding: .utf8)?
                .trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
            if !path.isEmpty, FileManager.default.isExecutableFile(atPath: path) {
                return URL(fileURLWithPath: path)
            }
        } catch {}
        return nil
    }

    public static func processRunner(command: CLICommand) throws -> Data {
        let process = Process()
        guard let execURL = resolveExecutablePath() else {
            throw CLIClientError.nonZeroExit(
                status: -1,
                stderr: "authsia CLI not found. Install it or ensure it is on your PATH."
            )
        }
        process.executableURL = execURL

        // Remove "authsia" from the start of arguments since we're calling it directly
        var args = command.arguments
        if args.first == "authsia" {
            args.removeFirst()
        }
        process.arguments = args

        let stdoutPipe = Pipe()
        let stderrPipe = Pipe()
        process.standardOutput = stdoutPipe
        process.standardError = stderrPipe

        try process.run()
        process.waitUntilExit()

        let stdoutData = stdoutPipe.fileHandleForReading.readDataToEndOfFile()
        let stderrData = stderrPipe.fileHandleForReading.readDataToEndOfFile()

        if process.terminationStatus != 0 {
            let stderrString = String(data: stderrData, encoding: .utf8) ?? ""
            throw CLIClientError.nonZeroExit(status: process.terminationStatus, stderr: stderrString)
        }

        if stdoutData.isEmpty {
            throw CLIClientError.emptyOutput
        }

        return stdoutData
    }
}
