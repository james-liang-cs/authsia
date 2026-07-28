import Foundation
import Security

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
            return ["authsia", "list", "otp", "--format", "json", "--chrome-native-host"]
        case .listPasswordsJSON:
            return ["authsia", "list", "passwords", "--format", "json", "--chrome-native-host"]
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

    static let signingInformationFlags = SecCSFlags(rawValue: kSecCSSigningInformation)

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

    static func candidatePaths(executableURL: URL?, homeDirectory: String?) -> [URL] {
        var paths: [URL] = []
        if let executableURL {
            paths.append(
                executableURL
                    .deletingLastPathComponent()
                    .appendingPathComponent("authsia", isDirectory: false)
            )
        }
        paths.append(URL(fileURLWithPath: "/usr/local/bin/authsia"))
        paths.append(URL(fileURLWithPath: "/opt/homebrew/bin/authsia"))
        if let homeDirectory {
            paths.append(
                URL(fileURLWithPath: homeDirectory, isDirectory: true)
                    .appendingPathComponent(".local/bin/authsia", isDirectory: false)
            )
        }
        return paths
    }

    private static func homeDirectoryFallback() -> String? {
        let pw = getpwuid(getuid())
        guard let dir = pw?.pointee.pw_dir else { return nil }
        return String(cString: dir)
    }

    static func resolveExecutablePath(
        candidatePaths: [URL],
        expectedTeamIdentifier: String?,
        isExecutable: (String) -> Bool,
        teamIdentifierForExecutable: (URL) -> String?
    ) -> URL? {
        guard let expectedTeamIdentifier else {
            return nil
        }
        return candidatePaths.first { candidate in
            isExecutable(candidate.path)
                && teamIdentifierForExecutable(candidate) == expectedTeamIdentifier
        }
    }

    private static func resolveExecutablePath() -> URL? {
        let homeDirectory = ProcessInfo.processInfo.environment["HOME"] ?? homeDirectoryFallback()
        return resolveExecutablePath(
            candidatePaths: candidatePaths(
                executableURL: Bundle.main.executableURL,
                homeDirectory: homeDirectory
            ),
            expectedTeamIdentifier: currentTeamIdentifier(),
            isExecutable: FileManager.default.isExecutableFile(atPath:),
            teamIdentifierForExecutable: teamIdentifier(forExecutable:)
        )
    }

    private static func currentTeamIdentifier() -> String? {
        var code: SecCode?
        guard SecCodeCopySelf(SecCSFlags(), &code) == errSecSuccess,
              let code else {
            return nil
        }
        return signingTeamIdentifier(for: code)
    }

    private static func teamIdentifier(forExecutable url: URL) -> String? {
        var code: SecStaticCode?
        guard SecStaticCodeCreateWithPath(url as CFURL, SecCSFlags(), &code) == errSecSuccess,
              let code,
              SecStaticCodeCheckValidity(code, SecCSFlags(), nil) == errSecSuccess else {
            return nil
        }
        return signingTeamIdentifier(for: code)
    }

    private static func signingTeamIdentifier(for code: SecStaticCode) -> String? {
        var information: CFDictionary?
        guard SecCodeCopySigningInformation(code, signingInformationFlags, &information) == errSecSuccess,
              let signingInformation = information as? [String: Any] else {
            return nil
        }
        return signingInformation[kSecCodeInfoTeamIdentifier as String] as? String
    }

    private static func signingTeamIdentifier(for code: SecCode) -> String? {
        var staticCode: SecStaticCode?
        guard SecCodeCopyStaticCode(code, SecCSFlags(), &staticCode) == errSecSuccess,
              let staticCode else {
            return nil
        }
        return signingTeamIdentifier(for: staticCode)
    }

    public static func processRunner(command: CLICommand) throws -> Data {
        let process = Process()
        guard let execURL = resolveExecutablePath() else {
            throw CLIClientError.nonZeroExit(
                status: -1,
                stderr: "A signed Authsia CLI could not be found."
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
