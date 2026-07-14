import XCTest
import Darwin
@testable import AuthsiaBridgeHost
import AuthenticatorBridge
import AuthenticatorData

final class SSHAgentAutomationAuthorizationTests: XCTestCase {
    func testAllowsInScopeSSHCredential() {
        let credentialID = UUID()
        let credential = makeCredential(id: credentialID, scope: "Team/API", allowedCommands: [.exec, .ssh])

        let decision = SSHAgentAutomationAuthorization.authorize(
            environment: [AutomationCredentialEnvironment.sshCredentialKey: credentialID.uuidString],
            keyFolderPath: "Team/API/Prod",
            credentialLookup: { id in
                XCTAssertEqual(id, credentialID)
                return .found(credential)
            },
            now: Date(timeIntervalSince1970: 1_700_000_100),
            currentMachineId: "machine-1"
        )

        XCTAssertEqual(decision, .allowWithoutApproval(scope: .folder("Team/API")))
    }

    func testAllowsGeneralCredentialMarkerForDirectSSHChildProcess() {
        let credentialID = UUID()
        let credential = makeCredential(id: credentialID, scope: "Team/API", allowedCommands: [.ssh])

        let decision = SSHAgentAutomationAuthorization.authorize(
            environment: [AutomationCredentialEnvironment.generalCredentialKey: credentialID.uuidString],
            keyFolderPath: "Team/API/Deploy",
            credentialLookup: { _ in .found(credential) },
            now: Date(timeIntervalSince1970: 1_700_000_100),
            currentMachineId: "machine-1"
        )

        XCTAssertEqual(decision, .allowWithoutApproval(scope: .folder("Team/API")))
    }

    func testAllowsGlobalScopeSSHCredentialForAnyKeyFolder() {
        let credentialID = UUID()
        let credential = makeCredential(id: credentialID, scope: nil, allowedCommands: [.ssh])

        let decision = SSHAgentAutomationAuthorization.authorize(
            environment: [AutomationCredentialEnvironment.generalCredentialKey: credentialID.uuidString],
            keyFolderPath: nil,
            credentialLookup: { _ in .found(credential) },
            now: Date(timeIntervalSince1970: 1_700_000_100),
            currentMachineId: "machine-1"
        )

        XCTAssertEqual(decision, .allowWithoutApproval(scope: .global))
    }

    func testDeniesCredentialWithoutSSHCapability() {
        let credentialID = UUID()
        let credential = makeCredential(id: credentialID, allowedCommands: [.exec])

        let decision = SSHAgentAutomationAuthorization.authorize(
            environment: [AutomationCredentialEnvironment.sshCredentialKey: credentialID.uuidString],
            keyFolderPath: "Team/API",
            credentialLookup: { _ in .found(credential) },
            now: Date(timeIntervalSince1970: 1_700_000_100),
            currentMachineId: "machine-1"
        )

        XCTAssertEqual(decision, .deny("Automation credential does not permit 'ssh'."))
    }

    func testDeniesOutOfScopeSSHKey() {
        let credentialID = UUID()
        let credential = makeCredential(id: credentialID, scope: "Team/API", allowedCommands: [.ssh])

        let decision = SSHAgentAutomationAuthorization.authorize(
            environment: [AutomationCredentialEnvironment.sshCredentialKey: credentialID.uuidString],
            keyFolderPath: "Team/Other",
            credentialLookup: { _ in .found(credential) },
            now: Date(timeIntervalSince1970: 1_700_000_100),
            currentMachineId: "machine-1"
        )

        XCTAssertEqual(
            decision,
            .deny("Automation credential scope 'Team/API' does not allow access to this SSH key.")
        )
    }

    func testReturnsNotAutomationWhenNoCredentialMarkerExists() {
        let decision = SSHAgentAutomationAuthorization.authorize(
            environment: [:],
            keyFolderPath: "Team/API",
            credentialLookup: { _ in XCTFail("lookup should not run"); return .credentialNotFound },
            currentMachineId: "machine-1"
        )

        XCTAssertEqual(decision, .notAutomation)
    }

    func testAllowsSessionGrantWhenProcessEnvironmentIsHidden() {
        let credentialID = UUID()
        let credential = makeCredential(id: credentialID, scope: "Team/API", allowedCommands: [.ssh])

        let decision = SSHAgentAutomationAuthorization.authorize(
            environment: [:],
            keyFolderPath: "Team/API/Deploy",
            sessionScope: "tty:/dev/ttys001:sid:100",
            ancestryPIDs: [300, 200],
            credentialLookup: { id in
                XCTAssertEqual(id, credentialID)
                return .found(credential)
            },
            grantCredentialLookup: { sessionScope, ancestryPIDs, _ in
                XCTAssertEqual(sessionScope, "tty:/dev/ttys001:sid:100")
                XCTAssertEqual(ancestryPIDs, [300, 200])
                return credentialID
            },
            now: Date(timeIntervalSince1970: 1_700_000_100),
            currentMachineId: "machine-1"
        )

        XCTAssertEqual(decision, .allowWithoutApproval(scope: .folder("Team/API")))
    }

    func testReturnsNotAutomationWhenNoEnvironmentOrGrantExists() {
        let decision = SSHAgentAutomationAuthorization.authorize(
            environment: [:],
            keyFolderPath: "Team/API",
            sessionScope: "tty:/dev/ttys001:sid:100",
            ancestryPIDs: [300, 200],
            credentialLookup: { _ in XCTFail("lookup should not run"); return .credentialNotFound },
            grantCredentialLookup: { _, _, _ in nil },
            currentMachineId: "machine-1"
        )

        XCTAssertEqual(decision, .notAutomation)
    }

    func testParsesProcessArgumentsAndEnvironment() {
        let buffer = makeProcessBuffer(
            executablePath: "/usr/bin/ssh",
            arguments: ["ssh", "git@github.com"],
            environment: [
                "AUTHSIA_SSH_ACCESS_CREDENTIAL=credential-id",
                "PATH=/usr/bin",
            ]
        )

        let result = SSHAgentListener.parseProcessArgumentsAndEnvironment(buffer, size: buffer.count)

        XCTAssertEqual(result?.arguments, ["ssh", "git@github.com"])
        XCTAssertEqual(result?.environment[AutomationCredentialEnvironment.sshCredentialKey], "credential-id")
        XCTAssertEqual(result?.environment["PATH"], "/usr/bin")
    }

    func testParsesLiveProcessEnvironmentFromKernelProcargs() throws {
        let credentialID = UUID().uuidString
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/python3")
        process.arguments = ["-c", "import time; time.sleep(5)"]
        var environment = ProcessInfo.processInfo.environment
        environment[AutomationCredentialEnvironment.sshCredentialKey] = credentialID
        process.environment = environment

        try process.run()
        defer {
            if process.isRunning {
                process.terminate()
                process.waitUntilExit()
            }
        }

        let result = try waitForProcessArgumentsAndEnvironment(pid: process.processIdentifier)

        XCTAssertTrue(result.arguments.contains("-c"))
        XCTAssertEqual(result.environment[AutomationCredentialEnvironment.sshCredentialKey], credentialID)
    }

    func testSSHAgentAdvertisesOnlyKeysWithCurrentSecrets() {
        let currentID = UUID()
        let staleID = UUID()
        let currentBlob = Data([1, 2, 3])
        let staleBlob = Data([4, 5, 6])
        let identities = SSHAgentListener.usableSSHIdentities(
            from: [
                makeSSHKeyMetadata(id: staleID, name: "Stale", blob: staleBlob),
                makeSSHKeyMetadata(id: currentID, name: "Current", blob: currentBlob),
            ],
            hasSSHKey: { id in
                id == currentID
            }
        )

        XCTAssertEqual(identities.map(\.comment), ["Current"])
        XCTAssertEqual(identities.map(\.blob), [currentBlob])
    }

    func testSSHAgentSkipsAdoptedKeysWhenRestoredLocalPrivateKeyExists() {
        let restoredID = UUID()
        let currentID = UUID()
        let restoredBlob = Data([1, 2, 3])
        let currentBlob = Data([4, 5, 6])
        let identities = SSHAgentListener.usableSSHIdentities(
            from: [
                makeSSHKeyMetadata(id: restoredID, name: "id_ed25519", blob: restoredBlob, isScraped: true),
                makeSSHKeyMetadata(id: currentID, name: "manual", blob: currentBlob),
            ],
            hasSSHKey: { _ in true },
            hasRestoredLocalPrivateKey: { $0.name == "id_ed25519" }
        )

        XCTAssertEqual(identities.map(\.comment), ["manual"])
        XCTAssertEqual(identities.map(\.blob), [currentBlob])
    }

    func testSSHAgentSkipsAllIdentitiesForHostHandledByRestoredAdoptedKey() {
        let restoredBlob = Data([1, 2, 3])
        let githubBlob = Data([4, 5, 6])
        let identities = SSHAgentListener.usableSSHIdentities(
            from: [
                makeSSHKeyMetadata(
                    id: UUID(),
                    name: "id_ed25519",
                    blob: restoredBlob,
                    isScraped: true,
                    boundHosts: ["github.com"]
                ),
                makeSSHKeyMetadata(id: UUID(), name: "github.key", blob: githubBlob, boundHosts: ["github.com"]),
            ],
            targetHost: "github.com",
            hasSSHKey: { _ in true },
            hasRestoredLocalPrivateKey: { $0.name == "id_ed25519" }
        )

        XCTAssertTrue(identities.isEmpty)
    }

    func testSSHAgentDoesNotSuppressOtherIdentitiesForRestoredKeyWithoutHostBinding() {
        let restoredBlob = Data([1, 2, 3])
        let githubBlob = Data([4, 5, 6])
        let identities = SSHAgentListener.usableSSHIdentities(
            from: [
                makeSSHKeyMetadata(id: UUID(), name: "id_ed25519", blob: restoredBlob, isScraped: true),
                makeSSHKeyMetadata(id: UUID(), name: "github.key", blob: githubBlob),
            ],
            targetHost: "github.com",
            hasSSHKey: { _ in true },
            hasRestoredLocalPrivateKey: { $0.name == "id_ed25519" }
        )

        XCTAssertEqual(identities.map(\.comment), ["github.key"])
        XCTAssertEqual(identities.map(\.blob), [githubBlob])
    }

    func testRestoredLocalPrivateKeyDetectionRequiresAdoptedRealPrivateKeyFile() throws {
        let homeDirectory = FileManager.default.temporaryDirectory
            .appendingPathComponent("authsia-ssh-restore-\(UUID().uuidString)", isDirectory: true)
        let sshDirectory = homeDirectory.appendingPathComponent(".ssh", isDirectory: true)
        try FileManager.default.createDirectory(at: sshDirectory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: homeDirectory) }

        let metadata = makeSSHKeyMetadata(
            id: UUID(),
            name: "id_ed25519",
            blob: Data([1, 2, 3]),
            isScraped: true
        )
        let keyURL = sshDirectory.appendingPathComponent("id_ed25519", isDirectory: false)

        try """
        -----BEGIN OPENSSH PRIVATE KEY-----
        restored
        -----END OPENSSH PRIVATE KEY-----
        """.write(to: keyURL, atomically: true, encoding: .utf8)
        XCTAssertTrue(SSHAgentListener.hasRestoredLocalPrivateKey(for: metadata, homeDirectory: homeDirectory))

        let manualMetadata = makeSSHKeyMetadata(id: UUID(), name: "id_ed25519", blob: Data([1, 2, 3]))
        XCTAssertFalse(SSHAgentListener.hasRestoredLocalPrivateKey(for: manualMetadata, homeDirectory: homeDirectory))

        try "# This SSH key is managed by Authsia.\n".write(to: keyURL, atomically: true, encoding: .utf8)
        XCTAssertFalse(SSHAgentListener.hasRestoredLocalPrivateKey(for: metadata, homeDirectory: homeDirectory))
    }

    private func makeCredential(
        id: UUID = UUID(),
        scope: String? = "Team/API",
        expiresAt: Date = Date(timeIntervalSince1970: 1_800_000_000),
        revokedAt: Date? = nil,
        machineId: String = "machine-1",
        allowedCommands: Set<CapabilityCommand>
    ) -> AutomationCredentialLookup.CredentialRecord {
        AutomationCredentialLookup.CredentialRecord(
            id: id,
            scope: scope,
            expiresAt: expiresAt,
            revokedAt: revokedAt,
            machineId: machineId,
            allowedCommands: allowedCommands
        )
    }

    private func makeProcessBuffer(
        executablePath: String,
        arguments: [String],
        environment: [String]
    ) -> [CChar] {
        var data = Data()
        var argc = Int32(arguments.count)
        withUnsafeBytes(of: &argc) { data.append(contentsOf: $0) }
        data.append(contentsOf: executablePath.utf8)
        data.append(0)
        data.append(0)
        for argument in arguments {
            data.append(contentsOf: argument.utf8)
            data.append(0)
        }
        for entry in environment {
            data.append(contentsOf: entry.utf8)
            data.append(0)
        }
        data.append(0)
        return data.map { CChar(bitPattern: $0) }
    }

    private func makeSSHKeyMetadata(
        id: UUID,
        name: String,
        blob: Data,
        isScraped: Bool = false,
        boundHosts: [String] = []
    ) -> SSHKeyMetadata {
        SSHKeyMetadata(
            id: id,
            name: name,
            publicKey: "ssh-ed25519 \(blob.base64EncodedString())",
            comment: name,
            fingerprint: "SHA256:\(name)",
            createdAt: Date(timeIntervalSince1970: 1_700_000_000),
            modifiedAt: Date(timeIntervalSince1970: 1_700_000_000),
            isFavorite: false,
            isCliEnabled: true,
            isScraped: isScraped,
            boundHosts: boundHosts
        )
    }

    private func waitForProcessArgumentsAndEnvironment(
        pid: pid_t,
        timeout: TimeInterval = 2
    ) throws -> (arguments: [String], environment: [String: String]) {
        let deadline = Date().addingTimeInterval(timeout)
        var lastResult: (arguments: [String], environment: [String: String])?

        repeat {
            if let result = SSHAgentListener.kernelProcessArgumentsAndEnvironment(pid: pid) {
                lastResult = result
                if result.environment[AutomationCredentialEnvironment.sshCredentialKey] != nil {
                    return result
                }
            }
            usleep(50_000)
        } while Date() < deadline

        if let lastResult {
            return lastResult
        }
        throw NSError(
            domain: "SSHAgentAutomationAuthorizationTests",
            code: 1,
            userInfo: [NSLocalizedDescriptionKey: "Unable to read process arguments for pid \(pid)"]
        )
    }
}
