import XCTest
@testable import AuthenticatorBridge

final class BridgeCoderTests: XCTestCase {
    func testRoundTripRequest() throws {
        let request = BridgeRequest(
            id: UUID(),
            type: .getOTP,
            query: "github",
            options: .init(field: nil, copy: false),
            context: .init(isTTY: true, isPiped: false, isSSH: false, isCI: false, timestamp: Date())
        )
        let data = try BridgeCoder.encode(request)
        let decoded = try BridgeCoder.decode(BridgeRequest.self, from: data)
        XCTAssertEqual(decoded.type, .getOTP)
        XCTAssertEqual(decoded.query, "github")
    }

    func testRoundTripRequestWithBody() throws {
        let payload = PasswordWritePayload(
            name: "GitHub",
            username: "octo",
            password: "secret",
            website: nil,
            notes: nil
        )
        let body = try BridgeCoder.encode(payload)

        let request = BridgeRequest(
            id: UUID(),
            type: .addPassword,
            query: "",
            options: .init(field: nil, copy: false),
            context: .init(isTTY: true, isPiped: false, isSSH: false, isCI: false, timestamp: Date()),
            body: body
        )
        let data = try BridgeCoder.encode(request)
        let decoded = try BridgeCoder.decode(BridgeRequest.self, from: data)
        XCTAssertEqual(decoded.type, .addPassword)
        XCTAssertNotNil(decoded.body)
    }

    func testAgentJITPreflightPayloadRoundTrips() throws {
        let payload = AgentJITPreflightPayload(
            requestedCommand: "exec",
            references: [
                AgentJITPreflightReference(
                    type: "password",
                    query: "GitHub",
                    folderPath: "Team/API",
                    isFolderScoped: true
                ),
                AgentJITPreflightReference(
                    type: "note",
                    query: "Runbook",
                    folderPath: nil,
                    isFolderScoped: false
                ),
            ]
        )
        let data = try BridgeCoder.encode(payload)
        let decoded = try BridgeCoder.decode(AgentJITPreflightPayload.self, from: data)
        XCTAssertEqual(decoded.requestedCommand, "exec")
        XCTAssertEqual(decoded.references.first?.folderPath, "Team/API")
        XCTAssertEqual(decoded.references.first?.isFolderScoped, true)
        XCTAssertEqual(decoded.references.last?.isFolderScoped, false)
    }

    func testAgentJITPreflightReferenceDefaultsMissingFolderScopedFlagToTrue() throws {
        let data = """
        {
          "type": "password",
          "query": "GitHub",
          "folderPath": null
        }
        """.data(using: .utf8)!

        let decoded = try BridgeCoder.decode(AgentJITPreflightReference.self, from: data)

        XCTAssertEqual(decoded.isFolderScoped, true)
    }

    func testBridgeListPayloadIncludesScrapedAndSSH() throws {
        let payload = BridgeListPayload(
            accounts: [
                BridgeAccount(
                    id: UUID(),
                    issuer: "GitHub",
                    label: "me",
                    isFavorite: false,
                    isCliEnabled: true,
                    isScraped: false,
                    createdAt: Date(),
                    updatedAt: Date()
                )
            ],
            passwords: [],
            certificates: [],
            notes: [],
            sshKeys: [
                BridgeSSHKey(
                    id: UUID(),
                    name: "Work",
                    comment: "laptop",
                    fingerprint: "SHA256:abc",
                    publicKey: "ssh-ed25519 AAAA",
                    isFavorite: false,
                    isCliEnabled: true,
                    isScraped: true,
                    createdAt: Date(),
                    updatedAt: Date()
                )
            ]
        )
        let data = try BridgeCoder.encode(payload)
        _ = try BridgeCoder.decode(BridgeListPayload.self, from: data)
    }

    func testPasswordWritePayloadIncludesScrapedFlag() throws {
        let payload = PasswordWritePayload(
            name: "GitHub",
            username: "octo",
            password: "secret",
            website: nil,
            notes: nil,
            isScraped: true
        )
        let data = try BridgeCoder.encode(payload)
        let decoded = try BridgeCoder.decode(PasswordWritePayload.self, from: data)
        XCTAssertEqual(decoded.isScraped, true)
    }

    func testPasswordWritePayloadIncludesExpiry() throws {
        let expiresAt = Date(timeIntervalSince1970: 1_800_000_000)
        let payload = PasswordWritePayload(
            name: "GitHub",
            username: "octo",
            password: "secret",
            website: nil,
            notes: nil,
            expiresAt: expiresAt,
            clearExpiresAt: true
        )
        let data = try BridgeCoder.encode(payload)
        let decoded = try BridgeCoder.decode(PasswordWritePayload.self, from: data)
        XCTAssertEqual(decoded.expiresAt, expiresAt)
        XCTAssertEqual(decoded.clearExpiresAt, true)
    }

    func testNoteWritePayloadIncludesScrapedFlag() throws {
        let payload = NoteWritePayload(title: "Config", content: "{\"key\": \"value\"}", isScraped: true)
        let data = try BridgeCoder.encode(payload)
        let decoded = try BridgeCoder.decode(NoteWritePayload.self, from: data)
        XCTAssertEqual(decoded.isScraped, true)
    }

    func testSSHWritePayloadIncludesScrapedFlag() throws {
        let payload = SSHKeyWritePayload(
            name: "Work",
            publicKey: "ssh-ed25519 AAAA",
            privateKey: "-----BEGIN OPENSSH PRIVATE KEY-----",
            comment: "laptop",
            fingerprint: "SHA256:abc",
            isScraped: true
        )
        let data = try BridgeCoder.encode(payload)
        let decoded = try BridgeCoder.decode(SSHKeyWritePayload.self, from: data)
        XCTAssertEqual(decoded.isScraped, true)
    }

    func testWritePayloadsIncludeFolderPath() throws {
        let passwordPayload = PasswordWritePayload(
            name: "GitHub",
            username: "octo",
            password: "secret",
            website: nil,
            notes: nil,
            isScraped: true,
            folderPath: "Engineering/Prod"
        )
        let passwordData = try BridgeCoder.encode(passwordPayload)
        let decodedPassword = try BridgeCoder.decode(PasswordWritePayload.self, from: passwordData)
        XCTAssertEqual(decodedPassword.folderPath, "Engineering/Prod")

        let notePayload = NoteWritePayload(
            title: "Config",
            content: "{\"key\": \"value\"}",
            isScraped: true,
            folderPath: "Engineering/Prod"
        )
        let noteData = try BridgeCoder.encode(notePayload)
        let decodedNote = try BridgeCoder.decode(NoteWritePayload.self, from: noteData)
        XCTAssertEqual(decodedNote.folderPath, "Engineering/Prod")

        let sshPayload = SSHKeyWritePayload(
            name: "Work",
            publicKey: "ssh-ed25519 AAAA",
            privateKey: "-----BEGIN OPENSSH PRIVATE KEY-----",
            comment: "laptop",
            fingerprint: "SHA256:abc",
            isScraped: true,
            folderPath: "Engineering/Prod"
        )
        let sshData = try BridgeCoder.encode(sshPayload)
        let decodedSSH = try BridgeCoder.decode(SSHKeyWritePayload.self, from: sshData)
        XCTAssertEqual(decodedSSH.folderPath, "Engineering/Prod")
    }

    func testWritePayloadsIncludeScrapeMachineAttributes() throws {
        let passwordPayload = PasswordWritePayload(
            name: "GitHub",
            username: "octo",
            password: "secret",
            website: nil,
            notes: nil,
            isScraped: true,
            folderPath: "Engineering/Prod",
            scrapeMachineName: "jamess-mac-mini",
            scrapeMachineId: "73C4AEA4-EB11-4AD7-AC14-DA296C404846"
        )
        let passwordData = try BridgeCoder.encode(passwordPayload)
        let decodedPassword = try BridgeCoder.decode(PasswordWritePayload.self, from: passwordData)
        XCTAssertEqual(decodedPassword.scrapeMachineName, "jamess-mac-mini")
        XCTAssertEqual(decodedPassword.scrapeMachineId, "73C4AEA4-EB11-4AD7-AC14-DA296C404846")

        let notePayload = NoteWritePayload(
            title: "Config",
            content: "{\"key\": \"value\"}",
            isScraped: true,
            folderPath: "Engineering/Prod",
            scrapeMachineName: "jamess-mac-mini",
            scrapeMachineId: "73C4AEA4-EB11-4AD7-AC14-DA296C404846"
        )
        let noteData = try BridgeCoder.encode(notePayload)
        let decodedNote = try BridgeCoder.decode(NoteWritePayload.self, from: noteData)
        XCTAssertEqual(decodedNote.scrapeMachineName, "jamess-mac-mini")
        XCTAssertEqual(decodedNote.scrapeMachineId, "73C4AEA4-EB11-4AD7-AC14-DA296C404846")

        let sshPayload = SSHKeyWritePayload(
            name: "Work",
            publicKey: "ssh-ed25519 AAAA",
            privateKey: "-----BEGIN OPENSSH PRIVATE KEY-----",
            comment: "laptop",
            fingerprint: "SHA256:abc",
            isScraped: true,
            folderPath: "Engineering/Prod",
            scrapeMachineName: "jamess-mac-mini",
            scrapeMachineId: "73C4AEA4-EB11-4AD7-AC14-DA296C404846"
        )
        let sshData = try BridgeCoder.encode(sshPayload)
        let decodedSSH = try BridgeCoder.decode(SSHKeyWritePayload.self, from: sshData)
        XCTAssertEqual(decodedSSH.scrapeMachineName, "jamess-mac-mini")
        XCTAssertEqual(decodedSSH.scrapeMachineId, "73C4AEA4-EB11-4AD7-AC14-DA296C404846")
    }

    func testBridgeListPayloadIncludesScrapeMachineAttributes() throws {
        let payload = BridgeListPayload(
            accounts: [],
            passwords: [
                BridgePassword(
                    id: UUID(),
                    name: "API_KEY",
                    username: "",
                    website: nil,
                    folderPath: nil,
                    isFavorite: false,
                    isCliEnabled: true,
                    isScraped: true,
                    createdAt: Date(),
                    updatedAt: Date(),
                    scrapeMachineName: "jamess-mac-mini",
                    scrapeMachineId: "73C4AEA4-EB11-4AD7-AC14-DA296C404846"
                )
            ],
            certificates: [],
            notes: [],
            sshKeys: []
        )

        let data = try BridgeCoder.encode(payload)
        let decoded = try BridgeCoder.decode(BridgeListPayload.self, from: data)
        XCTAssertEqual(decoded.passwords.first?.scrapeMachineName, "jamess-mac-mini")
        XCTAssertEqual(decoded.passwords.first?.scrapeMachineId, "73C4AEA4-EB11-4AD7-AC14-DA296C404846")
    }

    func testBridgeListPayloadIncludesAPIKeysWithoutUsername() throws {
        let now = Date(timeIntervalSince1970: 1_700_000_000)
        let apiKey = BridgeAPIKey(
            id: UUID(),
            name: "Stripe",
            website: "https://dashboard.stripe.com",
            folderPath: "Team/API",
            isFavorite: true,
            isCliEnabled: true,
            isScraped: false,
            createdAt: now,
            updatedAt: now,
            expiresAt: Date(timeIntervalSince1970: 1_800_000_000),
            hasSecret: true
        )
        let payload = BridgeListPayload(
            accounts: [],
            passwords: [],
            apiKeys: [apiKey],
            certificates: [],
            notes: [],
            sshKeys: []
        )

        let data = try BridgeCoder.encode(payload)
        let decoded = try BridgeCoder.decode(BridgeListPayload.self, from: data)

        XCTAssertEqual(decoded.apiKeys, [apiKey])
    }

    func testBridgeListItemsRoundTripEnvironmentMetadata() throws {
        let now = Date(timeIntervalSince1970: 1_700_000_000)
        let password = BridgePassword(
            id: UUID(),
            name: "DATABASE_URL",
            username: "service",
            website: nil,
            isFavorite: false,
            isCliEnabled: true,
            isScraped: false,
            createdAt: now,
            updatedAt: now,
            environments: ["Production", "Development"]
        )
        let apiKey = BridgeAPIKey(
            id: UUID(),
            name: "API_KEY",
            website: nil,
            isFavorite: false,
            isCliEnabled: true,
            isScraped: false,
            createdAt: now,
            updatedAt: now,
            environments: ["Production"]
        )

        let payload = BridgeListPayload(
            accounts: [],
            passwords: [password],
            apiKeys: [apiKey],
            certificates: [],
            notes: [],
            sshKeys: []
        )
        let decoded = try BridgeCoder.decode(
            BridgeListPayload.self,
            from: BridgeCoder.encode(payload)
        )

        XCTAssertEqual(decoded.passwords.first?.environments, ["Development", "Production"])
        XCTAssertEqual(decoded.apiKeys.first?.environments, ["Production"])
    }

    func testBridgePasswordDefaultsMissingEnvironmentsToDefaultEnvironment() throws {
        let password = BridgePassword(
            id: UUID(),
            name: "DATABASE_URL",
            username: "service",
            website: nil,
            isFavorite: false,
            isCliEnabled: true,
            isScraped: false,
            createdAt: Date(timeIntervalSince1970: 1_700_000_000),
            updatedAt: Date(timeIntervalSince1970: 1_700_000_001)
        )
        let encoded = try BridgeCoder.encode(password)
        var object = try XCTUnwrap(JSONSerialization.jsonObject(with: encoded) as? [String: Any])
        object.removeValue(forKey: "environments")

        let decoded = try BridgeCoder.decode(
            BridgePassword.self,
            from: JSONSerialization.data(withJSONObject: object)
        )

        XCTAssertEqual(decoded.environments, [])
    }

    func testWritePayloadsRoundTripEnvironmentReplacement() throws {
        let password = PasswordWritePayload(
            name: nil,
            username: nil,
            password: nil,
            website: nil,
            notes: nil,
            environments: ["Production", "Development"]
        )
        let note = NoteWritePayload(
            title: nil,
            content: nil,
            environments: []
        )

        XCTAssertEqual(
            try BridgeCoder.decode(PasswordWritePayload.self, from: BridgeCoder.encode(password)).environments,
            ["Development", "Production"]
        )
        XCTAssertEqual(
            try BridgeCoder.decode(NoteWritePayload.self, from: BridgeCoder.encode(note)).environments,
            []
        )
    }

    func testEnvironmentAccessScopeRoundTripsAndFiltersDefaultEnvironmentPlusNamedItems() throws {
        let named = EnvironmentAccessScope.named("Production")
        let defaultOnly = EnvironmentAccessScope.defaultOnly

        XCTAssertEqual(
            try BridgeCoder.decode(EnvironmentAccessScope.self, from: BridgeCoder.encode(named)),
            named
        )
        XCTAssertEqual(
            try BridgeCoder.decode(EnvironmentAccessScope.self, from: BridgeCoder.encode(defaultOnly)),
            defaultOnly
        )
        XCTAssertTrue(named.allows(itemEnvironments: []))
        XCTAssertTrue(named.allows(itemEnvironments: ["production"]))
        XCTAssertFalse(named.allows(itemEnvironments: ["Development"]))
        XCTAssertTrue(defaultOnly.allows(itemEnvironments: []))
        XCTAssertFalse(defaultOnly.allows(itemEnvironments: ["Production"]))
    }

    func testCertificateWritePayloadIncludesScrapedFlag() throws {
        let payload = CertificateWritePayload(
            name: "TLS Cert",
            certificate: "CERT_DATA",
            privateKey: "KEY_DATA",
            notes: "notes",
            isScraped: true
        )
        let data = try BridgeCoder.encode(payload)
        let decoded = try BridgeCoder.decode(CertificateWritePayload.self, from: data)
        XCTAssertEqual(decoded.isScraped, true)
    }
}
