import XCTest
@testable import AuthsiaBridgeHost
import AuthenticatorBridge
import AuthenticatorCore
import AuthenticatorData
import CryptoKit

@MainActor
final class XPCRequestHandlerWriteTests: XCTestCase {
    func testCreateAccessRequestsApprovalWithScopeAndAllowlist() async throws {
        let previousValue = UserDefaults.standard.bool(forKey: "cliAccessEnabled")
        UserDefaults.standard.set(true, forKey: "cliAccessEnabled")
        defer { UserDefaults.standard.set(previousValue, forKey: "cliAccessEnabled") }

        let approver = ApprovalTracker(result: true)
        let handler = XPCRequestHandler(approver: approver, repository: TestVaultRepository())
        let payload = AccessCreateApprovalPayload(
            name: "Claude",
            scope: "Team/API",
            ttlSeconds: 900,
            expiresAt: Date(timeIntervalSince1970: 1_700_000_900),
            machineId: "machine-123",
            machineName: "Example-MacBook",
            allowedCommands: ["exec", "ssh"]
        )
        let request = BridgeRequest(
            id: UUID(),
            type: .createAccess,
            query: "Team/API",
            options: .init(field: nil, copy: false),
            context: .init(isTTY: true, isPiped: false, isSSH: false, isCI: false, timestamp: Date()),
            body: try BridgeCoder.encode(payload)
        )
        let requestData = try BridgeCoder.encode(request)

        let expectation = XCTestExpectation(description: "reply")
        handler.addItem(requestData) { data, _ in
            let response = try? BridgeCoder.decode(BridgeResponse<WriteResultPayload>.self, from: data ?? Data())
            XCTAssertEqual(response?.payload?.message, "Access credential approved")
            expectation.fulfill()
        }
        await fulfillment(of: [expectation], timeout: 1)

        XCTAssertEqual(approver.requests.count, 1)
        XCTAssertEqual(approver.requests.first?.command, .createAccess)
        XCTAssertEqual(approver.requests.first?.itemLabel, "Team/API")
        XCTAssertEqual(approver.requests.first?.field, nil)
        XCTAssertEqual(approver.requests.first?.prompt.contains("Example-MacBook"), true)
        XCTAssertEqual(approver.requests.first?.prompt.contains("allow=exec,ssh"), true)
    }

    func testCreateAccessDenialReturnsNotAuthorized() async throws {
        let previousValue = UserDefaults.standard.bool(forKey: "cliAccessEnabled")
        UserDefaults.standard.set(true, forKey: "cliAccessEnabled")
        defer { UserDefaults.standard.set(previousValue, forKey: "cliAccessEnabled") }

        let approver = ApprovalTracker(result: false)
        let handler = XPCRequestHandler(approver: approver, repository: TestVaultRepository())
        let payload = AccessCreateApprovalPayload(
            name: "Claude",
            scope: "Team/API",
            ttlSeconds: 900,
            expiresAt: Date(timeIntervalSince1970: 1_700_000_900),
            machineId: "machine-123",
            machineName: "Example-MacBook",
            allowedCommands: ["exec"]
        )
        let request = BridgeRequest(
            id: UUID(),
            type: .createAccess,
            query: "Team/API",
            options: .init(field: nil, copy: false),
            context: .init(isTTY: true, isPiped: false, isSSH: false, isCI: false, timestamp: Date()),
            body: try BridgeCoder.encode(payload)
        )
        let requestData = try BridgeCoder.encode(request)

        let expectation = XCTestExpectation(description: "reply")
        handler.addItem(requestData) { data, _ in
            let response = try? BridgeCoder.decode(BridgeResponse<WriteResultPayload>.self, from: data ?? Data())
            XCTAssertEqual(response?.error?.code, .notAuthorized)
            XCTAssertNil(response?.payload)
            expectation.fulfill()
        }
        await fulfillment(of: [expectation], timeout: 1)

        XCTAssertEqual(approver.requests.count, 1)
        XCTAssertEqual(approver.requests.first?.command, .createAccess)
    }

    func testEnsureVaultFolderPersistsPasswordAndAPIKeyFoldersAfterApproval() async throws {
        let previousValue = UserDefaults.standard.bool(forKey: "cliAccessEnabled")
        UserDefaults.standard.set(true, forKey: "cliAccessEnabled")
        defer { UserDefaults.standard.set(previousValue, forKey: "cliAccessEnabled") }

        let approver = ApprovalTracker(result: true)
        let repository = TestVaultRepository()
        let handler = XPCRequestHandler(approver: approver, repository: repository)
        let payload = VaultFolderWritePayload(path: "Workspaces/docflow")
        let request = BridgeRequest(
            id: UUID(),
            type: .ensureVaultFolder,
            query: "Workspaces/docflow",
            options: .init(field: nil, copy: false),
            context: .init(isTTY: true, isPiped: false, isSSH: false, isCI: false, timestamp: Date()),
            body: try BridgeCoder.encode(payload)
        )
        let requestData = try BridgeCoder.encode(request)

        let expectation = XCTestExpectation(description: "reply")
        handler.addItem(requestData) { data, _ in
            let response = try? BridgeCoder.decode(BridgeResponse<WriteResultPayload>.self, from: data ?? Data())
            XCTAssertEqual(response?.payload?.id, "Workspaces/docflow")
            XCTAssertEqual(response?.payload?.message, "Vault folder ready")
            expectation.fulfill()
        }
        await fulfillment(of: [expectation], timeout: 1)

        XCTAssertEqual(repository.folders[.password], ["Workspaces/docflow"])
        XCTAssertEqual(repository.folders[.apiKey], ["Workspaces/docflow"])
        for type in VaultItemType.allCases where type != .password && type != .apiKey {
            XCTAssertNil(repository.folders[type])
        }
        XCTAssertEqual(approver.requests.count, 1)
        XCTAssertEqual(approver.requests.first?.command, .ensureVaultFolder)
        XCTAssertEqual(approver.requests.first?.itemLabel, "Workspaces/docflow")
    }

    func testDeleteVaultFolderRemovesPasswordFolderAfterApproval() async throws {
        let previousValue = UserDefaults.standard.bool(forKey: "cliAccessEnabled")
        UserDefaults.standard.set(true, forKey: "cliAccessEnabled")
        defer { UserDefaults.standard.set(previousValue, forKey: "cliAccessEnabled") }

        let approver = ApprovalTracker(result: true)
        let repository = TestVaultRepository()
        try repository.load()
        try repository.addFolder("Workspaces/AuthsiaCLIValidation/old", type: .password)
        try repository.addFolder("Workspaces/AuthsiaCLIValidation/new", type: .password)
        try repository.addFolder("Workspaces/AuthsiaCLIValidation/api", type: .apiKey)
        try repository.addPassword(
            PasswordItem(
                name: "AUTHSIA_SMOKE_PASSWORD",
                username: "",
                password: Data("pw".utf8),
                folderPath: "Workspaces/AuthsiaCLIValidation/new"
            )
        )
        try repository.addAPIKey(
            APIKeyItem(
                name: "AUTHSIA_SMOKE_API_KEY",
                key: Data("sk_live_smoke".utf8),
                folderPath: "Workspaces/AuthsiaCLIValidation/api"
            )
        )
        let handler = XPCRequestHandler(approver: approver, repository: repository)
        let payload = VaultFolderWritePayload(path: "Workspaces/AuthsiaCLIValidation")
        let request = BridgeRequest(
            id: UUID(),
            type: .deleteVaultFolder,
            query: "Workspaces/AuthsiaCLIValidation",
            options: .init(field: nil, copy: false),
            context: .init(isTTY: true, isPiped: false, isSSH: false, isCI: false, timestamp: Date()),
            body: try BridgeCoder.encode(payload)
        )
        let requestData = try BridgeCoder.encode(request)

        let expectation = XCTestExpectation(description: "reply")
        handler.deleteItem(requestData) { data, _ in
            let response = try? BridgeCoder.decode(BridgeResponse<WriteResultPayload>.self, from: data ?? Data())
            XCTAssertEqual(response?.payload?.id, "Workspaces/AuthsiaCLIValidation")
            XCTAssertEqual(response?.payload?.message, "Vault folder deleted")
            expectation.fulfill()
        }
        await fulfillment(of: [expectation], timeout: 1)

        XCTAssertFalse(repository.folders[.password, default: []].contains("Workspaces/AuthsiaCLIValidation/old"))
        XCTAssertFalse(repository.folders[.password, default: []].contains("Workspaces/AuthsiaCLIValidation/new"))
        XCTAssertFalse(repository.folders[.apiKey, default: []].contains("Workspaces/AuthsiaCLIValidation/api"))
        XCTAssertFalse(repository.passwords.contains { $0.name == "AUTHSIA_SMOKE_PASSWORD" })
        XCTAssertFalse(repository.apiKeys.contains { $0.name == "AUTHSIA_SMOKE_API_KEY" })
        XCTAssertEqual(approver.requests.count, 1)
        XCTAssertEqual(approver.requests.first?.command, .deleteVaultFolder)
        XCTAssertEqual(approver.requests.first?.itemLabel, "Workspaces/AuthsiaCLIValidation")
        XCTAssertEqual(approver.requests.first?.prompt, "Allow CLI to delete vault folder 'Workspaces/AuthsiaCLIValidation'")
    }

    func testAddPasswordReturnsWriteResult() async throws {
        let previousValue = UserDefaults.standard.bool(forKey: "cliAccessEnabled")
        UserDefaults.standard.set(true, forKey: "cliAccessEnabled")
        defer { UserDefaults.standard.set(previousValue, forKey: "cliAccessEnabled") }

        let approver = ApprovalTracker(result: true)
        let repository = TestVaultRepository()
        let handler = XPCRequestHandler(approver: approver, repository: repository)

        let payload = PasswordWritePayload(name: "GitHub", username: "octo", password: "pw", website: nil, notes: nil)
        let body = try BridgeCoder.encode(payload)
        let request = BridgeRequest(
            id: UUID(),
            type: .addPassword,
            query: "",
            options: .init(field: nil, copy: false),
            context: .init(isTTY: true, isPiped: false, isSSH: false, isCI: false, timestamp: Date()),
            body: body
        )
        let requestData = try BridgeCoder.encode(request)

        let expectation = XCTestExpectation(description: "reply")
        handler.addItem(requestData) { data, _ in
            let response = try? BridgeCoder.decode(BridgeResponse<WriteResultPayload>.self, from: data ?? Data())
            XCTAssertNotNil(response?.payload?.id)
            expectation.fulfill()
        }
        await fulfillment(of: [expectation], timeout: 1)

        XCTAssertEqual(repository.passwords.count, 2)
    }

    func testAddPasswordPersistsCallerProvidedScrapedProvenance() async throws {
        let previousValue = UserDefaults.standard.bool(forKey: "cliAccessEnabled")
        UserDefaults.standard.set(true, forKey: "cliAccessEnabled")
        defer { UserDefaults.standard.set(previousValue, forKey: "cliAccessEnabled") }

        let approver = ApprovalTracker(result: true)
        let repository = TestVaultRepository()
        let handler = XPCRequestHandler(approver: approver, repository: repository)

        let payload = PasswordWritePayload(
            name: "Scraped",
            username: "octo",
            password: "pw",
            website: nil,
            notes: nil,
            isScraped: true,
            scrapeMachineName: "jamess-mac-mini",
            scrapeMachineId: "73C4AEA4-EB11-4AD7-AC14-DA296C404846"
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
        let requestData = try BridgeCoder.encode(request)

        let expectation = XCTestExpectation(description: "reply")
        handler.addItem(requestData) { _, _ in
            expectation.fulfill()
        }
        await fulfillment(of: [expectation], timeout: 1)

        let metadata = repository.passwords.first { $0.name == "Scraped" }
        XCTAssertEqual(metadata?.isScraped, true)
        XCTAssertEqual(metadata?.scrapeMachineName, "jamess-mac-mini")
        XCTAssertEqual(metadata?.scrapeMachineId, "73C4AEA4-EB11-4AD7-AC14-DA296C404846")
    }

    func testAddAPIKeyReturnsWriteResultWithoutUsername() async throws {
        let previousValue = UserDefaults.standard.bool(forKey: "cliAccessEnabled")
        UserDefaults.standard.set(true, forKey: "cliAccessEnabled")
        defer { UserDefaults.standard.set(previousValue, forKey: "cliAccessEnabled") }

        let approver = ApprovalTracker(result: true)
        let repository = TestVaultRepository()
        let handler = XPCRequestHandler(approver: approver, repository: repository)

        let payload = APIKeyWritePayload(name: "Stripe", key: "sk_live_123", website: nil, notes: nil)
        let request = BridgeRequest(
            id: UUID(),
            type: .addAPIKey,
            query: "",
            options: .init(field: nil, copy: false),
            context: .init(isTTY: true, isPiped: false, isSSH: false, isCI: false, timestamp: Date()),
            body: try BridgeCoder.encode(payload)
        )
        let requestData = try BridgeCoder.encode(request)

        let expectation = XCTestExpectation(description: "reply")
        handler.addItem(requestData) { data, _ in
            let response = try? BridgeCoder.decode(BridgeResponse<WriteResultPayload>.self, from: data ?? Data())
            XCTAssertEqual(response?.payload?.message, "API key added")
            expectation.fulfill()
        }
        await fulfillment(of: [expectation], timeout: 1)

        let metadata = try XCTUnwrap(repository.apiKeys.first { $0.name == "Stripe" })
        let full = try repository.getFullAPIKey(metadata: metadata)
        XCTAssertEqual(String(data: full.key, encoding: .utf8), "sk_live_123")
        XCTAssertEqual(approver.requests.first?.command, .addAPIKey)
        XCTAssertEqual(approver.requests.first?.itemLabel, "Stripe")
    }

    func testUpdateAPIKeyChangesSecretAndMetadata() async throws {
        let previousValue = UserDefaults.standard.bool(forKey: "cliAccessEnabled")
        UserDefaults.standard.set(true, forKey: "cliAccessEnabled")
        defer { UserDefaults.standard.set(previousValue, forKey: "cliAccessEnabled") }

        let approver = ApprovalTracker(result: true)
        let repository = TestVaultRepository()
        try repository.load()
        let handler = XPCRequestHandler(approver: approver, repository: repository)

        let payload = APIKeyWritePayload(
            name: "Stripe",
            key: "sk_live_updated",
            website: "https://stripe.com",
            notes: "billing"
        )
        let request = BridgeRequest(
            id: UUID(),
            type: .updateAPIKey,
            query: "ExistingAPIKey",
            options: .init(field: nil, copy: false),
            context: .init(isTTY: true, isPiped: false, isSSH: false, isCI: false, timestamp: Date()),
            body: try BridgeCoder.encode(payload)
        )
        let requestData = try BridgeCoder.encode(request)

        let expectation = XCTestExpectation(description: "reply")
        handler.updateItem(requestData) { data, _ in
            let response = try? BridgeCoder.decode(BridgeResponse<WriteResultPayload>.self, from: data ?? Data())
            XCTAssertEqual(response?.payload?.message, "API key updated")
            expectation.fulfill()
        }
        await fulfillment(of: [expectation], timeout: 1)

        let metadata = try XCTUnwrap(repository.apiKeys.first { $0.name == "Stripe" })
        let full = try repository.getFullAPIKey(metadata: metadata)
        XCTAssertEqual(String(data: full.key, encoding: .utf8), "sk_live_updated")
        XCTAssertEqual(full.website, "https://stripe.com")
        XCTAssertEqual(full.notes, "billing")
        XCTAssertEqual(approver.requests.first?.command, .updateAPIKey)
    }

    func testConvertPasswordToAPIKeyPreservesUsernameInNotesAndDeletesPassword() async throws {
        let previousValue = UserDefaults.standard.bool(forKey: "cliAccessEnabled")
        UserDefaults.standard.set(true, forKey: "cliAccessEnabled")
        defer { UserDefaults.standard.set(previousValue, forKey: "cliAccessEnabled") }

        let approver = ApprovalTracker(result: true)
        let repository = TestVaultRepository()
        try repository.load()
        let handler = XPCRequestHandler(approver: approver, repository: repository)

        let request = BridgeRequest(
            id: UUID(),
            type: .convertPasswordToAPIKey,
            query: "Existing",
            options: .init(field: nil, copy: false),
            context: .init(isTTY: true, isPiped: false, isSSH: false, isCI: false, timestamp: Date()),
            body: try BridgeCoder.encode(PasswordConversionPayload(targetType: "api-key"))
        )
        let requestData = try BridgeCoder.encode(request)

        let expectation = XCTestExpectation(description: "reply")
        handler.updateItem(requestData) { data, _ in
            let response = try? BridgeCoder.decode(BridgeResponse<WriteResultPayload>.self, from: data ?? Data())
            XCTAssertEqual(response?.payload?.message, "Password converted to API key")
            expectation.fulfill()
        }
        await fulfillment(of: [expectation], timeout: 1)

        XCTAssertFalse(repository.passwords.contains { $0.name == "Existing" })
        let metadata = try XCTUnwrap(repository.apiKeys.first { $0.name == "Existing" })
        let full = try repository.getFullAPIKey(metadata: metadata)
        XCTAssertEqual(String(data: full.key, encoding: .utf8), "pw")
        XCTAssertEqual(full.notes, "Converted from password username: stored")
        XCTAssertEqual(approver.requests.first?.command, .convertPasswordToAPIKey)
    }

    func testAddCertificateReturnsWriteResult() async throws {
        let previousValue = UserDefaults.standard.bool(forKey: "cliAccessEnabled")
        UserDefaults.standard.set(true, forKey: "cliAccessEnabled")
        defer { UserDefaults.standard.set(previousValue, forKey: "cliAccessEnabled") }

        let approver = ApprovalTracker(result: true)
        let repository = TestVaultRepository()
        let handler = XPCRequestHandler(approver: approver, repository: repository)

        let payload = CertificateWritePayload(name: "Acme", certificate: "CERT", privateKey: "KEY", notes: nil)
        let body = try BridgeCoder.encode(payload)
        let request = BridgeRequest(
            id: UUID(),
            type: .addCertificate,
            query: "",
            options: .init(field: nil, copy: false),
            context: .init(isTTY: true, isPiped: false, isSSH: false, isCI: false, timestamp: Date()),
            body: body
        )
        let requestData = try BridgeCoder.encode(request)

        let expectation = XCTestExpectation(description: "reply")
        handler.addItem(requestData) { data, _ in
            let response = try? BridgeCoder.decode(BridgeResponse<WriteResultPayload>.self, from: data ?? Data())
            XCTAssertNotNil(response?.payload?.id)
            expectation.fulfill()
        }
        await fulfillment(of: [expectation], timeout: 1)

        XCTAssertEqual(repository.certificates.count, 2)
    }

    func testUpdateCertificateClearPrivateKeyRemovesExistingKey() async throws {
        let previousValue = UserDefaults.standard.bool(forKey: "cliAccessEnabled")
        UserDefaults.standard.set(true, forKey: "cliAccessEnabled")
        defer { UserDefaults.standard.set(previousValue, forKey: "cliAccessEnabled") }

        let approver = ApprovalTracker(result: true)
        let repository = TestVaultRepository()
        try repository.load()
        let handler = XPCRequestHandler(approver: approver, repository: repository)

        let payload = CertificateWritePayload(
            name: nil,
            certificate: "new-cert",
            privateKey: nil,
            clearPrivateKey: true,
            notes: nil
        )
        let body = try BridgeCoder.encode(payload)
        let request = BridgeRequest(
            id: UUID(),
            type: .updateCertificate,
            query: "ExistingCert",
            options: .init(field: nil, copy: false),
            context: .init(isTTY: true, isPiped: false, isSSH: false, isCI: false, timestamp: Date()),
            body: body
        )
        let requestData = try BridgeCoder.encode(request)

        let expectation = XCTestExpectation(description: "reply")
        handler.updateItem(requestData) { data, _ in
            let response = try? BridgeCoder.decode(BridgeResponse<WriteResultPayload>.self, from: data ?? Data())
            XCTAssertEqual(response?.payload?.message, "Certificate updated")
            expectation.fulfill()
        }
        await fulfillment(of: [expectation], timeout: 1)

        let metadata = try XCTUnwrap(repository.certificates.first { $0.name == "ExistingCert" })
        let full = try repository.getFullCertificate(metadata: metadata)
        XCTAssertEqual(String(data: full.certificateData, encoding: .utf8), "new-cert")
        XCTAssertNil(full.privateKeyData)
    }

    func testAddNoteReturnsWriteResult() async throws {
        let previousValue = UserDefaults.standard.bool(forKey: "cliAccessEnabled")
        UserDefaults.standard.set(true, forKey: "cliAccessEnabled")
        defer { UserDefaults.standard.set(previousValue, forKey: "cliAccessEnabled") }

        let approver = ApprovalTracker(result: true)
        let repository = TestVaultRepository()
        let handler = XPCRequestHandler(approver: approver, repository: repository)

        let payload = NoteWritePayload(title: "Hello", content: "World")
        let body = try BridgeCoder.encode(payload)
        let request = BridgeRequest(
            id: UUID(),
            type: .addNote,
            query: "",
            options: .init(field: nil, copy: false),
            context: .init(isTTY: true, isPiped: false, isSSH: false, isCI: false, timestamp: Date()),
            body: body
        )
        let requestData = try BridgeCoder.encode(request)

        let expectation = XCTestExpectation(description: "reply")
        handler.addItem(requestData) { data, _ in
            let response = try? BridgeCoder.decode(BridgeResponse<WriteResultPayload>.self, from: data ?? Data())
            XCTAssertNotNil(response?.payload?.id)
            expectation.fulfill()
        }
        await fulfillment(of: [expectation], timeout: 1)

        XCTAssertEqual(repository.notes.count, 2)
    }

    func testAddNotePersistsCallerProvidedScrapedProvenance() async throws {
        let previousValue = UserDefaults.standard.bool(forKey: "cliAccessEnabled")
        UserDefaults.standard.set(true, forKey: "cliAccessEnabled")
        defer { UserDefaults.standard.set(previousValue, forKey: "cliAccessEnabled") }

        let approver = ApprovalTracker(result: true)
        let repository = TestVaultRepository()
        let handler = XPCRequestHandler(approver: approver, repository: repository)

        let payload = NoteWritePayload(
            title: "Scraped Note",
            content: "World",
            isScraped: true,
            scrapeMachineName: "jamess-mac-mini",
            scrapeMachineId: "73C4AEA4-EB11-4AD7-AC14-DA296C404846"
        )
        let body = try BridgeCoder.encode(payload)
        let request = BridgeRequest(
            id: UUID(),
            type: .addNote,
            query: "",
            options: .init(field: nil, copy: false),
            context: .init(isTTY: true, isPiped: false, isSSH: false, isCI: false, timestamp: Date()),
            body: body
        )
        let requestData = try BridgeCoder.encode(request)

        let expectation = XCTestExpectation(description: "reply")
        handler.addItem(requestData) { _, _ in
            expectation.fulfill()
        }
        await fulfillment(of: [expectation], timeout: 1)

        let metadata = repository.notes.first { $0.title == "Scraped Note" }
        XCTAssertEqual(metadata?.isScraped, true)
        XCTAssertEqual(metadata?.scrapeMachineName, "jamess-mac-mini")
        XCTAssertEqual(metadata?.scrapeMachineId, "73C4AEA4-EB11-4AD7-AC14-DA296C404846")
    }

    func testAddSSHKeyPersistsCallerProvidedScrapedProvenance() async throws {
        let previousValue = UserDefaults.standard.bool(forKey: "cliAccessEnabled")
        UserDefaults.standard.set(true, forKey: "cliAccessEnabled")
        defer { UserDefaults.standard.set(previousValue, forKey: "cliAccessEnabled") }

        let approver = ApprovalTracker(result: true)
        let repository = TestVaultRepository()
        let handler = XPCRequestHandler(approver: approver, repository: repository)

        let payload = SSHKeyWritePayload(
            name: "ScrapedSSH",
            publicKey: "ssh-ed25519 AAAA",
            privateKey: "-----BEGIN OPENSSH PRIVATE KEY-----",
            comment: "laptop",
            fingerprint: "SHA256:abc",
            isScraped: true,
            scrapeMachineName: "jamess-mac-mini",
            scrapeMachineId: "73C4AEA4-EB11-4AD7-AC14-DA296C404846"
        )
        let body = try BridgeCoder.encode(payload)
        let request = BridgeRequest(
            id: UUID(),
            type: .addSSH,
            query: "",
            options: .init(field: nil, copy: false),
            context: .init(isTTY: true, isPiped: false, isSSH: false, isCI: false, timestamp: Date()),
            body: body
        )
        let requestData = try BridgeCoder.encode(request)

        let expectation = XCTestExpectation(description: "reply")
        handler.addItem(requestData) { _, _ in
            expectation.fulfill()
        }
        await fulfillment(of: [expectation], timeout: 1)

        let metadata = repository.sshKeys.first { $0.name == "ScrapedSSH" }
        XCTAssertEqual(metadata?.isScraped, true)
        XCTAssertEqual(metadata?.scrapeMachineName, "jamess-mac-mini")
        XCTAssertEqual(metadata?.scrapeMachineId, "73C4AEA4-EB11-4AD7-AC14-DA296C404846")
    }

    func testUpdatePasswordPersistsCallerProvidedScrapedProvenance() async throws {
        let previousValue = UserDefaults.standard.bool(forKey: "cliAccessEnabled")
        UserDefaults.standard.set(true, forKey: "cliAccessEnabled")
        defer { UserDefaults.standard.set(previousValue, forKey: "cliAccessEnabled") }

        let approver = ApprovalTracker(result: true)
        let repository = TestVaultRepository()
        let handler = XPCRequestHandler(approver: approver, repository: repository)
        try repository.load()

        let payload = PasswordWritePayload(
            name: nil,
            username: nil,
            password: nil,
            website: nil,
            notes: "updated",
            isScraped: true,
            scrapeMachineName: "jamess-mac-mini",
            scrapeMachineId: "73C4AEA4-EB11-4AD7-AC14-DA296C404846"
        )
        let body = try BridgeCoder.encode(payload)
        let request = BridgeRequest(
            id: UUID(),
            type: .updatePassword,
            query: "Existing",
            options: .init(field: nil, copy: false),
            context: .init(isTTY: true, isPiped: false, isSSH: false, isCI: false, timestamp: Date()),
            body: body
        )
        let requestData = try BridgeCoder.encode(request)

        let expectation = XCTestExpectation(description: "reply")
        handler.updateItem(requestData) { _, _ in
            expectation.fulfill()
        }
        await fulfillment(of: [expectation], timeout: 1)

        let metadata = repository.passwords.first { $0.name == "Existing" }
        XCTAssertEqual(metadata?.isScraped, true)
        XCTAssertEqual(metadata?.scrapeMachineName, "jamess-mac-mini")
        XCTAssertEqual(metadata?.scrapeMachineId, "73C4AEA4-EB11-4AD7-AC14-DA296C404846")
    }

    func testUpdatePasswordKeepsNilEnvironmentsAndClearsExplicitEmptyReplacement() async throws {
        let previousValue = UserDefaults.standard.bool(forKey: "cliAccessEnabled")
        UserDefaults.standard.set(true, forKey: "cliAccessEnabled")
        defer { UserDefaults.standard.set(previousValue, forKey: "cliAccessEnabled") }

        let repository = TestVaultRepository()
        let password = PasswordItem(
            name: "EnvironmentPassword",
            username: "service",
            password: Data("value".utf8),
            environments: ["Production"]
        )
        try repository.load()
        try repository.addPassword(password)
        let handler = XPCRequestHandler(approver: ApprovalTracker(result: true), repository: repository)

        try await updatePassword(
            handler: handler,
            query: password.id.uuidString,
            notes: "updated",
            environments: nil
        )
        XCTAssertEqual(
            repository.passwords.first(where: { $0.id == password.id })?.environments,
            ["Production"]
        )

        try await updatePassword(
            handler: handler,
            query: password.id.uuidString,
            notes: nil,
            environments: []
        )
        XCTAssertEqual(
            repository.passwords.first(where: { $0.id == password.id })?.environments,
            []
        )
    }

    private func updatePassword(
        handler: XPCRequestHandler,
        query: String,
        notes: String?,
        environments: [String]?
    ) async throws {
        let payload = PasswordWritePayload(
            name: nil,
            username: nil,
            password: nil,
            website: nil,
            notes: notes,
            environments: environments
        )
        let request = BridgeRequest(
            id: UUID(),
            type: .updatePassword,
            query: query,
            options: .init(field: nil, copy: false),
            context: .init(isTTY: true, isPiped: false, isSSH: false, isCI: false, timestamp: Date()),
            body: try BridgeCoder.encode(payload)
        )
        let expectation = XCTestExpectation(description: "reply")
        handler.updateItem(try BridgeCoder.encode(request)) { data, _ in
            let response = try? BridgeCoder.decode(BridgeResponse<WriteResultPayload>.self, from: data ?? Data())
            XCTAssertNotNil(response?.payload)
            XCTAssertNil(response?.error)
            expectation.fulfill()
        }
        await fulfillment(of: [expectation], timeout: 1)
    }

    func testGetPasswordRejectsAmbiguousExactName() async throws {
        let previousValue = UserDefaults.standard.bool(forKey: "cliAccessEnabled")
        UserDefaults.standard.set(true, forKey: "cliAccessEnabled")
        defer { UserDefaults.standard.set(previousValue, forKey: "cliAccessEnabled") }

        let approver = ApprovalTracker(result: true)
        let repository = TestVaultRepository()
        let handler = XPCRequestHandler(approver: approver, repository: repository)
        try repository.load()
        try repository.addPassword(
            PasswordItem(name: "Shared", username: "a", password: Data("one".utf8), folderPath: "Team/A")
        )
        try repository.addPassword(
            PasswordItem(name: "Shared", username: "b", password: Data("two".utf8), folderPath: "Team/B")
        )

        let request = BridgeRequest(
            id: UUID(),
            type: .getPassword,
            query: "Shared",
            options: .init(field: nil, copy: false),
            context: .init(isTTY: true, isPiped: false, isSSH: false, isCI: false, timestamp: Date())
        )
        let requestData = try BridgeCoder.encode(request)

        let expectation = XCTestExpectation(description: "reply")
        handler.getPassword(requestData) { data, _ in
            let response = try? BridgeCoder.decode(BridgeResponse<String>.self, from: data ?? Data())
            XCTAssertNil(response?.payload)
            XCTAssertNotNil(response?.error)
            expectation.fulfill()
        }
        await fulfillment(of: [expectation], timeout: 1)
    }

    func testPasswordSecretSentinelIsExcludedFromAuditAndErrorOutput() async throws {
        let defaults = BridgeSettings.appDefaults
        let key = BridgeSettings.cliAccessEnabledKey
        let hadSetting = defaults.object(forKey: key) != nil
        let previousValue = defaults.bool(forKey: key)
        defaults.set(true, forKey: key)
        defer {
            if hadSetting {
                defaults.set(previousValue, forKey: key)
            } else {
                defaults.removeObject(forKey: key)
            }
        }

        let secretSentinel = "fixture-secret-sentinel-7d25"
        let tempDirectory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        let auditURL = tempDirectory.appendingPathComponent("bridge_audit.log")
        defer { try? FileManager.default.removeItem(at: tempDirectory) }
        let auditLogger = BridgeAuditLogger(
            fileURL: auditURL,
            hmacKeyProvider: { SymmetricKey(data: Data(repeating: 0xA5, count: 32)) }
        )
        let handler = XPCRequestHandler(
            approver: ApprovalTracker(result: false),
            repository: TestVaultRepository(),
            auditLogger: auditLogger
        )
        let payload = PasswordWritePayload(
            name: nil,
            username: "fixture-user",
            password: secretSentinel,
            website: nil,
            notes: nil
        )
        let request = BridgeRequest(
            id: UUID(),
            type: .addPassword,
            query: "",
            options: .init(field: nil, copy: false),
            context: .init(isTTY: true, isPiped: false, isSSH: false, isCI: false, timestamp: Date()),
            body: try BridgeCoder.encode(payload)
        )
        let requestData = try BridgeCoder.encode(request)

        let expectation = XCTestExpectation(description: "invalid password write reply")
        var responseData: Data?
        handler.addItem(requestData) { data, _ in
            responseData = data
            expectation.fulfill()
        }
        await fulfillment(of: [expectation], timeout: 1)

        let encodedResponse = try XCTUnwrap(responseData)
        let response = try BridgeCoder.decode(BridgeResponse<String>.self, from: encodedResponse)
        XCTAssertEqual(response.error?.code, .invalidRequest)
        XCTAssertFalse(String(decoding: encodedResponse, as: UTF8.self).contains(secretSentinel))

        handler.recordAudit(
            command: .addPassword,
            itemId: "fixture-item",
            itemName: "Sentinel Account",
            approvedBy: "denied",
            caller: nil
        )
        let auditText = try String(contentsOf: auditURL, encoding: .utf8)
        XCTAssertFalse(auditText.contains(secretSentinel))
    }

    func testChromeNativeHostBypassesItemCLIRestrictionForPasswordAndAPIKeyOnlyForChromeContext() throws {
        let normalRequest = BridgeRequest(
            id: UUID(),
            type: .getPassword,
            query: "Disabled",
            options: .init(field: nil, copy: false),
            context: .init(
                isTTY: true,
                isPiped: false,
                isSSH: false,
                isCI: false,
                timestamp: Date(),
                requestedCommand: CapabilityCommand.get.rawValue
            )
        )
        let chromeRequest = BridgeRequest(
            id: UUID(),
            type: .getPassword,
            query: "Disabled",
            options: .init(field: nil, copy: false),
            context: .init(
                isTTY: false,
                isPiped: true,
                isSSH: false,
                isCI: false,
                timestamp: Date(),
                requestedCommand: BridgeContext.chromeNativeHostRequestedCommand
            )
        )
        let chromeAPIKeyRequest = BridgeRequest(
            id: UUID(),
            type: .getAPIKey,
            query: "Disabled",
            options: .init(field: nil, copy: false),
            context: .init(
                isTTY: false,
                isPiped: true,
                isSSH: false,
                isCI: false,
                timestamp: Date(),
                requestedCommand: BridgeContext.chromeNativeHostRequestedCommand
            )
        )

        let nativeHostCaller = CallerIdentity(
            pid: 100,
            processName: "authsia",
            bundleIdentifier: nil,
            signingTeamId: nil,
            signingIdentity: nil,
            parentProcess: ParentProcessInfo(pid: 99, processName: "AuthsiaNativeHost", bundleIdentifier: nil)
        )
        let shellCaller = CallerIdentity(
            pid: 100,
            processName: "authsia",
            bundleIdentifier: nil,
            signingTeamId: nil,
            signingIdentity: nil,
            parentProcess: ParentProcessInfo(pid: 99, processName: "zsh", bundleIdentifier: nil)
        )

        XCTAssertFalse(XPCRequestHandler.itemCLIRestrictionAllowsAccess(
            isCliEnabled: false,
            request: normalRequest,
            callerIdentity: nativeHostCaller
        ))
        XCTAssertTrue(XPCRequestHandler.itemCLIRestrictionAllowsAccess(
            isCliEnabled: true,
            request: normalRequest,
            callerIdentity: nil
        ))
        XCTAssertFalse(XPCRequestHandler.itemCLIRestrictionAllowsAccess(
            isCliEnabled: false,
            request: chromeRequest,
            callerIdentity: shellCaller
        ))
        XCTAssertFalse(XPCRequestHandler.itemCLIRestrictionAllowsAccess(
            isCliEnabled: false,
            request: chromeRequest,
            callerIdentity: nil
        ))
        XCTAssertTrue(XPCRequestHandler.itemCLIRestrictionAllowsAccess(
            isCliEnabled: false,
            request: chromeRequest,
            callerIdentity: nativeHostCaller
        ))
        // API keys intentionally mirror password CLI-toggle bypass behavior for
        // the authenticated Chrome native-host context.
        XCTAssertTrue(XPCRequestHandler.itemCLIRestrictionAllowsAccess(
            isCliEnabled: false,
            request: chromeAPIKeyRequest,
            callerIdentity: nativeHostCaller
        ))
    }

    func testUpdatePasswordRejectsAmbiguousExactNameWithoutMutation() async throws {
        let previousValue = UserDefaults.standard.bool(forKey: "cliAccessEnabled")
        UserDefaults.standard.set(true, forKey: "cliAccessEnabled")
        defer { UserDefaults.standard.set(previousValue, forKey: "cliAccessEnabled") }

        let approver = ApprovalTracker(result: true)
        let repository = TestVaultRepository()
        let handler = XPCRequestHandler(approver: approver, repository: repository)
        try repository.load()
        try repository.addPassword(
            PasswordItem(name: "Shared", username: "a", password: Data("one".utf8), folderPath: "Team/A")
        )
        try repository.addPassword(
            PasswordItem(name: "Shared", username: "b", password: Data("two".utf8), folderPath: "Team/B")
        )

        let payload = PasswordWritePayload(
            name: nil,
            username: nil,
            password: nil,
            website: nil,
            notes: "updated"
        )
        let request = BridgeRequest(
            id: UUID(),
            type: .updatePassword,
            query: "Shared",
            options: .init(field: nil, copy: false),
            context: .init(isTTY: true, isPiped: false, isSSH: false, isCI: false, timestamp: Date()),
            body: try BridgeCoder.encode(payload)
        )
        let requestData = try BridgeCoder.encode(request)

        let expectation = XCTestExpectation(description: "reply")
        handler.updateItem(requestData) { data, _ in
            let response = try? BridgeCoder.decode(BridgeResponse<WriteResultPayload>.self, from: data ?? Data())
            XCTAssertNil(response?.payload)
            XCTAssertNotNil(response?.error)
            expectation.fulfill()
        }
        await fulfillment(of: [expectation], timeout: 1)

        XCTAssertEqual(repository.passwords.filter { $0.name == "Shared" }.map(\.notes), [nil, nil])
    }

    func testDeletePasswordUsesCaseSensitiveExactNameBeforeAmbiguousCaseInsensitiveName() async throws {
        let previousValue = UserDefaults.standard.bool(forKey: "cliAccessEnabled")
        UserDefaults.standard.set(true, forKey: "cliAccessEnabled")
        defer { UserDefaults.standard.set(previousValue, forKey: "cliAccessEnabled") }

        let approver = ApprovalTracker(result: true)
        let repository = TestVaultRepository()
        let handler = XPCRequestHandler(approver: approver, repository: repository)
        try repository.load()
        let lowercase = PasswordItem(name: "password", username: "a", password: Data("one".utf8))
        let uppercase = PasswordItem(name: "PASSWORD", username: "b", password: Data("two".utf8))
        try repository.addPassword(lowercase)
        try repository.addPassword(uppercase)

        let request = BridgeRequest(
            id: UUID(),
            type: .deletePassword,
            query: "PASSWORD",
            options: .init(field: nil, copy: false),
            context: .init(isTTY: true, isPiped: false, isSSH: false, isCI: false, timestamp: Date())
        )
        let requestData = try BridgeCoder.encode(request)

        let expectation = XCTestExpectation(description: "reply")
        handler.deleteItem(requestData) { data, _ in
            let response = try? BridgeCoder.decode(BridgeResponse<WriteResultPayload>.self, from: data ?? Data())
            XCTAssertEqual(response?.payload?.id, uppercase.id.uuidString)
            XCTAssertNil(response?.error)
            expectation.fulfill()
        }
        await fulfillment(of: [expectation], timeout: 1)

        XCTAssertTrue(repository.passwords.contains { $0.id == lowercase.id })
        XCTAssertFalse(repository.passwords.contains { $0.id == uppercase.id })
    }

    func testUpdateSSHPersistsCallerProvidedScrapedProvenance() async throws {
        let previousValue = UserDefaults.standard.bool(forKey: "cliAccessEnabled")
        UserDefaults.standard.set(true, forKey: "cliAccessEnabled")
        defer { UserDefaults.standard.set(previousValue, forKey: "cliAccessEnabled") }

        let approver = ApprovalTracker(result: true)
        let repository = TestVaultRepository()
        let handler = XPCRequestHandler(approver: approver, repository: repository)
        try repository.load()

        let payload = SSHKeyWritePayload(
            name: nil,
            publicKey: nil,
            privateKey: nil,
            comment: "updated-comment",
            fingerprint: nil,
            isScraped: true,
            scrapeMachineName: "jamess-mac-mini",
            scrapeMachineId: "73C4AEA4-EB11-4AD7-AC14-DA296C404846"
        )
        let body = try BridgeCoder.encode(payload)
        let request = BridgeRequest(
            id: UUID(),
            type: .updateSSH,
            query: "ExistingSSH",
            options: .init(field: nil, copy: false),
            context: .init(isTTY: true, isPiped: false, isSSH: false, isCI: false, timestamp: Date()),
            body: body
        )
        let requestData = try BridgeCoder.encode(request)

        let expectation = XCTestExpectation(description: "reply")
        handler.updateItem(requestData) { _, _ in
            expectation.fulfill()
        }
        await fulfillment(of: [expectation], timeout: 1)

        let metadata = repository.sshKeys.first { $0.name == "ExistingSSH" }
        XCTAssertEqual(metadata?.isScraped, true)
        XCTAssertEqual(metadata?.scrapeMachineName, "jamess-mac-mini")
        XCTAssertEqual(metadata?.scrapeMachineId, "73C4AEA4-EB11-4AD7-AC14-DA296C404846")
    }
}

private final class ApprovalTracker: BridgeApprover {
    struct Request {
        let prompt: String
        let command: BridgeRequestType
        let itemLabel: String?
        let field: String?
    }

    private let result: Bool
    private(set) var requests: [Request] = []

    init(result: Bool) {
        self.result = result
    }

    func requestApproval(
        prompt: String,
        command: BridgeRequestType,
        itemLabel: String?,
        field: String?,
        callback: AuthsiaBridgeApprovalCallbackProtocol?
    ) async -> Bool {
        requests.append(Request(prompt: prompt, command: command, itemLabel: itemLabel, field: field))
        return result
    }
}

@MainActor
private final class TestVaultRepository: VaultRepositoryProviding {
    private(set) var passwords: [PasswordMetadata] = []
    private(set) var apiKeys: [APIKeyMetadata] = []
    private(set) var certificates: [CertificateMetadata] = []
    private(set) var notes: [SecureNoteMetadata] = []
    private(set) var sshKeys: [SSHKeyMetadata] = []
    private(set) var folders: [VaultItemType: [String]] = [:]
    var hasLoadedVaultState = false

    private var passwordItems: [PasswordItem] = []
    private var apiKeyItems: [APIKeyItem] = []
    private var certificateItems: [CertificateItem] = []
    private var noteItems: [SecureNoteItem] = []
    private var sshItems: [SSHKeyItem] = []
    private var hasLoaded = false

    func load() throws {
        guard !hasLoaded else { return }
        hasLoaded = true

        let existing = PasswordItem(
            name: "Existing",
            username: "stored",
            password: Data("pw".utf8),
            website: nil,
            notes: nil
        )
        let existingAPIKey = APIKeyItem(
            name: "ExistingAPIKey",
            key: Data("sk_live_existing".utf8),
            website: nil,
            notes: nil
        )
        let existingCertificate = CertificateItem(
            name: "ExistingCert",
            certificateData: Data("cert".utf8),
            privateKeyData: Data("key".utf8),
            notes: nil
        )
        let existingNote = SecureNoteItem(
            title: "ExistingNote",
            content: Data("note".utf8)
        )
        let existingSSH = SSHKeyItem(
            name: "ExistingSSH",
            publicKey: Data("ssh-ed25519 AAAA".utf8),
            privateKey: Data("-----BEGIN OPENSSH PRIVATE KEY-----".utf8),
            comment: "laptop",
            fingerprint: "SHA256:abc"
        )
        passwordItems = [existing]
        passwords = [PasswordMetadata(from: existing)]
        apiKeyItems = [existingAPIKey]
        apiKeys = [APIKeyMetadata(from: existingAPIKey)]
        certificateItems = [existingCertificate]
        certificates = [CertificateMetadata(from: existingCertificate)]
        noteItems = [existingNote]
        notes = [SecureNoteMetadata(from: existingNote)]
        sshItems = [existingSSH]
        sshKeys = [SSHKeyMetadata(from: existingSSH)]
    }

    func addPassword(_ item: PasswordItem) throws {
        passwordItems.append(item)
        passwords.append(PasswordMetadata(from: item))
    }

    func updatePassword(_ item: PasswordItem) throws {
        if let index = passwordItems.firstIndex(where: { $0.id == item.id }) {
            passwordItems[index] = item
        }
        if let index = passwords.firstIndex(where: { $0.id == item.id }) {
            passwords[index] = PasswordMetadata(from: item)
        }
    }

    func deletePassword(id: UUID) throws {
        passwordItems.removeAll { $0.id == id }
        passwords.removeAll { $0.id == id }
    }

    func getFullPassword(metadata: PasswordMetadata) throws -> PasswordItem {
        guard let item = passwordItems.first(where: { $0.id == metadata.id }) else {
            throw TestRepositoryError.notFound
        }
        return item
    }

    func convertPasswordToAPIKey(id: UUID, modifiedAt: Date) throws -> APIKeyItem? {
        guard let item = passwordItems.first(where: { $0.id == id }) else {
            return nil
        }
        let preservedNotes = [item.notes, "Converted from password username: \(item.username)"]
            .compactMap { value -> String? in
                guard let value, !value.isEmpty else { return nil }
                return value
            }
            .joined(separator: "\n\n")
        let apiKey = APIKeyItem(
            name: item.name,
            key: item.password,
            website: item.website,
            notes: preservedNotes.isEmpty ? nil : preservedNotes,
            folderPath: item.folderPath,
            createdAt: item.createdAt,
            modifiedAt: modifiedAt,
            isFavorite: item.isFavorite,
            isCliEnabled: item.isCliEnabled,
            isScraped: item.isScraped,
            scrapeMachineName: item.scrapeMachineName,
            scrapeMachineId: item.scrapeMachineId,
            expiresAt: item.expiresAt
        )
        try addAPIKey(apiKey)
        try deletePassword(id: item.id)
        return apiKey
    }

    func addAPIKey(_ item: APIKeyItem) throws {
        apiKeyItems.append(item)
        apiKeys.append(APIKeyMetadata(from: item))
    }

    func updateAPIKey(_ item: APIKeyItem) throws {
        if let index = apiKeyItems.firstIndex(where: { $0.id == item.id }) {
            apiKeyItems[index] = item
        }
        if let index = apiKeys.firstIndex(where: { $0.id == item.id }) {
            apiKeys[index] = APIKeyMetadata(from: item)
        }
    }

    func deleteAPIKey(id: UUID) throws {
        apiKeyItems.removeAll { $0.id == id }
        apiKeys.removeAll { $0.id == id }
    }

    func getFullAPIKey(metadata: APIKeyMetadata) throws -> APIKeyItem {
        guard let item = apiKeyItems.first(where: { $0.id == metadata.id }) else {
            throw TestRepositoryError.notFound
        }
        return item
    }

    func addCertificate(_ item: CertificateItem) throws {
        certificateItems.append(item)
        certificates.append(CertificateMetadata(from: item))
    }

    func updateCertificate(_ item: CertificateItem) throws {
        if let index = certificateItems.firstIndex(where: { $0.id == item.id }) {
            certificateItems[index] = item
        }
        if let index = certificates.firstIndex(where: { $0.id == item.id }) {
            certificates[index] = CertificateMetadata(from: item)
        }
    }

    func deleteCertificatePrivateKey(id: UUID) {
        guard let item = certificateItems.first(where: { $0.id == id }) else { return }
        let updated = CertificateItem(
            id: item.id,
            name: item.name,
            certificateData: item.certificateData,
            privateKeyData: nil,
            expirationDate: item.expirationDate,
            issuer: item.issuer,
            subject: item.subject,
            notes: item.notes,
            folderPath: item.folderPath,
            createdAt: item.createdAt,
            modifiedAt: item.modifiedAt,
            isFavorite: item.isFavorite,
            isCliEnabled: item.isCliEnabled,
            isScraped: item.isScraped,
            scrapeMachineName: item.scrapeMachineName,
            scrapeMachineId: item.scrapeMachineId
        )
        try? updateCertificate(updated)
    }

    func deleteCertificate(id: UUID) throws {
        certificateItems.removeAll { $0.id == id }
        certificates.removeAll { $0.id == id }
    }

    func getFullCertificate(metadata: CertificateMetadata) throws -> CertificateItem {
        guard let item = certificateItems.first(where: { $0.id == metadata.id }) else {
            throw TestRepositoryError.notFound
        }
        return item
    }

    func addNote(_ item: SecureNoteItem) throws {
        noteItems.append(item)
        notes.append(SecureNoteMetadata(from: item))
    }

    func updateNote(_ item: SecureNoteItem) throws {
        if let index = noteItems.firstIndex(where: { $0.id == item.id }) {
            noteItems[index] = item
        }
        if let index = notes.firstIndex(where: { $0.id == item.id }) {
            notes[index] = SecureNoteMetadata(from: item)
        }
    }

    func deleteNote(id: UUID) throws {
        noteItems.removeAll { $0.id == id }
        notes.removeAll { $0.id == id }
    }

    func getFullNote(metadata: SecureNoteMetadata) throws -> SecureNoteItem {
        guard let item = noteItems.first(where: { $0.id == metadata.id }) else {
            throw TestRepositoryError.notFound
        }
        return item
    }

    func addSSHKey(_ item: SSHKeyItem) throws {
        sshItems.append(item)
        sshKeys.append(SSHKeyMetadata(from: item))
    }

    func updateSSHKey(_ item: SSHKeyItem) throws {
        if let index = sshItems.firstIndex(where: { $0.id == item.id }) {
            sshItems[index] = item
        }
        if let index = sshKeys.firstIndex(where: { $0.id == item.id }) {
            sshKeys[index] = SSHKeyMetadata(from: item)
        }
    }

    func deleteSSHKey(id: UUID) throws {
        sshItems.removeAll { $0.id == id }
        sshKeys.removeAll { $0.id == id }
    }

    func getFullSSHKey(metadata: SSHKeyMetadata) throws -> SSHKeyItem {
        guard let item = sshItems.first(where: { $0.id == metadata.id }) else {
            throw TestRepositoryError.notFound
        }
        return item
    }

    func addFolder(_ path: String, type: VaultItemType) throws {
        folders[type, default: []].append(path)
    }

    func deleteFolder(path: String, type: VaultItemType) async throws {
        let matches: (String?) -> Bool = { folderPath in
            guard let folderPath else { return false }
            return folderPath == path || folderPath.hasPrefix("\(path)/")
        }
        folders[type] = folders[type, default: []].filter { !matches($0) }
        switch type {
        case .password:
            passwordItems.removeAll { matches($0.folderPath) }
            passwords.removeAll { matches($0.folderPath) }
        case .apiKey:
            apiKeyItems.removeAll { matches($0.folderPath) }
            apiKeys.removeAll { matches($0.folderPath) }
        case .certificate:
            certificateItems.removeAll { matches($0.folderPath) }
            certificates.removeAll { matches($0.folderPath) }
        case .secureNote:
            noteItems.removeAll { matches($0.folderPath) }
            notes.removeAll { matches($0.folderPath) }
        case .sshKey:
            sshItems.removeAll { matches($0.folderPath) }
            sshKeys.removeAll { matches($0.folderPath) }
        }
    }
}

private enum TestRepositoryError: Error {
    case notFound
}
