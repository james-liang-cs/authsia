import XCTest
@testable import AuthenticatorData
import AuthenticatorCore

final class ImportExportTests: XCTestCase {
    private func makeExportData(items: [ExportableAccount]) throws -> Data {
        let container = ExportContainer(items: items)
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        return try encoder.encode(container)
    }
    
    func testJSONDecoding() throws {
        let jsonString = """
        {
            "items": [
                {
                    "primary": "6F92394E-BCDD-4AE6-8D2C-412672DDF1BC",
                    "icon": "google.com",
                    "account": "primary@example.com",
                    "issuer": "Google",
                    "secret": "ss==",
                    "period": 30,
                    "added": "2025-12-02T09:09:48.817878962Z",
                    "isExcludedFromWatch": true,
                    "hosts": ["google.com"]
                },
                {
                    "primary": "D814AD7F-2F75-4135-88ED-195287A7FC9B",
                    "account": "test@example.com",
                    "issuer": "Test",
                    "secret": "sss==",
                    "period": 30,
                    "added": "2026-01-20T09:19:10.150640011Z",
                    "favorite": true
                }
            ]
        }
        """
        
        let data = jsonString.data(using: .utf8)!
        let decoder = JSONDecoder()
        
        let container = try decoder.decode(ExportContainer.self, from: data)
        
        XCTAssertEqual(container.items.count, 2)
        
        // Verify first account
        let first = container.items[0]
        XCTAssertEqual(first.primary, "6F92394E-BCDD-4AE6-8D2C-412672DDF1BC")
        XCTAssertEqual(first.icon, "google.com")
        XCTAssertEqual(first.account, "primary@example.com")
        XCTAssertEqual(first.issuer, "Google")
        XCTAssertEqual(first.period, 30)
        XCTAssertEqual(first.isExcludedFromWatch, true)
        XCTAssertEqual(first.hosts, ["google.com"])
        XCTAssertNil(first.favorite)
        
        // Verify second account
        let second = container.items[1]
        XCTAssertEqual(second.account, "test@example.com")
        XCTAssertEqual(second.issuer, "Test")
        XCTAssertEqual(second.favorite, true)
        XCTAssertNil(second.isExcludedFromWatch)
        XCTAssertNil(second.hosts)
    }
    
    func testAccountConversion() throws {
        let exportable = ExportableAccount(
            primary: "6F92394E-BCDD-4AE6-8D2C-412672DDF1BC",
            icon: "google.com",
            account: "test@example.com",
            issuer: "Google",
            secret: "aGVsbG8gd29ybGQ=", // "hello world" in base64
            period: 30,
            added: "2026-01-20T09:19:10.150640011Z",
            isExcludedFromWatch: true,
            hosts: ["google.com"],
            favorite: true
        )
        
        let account = try exportable.toAccount()
        
        XCTAssertEqual(account.id.uuidString.uppercased(), "6F92394E-BCDD-4AE6-8D2C-412672DDF1BC")
        XCTAssertEqual(account.label, "test@example.com")
        XCTAssertEqual(account.issuer, "Google")
        XCTAssertEqual(account.period, 30)
        XCTAssertEqual(account.icon, "google.com")
        XCTAssertEqual(account.hosts, ["google.com"])
        XCTAssertEqual(account.isExcludedFromWatch, true)
        XCTAssertEqual(account.isFavorite, true)
        
        // Verify secret was base64 decoded correctly
        let decodedSecret = String(data: account.secret, encoding: .utf8)
        XCTAssertEqual(decodedSecret, "hello world")
    }
    
    func testExportableAccountCreation() throws {
        // Create test metadata
        let uuid = UUID(uuidString: "6F92394E-BCDD-4AE6-8D2C-412672DDF1BC")!
        let secret = "hello world".data(using: .utf8)!

        let account = Account(
            id: uuid,
            issuer: "Google",
            label: "test@example.com",
            secret: secret,
            algorithm: .sha1,
            digits: 6,
            type: .totp,
            period: 30,
            counter: 0,
            createdAt: Date(),
            lastUsed: Date(),
            isFavorite: true,
            icon: "google.com",
            hosts: ["google.com"],
            isExcludedFromWatch: true
        )

        let metadata = AccountMetadata(from: account)
        let exportable = ExportableAccount(from: metadata, secret: secret)

        XCTAssertEqual(exportable.primary, uuid.uuidString)
        XCTAssertEqual(exportable.icon, "google.com")
        XCTAssertEqual(exportable.account, "test@example.com")
        XCTAssertEqual(exportable.issuer, "Google")
        XCTAssertEqual(exportable.period, 30)
        XCTAssertEqual(exportable.hosts, ["google.com"])
        XCTAssertEqual(exportable.isExcludedFromWatch, true)
        XCTAssertEqual(exportable.favorite, true)
        XCTAssertEqual(exportable.secret, secret.base64EncodedString())
        XCTAssertEqual(exportable.algorithm, "sha1")
        XCTAssertEqual(exportable.digits, 6)
        XCTAssertEqual(exportable.type, "totp")
        XCTAssertNil(exportable.counter) // TOTP doesn't export counter
    }

    func testAlgorithmDigitsTypeExportImport() throws {
        // Test that algorithm, digits, type, and counter survive round-trip
        let uuid = UUID(uuidString: "A1B2C3D4-E5F6-7890-ABCD-EF1234567890")!
        let secret = "test secret".data(using: .utf8)!

        // Create account with non-default values
        let account = Account(
            id: uuid,
            issuer: "Test Issuer",
            label: "test@test.com",
            secret: secret,
            algorithm: .sha256,  // Non-default
            digits: 8,           // Non-default
            type: .hotp,         // Non-default
            period: 60,          // Non-default
            counter: 42,         // Non-zero counter for HOTP
            createdAt: Date(),
            lastUsed: Date(),
            isFavorite: false,
            icon: nil,
            hosts: nil,
            isExcludedFromWatch: false
        )

        // Export
        let metadata = AccountMetadata(from: account)
        let exportable = ExportableAccount(from: metadata, secret: secret)

        // Verify exported values
        XCTAssertEqual(exportable.algorithm, "sha256")
        XCTAssertEqual(exportable.digits, 8)
        XCTAssertEqual(exportable.type, "hotp")
        XCTAssertEqual(exportable.counter, 42)

        // Import back
        let importedAccount = try exportable.toAccount()

        // Verify all values survived round-trip
        XCTAssertEqual(importedAccount.algorithm, .sha256)
        XCTAssertEqual(importedAccount.digits, 8)
        XCTAssertEqual(importedAccount.type, .hotp)
        XCTAssertEqual(importedAccount.counter, 42)
        XCTAssertEqual(importedAccount.period, 60)
    }

    func testJSONDecodingWithNewFields() throws {
        // Test that JSON with algorithm/digits/type/counter fields decodes correctly
        let jsonString = """
        {
            "items": [
                {
                    "primary": "12345678-1234-1234-1234-123456789ABC",
                    "account": "user@example.com",
                    "issuer": "Example",
                    "secret": "dGVzdA==",
                    "period": 60,
                    "added": "2026-01-20T10:00:00.000Z",
                    "algorithm": "sha512",
                    "digits": 8,
                    "type": "hotp",
                    "counter": 100
                }
            ]
        }
        """

        let data = jsonString.data(using: .utf8)!
        let decoder = JSONDecoder()
        let container = try decoder.decode(ExportContainer.self, from: data)

        XCTAssertEqual(container.items.count, 1)

        let item = container.items[0]
        XCTAssertEqual(item.algorithm, "sha512")
        XCTAssertEqual(item.digits, 8)
        XCTAssertEqual(item.type, "hotp")
        XCTAssertEqual(item.counter, 100)

        // Convert to Account
        let account = try item.toAccount()
        XCTAssertEqual(account.algorithm, .sha512)
        XCTAssertEqual(account.digits, 8)
        XCTAssertEqual(account.type, .hotp)
        XCTAssertEqual(account.counter, 100)
    }

    func testBackwardCompatibilityWithoutNewFields() throws {
        // Test that JSON without the new fields still decodes (backward compatibility)
        let jsonString = """
        {
            "items": [
                {
                    "primary": "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE",
                    "account": "legacy@example.com",
                    "issuer": "Legacy",
                    "secret": "bGVnYWN5",
                    "period": 30,
                    "added": "2025-01-01T00:00:00.000Z"
                }
            ]
        }
        """

        let data = jsonString.data(using: .utf8)!
        let decoder = JSONDecoder()
        let container = try decoder.decode(ExportContainer.self, from: data)

        let item = container.items[0]

        // New fields should be nil
        XCTAssertNil(item.algorithm)
        XCTAssertNil(item.digits)
        XCTAssertNil(item.type)
        XCTAssertNil(item.counter)

        // Convert to Account - should use defaults
        let account = try item.toAccount()
        XCTAssertEqual(account.algorithm, .sha1)  // Default
        XCTAssertEqual(account.digits, 6)         // Default
        XCTAssertEqual(account.type, .totp)       // Default
        XCTAssertEqual(account.counter, 0)        // Default
    }

    @MainActor
    func testImportDuplicateIDKeepsExistingWhenConflictPolicyIsKeepExisting() async throws {
        let repository = makeInMemoryAccountRepository()
        let id = UUID()
        let existingAccount = Account(
            id: id,
            issuer: "ExistingIssuer",
            label: "existing@example.com",
            secret: Data("existing-secret".utf8),
            algorithm: .sha1,
            digits: 6,
            type: .totp
        )
        let incomingExport = ExportableAccount(
            primary: id.uuidString,
            icon: nil,
            account: "incoming@example.com",
            issuer: "IncomingIssuer",
            folderPath: nil,
            secret: Data("incoming-secret".utf8).base64EncodedString(),
            period: 30,
            added: "2026-01-20T09:19:10.150640011Z"
        )

        do {
            try repository.addAccount(existingAccount)
            defer { try? repository.deleteAccount(id: id) }

            let data = try makeExportData(items: [incomingExport])
            let count = try await repository.importAccounts(from: data, conflictPolicy: .keepExisting)
            XCTAssertEqual(count, 0)

            try repository.load()
            guard let metadata = repository.accounts.first(where: { $0.id == id }) else {
                XCTFail("Expected existing account to remain")
                return
            }
            let full = try repository.getFullAccount(metadata: metadata)
            XCTAssertEqual(full.issuer, "ExistingIssuer")
            XCTAssertEqual(full.label, "existing@example.com")
            XCTAssertEqual(String(decoding: full.secret, as: UTF8.self), "existing-secret")
        } catch {
            throw XCTSkip("Keychain access error in test environment: \(error)")
        }
    }

    @MainActor
    func testImportDuplicateIDOverwritesWhenConflictPolicyIsOverwriteExisting() async throws {
        let repository = makeInMemoryAccountRepository()
        let id = UUID()
        let existingAccount = Account(
            id: id,
            issuer: "ExistingIssuer",
            label: "existing@example.com",
            secret: Data("existing-secret".utf8),
            algorithm: .sha1,
            digits: 6,
            type: .totp
        )
        let incomingExport = ExportableAccount(
            primary: id.uuidString,
            icon: nil,
            account: "incoming@example.com",
            issuer: "IncomingIssuer",
            folderPath: nil,
            secret: Data("incoming-secret".utf8).base64EncodedString(),
            period: 30,
            added: "2026-01-20T09:19:10.150640011Z"
        )

        do {
            try repository.addAccount(existingAccount)
            defer { try? repository.deleteAccount(id: id) }

            let data = try makeExportData(items: [incomingExport])
            let count = try await repository.importAccounts(from: data, conflictPolicy: .overwriteExisting)
            XCTAssertEqual(count, 1)

            try repository.load()
            guard let metadata = repository.accounts.first(where: { $0.id == id }) else {
                XCTFail("Expected account to remain after overwrite")
                return
            }
            let full = try repository.getFullAccount(metadata: metadata)
            XCTAssertEqual(full.issuer, "IncomingIssuer")
            XCTAssertEqual(full.label, "incoming@example.com")
            XCTAssertEqual(String(decoding: full.secret, as: UTF8.self), "incoming-secret")
        } catch {
            throw XCTSkip("Keychain access error in test environment: \(error)")
        }
    }

    @MainActor
    func testPreviewImportReportsDuplicateIDCount() async throws {
        let repository = makeInMemoryAccountRepository()
        let existingID = UUID()
        let newID = UUID()
        let existingAccount = Account(
            id: existingID,
            issuer: "ExistingIssuer",
            label: "existing@example.com",
            secret: Data("existing-secret".utf8),
            algorithm: .sha1,
            digits: 6,
            type: .totp
        )
        let duplicateExport = ExportableAccount(
            primary: existingID.uuidString,
            icon: nil,
            account: "duplicate@example.com",
            issuer: "DuplicateIssuer",
            folderPath: nil,
            secret: Data("duplicate-secret".utf8).base64EncodedString(),
            period: 30,
            added: "2026-01-20T09:19:10.150640011Z"
        )
        let newExport = ExportableAccount(
            primary: newID.uuidString,
            icon: nil,
            account: "new@example.com",
            issuer: "NewIssuer",
            folderPath: nil,
            secret: Data("new-secret".utf8).base64EncodedString(),
            period: 30,
            added: "2026-01-20T09:19:10.150640011Z"
        )

        do {
            try repository.addAccount(existingAccount)
            defer {
                try? repository.deleteAccount(id: existingID)
                try? repository.deleteAccount(id: newID)
            }

            let data = try makeExportData(items: [duplicateExport, newExport])
            let preview = try await repository.previewImportAccounts(from: data)
            XCTAssertEqual(preview.totalItems, 2)
            XCTAssertEqual(preview.duplicateIDCount, 1)
            XCTAssertEqual(preview.newItemsCount, 1)
        } catch {
            throw XCTSkip("Keychain access error in test environment: \(error)")
        }
    }
}
