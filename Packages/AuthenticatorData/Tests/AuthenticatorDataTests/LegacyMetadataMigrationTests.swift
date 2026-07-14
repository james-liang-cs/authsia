import XCTest
@testable import AuthenticatorData

final class LegacyMetadataMigrationTests: XCTestCase {
    private var tempDir: URL!

    override func setUp() {
        super.setUp()
        tempDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("legacy-metadata-tests-\(UUID().uuidString)", isDirectory: true)
        try! FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
    }

    override func tearDown() {
        try? FileManager.default.removeItem(at: tempDir)
        super.tearDown()
    }

    func testMigratesNonEmptyFileIntoKeychainAndDeletesFile() throws {
        let fileURL = tempDir.appendingPathComponent("vault_passwords_metadata.json")
        let payload = Data("[{\"id\":\"00000000-0000-0000-0000-000000000001\"}]".utf8)
        try payload.write(to: fileURL)
        let keychain = InMemoryMigrationKeychain()

        let result = try LegacyMetadataMigration.run(
            fileURL: fileURL,
            keychainKey: "vault_passwords_metadata",
            keychain: keychain
        )

        XCTAssertEqual(result, .migrated)
        XCTAssertEqual(keychain.stored["vault_passwords_metadata"], payload)
        XCTAssertFalse(FileManager.default.fileExists(atPath: fileURL.path))
    }

    func testNoOpWhenKeychainAlreadyHasDataAndDeletesFile() throws {
        let fileURL = tempDir.appendingPathComponent("vault_passwords_metadata.json")
        try Data("[{\"id\":\"file-only\"}]".utf8).write(to: fileURL)
        let existing = Data("[{\"id\":\"keychain-existing\"}]".utf8)
        let keychain = InMemoryMigrationKeychain(initial: ["vault_passwords_metadata": existing])

        let result = try LegacyMetadataMigration.run(
            fileURL: fileURL,
            keychainKey: "vault_passwords_metadata",
            keychain: keychain
        )

        XCTAssertEqual(result, .alreadyMigrated)
        XCTAssertEqual(keychain.stored["vault_passwords_metadata"], existing)
        XCTAssertFalse(FileManager.default.fileExists(atPath: fileURL.path))
    }

    func testNoOpWhenFileMissing() throws {
        let fileURL = tempDir.appendingPathComponent("does_not_exist.json")
        let keychain = InMemoryMigrationKeychain()

        let result = try LegacyMetadataMigration.run(
            fileURL: fileURL,
            keychainKey: "vault_passwords_metadata",
            keychain: keychain
        )

        XCTAssertEqual(result, .nothingToDo)
        XCTAssertNil(keychain.stored["vault_passwords_metadata"])
    }

    func testNoOpWhenFileIsEmptyArrayAndDeletesFile() throws {
        let fileURL = tempDir.appendingPathComponent("vault_passwords_metadata.json")
        try Data("[]".utf8).write(to: fileURL)
        let keychain = InMemoryMigrationKeychain()

        let result = try LegacyMetadataMigration.run(
            fileURL: fileURL,
            keychainKey: "vault_passwords_metadata",
            keychain: keychain
        )

        XCTAssertEqual(result, .nothingToDo)
        XCTAssertNil(keychain.stored["vault_passwords_metadata"])
        XCTAssertFalse(FileManager.default.fileExists(atPath: fileURL.path))
    }

    func testKeepsFileWhenKeychainLoadFails() throws {
        let fileURL = tempDir.appendingPathComponent("vault_passwords_metadata.json")
        let payload = Data("[{\"id\":\"file-only\"}]".utf8)
        try payload.write(to: fileURL)
        let keychain = InMemoryMigrationKeychain(loadError: KeychainError.unknown(errSecMissingEntitlement))

        XCTAssertThrowsError(try LegacyMetadataMigration.run(
            fileURL: fileURL,
            keychainKey: "vault_passwords_metadata",
            keychain: keychain
        ))

        XCTAssertEqual(try Data(contentsOf: fileURL), payload)
    }

    func testRunJobsContinuesAfterOneMigrationFails() throws {
        let failedURL = tempDir.appendingPathComponent("failed.json")
        let migratedURL = tempDir.appendingPathComponent("migrated.json")
        let failedPayload = Data("[{\"id\":\"failed\"}]".utf8)
        let migratedPayload = Data("[{\"id\":\"migrated\"}]".utf8)
        try failedPayload.write(to: failedURL)
        try migratedPayload.write(to: migratedURL)
        let failingKeychain = InMemoryMigrationKeychain(loadError: KeychainError.unknown(errSecMissingEntitlement))
        let migratingKeychain = InMemoryMigrationKeychain()

        let reports = LegacyMetadataMigration.run(jobs: [
            LegacyMetadataMigrationJob(
                fileURL: failedURL,
                keychainKey: "failed_metadata",
                keychain: failingKeychain
            ),
            LegacyMetadataMigrationJob(
                fileURL: migratedURL,
                keychainKey: "migrated_metadata",
                keychain: migratingKeychain
            ),
        ])

        XCTAssertEqual(reports.count, 2)
        XCTAssertNil(reports[0].outcome)
        XCTAssertNotNil(reports[0].errorDescription)
        XCTAssertEqual(reports[1].outcome, .migrated)
        XCTAssertNil(reports[1].errorDescription)
        XCTAssertEqual(try Data(contentsOf: failedURL), failedPayload)
        XCTAssertFalse(FileManager.default.fileExists(atPath: migratedURL.path))
        XCTAssertEqual(migratingKeychain.stored["migrated_metadata"], migratedPayload)
    }
}

private final class InMemoryMigrationKeychain: LegacyMetadataMigrationKeychain {
    var stored: [String: Data]
    var loadError: Error?

    init(initial: [String: Data] = [:], loadError: Error? = nil) {
        self.stored = initial
        self.loadError = loadError
    }

    func load(key: String) throws -> Data? {
        if let loadError { throw loadError }
        return stored[key]
    }

    func save(data: Data, key: String) throws {
        stored[key] = data
    }
}
