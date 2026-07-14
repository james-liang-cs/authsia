import XCTest
import Security
@testable import AuthenticatorData

final class KeychainQueryTests: XCTestCase {
    func testVaultSecretQueriesUseDataProtectionKeychainOnMacOS() {
        let query = VaultKeychainStore.baseQueryForTesting(account: "password-id", synchronizable: false)

        #if os(macOS)
        XCTAssertEqual(query[kSecUseDataProtectionKeychain as String] as? Bool, true)
        #else
        XCTAssertNil(query[kSecUseDataProtectionKeychain as String])
        #endif
    }

    func testSharedKeychainAccessGroupSelectsMainAuthsiaGroup() {
        let accessGroup = SharedKeychainAccessGroup.accessGroup(from: [
            "33M8QU65SP.app.authsia.headless",
            "33M8QU65SP.app.authsia",
        ])

        XCTAssertEqual(accessGroup, "33M8QU65SP.app.authsia")
    }

    func testVaultSecretQueriesUseSharedAccessGroupWhenAvailable() {
        let query = VaultKeychainStore.baseQueryForTesting(
            account: "password-id",
            synchronizable: false,
            accessGroup: "33M8QU65SP.app.authsia"
        )

        XCTAssertEqual(query[kSecAttrAccessGroup as String] as? String, "33M8QU65SP.app.authsia")
    }

    func testVaultSecretReadQueriesIncludeLegacyServiceAfterNamespaceMigration() {
        let queries = VaultKeychainStore.readQueriesForTesting(account: "password-id", synchronizable: true)
        let services = queries.compactMap { $0[kSecAttrService as String] as? String }

        XCTAssertEqual(services.first, "com.authsia.vault")
        XCTAssertTrue(services.contains("com.authenticator.vault"))
    }

    func testOTPSecretQueriesUseDataProtectionKeychainOnMacOS() {
        let query = KeychainStore.baseQueryForTesting(account: "account-id", synchronizable: false)

        #if os(macOS)
        XCTAssertEqual(query[kSecUseDataProtectionKeychain as String] as? Bool, true)
        #else
        XCTAssertNil(query[kSecUseDataProtectionKeychain as String])
        #endif
    }

    func testVaultMetadataLocalFallbackUsesDistinctService() {
        let syncedQuery = SecurityVaultMetadataKeychainStore.baseQueryForTesting(
            key: "vault_passwords_metadata",
            synchronizable: true
        )
        let localQuery = SecurityVaultMetadataKeychainStore.baseQueryForTesting(
            key: "vault_passwords_metadata",
            synchronizable: false
        )

        XCTAssertEqual(syncedQuery[kSecAttrService as String] as? String, "com.authsia.vault.metadata")
        XCTAssertEqual(localQuery[kSecAttrService as String] as? String, "com.authsia.vault.metadata.local")

        #if os(macOS)
        XCTAssertEqual(localQuery[kSecUseDataProtectionKeychain as String] as? Bool, true)
        #else
        XCTAssertNil(localQuery[kSecUseDataProtectionKeychain as String])
        #endif
    }

    func testVaultMetadataQueriesUseSharedAccessGroupWhenAvailable() {
        let query = SecurityVaultMetadataKeychainStore.baseQueryForTesting(
            key: "vault_passwords_metadata",
            synchronizable: false,
            accessGroup: "33M8QU65SP.app.authsia"
        )

        XCTAssertEqual(query[kSecAttrAccessGroup as String] as? String, "33M8QU65SP.app.authsia")
    }

    func testOTPWriteTargetsAreLocalOnlyWhenSyncDisabled() {
        let store = KeychainStore(syncPolicy: .fixed(false))

        XCTAssertEqual(store.writeSynchronizableValuesForTesting(), [false])
    }

    func testOTPWriteTargetsIncludeSyncedAndLocalWhenSyncEnabled() {
        let store = KeychainStore(syncPolicy: .fixed(true))

        XCTAssertEqual(store.writeSynchronizableValuesForTesting(), [true, false])
    }

    func testOTPReadTargetsPreferLocalWhenSyncDisabled() {
        let store = KeychainStore(syncPolicy: .fixed(false))

        XCTAssertEqual(store.readSynchronizableValuesForTesting(), [false, true])
    }

    func testOTPReadTargetsPreferSyncedWhenSyncEnabled() {
        let store = KeychainStore(syncPolicy: .fixed(true))

        XCTAssertEqual(store.readSynchronizableValuesForTesting(), [true, false])
    }

    func testOTPDeleteTargetsAlwaysIncludeSyncedAndLocal() {
        let disabledStore = KeychainStore(syncPolicy: .fixed(false))
        let enabledStore = KeychainStore(syncPolicy: .fixed(true))

        XCTAssertEqual(disabledStore.deleteSynchronizableValuesForTesting(), [true, false])
        XCTAssertEqual(enabledStore.deleteSynchronizableValuesForTesting(), [true, false])
    }

    func testVaultWriteTargetsAreLocalOnlyWhenSyncDisabled() {
        let store = VaultKeychainStore(syncPolicy: .fixed(false))

        XCTAssertEqual(store.writeSynchronizableValuesForTesting(), [false])
    }

    func testVaultWriteTargetsIncludeSyncedAndLocalWhenSyncEnabled() {
        let store = VaultKeychainStore(syncPolicy: .fixed(true))

        XCTAssertEqual(store.writeSynchronizableValuesForTesting(), [true, false])
    }

    func testVaultReadTargetsPreferLocalWhenSyncDisabled() {
        let store = VaultKeychainStore(syncPolicy: .fixed(false))

        XCTAssertEqual(store.readSynchronizableValuesForTesting(), [false, true])
    }

    func testVaultDeleteTargetsAlwaysIncludeSyncedAndLocal() {
        let store = VaultKeychainStore(syncPolicy: .fixed(false))

        XCTAssertEqual(store.deleteSynchronizableValuesForTesting(), [true, false])
    }

    func testVaultMetadataWriteTargetsAreLocalOnlyWhenSyncDisabled() {
        let store = SecurityVaultMetadataKeychainStore(syncPolicy: .fixed(false))

        XCTAssertEqual(store.writeSynchronizableValuesForTesting(), [false])
    }

    func testVaultMetadataWriteTargetsIncludeSyncedAndLocalWhenSyncEnabled() {
        let store = SecurityVaultMetadataKeychainStore(syncPolicy: .fixed(true))

        XCTAssertEqual(store.writeSynchronizableValuesForTesting(), [true, false])
    }

    func testVaultMetadataReadTargetsPreferLocalWhenSyncDisabled() {
        let store = SecurityVaultMetadataKeychainStore(syncPolicy: .fixed(false))

        XCTAssertEqual(store.readSynchronizableValuesForTesting(), [false, true])
    }
}
