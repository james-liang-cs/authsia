import Foundation
import AuthenticatorBridge
@testable import authsia

enum AccessCredentialStoreFixture {
    /// Create a fresh `AccessCredentialStore` backed by a throwaway temp directory.
    /// Caller is responsible for removing `directory` (`try? FileManager.default.removeItem(at: directory)`
    /// in a `defer`).
    static func make(prefix: String = "access-fixture") throws -> (store: AccessCredentialStore, directory: URL) {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("\(prefix)-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let store = AccessCredentialStore(fileURL: directory.appendingPathComponent("access-credentials.json"))
        return (store, directory)
    }

    static func token(for credential: AccessCredential) -> String {
        try! AutomationCredentialToken.issue(
            id: credential.id,
            randomBytes: Data(repeating: 0x41, count: AutomationCredentialToken.randomByteCount)
        )
    }
}
