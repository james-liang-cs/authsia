import Foundation

public struct SSHKeyPassphraseRequest: Equatable, Sendable {
    public let keyID: UUID
    public let keyName: String

    public init(keyID: UUID, keyName: String) {
        self.keyID = keyID
        self.keyName = keyName
    }
}

public protocol SSHKeyPassphraseProviding {
    func passphrase(for request: SSHKeyPassphraseRequest) -> String?
}
