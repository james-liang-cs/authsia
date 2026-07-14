import Foundation

struct AuthsiaReference: Hashable {
    enum ItemType: String, Hashable {
        case password
        case apiKey = "api-key"
        case note
        case ssh
        case certificate
    }

    let itemType: ItemType
    let query: String
    let folderPath: String?

    init(itemType: ItemType, query: String, folderPath: String? = nil) {
        self.itemType = itemType
        self.query = query
        self.folderPath = folderPath
    }
}
