import Foundation

enum DataString {
    static func string(from data: Data) -> String {
        if let value = String(data: data, encoding: .utf8) {
            return value
        }
        return "base64:" + data.base64EncodedString()
    }
}
