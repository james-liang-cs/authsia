import Foundation

enum StandardError {
    static func write(_ message: String) {
        FileHandle.standardError.write(Data(message.utf8))
    }

    static func writeLine(_ message: String) {
        write("\(message)\n")
    }
}
