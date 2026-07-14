import Foundation

public struct PasswordGenerator {

    public static func generate(
        length: Int = 20,
        includeUppercase: Bool = true,
        includeLowercase: Bool = true,
        includeNumbers: Bool = true,
        includeSymbols: Bool = true
    ) -> String {
        var characterSet = ""
        if includeLowercase { characterSet += "abcdefghijklmnopqrstuvwxyz" }
        if includeUppercase { characterSet += "ABCDEFGHIJKLMNOPQRSTUVWXYZ" }
        if includeNumbers { characterSet += "0123456789" }
        if includeSymbols { characterSet += "!@#$%^&*_+-=?" }

        guard !characterSet.isEmpty else { return "" }

        var password = ""
        for _ in 0..<length {
            if let char = characterSet.randomElement() {
                password.append(char)
            }
        }

        return password
    }
}
