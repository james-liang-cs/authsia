import Foundation

enum CLIPrompt {
    
    static func confirm(_ message: String, defaultValue: Bool = false) -> Bool {
        let defaultIndicator = defaultValue ? "[Y/n]" : "[y/N]"
        StandardError.write("\(message) \(defaultIndicator): ")
        
        guard let input = readLine()?.trimmingCharacters(in: .whitespaces).lowercased() else {
            return defaultValue
        }
        
        if input.isEmpty {
            return defaultValue
        }
        
        return input == "y" || input == "yes"
    }
    
    static func prompt(_ message: String, defaultValue: String? = nil) -> String? {
        if let defaultValue = defaultValue {
            StandardError.write("\(message) [\(defaultValue)]: ")
        } else {
            StandardError.write("\(message): ")
        }
        
        guard let input = readLine()?.trimmingCharacters(in: .whitespaces) else {
            return defaultValue
        }
        
        return input.isEmpty ? defaultValue : input
    }
}
