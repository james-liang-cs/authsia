import Foundation
import Combine

public class CoreLogger: @unchecked Sendable {
    public static let shared = CoreLogger()
    
    public struct LogEntry: Identifiable {
        public let id = UUID()
        public let timestamp = Date()
        public let message: String
        public let type: LogType
    }
    
    public enum LogType {
        case info
        case error
        case success
    }
    
    // Using a subject to broadcast logs to UI listeners
    public let logSubject = PassthroughSubject<LogEntry, Never>()
    
    private init() {}
    
    public func info(_ message: String) {
        logSubject.send(LogEntry(message: message, type: .info))
        print("ℹ️ \(message)")
    }
    
    public func error(_ message: String) {
        logSubject.send(LogEntry(message: message, type: .error))
        print("❌ \(message)")
    }
    
    public func success(_ message: String) {
        logSubject.send(LogEntry(message: message, type: .success))
        print("✅ \(message)")
    }
}
