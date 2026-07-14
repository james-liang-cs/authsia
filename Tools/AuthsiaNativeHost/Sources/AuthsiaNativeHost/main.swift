import Foundation
import AuthsiaNativeHostCore

private let stdinHandle = FileHandle.standardInput
private let stdoutHandle = FileHandle.standardOutput

private let isDebug = ProcessInfo.processInfo.environment["AUTHSIA_DEBUG"] != nil

let handler = NativeHostHandler()
let encoder = JSONEncoder()
encoder.dateEncodingStrategy = .iso8601

func log(_ message: String) {
    guard isDebug else { return }
    let logFile = URL(fileURLWithPath: "/tmp/authsia-native.log")
    let timestamp = ISO8601DateFormatter().string(from: Date())
    let line = "[\(timestamp)] \(message)\n"
    if let handle = try? FileHandle(forWritingTo: logFile) {
        handle.seekToEndOfFile()
        handle.write(line.data(using: .utf8)!)
        handle.closeFile()
    } else {
        try? line.write(to: logFile, atomically: true, encoding: .utf8)
    }
}

log("Host process started")

while true {
    do {
        guard let payload = try NativeMessaging.readMessage(from: stdinHandle) else {
            log("Stdin closed, exiting.")
            break
        }

        log("Received request")

        let responsePayload = handler.handleRequestData(payload)

        log("Sending response")

        NativeMessaging.writeMessage(responsePayload, to: stdoutHandle)
    } catch {
        log("Error: \(error)")
        let errorResponse = NativeHostResponse.failure(.invalidRequest, detail: String(describing: error))
        let responsePayload = (try? encoder.encode(errorResponse)) ?? Data("{\"ok\":false,\"error\":\"invalidRequest\"}".utf8)
        NativeMessaging.writeMessage(responsePayload, to: stdoutHandle)
    }
}
