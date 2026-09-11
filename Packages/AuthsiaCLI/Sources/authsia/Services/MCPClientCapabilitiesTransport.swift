import Foundation
import Logging
import MCP

/// The tools-only endpoints do not consume experimental client capabilities.
/// Swift MCP 0.12.1 decodes their values as strings, while clients may legally
/// send arbitrary JSON (for example Codex IDE's `codex/auth-change: {}`).
/// Ignore this unsupported capability before SDK decoding, not tool arguments.
actor MCPClientCapabilitiesTransport: Transport {
    nonisolated let logger: Logger
    private let base: any Transport

    init(_ base: any Transport) async {
        self.base = base
        self.logger = await base.logger
    }

    func connect() async throws { try await base.connect() }
    func disconnect() async { await base.disconnect() }
    func send(_ data: Data) async throws { try await base.send(data) }

    func receive() -> AsyncThrowingStream<Data, Error> {
        AsyncThrowingStream { continuation in
            let task = Task {
                do {
                    for try await data in await base.receive() {
                        try Task.checkCancellation()
                        continuation.yield(Self.normalizedInitialization(data))
                    }
                    continuation.finish()
                } catch { continuation.finish(throwing: error) }
            }
            continuation.onTermination = { _ in task.cancel() }
        }
    }

    static func normalizedInitialization(_ data: Data) -> Data {
        guard var message = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any],
              message["method"] as? String == "initialize",
              var parameters = message["params"] as? [String: Any],
              var capabilities = parameters["capabilities"] as? [String: Any],
              capabilities["experimental"] is [String: Any] else { return data }
        capabilities.removeValue(forKey: "experimental")
        parameters["capabilities"] = capabilities
        message["params"] = parameters
        return (try? JSONSerialization.data(withJSONObject: message)) ?? data
    }
}
