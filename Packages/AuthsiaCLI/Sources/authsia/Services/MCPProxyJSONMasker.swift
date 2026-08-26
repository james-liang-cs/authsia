import Foundation

struct MCPProxyJSONMasker {
    private static let minimumSecretByteCount = 4

    private let masker: OutputMasker

    init(secrets: [String]) {
        masker = OutputMasker(exactSecrets: secrets.filter {
            $0.utf8.count >= Self.minimumSecretByteCount
        })
    }

    func mask<Value: Codable>(_ value: Value) throws -> Value {
        let encoded = try JSONEncoder().encode(value)
        let masked = try maskJSONData(encoded)
        return try JSONDecoder().decode(Value.self, from: masked)
    }

    func maskJSONData(_ data: Data) throws -> Data {
        let object = try JSONSerialization.jsonObject(with: data, options: [.fragmentsAllowed])
        return try JSONSerialization.data(
            withJSONObject: maskJSONValue(object),
            options: [.fragmentsAllowed]
        )
    }

    private func maskJSONValue(_ value: Any) -> Any {
        switch value {
        case let string as String:
            return masker.mask(string)
        case let array as [Any]:
            return array.map(maskJSONValue)
        case let object as [String: Any]:
            return object.mapValues(maskJSONValue)
        default:
            return value
        }
    }
}
