#if os(macOS)
import Foundation

public enum BridgeJSON {
    public static var encoder: JSONEncoder {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        return encoder
    }

    public static var decoder: JSONDecoder {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return decoder
    }
}

public extension JSONEncoder {
    static var bridge: JSONEncoder { BridgeJSON.encoder }
}

public extension JSONDecoder {
    static var bridge: JSONDecoder { BridgeJSON.decoder }
}
#endif
