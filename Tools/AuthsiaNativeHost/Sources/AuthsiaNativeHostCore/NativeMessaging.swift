import Foundation

public enum NativeMessagingError: Error, Equatable {
    case insufficientData
    case invalidLength
}

public enum NativeMessaging {
    public struct DecodedFrame: Equatable {
        public let payload: Data
        public let bytesConsumed: Int

        public init(payload: Data, bytesConsumed: Int) {
            self.payload = payload
            self.bytesConsumed = bytesConsumed
        }
    }

    public static func encodeFrame(_ payload: Data) -> Data {
        var length = UInt32(payload.count).littleEndian
        var framed = Data(bytes: &length, count: MemoryLayout<UInt32>.size)
        framed.append(payload)
        return framed
    }

    public static func decodeFrame(_ data: Data) throws -> DecodedFrame {
        let headerSize = MemoryLayout<UInt32>.size
        guard data.count >= headerSize else {
            throw NativeMessagingError.insufficientData
        }

        var length: UInt32 = 0
        _ = withUnsafeMutableBytes(of: &length) { buffer in
            data.copyBytes(to: buffer, count: headerSize)
        }
        let payloadLength = Int(UInt32(littleEndian: length))
        guard payloadLength >= 0 else {
            throw NativeMessagingError.invalidLength
        }

        let totalLength = headerSize + payloadLength
        guard data.count >= totalLength else {
            throw NativeMessagingError.insufficientData
        }

        let payload = data.subdata(in: headerSize ..< totalLength)
        return DecodedFrame(payload: payload, bytesConsumed: totalLength)
    }

    public static func readMessage(from handle: FileHandle) throws -> Data? {
        let headerSize = MemoryLayout<UInt32>.size
        let headerData = handle.readData(ofLength: headerSize)
        guard headerData.count == headerSize else {
            return nil
        }

        var length: UInt32 = 0
        _ = withUnsafeMutableBytes(of: &length) { buffer in
            headerData.copyBytes(to: buffer, count: headerSize)
        }
        let payloadLength = Int(UInt32(littleEndian: length))
        guard payloadLength >= 0 else {
            throw NativeMessagingError.invalidLength
        }

        let payload = handle.readData(ofLength: payloadLength)
        guard payload.count == payloadLength else {
            return nil
        }

        return payload
    }

    public static func writeMessage(_ payload: Data, to handle: FileHandle) {
        let framed = encodeFrame(payload)
        handle.write(framed)
    }
}
