import XCTest
@testable import AuthenticatorBridge

final class RemoteJITApprovalCanonicalCodingTests: XCTestCase {
    func testDescriptorMatchesIndependentGoldenBytes() throws {
        let fixture = try RemoteJITApprovalGoldenFixture.load()
        let descriptor = try fixture.makeDescriptor()

        let bytes = try RemoteJITApprovalCanonicalCoding.encodeDescriptor(descriptor)

        XCTAssertEqual(bytes.hexString, fixture.expected.descriptorHex)
        XCTAssertEqual(
            try RemoteJITApprovalCanonicalCoding.decodeDescriptor(bytes),
            descriptor
        )
    }

    func testRejectsMalformedAndNoncanonicalDescriptors() throws {
        let fixture = try RemoteJITApprovalGoldenFixture.load()
        let golden = try Data(hexadecimal: fixture.expected.descriptorHex)
        let layout = try DescriptorLayout(data: golden)

        let mutations = try malformedMutations(golden: golden, layout: layout)
        for mutation in mutations {
            XCTAssertThrowsError(
                try RemoteJITApprovalCanonicalCoding.decodeDescriptor(mutation.bytes),
                mutation.name
            )
        }
    }

    func testDecodesDescriptorDataSliceWithNonzeroStartIndex() throws {
        let fixture = try RemoteJITApprovalGoldenFixture.load()
        let golden = try Data(hexadecimal: fixture.expected.descriptorHex)
        let padded = Data([0xFF]) + golden

        XCTAssertEqual(
            try RemoteJITApprovalCanonicalCoding.decodeDescriptor(padded[1...]),
            try fixture.makeDescriptor()
        )
    }

    private func malformedMutations(
        golden: Data,
        layout: DescriptorLayout
    ) throws -> [NamedMutation] {
        var mutations: [NamedMutation] = []

        mutations.append(.init(name: "wrong domain", bytes: changing(golden, at: 0, to: 0)))
        mutations.append(.init(name: "unsupported schema", bytes: changing(golden, at: 41, to: 2)))
        mutations.append(.init(name: "unsupported protocol", bytes: changing(golden, at: 43, to: 2)))
        mutations.append(.init(
            name: "invalid optional marker",
            bytes: changing(golden, at: layout.optionalMarkerOffsets[0], to: 2)
        ))

        var invalidUTF8 = golden
        invalidUTF8[layout.processString.value.lowerBound] = 0xFF
        mutations.append(.init(name: "invalid UTF-8", bytes: invalidUTF8))

        var nonNFC = golden
        nonNFC.replaceSubrange(
            layout.processString.value.lowerBound..<(layout.processString.value.lowerBound + 3),
            with: [0x65, 0xCC, 0x81]
        )
        mutations.append(.init(name: "non-NFC string", bytes: nonNFC))

        mutations.append(.init(
            name: "NUL string",
            bytes: changing(golden, at: layout.processString.value.lowerBound, to: 0)
        ))
        var formatControl = golden
        formatControl.replaceSubrange(
            layout.processString.value.lowerBound..<(layout.processString.value.lowerBound + 3),
            with: [0xE2, 0x80, 0xAE]
        )
        mutations.append(.init(name: "format-control string", bytes: formatControl))

        mutations.append(.init(
            name: "zero required string length",
            bytes: replacingString(golden, layout.processString, with: "")
        ))
        mutations.append(.init(
            name: "oversized string length",
            bytes: writingUInt32(golden, at: layout.processString.prefixOffset, value: 256)
        ))
        mutations.append(.init(
            name: "truncated UUID",
            bytes: Data(golden.prefix(layout.approvalID.lowerBound + 8))
        ))
        mutations.append(.init(
            name: "truncated fixed data",
            bytes: Data(golden.prefix(layout.approvalNonce.lowerBound + 16))
        ))

        mutations.append(.init(
            name: "oversized capability count",
            bytes: writingUInt32(golden, at: layout.capabilityCountOffset, value: 3)
        ))
        mutations.append(.init(
            name: "unknown capability tag",
            bytes: changing(golden, at: layout.capabilityTags.lowerBound, to: 3)
        ))
        var unsortedCapabilities = golden
        unsortedCapabilities.replaceSubrange(layout.capabilityTags, with: [0x02, 0x01])
        mutations.append(.init(name: "unsorted capabilities", bytes: unsortedCapabilities))
        mutations.append(.init(
            name: "duplicate capabilities",
            bytes: changing(golden, at: layout.capabilityTags.upperBound - 1, to: 1)
        ))

        mutations.append(.init(
            name: "unknown folder tag",
            bytes: changing(golden, at: layout.folderTagOffset, to: 2)
        ))
        mutations.append(.init(
            name: "noncanonical folder scope",
            bytes: replacingString(golden, try XCTUnwrap(layout.folderString), with: "Team//API")
        ))
        mutations.append(.init(
            name: "unknown environment tag",
            bytes: changing(golden, at: layout.environmentTagOffset, to: 3)
        ))
        mutations.append(.init(
            name: "noncanonical named environment",
            bytes: replacingString(golden, try XCTUnwrap(layout.environmentString), with: " Production ")
        ))

        var zeroItems = writingUInt32(golden, at: layout.itemCountOffset, value: 0)
        zeroItems.removeSubrange(layout.items[0].whole.lowerBound..<layout.items[1].whole.upperBound)
        mutations.append(.init(name: "zero item count", bytes: zeroItems))
        mutations.append(.init(
            name: "oversized item count",
            bytes: writingUInt32(golden, at: layout.itemCountOffset, value: 1_025)
        ))
        mutations.append(.init(
            name: "unknown item tag",
            bytes: changing(golden, at: layout.items[0].tagOffset, to: 6)
        ))
        var unsortedItems = golden
        let firstItem = Data(golden[layout.items[0].whole])
        let secondItem = Data(golden[layout.items[1].whole])
        unsortedItems.replaceSubrange(
            layout.items[0].whole.lowerBound..<layout.items[1].whole.upperBound,
            with: secondItem + firstItem
        )
        mutations.append(.init(name: "unsorted items", bytes: unsortedItems))
        var duplicateItems = golden
        duplicateItems.replaceSubrange(
            layout.items[1].uuid,
            with: golden[layout.items[0].uuid]
        )
        mutations.append(.init(name: "duplicate item UUID", bytes: duplicateItems))
        mutations.append(.init(
            name: "noncanonical item folder",
            bytes: replacingString(
                golden,
                try XCTUnwrap(layout.items[1].folderString),
                with: "Team/API//Build"
            )
        ))
        mutations.append(.init(
            name: "noncanonical working directory",
            bytes: replacingString(
                golden,
                layout.workingDirectoryString,
                with: "/workspace/./synthetic-demo"
            )
        ))

        mutations.append(.init(name: "truncation", bytes: Data(golden.dropLast())))
        mutations.append(.init(name: "trailing byte", bytes: golden + Data([0])))
        mutations.append(.init(
            name: "oversized descriptor",
            bytes: Data(repeating: 0, count: 1_000_001)
        ))
        return mutations
    }

    private func changing(_ data: Data, at offset: Int, to byte: UInt8) -> Data {
        var result = data
        result[offset] = byte
        return result
    }

    private func writingUInt32(_ data: Data, at offset: Int, value: UInt32) -> Data {
        var result = data
        result.replaceSubrange(offset..<(offset + 4), with: bigEndianBytes(value))
        return result
    }

    private func replacingString(
        _ data: Data,
        _ encoded: EncodedString,
        with value: String
    ) -> Data {
        let bytes = Data(value.utf8)
        var result = data
        result.replaceSubrange(
            encoded.prefixOffset..<encoded.value.upperBound,
            with: bigEndianBytes(UInt32(bytes.count)) + bytes
        )
        return result
    }
}

private struct NamedMutation {
    let name: String
    let bytes: Data
}

private struct EncodedString {
    let prefixOffset: Int
    let value: Range<Int>
}

private struct EncodedItem {
    let whole: Range<Int>
    let tagOffset: Int
    let uuid: Range<Int>
    let folderString: EncodedString?
}

private struct DescriptorLayout {
    let approvalID: Range<Int>
    let approvalNonce: Range<Int>
    let processString: EncodedString
    let workingDirectoryString: EncodedString
    let optionalMarkerOffsets: [Int]
    let capabilityCountOffset: Int
    let capabilityTags: Range<Int>
    let folderTagOffset: Int
    let folderString: EncodedString?
    let environmentTagOffset: Int
    let environmentString: EncodedString?
    let itemCountOffset: Int
    let items: [EncodedItem]

    init(data: Data) throws {
        var cursor = DescriptorCursor(data: data)
        try cursor.skip(40 + 2 + 2)
        approvalID = try cursor.range(count: 16)
        approvalNonce = try cursor.range(count: 32)
        try cursor.skip(16 * 4 + 32 * 2 + 8 * 2)

        var optionalMarkerOffsets: [Int] = []
        processString = try cursor.string()
        for _ in 0..<7 {
            optionalMarkerOffsets.append(cursor.offset)
            switch try cursor.byte() {
            case 0:
                break
            case 1:
                _ = try cursor.string()
            default:
                throw LayoutError.unexpectedFixture
            }
        }
        _ = try cursor.string()
        workingDirectoryString = try cursor.string()
        self.optionalMarkerOffsets = optionalMarkerOffsets

        capabilityCountOffset = cursor.offset
        let capabilityCount = try cursor.uint32()
        capabilityTags = try cursor.range(count: Int(capabilityCount))

        folderTagOffset = cursor.offset
        let folderTag = try cursor.byte()
        folderString = folderTag == 1 ? try cursor.string() : nil

        environmentTagOffset = cursor.offset
        let environmentTag = try cursor.byte()
        environmentString = environmentTag == 2 ? try cursor.string() : nil

        itemCountOffset = cursor.offset
        let itemCount = try cursor.uint32()
        var items: [EncodedItem] = []
        for _ in 0..<itemCount {
            let start = cursor.offset
            let tagOffset = cursor.offset
            try cursor.skip(1)
            let uuid = try cursor.range(count: 16)
            let marker = try cursor.byte()
            let folder = marker == 1 ? try cursor.string() : nil
            items.append(.init(
                whole: start..<cursor.offset,
                tagOffset: tagOffset,
                uuid: uuid,
                folderString: folder
            ))
        }
        self.items = items
    }
}

private struct DescriptorCursor {
    let data: Data
    var offset = 0

    mutating func byte() throws -> UInt8 {
        let range = try range(count: 1)
        return data[range.lowerBound]
    }

    mutating func uint32() throws -> UInt32 {
        let range = try range(count: 4)
        return data[range].reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
    }

    mutating func string() throws -> EncodedString {
        let prefixOffset = offset
        let length = try uint32()
        return EncodedString(
            prefixOffset: prefixOffset,
            value: try range(count: Int(length))
        )
    }

    mutating func skip(_ count: Int) throws {
        _ = try range(count: count)
    }

    mutating func range(count: Int) throws -> Range<Int> {
        guard count >= 0, count <= data.count - offset else {
            throw LayoutError.unexpectedFixture
        }
        let result = offset..<(offset + count)
        offset += count
        return result
    }
}

private enum LayoutError: Error {
    case unexpectedFixture
}

private func bigEndianBytes(_ value: UInt32) -> Data {
    Data([
        UInt8(truncatingIfNeeded: value >> 24),
        UInt8(truncatingIfNeeded: value >> 16),
        UInt8(truncatingIfNeeded: value >> 8),
        UInt8(truncatingIfNeeded: value),
    ])
}
