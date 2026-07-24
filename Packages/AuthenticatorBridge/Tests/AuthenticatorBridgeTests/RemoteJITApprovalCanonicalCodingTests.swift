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

    func testRequestEncoderRejectsCallerConstructedDigestMismatch() throws {
        let fixture = try RemoteJITApprovalGoldenFixture.load()
        let request = try RemoteJITApprovalRequest(
            descriptor: fixture.makeDescriptor(),
            requestDigest: changing(
                try Data(hexadecimal: fixture.expected.requestDigestHex),
                at: 0,
                to: 0
            ),
            requestSignature: Data(hexadecimal: fixture.expected.requestSignatureHex)
        )

        XCTAssertThrowsError(
            try RemoteJITApprovalCanonicalCoding.encodeRequest(request)
        )
    }

    func testRejectsMalformedRequestEnvelopes() throws {
        let fixture = try RemoteJITApprovalGoldenFixture.load()
        let golden = try Data(hexadecimal: fixture.expected.requestEnvelopeHex)
        let domain = Data("Authsia.RemoteJITApproval.RequestEnvelope.V1\0".utf8)
        let descriptor = try Data(hexadecimal: fixture.expected.descriptorHex)
        let digestOffset = domain.count + 4 + descriptor.count
        let signatureOffset = digestOffset + 32

        var derSignature = golden
        derSignature.replaceSubrange(
            signatureOffset..<golden.count,
            with: Data([0x30, 0x44]) + Data(repeating: 0, count: 68)
        )
        let mutations = [
            NamedMutation(name: "wrong request domain", bytes: changing(golden, at: 0, to: 0)),
            NamedMutation(
                name: "descriptor length mismatch",
                bytes: writingUInt32(golden, at: domain.count, value: UInt32(descriptor.count + 1))
            ),
            NamedMutation(
                name: "decoded digest mismatch",
                bytes: changing(golden, at: digestOffset, to: golden[digestOffset] ^ 0x01)
            ),
            NamedMutation(name: "DER signature", bytes: derSignature),
            NamedMutation(name: "short signature", bytes: Data(golden.dropLast())),
            NamedMutation(name: "truncation", bytes: Data(golden.prefix(domain.count + 8))),
            NamedMutation(name: "trailing byte", bytes: golden + Data([0])),
        ]
        for mutation in mutations {
            XCTAssertThrowsError(
                try RemoteJITApprovalCanonicalCoding.decodeRequest(mutation.bytes),
                mutation.name
            )
        }

        assertOversized {
            _ = try RemoteJITApprovalCanonicalCoding.decodeRequest(
                writingUInt32(golden, at: domain.count, value: 1_000_001)
            )
        }
        assertOversized {
            _ = try RemoteJITApprovalCanonicalCoding.decodeRequest(
                Data(repeating: 0, count: 1_048_577)
            )
        }
    }

    func testRejectsMalformedDecisionEnvelopes() throws {
        let fixture = try RemoteJITApprovalGoldenFixture.load()
        let golden = try Data(hexadecimal: fixture.expected.approveDecisionEnvelopeHex)
        let domain = Data("Authsia.RemoteJITApproval.DecisionEnvelope.V1\0".utf8)
        let decisionTagOffset = domain.count + 4 + 16 + 32 + 32 + 16 + 16 + 16
        let expiryOffset = decisionTagOffset + 1
        let signatureOffset = expiryOffset + 8

        var invalidExpiry = golden
        invalidExpiry.replaceSubrange(expiryOffset..<(expiryOffset + 8), with: Data(repeating: 0xFF, count: 8))
        var derSignature = golden
        derSignature.replaceSubrange(
            signatureOffset..<golden.count,
            with: Data([0x30, 0x44]) + Data(repeating: 0, count: 68)
        )
        let mutations = [
            NamedMutation(name: "wrong decision domain", bytes: changing(golden, at: 0, to: 0)),
            NamedMutation(name: "unsupported decision schema", bytes: changing(golden, at: domain.count + 1, to: 3)),
            NamedMutation(name: "unsupported decision protocol", bytes: changing(golden, at: domain.count + 3, to: 3)),
            NamedMutation(name: "unknown decision tag", bytes: changing(golden, at: decisionTagOffset, to: 3)),
            NamedMutation(name: "invalid decision expiry", bytes: invalidExpiry),
            NamedMutation(name: "DER decision signature", bytes: derSignature),
            NamedMutation(name: "short decision signature", bytes: Data(golden.dropLast())),
            NamedMutation(name: "decision truncation", bytes: Data(golden.prefix(domain.count + 8))),
            NamedMutation(name: "decision trailing byte", bytes: golden + Data([0])),
        ]
        for mutation in mutations {
            XCTAssertThrowsError(
                try RemoteJITApprovalCanonicalCoding.decodeDecision(mutation.bytes),
                mutation.name
            )
        }

        assertOversized {
            _ = try RemoteJITApprovalCanonicalCoding.decodeDecision(
                Data(repeating: 0, count: 1_048_577)
            )
        }
    }

    func testEveryDecisionPayloadFieldChangesUnsignedBytes() throws {
        let fixture = try RemoteJITApprovalGoldenFixture.load()
        let payload = try fixture.makeApprovePayload()
        let golden = try RemoteJITApprovalCanonicalCoding.unsignedDecisionBytes(payload)
        let changedNonce = changing(payload.approvalNonce, at: 0, to: payload.approvalNonce[0] ^ 0x01)
        let changedDigest = changing(payload.requestDigest, at: 0, to: payload.requestDigest[0] ^ 0x01)
        let variants = try [
            copiedPayload(payload, approvalID: XCTUnwrap(UUID(uuidString: "aaaaaaaa-1111-4111-8111-111111111111"))),
            copiedPayload(payload, approvalNonce: changedNonce),
            copiedPayload(payload, requestDigest: changedDigest),
            copiedPayload(payload, pairingGenerationID: XCTUnwrap(UUID(uuidString: "aaaaaaaa-3333-4333-8333-333333333333"))),
            copiedPayload(payload, macDeviceID: XCTUnwrap(UUID(uuidString: "aaaaaaaa-4444-4444-8444-444444444444"))),
            copiedPayload(payload, iphoneDeviceID: XCTUnwrap(UUID(uuidString: "aaaaaaaa-5555-4555-8555-555555555555"))),
            copiedPayload(payload, value: .deny),
            copiedPayload(payload, requestExpiresAtMilliseconds: payload.requestExpiresAtMilliseconds - 1),
        ]

        for variant in variants {
            XCTAssertNotEqual(
                try RemoteJITApprovalCanonicalCoding.unsignedDecisionBytes(variant),
                golden
            )
        }
    }

    func testEnvelopeDecodersPreserveOpaqueHighSSignatures() throws {
        let fixture = try RemoteJITApprovalGoldenFixture.load()
        var requestBytes = try Data(hexadecimal: fixture.expected.requestEnvelopeHex)
        requestBytes.replaceSubrange((requestBytes.count - 32)..<requestBytes.count, with: Data(repeating: 0xFF, count: 32))
        let request = try RemoteJITApprovalCanonicalCoding.decodeRequest(requestBytes)
        XCTAssertEqual(request.requestSignature.suffix(32), Data(repeating: 0xFF, count: 32))
        XCTAssertEqual(try RemoteJITApprovalCanonicalCoding.encodeRequest(request), requestBytes)

        var decisionBytes = try Data(hexadecimal: fixture.expected.approveDecisionEnvelopeHex)
        decisionBytes.replaceSubrange((decisionBytes.count - 32)..<decisionBytes.count, with: Data(repeating: 0xFF, count: 32))
        let decision = try RemoteJITApprovalCanonicalCoding.decodeDecision(decisionBytes)
        XCTAssertEqual(decision.decisionSignature.suffix(32), Data(repeating: 0xFF, count: 32))
        XCTAssertEqual(try RemoteJITApprovalCanonicalCoding.encodeDecision(decision), decisionBytes)
    }

    func testEnvelopeDecodersAcceptDataSlicesWithNonzeroStartIndex() throws {
        let fixture = try RemoteJITApprovalGoldenFixture.load()
        let requestBytes = try Data(hexadecimal: fixture.expected.requestEnvelopeHex)
        let decisionBytes = try Data(hexadecimal: fixture.expected.approveDecisionEnvelopeHex)

        XCTAssertEqual(
            try RemoteJITApprovalCanonicalCoding.encodeRequest(
                RemoteJITApprovalCanonicalCoding.decodeRequest((Data([0xFF]) + requestBytes)[1...])
            ),
            requestBytes
        )
        XCTAssertEqual(
            try RemoteJITApprovalCanonicalCoding.encodeDecision(
                RemoteJITApprovalCanonicalCoding.decodeDecision((Data([0xFF]) + decisionBytes)[1...])
            ),
            decisionBytes
        )
    }

    private func malformedMutations(
        golden: Data,
        layout: DescriptorLayout
    ) throws -> [NamedMutation] {
        var mutations: [NamedMutation] = []

        mutations.append(.init(name: "wrong domain", bytes: changing(golden, at: 0, to: 0)))
        mutations.append(.init(name: "unsupported schema", bytes: changing(golden, at: 41, to: 3)))
        mutations.append(.init(name: "unsupported protocol", bytes: changing(golden, at: 43, to: 3)))
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
            name: "unsafe item name",
            bytes: replacingString(
                golden,
                layout.items[0].nameString,
                with: "Deploy\u{202E}password"
            )
        ))
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

    private func copiedPayload(
        _ payload: RemoteJITApprovalDecisionPayload,
        approvalID: UUID? = nil,
        approvalNonce: Data? = nil,
        requestDigest: Data? = nil,
        pairingGenerationID: UUID? = nil,
        macDeviceID: UUID? = nil,
        iphoneDeviceID: UUID? = nil,
        value: RemoteJITApprovalDecisionValue? = nil,
        requestExpiresAtMilliseconds: Int64? = nil
    ) throws -> RemoteJITApprovalDecisionPayload {
        try RemoteJITApprovalDecisionPayload(
            approvalID: approvalID ?? payload.approvalID,
            approvalNonce: approvalNonce ?? payload.approvalNonce,
            requestDigest: requestDigest ?? payload.requestDigest,
            pairingGenerationID: pairingGenerationID ?? payload.pairingGenerationID,
            macDeviceID: macDeviceID ?? payload.macDeviceID,
            iphoneDeviceID: iphoneDeviceID ?? payload.iphoneDeviceID,
            value: value ?? payload.value,
            requestExpiresAtMilliseconds: requestExpiresAtMilliseconds ?? payload.requestExpiresAtMilliseconds
        )
    }

    private func assertOversized(
        file: StaticString = #filePath,
        line: UInt = #line,
        _ operation: () throws -> Void
    ) {
        XCTAssertThrowsError(try operation(), file: file, line: line) { error in
            XCTAssertEqual(
                error as? RemoteJITApprovalValidationError,
                .oversized,
                file: file,
                line: line
            )
        }
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
    let nameString: EncodedString
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
            let name = try cursor.string()
            let marker = try cursor.byte()
            let folder = marker == 1 ? try cursor.string() : nil
            items.append(.init(
                whole: start..<cursor.offset,
                tagOffset: tagOffset,
                uuid: uuid,
                nameString: name,
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
