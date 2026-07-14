import XCTest
@testable import AuthsiaBridgeHost
import AuthenticatorBridge
import AuthenticatorData
import Security

final class BridgeListFailureMapperTests: XCTestCase {
    func testMapsMetadataKeychainFailureWithoutGenericPrefix() {
        let result = BridgeListFailureMapper.mapping(
            for: MetadataLoadError.keychainUnavailable(errSecMissingEntitlement)
        )

        XCTAssertEqual(result.code, .appUnavailable)
        XCTAssertEqual(
            result.message,
            MetadataLoadError.keychainUnavailable(errSecMissingEntitlement).localizedDescription
        )
    }

    func testMapsMetadataDecodeFailureWithDecodeMessage() {
        let result = BridgeListFailureMapper.mapping(for: MetadataLoadError.decodeFailed("bad json"))

        XCTAssertEqual(result.code, .appUnavailable)
        XCTAssertEqual(result.message, "Authsia could not decode keychain metadata: bad json")
    }

    func testMapsKeychainAccessDeniedToActionableMessage() {
        let result = BridgeListFailureMapper.mapping(for: KeychainError.unknown(errSecInteractionNotAllowed))

        XCTAssertEqual(result.code, .appUnavailable)
        XCTAssertTrue(result.message.contains("not authorized to read the keychain"))
    }

    func testMapsGenericFailureWithGenericListPrefix() {
        let result = BridgeListFailureMapper.mapping(for: GenericListError())

        XCTAssertEqual(result.code, .appUnavailable)
        XCTAssertEqual(result.message, "Failed to list items: generic failure")
    }

    private struct GenericListError: LocalizedError {
        var errorDescription: String? { "generic failure" }
    }
}
