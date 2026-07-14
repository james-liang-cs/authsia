import XCTest
@testable import AuthenticatorCore

final class OTPAuthParserTests: XCTestCase {
    
    // MARK: - Golden Samples (Simulated)
    
    func testGoogleStyle() throws {
        // Typical Google: otpauth://totp/Google%3Aalice%40example.com?secret=JBSWY3DPEHPK3PXP&issuer=Google
        let uri = "otpauth://totp/Google%3Aalice%40example.com?secret=JBSWY3DPEHPK3PXP&issuer=Google"
        let account = try OTPAuthParser.parse(uri)
        
        XCTAssertEqual(account.issuer, "Google")
        XCTAssertEqual(account.label, "alice@example.com")
        XCTAssertEqual(account.secret, try Base32.decode("JBSWY3DPEHPK3PXP"))
        XCTAssertEqual(account.algorithm, .sha1)
        XCTAssertEqual(account.digits, 6)
        XCTAssertEqual(account.type, .totp)
    }
    
    func testGitHubStyle() throws {
        // Typical GitHub: otpauth://totp/GitHub:Alice?secret=JBSWY3DPEHPK3PXP&issuer=GitHub
        let uri = "otpauth://totp/GitHub:Alice?secret=JBSWY3DPEHPK3PXP&issuer=GitHub"
        let account = try OTPAuthParser.parse(uri)
        
        XCTAssertEqual(account.issuer, "GitHub")
        XCTAssertEqual(account.label, "Alice")
    }
    
    func testAWSStyle() throws {
        // AWS often uses just label, no issuer param: otpauth://totp/Amazon%20Web%20Services:Alice?secret=JBSWY3DPEHPK3PXP
        let uri = "otpauth://totp/Amazon%20Web%20Services:Alice?secret=JBSWY3DPEHPK3PXP"
        let account = try OTPAuthParser.parse(uri)
        
        XCTAssertEqual(account.issuer, "Amazon Web Services")
        XCTAssertEqual(account.label, "Alice")
    }
    
    func testMicrosoftStyle() throws {
        // Microsoft sometimes omits issuer in path: otpauth://totp/Alice?secret=JBSWY3DPEHPK3PXP&issuer=Microsoft
        let uri = "otpauth://totp/Alice?secret=JBSWY3DPEHPK3PXP&issuer=Microsoft"
        let account = try OTPAuthParser.parse(uri)
        
        XCTAssertEqual(account.issuer, "Microsoft")
        XCTAssertEqual(account.label, "Alice")
    }
    
    // MARK: - Edge Cases
    
    func testSpacesInSecret() throws {
        // otpauth://totp/Label?secret=JBSW Y3DP EHPK 3PXP
        let uri = "otpauth://totp/Label?secret=JBSW%20Y3DP%20EHPK%203PXP"
        let account = try OTPAuthParser.parse(uri)
        XCTAssertEqual(account.secret, try Base32.decode("JBSWY3DPEHPK3PXP"))
    }
    
    func testLowercaseSecret() throws {
        let uri = "otpauth://totp/Label?secret=jbswy3dpehpk3pxp"
        let account = try OTPAuthParser.parse(uri)
        XCTAssertEqual(account.secret, try Base32.decode("JBSWY3DPEHPK3PXP"))
    }
    
    func testAdvancedParams() throws {
        // SHA256, 8 digits, 60s period
        let uri = "otpauth://totp/Label?secret=JBSWY3DPEHPK3PXP&algorithm=SHA256&digits=8&period=60"
        let account = try OTPAuthParser.parse(uri)
        
        XCTAssertEqual(account.algorithm, .sha256)
        XCTAssertEqual(account.digits, 8)
        XCTAssertEqual(account.period, 60)
    }
    
    func testHOTP() throws {
        let uri = "otpauth://hotp/Label?secret=JBSWY3DPEHPK3PXP&counter=10"
        let account = try OTPAuthParser.parse(uri)
        
        XCTAssertEqual(account.type, .hotp)
        XCTAssertEqual(account.counter, 10)
    }
    
    func testInvalidScheme() {
         XCTAssertThrowsError(try OTPAuthParser.parse("http://google.com")) { error in
             guard let otpError = error as? OTPAuthError,
                   case .invalidScheme(let scheme) = otpError else {
                 XCTFail("Expected invalidScheme error, got \(error)")
                 return
             }
             XCTAssertEqual(scheme, "http")
         }
    }

    func testMigrationScheme() {
         XCTAssertThrowsError(try OTPAuthParser.parse("otpauth-migration://offline?data=...")) { error in
             guard let otpError = error as? OTPAuthError,
                   case .migrationNotSupported = otpError else {
                 XCTFail("Expected migrationNotSupported error, got \(error)")
                 return
             }
         }
    }
    
    func testMissingSecret() {
        let uri = "otpauth://totp/Label?issuer=Foo"
        XCTAssertThrowsError(try OTPAuthParser.parse(uri)) { error in
            XCTAssertEqual(error as? OTPAuthError, .missingSecret)
        }
    }
}
