import XCTest
@testable import SMBee

final class SMBeeTests: XCTestCase {
    func testVersionIsNotEmpty() {
        XCTAssertFalse(SMBee.version.isEmpty)
    }
}
