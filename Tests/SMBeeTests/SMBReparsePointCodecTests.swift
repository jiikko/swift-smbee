import XCTest
@testable import SMBee

final class SMBReparsePointCodecTests: XCTestCase {
    func testRelativeSymbolicLinkEncodingRoundTrips() throws {
        let encoded = try SMB2ReparsePoint.encodeSymbolicLink(
            substituteName: "../target.txt",
            printName: "../target.txt",
            relative: true
        )

        let decoded = try SMB2ReparsePoint.decode(encoded)
        XCTAssertEqual(decoded.tag, SMBReparseTags.symlink)
        XCTAssertEqual(decoded.kind, .symlink)
        XCTAssertEqual(decoded.substituteName, "../target.txt")
        XCTAssertEqual(decoded.printName, "../target.txt")
        XCTAssertEqual(decoded.flags, 1)
    }

    func testSetReparsePointCreateDoesNotFollowTheTarget() {
        let request = SMB2CreateRequest.setReparsePoint(path: "link")

        XCTAssertEqual(request.desiredAccess, 0x0000_0100)
        XCTAssertEqual(request.createDisposition, 0x0000_0001)
        XCTAssertEqual(request.createOptions, 0x0000_0040 | 0x0020_0000)
    }
}
