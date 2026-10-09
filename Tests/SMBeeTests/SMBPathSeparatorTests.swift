import XCTest
@testable import SMBee

final class SMBPathSeparatorTests: XCTestCase {
    func testEverySeparatorOperationUsesUnicodeScalarBoundaries() {
        XCTAssertEqual(
            SMBPathSeparator.split("a\\\u{0301}b/c\u{0600}/d", kind: .smb),
            ["a", "\u{0301}b", "c\u{0600}", "d"]
        )
        XCTAssertTrue(SMBPathSeparator.contains("x\\\u{0301}y", kind: .smb))
        XCTAssertTrue(SMBPathSeparator.contains("x\u{0600}/y", kind: .smb))
        XCTAssertEqual(
            SMBPathSeparator.trimmingBoundarySeparators("/\u{0301}x\u{0600}/", kind: .slash),
            "\u{0301}x\u{0600}"
        )
        XCTAssertTrue(SMBPathSeparator.hasLeadingSeparators("\\\\\u{0301}server", kind: .backslash, count: 2))
        XCTAssertTrue(SMBPathSeparator.hasTrailingSeparator("x\u{0600}/", kind: .slash))
        XCTAssertEqual(
            SMBPathSeparator.replacingSeparators("a\\\u{0301}b/c\u{0600}/d", kind: .smb, with: "-"),
            "a-\u{0301}b-c\u{0600}-d"
        )
    }

    func testA1SMBPathUsesScalarSeparatorBoundariesForDotSegments() throws {
        let rejectedPaths = [
            "../\u{0301}y",
            "x/../\u{0301}y",
            "a\\..\\\u{0301}b",
            "x\u{0600}/..",
            "a\u{0600}\\.."
        ]
        for path in rejectedPaths {
            XCTAssertThrowsError(try SMBPath.normalize(path), "expected dot component rejection for \(path)")
        }

        XCTAssertEqual(try SMBPath.normalize("x/\u{0301}y"), "x\\\u{0301}y")
        XCTAssertEqual(try SMBPath.normalize("a\\\u{0301}.."), "a\\\u{0301}..")
    }

    func testA2ShareEntryAndDecodedURLComponentsRejectHiddenSeparators() throws {
        for name in ["share/\u{0301}name", "share\\\u{0301}name"] {
            XCTAssertThrowsError(try SMBShareName(name))
            XCTAssertThrowsError(try SMBPath.validateDirectoryEntryName(name))
        }
        XCTAssertThrowsError(try SMBPath.validateDirectoryEntryName("entry/\u{0301}name"))
        XCTAssertThrowsError(try SMBPath.validateDirectoryEntryName("entry\\\u{0301}name"))

        XCTAssertThrowsError(try SMBURLParser.parseReadURL("smb://server/share/dir%2F%CC%81name"))
        XCTAssertThrowsError(try SMBURLParser.parseReadURL("smb://server/share/dir%5C%CC%81name"))
        XCTAssertThrowsError(try SMBURLParser.parseReadURL("smb://server/share%2F%CC%81name/file"))
    }

    func testA3CopyTargetAndDFSComponentBoundariesPreserveCombiningScalars() throws {
        XCTAssertThrowsError(try SMBPath.validateDirectoryCopyTarget(fromPath: "a", toPath: "a\\\u{0301}b"))

        let dfsPath = "\\\\server\\share\\\u{0301}leaf"
        XCTAssertEqual(try SMBClient.dfsShare(from: dfsPath), "share")
        XCTAssertEqual(try SMBClient.dfsRelativePath(from: dfsPath), "\u{0301}leaf")
        let target = try SMBClient.dfsTarget(from: "\\\\server\\\u{0301}share")
        XCTAssertEqual(target.share, "\u{0301}share")
        XCTAssertEqual(try SMBClient.dfsShare(from: "\\\\server/share\\leaf"), "share")
        XCTAssertEqual(try SMBClient.dfsRelativePath(from: "\\\\server\\share\\dir/file"), "dir\\file")
        XCTAssertEqual(
            try SMBClient.dfsRelativePath(from: "\\\\server\\share\\dir/\u{0301}file"),
            "dir\\\u{0301}file"
        )

        let parsedTarget = try SMBClient.dfsTarget(from: "\\\\server/share\\leaf")
        XCTAssertEqual(parsedTarget.host, "server")
        XCTAssertEqual(parsedTarget.share, "share")

        let markedHostTarget = try SMBClient.dfsTarget(from: "\\\\\u{0301}server/share")
        XCTAssertEqual(markedHostTarget.host, "\u{0301}server")
        XCTAssertEqual(markedHostTarget.share, "share")

        let referralTarget = SMBDfsReferralTarget(networkAddress: "\\\\server/share\\leaf")
        XCTAssertEqual(referralTarget?.host, "server")
        XCTAssertEqual(referralTarget?.share, "share")
    }

    func testTreeConnectUNCParsingPreservesCombiningMarkAtShareBoundary() throws {
        let path = "\\\\server\\\u{0301}share"
        let packet = try SMB2TreeConnect.encodeRequest(messageId: 1, sessionId: 2, path: path)
        let nameOffset = Int(packet[68]) | (Int(packet[69]) << 8)
        let nameLength = Int(packet[70]) | (Int(packet[71]) << 8)
        let encodedPath = Array(packet[nameOffset..<nameOffset + nameLength])

        let decodedPath = decodeUTF16LE(encodedPath)
        XCTAssertEqual(decodedPath, path)
    }

    func testTreeConnectDetectsUNCWhenCombiningMarkFollowsLeadingSeparator() {
        let malformedUNC = "\\\\\u{0301}server\\share\\extra"
        XCTAssertThrowsError(try SMB2TreeConnect.encodeRequest(messageId: 1, sessionId: 2, path: malformedUNC))
    }

    func testDfsPathSuffixRestoresUncSeparatorBeforeCombiningHost() throws {
        let path = "\\\\\u{0301}server\\share\\leaf"
        XCTAssertEqual(try SMBClient.dfsPathSuffix(path, consumedUTF16Bytes: 28), "\\leaf")
    }
}
