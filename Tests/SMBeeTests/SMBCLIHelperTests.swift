import ArgumentParser
import Foundation
import SMBee
@testable import smbcli
import XCTest

// smbcli の pure helper (run() の network 経路から独立した deterministic ロジック) の unit test。
// run() 自体は実サーバ orchestration なので E2E で担保し、ここでは helper だけを対象にする。
final class SMBCLIHelperTests: XCTestCase {
    // MARK: - validateSameShare (mv / cp の same-share guard)

    private func readURL(_ url: String) throws -> SMBURLParser.ReadURL {
        try SMBURLParser.parseReadURL(url)
    }

    func testValidateSameShareAllowsIdenticalUserHostPortShare() throws {
        let from = try readURL("smb://user@host:445/share/a.txt")
        let to = try readURL("smb://user@host:445/share/b.txt")
        XCTAssertNoThrow(try validateSameShare(source: from, destination: to, commandName: "mv"))
    }

    func testValidateSameShareRejectsDifferentShare() throws {
        let from = try readURL("smb://user@host/share/a.txt")
        let to = try readURL("smb://user@host/other/b.txt")
        XCTAssertThrowsError(try validateSameShare(source: from, destination: to, commandName: "cp"))
    }

    func testValidateSameShareRejectsDifferentHostPortUser() throws {
        let base = try readURL("smb://user@host:445/share/a.txt")
        let host = try readURL("smb://user@host2:445/share/b.txt")
        let port = try readURL("smb://user@host:446/share/b.txt")
        let user = try readURL("smb://user2@host:445/share/b.txt")
        XCTAssertThrowsError(try validateSameShare(source: base, destination: host, commandName: "mv"))
        XCTAssertThrowsError(try validateSameShare(source: base, destination: port, commandName: "mv"))
        XCTAssertThrowsError(try validateSameShare(source: base, destination: user, commandName: "mv"))
    }

    func testValidateSameShareErrorMessageIncludesCommandName() throws {
        let from = try readURL("smb://user@host/share/a.txt")
        let to = try readURL("smb://user@host/other/b.txt")
        XCTAssertThrowsError(try validateSameShare(source: from, destination: to, commandName: "mv")) { error in
            XCTAssertTrue("\(error)".contains("mv"))
        }
    }

    // MARK: - parseNTHash

    func testParseNTHashAcceptsValid32Hex() throws {
        let bytes = try parseNTHash("00112233445566778899aabbccddeeff")
        XCTAssertEqual(bytes.count, 16)
        XCTAssertEqual(bytes.first, 0x00)
        XCTAssertEqual(bytes.last, 0xff)
    }

    func testParseNTHashRejectsWrongLengthOrNonHex() {
        XCTAssertThrowsError(try parseNTHash("00112233"))
        XCTAssertThrowsError(try parseNTHash("zz112233445566778899aabbccddeeff"))
    }

    // MARK: - parseRange

    func testParseRangeConvertsInclusiveEndToOffsetLength() throws {
        let range = try parseRange("10-19")
        XCTAssertEqual(range.offset, 10)
        XCTAssertEqual(range.length, 10)
    }

    func testParseRangeRejectsMalformedOrReversed() {
        XCTAssertThrowsError(try parseRange("10"))
        XCTAssertThrowsError(try parseRange("20-10"))
        XCTAssertThrowsError(try parseRange("a-b"))
    }

    // MARK: - formatTransferProgress

    func testFormatTransferProgressWithTotalShowsPercent() {
        let progress = SMBTransferProgress(bytesTransferred: 512, totalBytes: 1024, bytesPerSecond: 256)
        let text = formatTransferProgress(progress)
        XCTAssertTrue(text.contains("(50%)"), text)
        XCTAssertTrue(text.contains("/s"), text)
    }

    func testFormatTransferProgressWithoutTotalOmitsPercent() {
        let progress = SMBTransferProgress(bytesTransferred: 100, totalBytes: nil, bytesPerSecond: 0)
        let text = formatTransferProgress(progress)
        XCTAssertFalse(text.contains("%"), text)
        XCTAssertTrue(text.hasPrefix("transferred "), text)
    }

    // MARK: - makeCredential (排他ルール)

    func testMakeCredentialAnonymousRejectsUsername() throws {
        let auth = try AuthOptions.parse(["--anonymous"])
        XCTAssertThrowsError(
            try makeCredential(username: "user", password: "pass", auth: auth)
        )
    }

    func testMakeCredentialPasswordProducesCredential() throws {
        let auth = try AuthOptions.parse([])
        let credential = try makeCredential(username: "user", password: "pass", auth: auth)
        XCTAssertEqual(credential.username, "user")
    }

    func testMakeCredentialRejectsBothNTHashAndPassword() throws {
        let auth = try AuthOptions.parse(["--nt-hash", "00112233445566778899aabbccddeeff"])
        XCTAssertThrowsError(
            try makeCredential(username: "user", password: "pass", auth: auth)
        )
    }

    // MARK: - TransportOptions.duration

    func testTransportDurationNilWhenUnset() throws {
        let options = try TransportOptions.parse([])
        XCTAssertNil(options.duration)
        XCTAssertNil(options.operationDuration)
        XCTAssertNil(options.perFileDuration)
    }

    func testTransportDurationConvertsSeconds() throws {
        let options = try TransportOptions.parse(["--timeout", "2", "--operation-timeout", "2.5", "--per-file-timeout", "1.25"])
        XCTAssertEqual(options.duration, .seconds(2))
        XCTAssertEqual(options.operationDuration, .seconds(2) + .milliseconds(500))
        XCTAssertEqual(options.perFileDuration, .seconds(1) + .milliseconds(250))
    }

    func testTransportDurationRejectsInvalidValues() {
        for value in ["0", "-1", "nan", "inf", "999999999"] {
            XCTAssertThrowsError(try TransportOptions.parse(["--timeout", value]))
        }
    }

    func testSuccessJSONStringShape() throws {
        let data = try XCTUnwrap(successJSONString(command: "put", path: "dir\\file.txt").data(using: .utf8))
        let object = try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])

        XCTAssertEqual(object["ok"] as? Bool, true)
        XCTAssertEqual(object["command"] as? String, "put")
        XCTAssertEqual(object["path"] as? String, "dir\\file.txt")
    }

    func testErrorJSONStringShape() throws {
        let error = SMBError.notFound(status: 0xc000_0034, operation: "CREATE")
        let data = try XCTUnwrap(errorJSONString(error).data(using: .utf8))
        let object = try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])

        XCTAssertEqual(object["ok"] as? Bool, false)
        XCTAssertEqual(object["category"] as? String, "smb")
        XCTAssertEqual(object["exitCode"] as? Int, Int(SMBCLIExitCode.notFound))
        XCTAssertNotNil(object["error"] as? String)
    }
}
