import Foundation
import XCTest
@testable import SMBee

final class SMBCLIOutputTests: XCTestCase {
    func testProbeJSONUsesStableCamelCaseKeysAndHexStrings() throws {
        let probe = SMBProbeResult(
            dialect: 0x0311,
            signingRequired: true,
            signingAlgorithm: 0x0002,
            cipher: 0x0004,
            preauthHashAlgorithm: 0x0001,
            serverGuid: UUID(uuidString: "00112233-4455-6677-8899-AABBCCDDEEFF")!,
            maxTransactSize: 1_048_576,
            maxReadSize: 2_097_152,
            maxWriteSize: 4_194_304
        )

        let object = try jsonObject(SMBCLIOutput.jsonData(for: probe))

        XCTAssertEqual(object["dialect"] as? String, "0x0311")
        XCTAssertEqual(object["signingRequired"] as? Bool, true)
        XCTAssertEqual(object["signingAlgorithm"] as? String, "0x0002")
        XCTAssertEqual(object["cipher"] as? String, "0x0004")
        XCTAssertEqual(object["preauthHashAlgorithm"] as? String, "0x0001")
        XCTAssertEqual(object["serverGuid"] as? String, "00112233-4455-6677-8899-AABBCCDDEEFF")
        XCTAssertEqual(object["maxTransactSize"] as? Int, 1_048_576)
        XCTAssertEqual(object["maxReadSize"] as? Int, 2_097_152)
        XCTAssertEqual(object["maxWriteSize"] as? Int, 4_194_304)
    }

    func testDirectoryEntriesJSONShape() throws {
        let entries = [
            SMBDirectoryEntry(name: "docs", fileSize: 0, isDirectory: true, attributes: 0x0000_0010),
            SMBDirectoryEntry(name: "readme.txt", fileSize: 42, isDirectory: false, attributes: 0x0000_0020),
        ]

        let array = try jsonArray(SMBCLIOutput.jsonData(for: entries))

        XCTAssertEqual(array.count, 2)
        XCTAssertEqual(array[0]["name"] as? String, "docs")
        XCTAssertEqual(array[0]["size"] as? Int, 0)
        XCTAssertEqual(array[0]["isDirectory"] as? Bool, true)
        XCTAssertEqual(array[0]["attributes"] as? String, "0x00000010")
        XCTAssertEqual(array[1]["name"] as? String, "readme.txt")
        XCTAssertEqual(array[1]["size"] as? Int, 42)
        XCTAssertEqual(array[1]["isDirectory"] as? Bool, false)
        XCTAssertEqual(array[1]["attributes"] as? String, "0x00000020")
    }

    func testStatJSONUsesISO8601Dates() throws {
        let date = Date(timeIntervalSince1970: 1_704_067_200.125)
        let stat = SMBFileStat(
            size: 123,
            modifiedTime: date,
            isDirectory: false,
            attributes: 0x0000_0080,
            creationTime: date,
            lastAccessTime: date,
            changeTime: date
        )

        let object = try jsonObject(SMBCLIOutput.jsonData(for: stat))

        XCTAssertEqual(object["size"] as? Int, 123)
        XCTAssertEqual(object["isDirectory"] as? Bool, false)
        XCTAssertEqual(object["attributes"] as? String, "0x00000080")
        XCTAssertEqual(object["creationTime"] as? String, "2024-01-01T00:00:00.125Z")
        XCTAssertEqual(object["lastAccessTime"] as? String, "2024-01-01T00:00:00.125Z")
        XCTAssertEqual(object["modifiedTime"] as? String, "2024-01-01T00:00:00.125Z")
        XCTAssertEqual(object["changeTime"] as? String, "2024-01-01T00:00:00.125Z")
    }

    func testSharesJSONShape() throws {
        let shares = [
            SMBShareInfo(name: "public", type: 0x0000_0000, comment: "Public files"),
            SMBShareInfo(name: "ipc$", type: nil, comment: nil),
        ]

        let array = try jsonArray(SMBCLIOutput.jsonData(for: shares))

        XCTAssertEqual(array.count, 2)
        XCTAssertEqual(array[0]["name"] as? String, "public")
        XCTAssertEqual(array[0]["type"] as? String, "0x00000000")
        XCTAssertEqual(array[0]["comment"] as? String, "Public files")
        XCTAssertEqual(array[1]["name"] as? String, "ipc$")
        XCTAssertNil(array[1]["type"])
        XCTAssertNil(array[1]["comment"])
    }

    func testSMBErrorExitCodeMapping() {
        XCTAssertEqual(SMBCLIExitCode.code(for: .logonFailure(status: 0, operation: "SESSION_SETUP")), 3)
        XCTAssertEqual(SMBCLIExitCode.code(for: .accessDenied(status: 0, operation: "CREATE")), 3)
        XCTAssertEqual(SMBCLIExitCode.code(for: .notFound(status: 0, operation: "CREATE")), 4)
        XCTAssertEqual(SMBCLIExitCode.code(for: .connectionLost(operation: "READ")), 5)
        XCTAssertEqual(SMBCLIExitCode.code(for: .transport("connection refused")), 5)
        XCTAssertEqual(SMBCLIExitCode.code(for: .networkNameDeleted(status: 0, operation: "TREE_CONNECT")), 5)
        XCTAssertEqual(SMBCLIExitCode.code(for: .unsupported(status: 0, operation: "NEGOTIATE")), 1)
        XCTAssertEqual(SMBCLIExitCode.code(for: .protocolError("bad packet")), 1)
    }

    private func jsonObject(_ data: Data) throws -> [String: Any] {
        try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
    }

    private func jsonArray(_ data: Data) throws -> [[String: Any]] {
        try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [[String: Any]])
    }
}
