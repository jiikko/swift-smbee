import XCTest
@testable import SMBee

final class SMBeeE2ETests: XCTestCase {
    func testProbeNegotiatesMacOSMirrorSMB302WithSigningRequired() async throws {
        guard ProcessInfo.processInfo.environment["SMBEE_E2E"] == "1" else {
            throw XCTSkip("Set SMBEE_E2E=1 to run Samba-backed E2E tests")
        }

        let environment = ProcessInfo.processInfo.environment
        let host = environment["SMBEE_E2E_HOST"] ?? "127.0.0.1"
        let portString = environment["SMBEE_E2E_PORT"] ?? "445"
        guard let port = UInt16(portString) else {
            XCTFail("SMBEE_E2E_PORT must be a valid UInt16, got \(portString)")
            return
        }

        let result = try await SMBProbe.probe(host: host, port: port)
        XCTAssertEqual(result.dialect, SMBNegotiateConstants.dialect302)
        XCTAssertTrue(result.signingRequired)
        XCTAssertNil(result.signingAlgorithm)
        XCTAssertNil(result.cipher)
        XCTAssertNil(result.preauthHashAlgorithm)
    }

    func testAuthenticatedTreeConnectAndListShowsKnownFile() async throws {
        guard ProcessInfo.processInfo.environment["SMBEE_E2E"] == "1" else {
            throw XCTSkip("Set SMBEE_E2E=1 to run Samba-backed E2E tests")
        }

        let environment = ProcessInfo.processInfo.environment
        let host = environment["SMBEE_E2E_HOST"] ?? "127.0.0.1"
        let portString = environment["SMBEE_E2E_PORT"] ?? "445"
        guard let port = UInt16(portString) else {
            XCTFail("SMBEE_E2E_PORT must be a valid UInt16, got \(portString)")
            return
        }
        let username = environment["SMBEE_E2E_USERNAME"] ?? "smbee"
        let password = environment["SMBEE_E2E_PASSWORD"] ?? "smbee"
        let share = environment["SMBEE_E2E_SHARE"] ?? "public"

        let entries = try await SMBee.list(
            host: host,
            port: port,
            credential: SMBCredential(username: username, password: password),
            share: share
        )
        XCTAssertTrue(entries.contains { $0.name == "known.txt" && !$0.isDirectory })

        let credential = SMBCredential(username: username, password: password)
        let stat = try await SMBee.stat(
            host: host,
            port: port,
            credential: credential,
            share: share,
            path: "known.txt"
        )
        XCTAssertEqual(stat.size, 21)
        XCTAssertFalse(stat.isDirectory)

        let data = try await SMBee.read(
            host: host,
            port: port,
            credential: credential,
            share: share,
            path: "known.txt"
        )
        XCTAssertEqual(String(decoding: data, as: UTF8.self), "hello from SMBee E2E\n")
    }
}
