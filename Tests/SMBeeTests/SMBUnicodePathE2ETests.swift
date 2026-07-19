import XCTest
@testable import SMBee

final class SMBUnicodePathE2ETests: XCTestCase {
    func testUnicodeComposedAndDecomposedPathRoundTripsOnSamba() async throws {
        let environment = ProcessInfo.processInfo.environment
        guard environment["SMBEE_E2E"] == "1" else {
            throw XCTSkip("Set SMBEE_E2E=1 to run Samba-backed E2E tests")
        }
        guard environment["SMBEE_E2E_PROFILE"] == "smb302-encrypted-required" else {
            throw XCTSkip("Runs on the primary authenticated Samba profile")
        }
        guard let port = UInt16(environment["SMBEE_E2E_PORT"] ?? "445") else {
            XCTFail("SMBEE_E2E_PORT must be a valid UInt16")
            return
        }

        let host = environment["SMBEE_E2E_HOST"] ?? "127.0.0.1"
        let share = environment["SMBEE_E2E_SHARE"] ?? "public"
        let credential = SMBCredential(
            username: environment["SMBEE_E2E_USERNAME"] ?? "smbee",
            password: environment["SMBEE_E2E_PASSWORD"] ?? "smbee"
        )
        let path = "smbee-unicode-e\u{301}-\(UUID().uuidString).txt"
        let payload = Array("unicode path\n".utf8)

        do {
            try await SMBee.upload(host: host, port: port, credential: credential, share: share, path: path, data: payload)
            let entries = try await SMBee.list(host: host, port: port, credential: credential, share: share)
            XCTAssertTrue(entries.contains { $0.name == path })
            let stat = try await SMBee.stat(host: host, port: port, credential: credential, share: share, path: path)
            XCTAssertEqual(stat.size, UInt64(payload.count))
            let received = try await SMBee.read(host: host, port: port, credential: credential, share: share, path: path)
            XCTAssertEqual(received, payload)
        } catch {
            try? await SMBee.delete(host: host, port: port, credential: credential, share: share, path: path)
            throw error
        }
        try await SMBee.delete(host: host, port: port, credential: credential, share: share, path: path)
    }
}
