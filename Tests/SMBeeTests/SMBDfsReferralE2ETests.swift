import XCTest
@testable import SMBee

final class SMBDfsReferralE2ETests: XCTestCase {
    func testDfsReferralDecodesSambaMsdfsLink() async throws {
        let environment = ProcessInfo.processInfo.environment
        guard environment["SMBEE_E2E"] == "1" else {
            throw XCTSkip("Set SMBEE_E2E=1 to run Samba-backed E2E tests")
        }
        guard environment["SMBEE_E2E_PROFILE"] == "msdfs" else {
            throw XCTSkip("Requires SMBEE_E2E_PROFILE=msdfs")
        }
        guard let port = UInt16(environment["SMBEE_E2E_PORT"] ?? "445") else {
            XCTFail("SMBEE_E2E_PORT must be a valid UInt16")
            return
        }

        let host = environment["SMBEE_E2E_HOST"] ?? "127.0.0.1"
        let credential = SMBCredential(
            username: environment["SMBEE_E2E_USERNAME"] ?? "smbee",
            password: environment["SMBEE_E2E_PASSWORD"] ?? "smbee"
        )
        let session = try await SMBee.connect(host: host, port: port, credential: credential, share: "public")
        defer { Task { await session.close() } }

        let result = try await session.dfsReferral(
            share: "dfsroot", path: "\\\\\(host)\\dfsroot\\public-link"
        )
        XCTAssertFalse(result.referrals.isEmpty)
        XCTAssertTrue(result.referrals.contains { referral in
            referral.networkAddress?.lowercased().contains("public") == true
        }, "unexpected DFS referrals: \(result.referrals.map { $0.networkAddress })")
        XCTAssertGreaterThan(result.pathConsumed, 0)
    }
}
