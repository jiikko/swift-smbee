import XCTest
@testable import SMBee

final class SMBeeE2ETests: XCTestCase {
    func testProbeNegotiatesSMB311GMACAndGCM() async throws {
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
        XCTAssertEqual(result.dialect, SMBNegotiateConstants.dialect311)
        XCTAssertEqual(result.signingAlgorithm, SMBNegotiateConstants.aesGMAC)
        XCTAssertEqual(result.cipher, SMBNegotiateConstants.aes128GCM)
    }
}
