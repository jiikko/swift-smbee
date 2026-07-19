import XCTest
@testable import SMBee

final class SMBOperationalCoverageE2ETests: XCTestCase {
    func testStatReportsAllocationSizeOnRealServer() async throws {
        let details = try connectionDetails()
        let stat = try await SMBee.stat(
            host: details.host, port: details.port, credential: details.credential,
            share: details.share, path: "known.txt"
        )
        XCTAssertNotNil(stat.allocationSize)
        XCTAssertGreaterThanOrEqual(stat.allocationSize ?? 0, stat.size)
    }

    func testReadOperationTimeoutReturnsTimedOutOnRealServer() async throws {
        let details = try connectionDetails()
        do {
            _ = try await SMBee.read(
                host: details.host, port: details.port, credential: details.credential,
                share: details.share, path: "large-4gib-plus.bin",
                operationTimeout: .milliseconds(1)
            )
            XCTFail("read unexpectedly completed before the operation deadline")
        } catch SMBTransportError.timedOut {
            // Expected: the deadline covers connect, CREATE, QUERY_INFO, and READ.
        }
    }

    private struct ConnectionDetails {
        let host: String
        let port: UInt16
        let credential: SMBCredential
        let share: String
    }

    private func connectionDetails() throws -> ConnectionDetails {
        let environment = ProcessInfo.processInfo.environment
        guard environment["SMBEE_E2E"] == "1" else {
            throw XCTSkip("Set SMBEE_E2E=1 to run Samba-backed E2E tests")
        }
        guard let port = UInt16(environment["SMBEE_E2E_PORT"] ?? "445") else {
            XCTFail("SMBEE_E2E_PORT must be a valid UInt16")
            throw E2EConfigurationError.invalidPort
        }
        return ConnectionDetails(
            host: environment["SMBEE_E2E_HOST"] ?? "127.0.0.1",
            port: port,
            credential: SMBCredential(
                username: environment["SMBEE_E2E_USERNAME"] ?? "smbee",
                password: environment["SMBEE_E2E_PASSWORD"] ?? "smbee"
            ),
            share: environment["SMBEE_E2E_SHARE"] ?? "public"
        )
    }
}

private enum E2EConfigurationError: Error {
    case invalidPort
}
