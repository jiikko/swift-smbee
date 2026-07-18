import XCTest
@testable import SMBee

final class SMB311EncryptedLargeIOE2ETests: XCTestCase {
    func testSMB311EncryptedLargeReadWrite() async throws {
        let environment = ProcessInfo.processInfo.environment
        guard environment["SMBEE_E2E"] == "1" else {
            throw XCTSkip("Set SMBEE_E2E=1 to run Samba-backed E2E tests")
        }
        guard environment["SMBEE_E2E_PROFILE"] == "smb311-encrypted-required" else {
            throw XCTSkip("Requires SMBEE_E2E_PROFILE=smb311-encrypted-required")
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
        let path = "smbee-e2e-smb311-large-\(UUID().uuidString).bin"
        // Exceeds the 1 MiB local transfer limit, forcing multiple encrypted
        // credit-charged WRITE requests and streaming READ requests.
        let payload = (0..<(2 * 1024 * 1024 + 123)).map { UInt8($0 & 0xff) }
        let accumulator = SMB311LargeReadAccumulator()

        do {
            try await SMBee.upload(host: host, port: port, credential: credential, share: share, path: path, data: payload)
            let stat = try await SMBee.stat(host: host, port: port, credential: credential, share: share, path: path)
            XCTAssertEqual(stat.size, UInt64(payload.count))
            try await SMBee.withReadStream(host: host, port: port, credential: credential, share: share, path: path) {
                accumulator.append($0)
            }
            let received = accumulator.bytes
            XCTAssertEqual(received, payload)
            try await SMBee.delete(host: host, port: port, credential: credential, share: share, path: path)
        } catch {
            try? await SMBee.delete(host: host, port: port, credential: credential, share: share, path: path)
            throw error
        }
    }
}

private final class SMB311LargeReadAccumulator: @unchecked Sendable {
    private let lock = NSLock()
    private var storage: [UInt8] = []

    var bytes: [UInt8] {
        lock.lock()
        defer { lock.unlock() }
        return storage
    }

    func append(_ chunk: [UInt8]) {
        lock.lock()
        storage += chunk
        lock.unlock()
    }
}
