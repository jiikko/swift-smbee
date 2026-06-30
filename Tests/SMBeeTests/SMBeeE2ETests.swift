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

    func testAuthenticatedWriteOperations() async throws {
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
        let credential = SMBCredential(username: username, password: password)
        let suffix = UUID().uuidString
        let directory = "smbee-e2e-\(suffix)"
        let original = "\(directory)\\upload.txt"
        let copied = "\(directory)\\copied.txt"
        let renamed = "\(directory)\\renamed.txt"
        let large = "\(directory)\\large.bin"
        let nested = "\(directory)\\nested"
        let nestedChild = "\(nested)\\child"
        let nestedFile = "\(nestedChild)\\delete-me.txt"
        let payload = Array("hello write path \(suffix)\n".utf8)

        try await SMBee.makeDirectory(host: host, port: port, credential: credential, share: share, path: directory)
        var entries = try await SMBee.list(host: host, port: port, credential: credential, share: share)
        XCTAssertTrue(entries.contains { $0.name == directory && $0.isDirectory })

        try await SMBee.upload(host: host, port: port, credential: credential, share: share, path: original, data: payload)
        let data = try await SMBee.read(host: host, port: port, credential: credential, share: share, path: original)
        XCTAssertEqual(data, payload)
        try await SMBee.copy(
            host: host,
            port: port,
            credential: credential,
            share: share,
            fromPath: original,
            toPath: copied
        )
        let copiedData = try await SMBee.read(host: host, port: port, credential: credential, share: share, path: copied)
        XCTAssertEqual(copiedData, payload)
        let localDownloadFile = FileManager.default.temporaryDirectory.appendingPathComponent("smbee-e2e-download-\(suffix).txt")
        defer { try? FileManager.default.removeItem(at: localDownloadFile) }
        try await SMBee.download(
            host: host,
            port: port,
            credential: credential,
            share: share,
            path: original,
            localFile: localDownloadFile
        )
        XCTAssertEqual(try Data(contentsOf: localDownloadFile), Data(payload))

        let largePayload = (0..<(1024 * 1024)).map { UInt8($0 & 0xff) }
        let localLargeFile = FileManager.default.temporaryDirectory.appendingPathComponent("smbee-e2e-\(suffix).bin")
        try Data(largePayload).write(to: localLargeFile)
        defer { try? FileManager.default.removeItem(at: localLargeFile) }
        try await SMBee.upload(
            host: host,
            port: port,
            credential: credential,
            share: share,
            path: large,
            localFile: localLargeFile
        )
        let largeData = try await SMBee.read(host: host, port: port, credential: credential, share: share, path: large)
        XCTAssertEqual(largeData, largePayload)

        try await SMBee.rename(
            host: host,
            port: port,
            credential: credential,
            share: share,
            fromPath: original,
            toPath: renamed
        )
        entries = try await SMBee.list(host: host, port: port, credential: credential, share: share, path: directory)
        XCTAssertFalse(entries.contains { $0.name == "upload.txt" })
        XCTAssertTrue(entries.contains { $0.name == "renamed.txt" })

        try await SMBee.delete(host: host, port: port, credential: credential, share: share, path: renamed)
        entries = try await SMBee.list(host: host, port: port, credential: credential, share: share, path: directory)
        XCTAssertFalse(entries.contains { $0.name == "renamed.txt" })
        try await SMBee.delete(host: host, port: port, credential: credential, share: share, path: copied)

        try await SMBee.makeDirectory(host: host, port: port, credential: credential, share: share, path: nested)
        try await SMBee.makeDirectory(host: host, port: port, credential: credential, share: share, path: nestedChild)
        try await SMBee.upload(host: host, port: port, credential: credential, share: share, path: nestedFile, data: payload)
        try await SMBee.delete(host: host, port: port, credential: credential, share: share, path: nested, directory: true, recursive: true)
        entries = try await SMBee.list(host: host, port: port, credential: credential, share: share, path: directory)
        XCTAssertFalse(entries.contains { $0.name == "nested" })

        try await SMBee.delete(host: host, port: port, credential: credential, share: share, path: large)
        try await SMBee.delete(host: host, port: port, credential: credential, share: share, path: directory, directory: true)
    }

    func testReadStreamCountsFileLargerThan4GiB() async throws {
        let environment = ProcessInfo.processInfo.environment
        guard environment["SMBEE_E2E"] == "1" else {
            throw XCTSkip("Set SMBEE_E2E=1 to run Samba-backed E2E tests")
        }
        guard environment["SMBEE_E2E_LARGE"] == "1" else {
            throw XCTSkip("Set SMBEE_E2E_LARGE=1 to run the >4GiB read-stream E2E test")
        }

        let host = environment["SMBEE_E2E_HOST"] ?? "127.0.0.1"
        let portString = environment["SMBEE_E2E_PORT"] ?? "445"
        guard let port = UInt16(portString) else {
            XCTFail("SMBEE_E2E_PORT must be a valid UInt16, got \(portString)")
            return
        }
        let username = environment["SMBEE_E2E_USERNAME"] ?? "smbee"
        let password = environment["SMBEE_E2E_PASSWORD"] ?? "smbee"
        let share = environment["SMBEE_E2E_SHARE"] ?? "public"
        let path = environment["SMBEE_E2E_LARGE_PATH"] ?? "large-4gib-plus.bin"
        let credential = SMBCredential(username: username, password: password)

        // Prepare this file manually; do not store it in git or require it in CI.
        // With test/e2e/start-local-samba.sh:
        //   docker exec smbee-samba-local truncate -s 4294967297 /srv/smbee/public/large-4gib-plus.bin
        //
        // This test validates that the streaming read path keeps offsets and
        // lengths on the UInt64 route while crossing the 4GiB boundary. It only
        // keeps a running byte count, never the full file contents in memory.
        let stat = try await SMBee.stat(host: host, port: port, credential: credential, share: share, path: path)
        XCTAssertFalse(stat.isDirectory)
        XCTAssertGreaterThan(stat.size, UInt64(UInt32.max))

        let accumulator = LargeReadAccumulator()
        try await SMBee.withReadStream(
            host: host,
            port: port,
            credential: credential,
            share: share,
            path: path
        ) { chunk in
            XCTAssertFalse(chunk.isEmpty)
            await accumulator.record(byteCount: chunk.count)
        }

        let total = await accumulator.total
        XCTAssertEqual(total, stat.size)
    }
}

private actor LargeReadAccumulator {
    private var byteCount: UInt64 = 0

    var total: UInt64 {
        byteCount
    }

    func record(byteCount: Int) {
        self.byteCount += UInt64(byteCount)
    }
}
