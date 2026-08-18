import XCTest
@testable import SMBee

final class SMBOperationalCoverageE2ETests: XCTestCase {
    func testStatReportsAllocationSizeOnRealServer() async throws {
        let details = try connectionDetails()
        if ProcessInfo.processInfo.environment["SMBEE_E2E_PROFILE"] == "guest" {
            throw XCTSkip("allocation-size stat coverage requires an authenticated Samba profile")
        }
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

    /// issue 505 (obaket): case-insensitive (case-preserving) share で、要求 leaf の
    /// case が実体と違っても server 側の canonical name を回収できることを実サーバで
    /// 実証する。in-memory transport の wire テストは「自分が組んだ応答」しか見ないので、
    /// server が本当に pattern を case-insensitive にマッチさせるかはここでしか分からない。
    func testDirectoryEntryMatchingRecoversCanonicalCaseOnRealServer() async throws {
        let details = try connectionDetails()
        if ProcessInfo.processInfo.environment["SMBEE_E2E_PROFILE"] == "guest" {
            throw XCTSkip("canonical-name coverage requires a writable authenticated Samba profile")
        }
        let canonicalName = "Report-\(UUID().uuidString).TXT"
        let payload = Array("canonical".utf8)

        try await SMBee.upload(
            host: details.host, port: details.port, credential: details.credential,
            share: details.share, path: canonicalName, data: payload
        )

        func removeFixture() async throws {
            try await SMBee.delete(
                host: details.host, port: details.port, credential: details.credential,
                share: details.share, path: canonicalName
            )
        }

        // connect 前に失敗したら fixture だけ片付けて抜ける (session はまだ無い)
        let session: SMBClientSession
        do {
            session = try await SMBee.connect(
                host: details.host, port: details.port, credential: details.credential, share: details.share
            )
        } catch {
            try? await removeFixture()
            throw error
        }

        // 検証中に throw しても session.close / fixture 削除を必ず 1 回ずつ通す
        // (defer + Task の fire-and-forget は close の完了を保証できないため使わない)
        var thrown: Error?
        var entry: SMBDirectoryEntry?
        var missing: SMBDirectoryEntry?
        do {
            // 実体と違う case で引いても canonical (case-preserved) name が返る
            entry = try await session.directoryEntry(matching: canonicalName.lowercased())
            // 存在しない leaf は throw ではなく nil (pattern 無マッチ = 空の列挙)
            missing = try await session.directoryEntry(matching: "missing-\(UUID().uuidString).txt")
        } catch {
            thrown = error
        }
        await session.close()

        if let thrown {
            try? await removeFixture()
            throw thrown
        }

        XCTAssertEqual(entry?.name, canonicalName)
        XCTAssertEqual(entry?.fileSize, UInt64(payload.count))
        XCTAssertFalse(entry?.isDirectory ?? true)
        XCTAssertNil(missing)

        // listing の表記と一致する (= write/stat 経路が listing と同じ identity を返せる)
        let entries = try await SMBee.list(
            host: details.host, port: details.port, credential: details.credential, share: details.share
        )
        XCTAssertTrue(
            entries.contains { $0.name == canonicalName },
            "listing should expose the canonical name that directoryEntry(matching:) returned"
        )

        try await removeFixture()
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
