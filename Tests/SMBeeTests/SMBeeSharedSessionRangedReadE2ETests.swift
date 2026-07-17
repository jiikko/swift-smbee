import XCTest
@testable import SMBee

/// obaket の SMB 動画プレビュー相当の使い方 (保持した session インスタンス +
/// range 付き streaming read + スキップ相当の cancel→継続) を container Samba に
/// 対して回す E2E 回帰テスト。frame-safe cancellation を再実装するときの緑ガード。
///
/// 既存 E2E smoke は `SMBee.withReadStream` 等の **static = 使い捨てセッション** しか
/// 叩かず、obaket が使う「保持した session instance + background receiveLoop + 並行
/// read」経路を踏まないため、frame-safe cancellation の退行 (通常 range read が
/// connection-lost) を見逃した。本ファイルはその経路を専用に再現する。
///
/// `SMBEE_E2E=1` でない環境では skip。
final class SMBeeSharedSessionRangedReadE2ETests: XCTestCase {

    /// 通常再生の最小再現 (cancel なし): 保持した 1 session で異なる offset の
    /// range streaming read を逐次 10 回行い、全部が期待バイトを受信し
    /// connection-lost しないことを確認する。
    func testSharedSessionRepeatedRangedStreamingRead() async throws {
        let details = try sharedSessionConnectionDetails()
        let session = try await SMBee.connect(
            host: details.host, port: details.port,
            credential: details.credential, share: details.share
        )
        let suffix = UUID().uuidString
        let path = "smbee-shared-ranged-read-\(suffix).bin"
        let payload = Self.rangedReadPayload(byteCount: 4 * 1024 * 1024)
        let rangeLength: UInt64 = 256 * 1024

        do {
            try await session.upload(path: path, data: payload)
            for index in 0..<10 {
                let offset = UInt64(index) * rangeLength
                let received = SharedSessionByteAccumulator()
                try await session.withReadStream(
                    path: path,
                    range: SMBReadRange(offset: offset, length: rangeLength)
                ) { chunk in
                    await received.append(chunk)
                }
                let receivedBytes = await received.bytes
                XCTAssertEqual(
                    receivedBytes,
                    Array(payload[Int(offset)..<Int(offset + rangeLength)]),
                    "ranged read \(index) returned unexpected bytes"
                )
            }
            try await session.delete(path: path)
            await session.close()
        } catch {
            try? await session.delete(path: path)
            await session.close()
            throw error
        }
    }

    /// スキップ連打の再現: 同じ保持 session で range read の Task を最初の chunk 受信
    /// 直後に cancel → 即座に別 offset の read を開始、を 10 回連打し、最後に
    /// cancel なしの read が成功する (= session が desync せず生きている) ことを確認。
    func testSharedSessionRangedReadCancelStorm() async throws {
        // 既知バグ (issue 062): 保持 session 上の range read を cancel すると session が
        // connection-lost で壊れる。修正 (設計見直し) が入るまで skip。skip を外して
        // 緑になったら修正完了。root cause / 失敗した 2 アプローチは issue 062 参照。
        throw XCTSkip("known bug: cancelling a ranged read tears down a shared session (issue 062)")
        // swiftlint:disable:next unreachable_code
        let details = try sharedSessionConnectionDetails()
        let session = try await SMBee.connect(
            host: details.host, port: details.port,
            credential: details.credential, share: details.share
        )
        let suffix = UUID().uuidString
        let path = "smbee-shared-ranged-cancel-\(suffix).bin"
        let payload = Self.rangedReadPayload(byteCount: 4 * 1024 * 1024)
        let rangeLength: UInt64 = 512 * 1024

        do {
            try await session.upload(path: path, data: payload)
            for index in 0..<10 {
                let offset = UInt64(index) * rangeLength
                let firstChunk = SharedSessionFirstChunkArrival()
                let received = SharedSessionByteAccumulator()
                let readTask = Task {
                    try await session.withReadStream(
                        path: path,
                        range: SMBReadRange(offset: offset, length: rangeLength)
                    ) { chunk in
                        await received.append(chunk)
                        await firstChunk.record()
                    }
                }

                try await sharedSessionAwaitWithTimeout {
                    while !(await firstChunk.hasArrived) {
                        try await Task.sleep(for: .milliseconds(1))
                    }
                }
                readTask.cancel()

                let nextOffset = UInt64((index + 1) % 10) * rangeLength
                let nextRead = SharedSessionByteAccumulator()
                try await session.withReadStream(
                    path: path,
                    range: SMBReadRange(offset: nextOffset, length: rangeLength)
                ) { chunk in
                    await nextRead.append(chunk)
                }
                let nextByteCount = await nextRead.byteCount
                XCTAssertEqual(
                    nextByteCount,
                    Int(rangeLength),
                    "follow-up ranged read \(index) did not complete on the shared session"
                )

                do {
                    _ = try await sharedSessionAwaitWithTimeout { try await readTask.value }
                } catch is SharedSessionE2ETimeout {
                    XCTFail("cancelled ranged read \(index) did not finish before the deadline")
                } catch {
                    // キャンセル (または中断された read) は想定内。生きているかの assert は
                    // 直後の follow-up read が担う。
                }
            }

            let finalRead = SharedSessionByteAccumulator()
            try await session.withReadStream(
                path: path,
                range: SMBReadRange(offset: 0, length: rangeLength)
            ) { chunk in
                await finalRead.append(chunk)
            }
            let finalBytes = await finalRead.bytes
            XCTAssertEqual(finalBytes, Array(payload[0..<Int(rangeLength)]))
            try await session.delete(path: path)
            await session.close()
        } catch {
            try? await session.delete(path: path)
            await session.close()
            throw error
        }
    }

    private static func rangedReadPayload(byteCount: Int) -> [UInt8] {
        (0..<byteCount).map { UInt8($0 % 251) }
    }
}

private actor SharedSessionByteAccumulator {
    private var storage: [UInt8] = []
    var bytes: [UInt8] { storage }
    var byteCount: Int { storage.count }
    func append(_ chunk: [UInt8]) { storage.append(contentsOf: chunk) }
}

private actor SharedSessionFirstChunkArrival {
    private var arrived = false
    var hasArrived: Bool { arrived }
    func record() { arrived = true }
}

private struct SharedSessionE2ETimeout: Error {}

private func sharedSessionAwaitWithTimeout<T: Sendable>(
    seconds: Double = 30,
    _ body: @escaping @Sendable () async throws -> T
) async throws -> T {
    try await withThrowingTaskGroup(of: T.self) { group in
        group.addTask { try await body() }
        group.addTask {
            try await Task.sleep(for: .seconds(seconds))
            throw SharedSessionE2ETimeout()
        }
        let result = try await group.next()!
        group.cancelAll()
        return result
    }
}

private struct SharedSessionConnectionDetails {
    let host: String
    let port: UInt16
    let credential: SMBCredential
    let share: String
}

private func sharedSessionConnectionDetails() throws -> SharedSessionConnectionDetails {
    guard ProcessInfo.processInfo.environment["SMBEE_E2E"] == "1" else {
        throw XCTSkip("Set SMBEE_E2E=1 to run Samba-backed E2E tests")
    }
    let env = ProcessInfo.processInfo.environment
    let host = env["SMBEE_E2E_HOST"] ?? "127.0.0.1"
    guard let port = UInt16(env["SMBEE_E2E_PORT"] ?? "445") else {
        throw SharedSessionE2ETimeout()
    }
    let username = env["SMBEE_E2E_USERNAME"] ?? "smbee"
    let password = env["SMBEE_E2E_PASSWORD"] ?? "smbee"
    let share = env["SMBEE_E2E_SHARE"] ?? "public"
    return SharedSessionConnectionDetails(
        host: host, port: port,
        credential: SMBCredential(username: username, password: password),
        share: share
    )
}
