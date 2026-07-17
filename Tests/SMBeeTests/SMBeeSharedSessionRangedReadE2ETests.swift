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

    /// スキップ連打の再現: 同じ保持 session で「offset から末尾まで」の大 range read を
    /// 始めて最初の chunk 直後に cancel、を offset を進めながら 10 回連打し、最後に
    /// cancel なしの read が成功する (= session が生きている) ことを確認。
    ///
    /// ⚠️ 注意 (issue 062): **container Samba (localhost) ではこのテストは PASS する**。
    /// localhost は READ 応答が速く、cancel 時点で応答がほぼ届いており receiveLoop が
    /// クリーンにドレインするため socket が壊れない。obaket が実 NAS で踏む
    /// `connection-lost` (latency 依存) は本テストでは再現できていない。本テストは
    /// 「container 上で cancel 経路が socket を壊さないこと」の guard として active に保つ
    /// (Task.detached 系の退行も捕まえる)。実 NAS のバグ再現/修正は issue 062 で継続。
    func testSharedSessionRangedReadCancelStorm() async throws {
        let details = try sharedSessionConnectionDetails()
        let session = try await SMBee.connect(
            host: details.host, port: details.port,
            credential: details.credential, share: details.share
        )
        let suffix = UUID().uuidString
        let path = "smbee-shared-ranged-cancel-\(suffix).bin"
        // 大きめのファイル + 「offset から末尾まで」の巨大 range を read することで、
        // obaket の動画スキップ (残り全部を streaming read → スキップで即 cancel) を
        // 忠実に再現する。cancel が単一 chunk 内の wire read が in-flight のうちに当たる。
        let fileSize = 64 * 1024 * 1024
        let payload = Self.rangedReadPayload(byteCount: fileSize)
        let probeLength: UInt64 = 256 * 1024

        do {
            try await session.upload(path: path, data: payload)
            // スキップ連打相当: 「offset から末尾まで」の read を始めて最初の chunk 到着
            // 直後に cancel、を offset を進めながら 10 回。obaket と同じく follow-up read
            // ではなく次の read 自体が次のスキップに相当する。
            for index in 0..<10 {
                let offset = UInt64(index) * UInt64(4 * 1024 * 1024) // 0, 4, 8, ... MiB (< fileSize)
                let firstChunk = SharedSessionFirstChunkArrival()
                let readTask = Task {
                    try await session.withReadStream(
                        path: path,
                        range: SMBReadRange(offset: offset, length: UInt64(fileSize) - offset)
                    ) { chunk in
                        await firstChunk.record()
                        _ = chunk
                    }
                }
                try await sharedSessionAwaitWithTimeout {
                    while !(await firstChunk.hasArrived) {
                        try await Task.sleep(for: .milliseconds(1))
                    }
                }
                readTask.cancel()
                // cancel した read の後始末を待つ (session を再利用する前に)。
                _ = try? await sharedSessionAwaitWithTimeout { try await readTask.value }
            }

            // スキップ連打の後、cancel なしの通常 range read が成功する
            // (= session が connection-lost で壊れていない) ことを確認する。
            let finalRead = SharedSessionByteAccumulator()
            try await session.withReadStream(
                path: path,
                range: SMBReadRange(offset: 0, length: probeLength)
            ) { chunk in
                await finalRead.append(chunk)
            }
            let finalBytes = await finalRead.bytes
            XCTAssertEqual(
                finalBytes,
                Array(payload[0..<Int(probeLength)]),
                "follow-up read after cancel-storm failed — shared session was torn down"
            )
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
