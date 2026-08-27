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

    /// Consumer callback を止めずに 1 MiB の重なり range 3 本を同じ session / file 上で走らせ、
    /// 全 read の実行期間をサンプリングして、wire session に送信済み response 待ちが同時に
    /// 2 本以上存在したことを確認する。サンプリングなので短い重複を見逃す可能性はあるが、
    /// その場合は false negative としてテストを失敗させ、wire 上の並行性という主張は弱めない。
    /// 1 MiB は SMBee の最大 READ chunk なので、各 range は credit charge 16 の multi-credit
    /// READ になる。4 MiB window × 3 本の並行はローカル container では完走を確認済み
    /// (2026-08-12)。range を重ねて upload は 1 MiB + 128 KiB に抑えつつ、全 read を完走させ、
    /// 全 byte と長さが期待 range と一致することも確認する。
    ///
    /// issue 080 の調査が終わるまで local 専用。local では green (0.23s) だが、CI では
    /// タイミング依存で接続断する (詳細は issue 080)。既存の `SMBEE_E2E=1` に加えて
    /// `SMBEE_E2E_WIRE_MULTIFLIGHT=1` で有効化する。Apple container でこの 1 本だけ走らせる例:
    /// ```sh
    /// SMBEE_E2E_WIRE_MULTIFLIGHT=1 \
    /// SMBEE_E2E_TEST_FILTER=SMBeeSharedSessionRangedReadE2ETests.testSharedSessionRangedReadsHaveMultipleWireResponsesInFlight \
    /// SMBEE_E2E_SKIP_EXTRA_API_TESTS=1 SMBEE_E2E_SKIP_CLI_SMOKE=1 \
    /// bin/e2e/container-samba.sh
    /// ```
    func testSharedSessionRangedReadsHaveMultipleWireResponsesInFlight() async throws {
        let details = try sharedSessionConnectionDetails()
        guard ProcessInfo.processInfo.environment["SMBEE_E2E_WIRE_MULTIFLIGHT"] == "1" else {
            throw XCTSkip(
                "Set SMBEE_E2E_WIRE_MULTIFLIGHT=1 to run this local-only test; " +
                    "local is green (0.23s), but CI has timing-dependent connection closures (issue 080)"
            )
        }
        let rangeLength: UInt64 = 1 * 1024 * 1024
        let rangeStride: UInt64 = 64 * 1024
        let payload = Self.rangedReadPayload(
            byteCount: Int(rangeLength + 2 * rangeStride)
        )
        let ranges = (0..<3).map {
            SMBReadRange(offset: UInt64($0) * rangeStride, length: rangeLength)
        }

        let session = try await SMBee.connect(
            host: details.host, port: details.port,
            credential: details.credential, share: details.share
        )
        let path = "smbee-shared-wire-multiflight-ranged-\(UUID().uuidString).bin"

        do {
            try await session.upload(path: path, data: payload)
            try await sharedSessionAwaitWithTimeout {
                let wireSession = await session.wireSessionForTesting()
                let accumulators = ranges.map { _ in SharedSessionByteAccumulator() }
                let initialPendingCount = await wireSession.pendingCountForTesting()
                let initialSentPendingCount = await wireSession.sentPendingResponseCountForTesting()
                let pendingObservation = Task {
                    var maximumPendingCount = initialPendingCount
                    var maximumSentPendingCount = initialSentPendingCount
                    while !Task.isCancelled {
                        maximumPendingCount = max(
                            maximumPendingCount,
                            await wireSession.pendingCountForTesting()
                        )
                        maximumSentPendingCount = max(
                            maximumSentPendingCount,
                            await wireSession.sentPendingResponseCountForTesting()
                        )
                        do {
                            try await Task.sleep(for: .milliseconds(5))
                        } catch {
                            break
                        }
                    }
                    return (maximumPendingCount, maximumSentPendingCount)
                }
                let readTasks = ranges.indices.map { index in
                    Task {
                        try await session.withReadStream(
                            path: path,
                            range: ranges[index],
                            knownSize: UInt64(payload.count)
                        ) { chunk in
                            await accumulators[index].append(chunk)
                        }
                    }
                }

                do {
                    try await withTaskCancellationHandler {
                        for readTask in readTasks {
                            try await readTask.value
                        }
                        try Task.checkCancellation()
                    } onCancel: {
                        pendingObservation.cancel()
                        readTasks.forEach { $0.cancel() }
                    }
                    pendingObservation.cancel()
                    let observation = await pendingObservation.value
                    XCTAssertGreaterThanOrEqual(
                        observation.1,
                        2,
                        "ranged READs never had two sent wire responses pending concurrently " +
                            "(maximum pending: \(observation.0), maximum sent pending: \(observation.1))"
                    )
                } catch {
                    pendingObservation.cancel()
                    readTasks.forEach { $0.cancel() }
                    for readTask in readTasks {
                        _ = try? await readTask.value
                    }
                    _ = await pendingObservation.value
                    throw error
                }

                for index in ranges.indices {
                    let range = ranges[index]
                    let bytes = await accumulators[index].bytes
                    let expected = Array(payload[Int(range.offset)..<Int(range.offset + range.length)])
                    XCTAssertEqual(
                        bytes.count,
                        Int(range.length),
                        "multi-flight ranged read \(index) returned the wrong length"
                    )
                    XCTAssertEqual(
                        bytes,
                        expected,
                        "multi-flight ranged read \(index) returned unexpected bytes"
                    )
                }
            }
            try await session.delete(path: path)
            await session.close()
        } catch {
            try? await session.delete(path: path)
            await session.close()
            throw error
        }
    }

    /// multi-credit になる 512 KiB window 3 本を同じ session / file 上で同時に開始する。
    /// 各 stream は first chunk を受け取った位置で gate に留まるため、全 range が開始済みに
    /// なるまでどの range も完了できない。これは wire 上の multi-flight の証明ではなく、
    /// 3 本が同じ session で進行できることと、gate 解放後の byte correctness を確認する回帰テスト。
    func testSharedSessionConcurrentRangedReadsReturnExactBytes() async throws {
        let details = try sharedSessionConnectionDetails()
        let rangeLength: UInt64 = 512 * 1024
        let payload = Self.rangedReadPayload(byteCount: 3 * Int(rangeLength))
        let ranges = (0..<3).map {
            SMBReadRange(offset: UInt64($0) * rangeLength, length: rangeLength)
        }

        let session = try await SMBee.connect(
            host: details.host, port: details.port,
            credential: details.credential, share: details.share
        )
        let path = "smbee-shared-concurrent-ranged-\(UUID().uuidString).bin"

        do {
            try await session.upload(path: path, data: payload)
            try await sharedSessionAwaitWithTimeout {
                let result = try await Self.runConcurrentRangedReads(
                    session: session,
                    path: path,
                    fileSize: UInt64(payload.count),
                    ranges: ranges
                )

                XCTAssertFalse(result.cancelledReadObserved)
                for index in ranges.indices {
                    let range = ranges[index]
                    let expected = Array(payload[Int(range.offset)..<Int(range.offset + range.length)])
                    XCTAssertEqual(
                        result.bytes[index].count,
                        Int(range.length),
                        "concurrent ranged read \(index) returned the wrong length"
                    )
                    XCTAssertEqual(
                        result.bytes[index],
                        expected,
                        "concurrent ranged read \(index) returned unexpected bytes"
                    )
                }
            }
            try await session.delete(path: path)
            await session.close()
        } catch {
            try? await session.delete(path: path)
            await session.close()
            throw error
        }
    }

    /// 1 MiB の local READ chunk 上限より長い、重なり window 3 本が同じ session で進行し、
    /// すべてが first chunk を受信した時点で中央の read だけを cancel する
    /// (wire 上の multi-flight を証明するテストではない)。
    /// cancel 対象の `withReadStream` が CLOSE を含む後始末を終えるまで await し、
    /// 残り 2 本の完走と、同じ session 上の follow-up read の成功を確認する。
    func testSharedSessionConcurrentRangedReadsSurviveOneCancellation() async throws {
        let details = try sharedSessionConnectionDetails()
        let rangeLength: UInt64 = 1152 * 1024
        let rangeStride: UInt64 = 64 * 1024
        let payload = Self.rangedReadPayload(
            byteCount: Int(rangeLength + 2 * rangeStride)
        )
        let ranges = (0..<3).map {
            SMBReadRange(offset: UInt64($0) * rangeStride, length: rangeLength)
        }
        let cancelledIndex = 1

        let session = try await SMBee.connect(
            host: details.host, port: details.port,
            credential: details.credential, share: details.share
        )
        let path = "smbee-shared-concurrent-cancel-\(UUID().uuidString).bin"

        do {
            try await session.upload(path: path, data: payload)
            try await sharedSessionAwaitWithTimeout {
                let result = try await Self.runConcurrentRangedReads(
                    session: session,
                    path: path,
                    fileSize: UInt64(payload.count),
                    ranges: ranges,
                    cancelling: cancelledIndex
                )

                XCTAssertTrue(result.cancelledReadObserved)
                XCTAssertGreaterThan(result.bytes[cancelledIndex].count, 0)
                XCTAssertLessThan(
                    result.bytes[cancelledIndex].count,
                    Int(ranges[cancelledIndex].length),
                    "cancelled ranged read unexpectedly completed before cancellation"
                )
                for index in ranges.indices where index != cancelledIndex {
                    let range = ranges[index]
                    let expected = Array(payload[Int(range.offset)..<Int(range.offset + range.length)])
                    XCTAssertEqual(result.bytes[index].count, Int(range.length))
                    XCTAssertEqual(
                        result.bytes[index],
                        expected,
                        "surviving ranged read \(index) was damaged by another read's cancellation"
                    )
                }

                let followUpRange = SMBReadRange(offset: rangeLength / 2, length: 256 * 1024)
                let followUp = SharedSessionByteAccumulator()
                try await session.withReadStream(
                    path: path,
                    range: followUpRange,
                    knownSize: UInt64(payload.count)
                ) { chunk in
                    await followUp.append(chunk)
                }
                let followUpBytes = await followUp.bytes
                XCTAssertEqual(followUpBytes.count, Int(followUpRange.length))
                XCTAssertEqual(
                    followUpBytes,
                    Array(payload[Int(followUpRange.offset)..<Int(followUpRange.offset + followUpRange.length)]),
                    "follow-up read failed after concurrent cancellation cleanup"
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

    /// success-only と one-cancel の 3-way gate read を同じ session で 2 round 反復する。
    /// wire 上の multi-flight ではなく、同じ session での進行と cancel の隔離を反復検証する。
    /// 各 round の byte correctness に加え、最後の probe が成功することで pending
    /// response / credit / remote handle が反復によって枯渇していないことを確認する。
    func testSharedSessionConcurrentRangedReadsRemainReusableAfterRepetition() async throws {
        let details = try sharedSessionConnectionDetails()
        let rangeLength: UInt64 = 1152 * 1024
        let rangeStride: UInt64 = 64 * 1024
        let payload = Self.rangedReadPayload(
            byteCount: Int(rangeLength + 2 * rangeStride)
        )
        let ranges = (0..<3).map {
            SMBReadRange(offset: UInt64($0) * rangeStride, length: rangeLength)
        }

        let session = try await SMBee.connect(
            host: details.host, port: details.port,
            credential: details.credential, share: details.share
        )
        let path = "smbee-shared-concurrent-repeat-\(UUID().uuidString).bin"

        do {
            try await session.upload(path: path, data: payload)
            try await sharedSessionAwaitWithTimeout {
                for round in 0..<2 {
                    let cancelledIndex = round.isMultiple(of: 2) ? nil : round % ranges.count
                    let result = try await Self.runConcurrentRangedReads(
                        session: session,
                        path: path,
                        fileSize: UInt64(payload.count),
                        ranges: ranges,
                        cancelling: cancelledIndex
                    )

                    XCTAssertEqual(
                        result.cancelledReadObserved,
                        cancelledIndex != nil,
                        "round \(round) did not take the expected cancellation path"
                    )
                    for index in ranges.indices {
                        let range = ranges[index]
                        if index == cancelledIndex {
                            XCTAssertGreaterThan(result.bytes[index].count, 0)
                            XCTAssertLessThan(result.bytes[index].count, Int(range.length))
                        } else {
                            XCTAssertEqual(result.bytes[index].count, Int(range.length))
                            XCTAssertEqual(
                                result.bytes[index],
                                Array(payload[Int(range.offset)..<Int(range.offset + range.length)]),
                                "round \(round), ranged read \(index) returned unexpected bytes"
                            )
                        }
                    }
                }

                let finalRange = SMBReadRange(offset: 2 * rangeStride, length: 256 * 1024)
                let finalRead = SharedSessionByteAccumulator()
                try await session.withReadStream(
                    path: path,
                    range: finalRange,
                    knownSize: UInt64(payload.count)
                ) { chunk in
                    await finalRead.append(chunk)
                }
                let finalBytes = await finalRead.bytes
                XCTAssertEqual(finalBytes.count, Int(finalRange.length))
                XCTAssertEqual(
                    finalBytes,
                    Array(payload[Int(finalRange.offset)..<Int(finalRange.offset + finalRange.length)]),
                    "follow-up read failed after repeated concurrent ranged reads"
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
                let firstChunk = SharedSessionFirstChunkGate(expectedCount: 1)
                let readTask = Task {
                    try await session.withReadStream(
                        path: path,
                        range: SMBReadRange(offset: offset, length: UInt64(fileSize) - offset)
                    ) { chunk in
                        await firstChunk.arriveAndWaitForRelease()
                        _ = chunk
                    }
                }
                try await sharedSessionAwaitWithTimeout { await firstChunk.waitUntilAllArrived() }
                readTask.cancel()
                await firstChunk.releaseAll()
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

    /// Starts every public `withReadStream` before releasing any first chunk. Explicit
    /// task handles are used so exactly one read can be cancelled while its siblings stay live.
    private static func runConcurrentRangedReads(
        session: SMBClientSession,
        path: String,
        fileSize: UInt64,
        ranges: [SMBReadRange],
        cancelling cancelledIndex: Int? = nil
    ) async throws -> (bytes: [[UInt8]], cancelledReadObserved: Bool) {
        precondition(!ranges.isEmpty)
        if let cancelledIndex {
            precondition(ranges.indices.contains(cancelledIndex))
        }

        let gate = SharedSessionFirstChunkGate(expectedCount: ranges.count)
        let accumulators = ranges.map { _ in SharedSessionByteAccumulator() }
        let readTasks = ranges.indices.map { index in
            Task {
                do {
                    try await session.withReadStream(
                        path: path,
                        range: ranges[index],
                        knownSize: fileSize
                    ) { chunk in
                        if await accumulators[index].append(chunk) {
                            await gate.arriveAndWaitForRelease()
                        }
                    }
                } catch {
                    await gate.abort()
                    throw error
                }
            }
        }

        var cancelledReadObserved = false
        try await withTaskCancellationHandler {
            do {
                await gate.waitUntilAllArrived()
                try Task.checkCancellation()
                if let cancelledIndex {
                    readTasks[cancelledIndex].cancel()
                }
                await gate.releaseAll()

                for index in readTasks.indices {
                    do {
                        try await readTasks[index].value
                    } catch is CancellationError {
                        guard index == cancelledIndex else { throw CancellationError() }
                        cancelledReadObserved = true
                    }
                }
                try Task.checkCancellation()
            } catch {
                readTasks.forEach { $0.cancel() }
                await gate.abort()
                for readTask in readTasks {
                    _ = try? await readTask.value
                }
                throw error
            }
        } onCancel: {
            readTasks.forEach { $0.cancel() }
            Task { await gate.abort() }
        }

        var bytes: [[UInt8]] = []
        bytes.reserveCapacity(accumulators.count)
        for accumulator in accumulators {
            bytes.append(await accumulator.bytes)
        }
        return (bytes, cancelledReadObserved)
    }
}

private actor SharedSessionByteAccumulator {
    private var storage: [UInt8] = []
    var bytes: [UInt8] { storage }
    @discardableResult
    func append(_ chunk: [UInt8]) -> Bool {
        let isFirstChunk = storage.isEmpty
        storage.append(contentsOf: chunk)
        return isFirstChunk
    }
}

/// A cancellation-aware first-chunk latch. Stream tasks stop in their public `onChunk`
/// callback until the test has observed every arrival; timeout cancellation resumes all
/// stored continuations so a failed E2E cannot leave its structured timeout waiting forever.
private actor SharedSessionFirstChunkGate {
    private let expectedCount: Int
    private var arrivalCount = 0
    private var released = false
    private var allArrivedWaiters: [UUID: CheckedContinuation<Void, Never>] = [:]
    private var releaseWaiters: [UUID: CheckedContinuation<Void, Never>] = [:]

    init(expectedCount: Int) {
        precondition(expectedCount > 0)
        self.expectedCount = expectedCount
    }

    func arriveAndWaitForRelease() async {
        guard !released else { return }
        arrivalCount += 1
        if arrivalCount >= expectedCount {
            let waiters = Array(allArrivedWaiters.values)
            allArrivedWaiters.removeAll()
            for waiter in waiters {
                waiter.resume()
            }
        }

        guard !released else { return }
        let waiterID = UUID()
        await withTaskCancellationHandler {
            await withCheckedContinuation { continuation in
                if released || Task.isCancelled {
                    continuation.resume()
                } else {
                    releaseWaiters[waiterID] = continuation
                }
            }
        } onCancel: {
            Task { await self.resumeReleaseWaiter(waiterID) }
        }
    }

    func waitUntilAllArrived() async {
        guard arrivalCount < expectedCount, !released else { return }
        let waiterID = UUID()
        await withTaskCancellationHandler {
            await withCheckedContinuation { continuation in
                if arrivalCount >= expectedCount || released || Task.isCancelled {
                    continuation.resume()
                } else {
                    allArrivedWaiters[waiterID] = continuation
                }
            }
        } onCancel: {
            Task { await self.resumeAllArrivedWaiter(waiterID) }
        }
    }

    func releaseAll() {
        guard !released else { return }
        released = true
        resumeAllWaiters()
    }

    func abort() {
        released = true
        resumeAllWaiters()
    }

    private func resumeAllWaiters() {
        let waiters = Array(allArrivedWaiters.values) + Array(releaseWaiters.values)
        allArrivedWaiters.removeAll()
        releaseWaiters.removeAll()
        for waiter in waiters {
            waiter.resume()
        }
    }

    private func resumeAllArrivedWaiter(_ waiterID: UUID) {
        allArrivedWaiters.removeValue(forKey: waiterID)?.resume()
    }

    private func resumeReleaseWaiter(_ waiterID: UUID) {
        releaseWaiters.removeValue(forKey: waiterID)?.resume()
    }
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
        defer { group.cancelAll() }
        return try await group.next()!
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
