import Foundation
import XCTest
@testable import SMBee

final class SMBStaticReadProgressRetryTests: XCTestCase {
    func testStaticReadRetryResetsProgressAndDrainsNotificationsBeforeReturn() async throws {
        let chunkSize = 1_048_576
        let fileSize = UInt64(chunkSize * 3)
        let firstTransport = try SMBStaticReadRetryScriptTransport(
            fileSize: fileSize,
            completesReadsAutomatically: false
        )
        let retryTransport = try SMBStaticReadRetryScriptTransport(
            fileSize: fileSize,
            completesReadsAutomatically: true
        )
        let transports = SMBContinuationTransportFactory(transports: [firstTransport, retryTransport])
        let progress = SMBStaticReadRetryProgressRecorder(totalBytes: fileSize)
        defer {
            firstTransport.failConnection()
            retryTransport.failConnection()
        }

        let read = Task {
            let data = try await SMBClient.read(
                host: "server",
                share: "share",
                path: "retry-progress.bin",
                credential: .anonymous,
                makeTransport: transports.makeTransport,
                onProgress: progress.append
            )
            progress.markReadReturned()
            return data
        }

        let partialRead = await firstTransport.waitForRead(offset: 0)
        try firstTransport.respond(
            to: partialRead,
            payload: Array(repeating: 0x31, count: Int(partialRead.length))
        )
        await progress.waitForPositiveProgress()
        firstTransport.failConnection()

        let data = try await read.value
        await progress.waitForCompletedProgress()

        XCTAssertEqual(transports.makeCount, 2, "READ should reconnect once after the first transport drops")
        XCTAssertEqual(data, Array(repeating: 0x5a, count: Int(fileSize)))

        let snapshots = progress.snapshots
        XCTAssertFalse(snapshots.isEmpty)
        XCTAssertEqual(snapshots.last?.bytesTransferred, fileSize)
        XCTAssertTrue(
            snapshots.allSatisfy { $0.totalBytes == fileSize && $0.bytesTransferred <= fileSize },
            "progress from the failed attempt must not carry into the retry"
        )
        XCTAssertEqual(progress.callbacksAfterReadReturned, 0)
        XCTAssertEqual(progress.callbackCount, progress.callbackCountAtReadReturn)
    }
}

private final class SMBStaticReadRetryProgressRecorder: @unchecked Sendable {
    private let lock = NSLock()
    private let totalBytes: UInt64
    private let positiveProgress = SMBStaticReadRetryEventSignal()
    private let completedProgress = SMBStaticReadRetryEventSignal()
    private var snapshotsStorage: [SMBTransferProgress] = []
    private var readReturned = false
    private var callbackCountAtReturnStorage: Int?
    private var callbacksAfterReturnStorage = 0

    init(totalBytes: UInt64) {
        self.totalBytes = totalBytes
    }

    func append(_ progress: SMBTransferProgress) {
        lock.lock()
        snapshotsStorage.append(progress)
        if readReturned {
            callbacksAfterReturnStorage += 1
        }
        lock.unlock()

        if progress.bytesTransferred > 0 {
            positiveProgress.signal()
        }
        if progress.totalBytes == totalBytes && progress.bytesTransferred >= totalBytes {
            completedProgress.signal()
        }
    }

    func markReadReturned() {
        lock.lock()
        readReturned = true
        callbackCountAtReturnStorage = snapshotsStorage.count
        lock.unlock()
    }

    func waitForPositiveProgress() async {
        await positiveProgress.wait()
    }

    func waitForCompletedProgress() async {
        await completedProgress.wait()
    }

    var snapshots: [SMBTransferProgress] {
        lock.withLock { snapshotsStorage }
    }

    var callbackCount: Int {
        lock.withLock { snapshotsStorage.count }
    }

    var callbackCountAtReadReturn: Int? {
        lock.withLock { callbackCountAtReturnStorage }
    }

    var callbacksAfterReadReturned: Int {
        lock.withLock { callbacksAfterReturnStorage }
    }
}

private final class SMBStaticReadRetryEventSignal: @unchecked Sendable {
    private let lock = NSLock()
    private var signaled = false
    private var waiters: [CheckedContinuation<Void, Never>] = []

    func signal() {
        let ready = lock.withLock { () -> [CheckedContinuation<Void, Never>] in
            guard !signaled else { return [] }
            signaled = true
            defer { waiters.removeAll() }
            return waiters
        }
        ready.forEach { $0.resume() }
    }

    func wait() async {
        await withCheckedContinuation { continuation in
            let ready = lock.withLock { () -> Bool in
                guard !signaled else { return true }
                waiters.append(continuation)
                return false
            }
            if ready { continuation.resume() }
        }
    }
}
