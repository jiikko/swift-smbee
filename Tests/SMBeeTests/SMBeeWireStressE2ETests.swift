import Foundation
import XCTest
@testable import SMBee

/// Persistent-session load used to observe first-fault diagnostics around concurrent reads and
/// share enumeration. Connection loss is deliberately observational; other failures are real
/// test failures because they usually indicate a broken harness or an unrelated regression.
final class SMBeeWireStressE2ETests: XCTestCase {
    func testPersistentSessionReadPrefixAndListStress() async throws {
        let environment = ProcessInfo.processInfo.environment
        guard environment["SMBEE_E2E"] == "1" else {
            throw XCTSkip("Set SMBEE_E2E=1 to run Samba-backed E2E tests")
        }
        guard environment["SMBEE_E2E_STRESS"] == "1" else {
            throw XCTSkip("Set SMBEE_E2E_STRESS=1 to run wire stress E2E tests")
        }
        let host = environment["SMBEE_E2E_HOST"] ?? "127.0.0.1"
        let port = try XCTUnwrap(UInt16(environment["SMBEE_E2E_PORT"] ?? "445"))
        let share = environment["SMBEE_E2E_SHARE"] ?? "public"
        let credential = SMBCredential(
            username: environment["SMBEE_E2E_USERNAME"] ?? "smbee",
            password: environment["SMBEE_E2E_PASSWORD"] ?? "smbee"
        )
        let concurrency = max(1, Int(environment["SMBEE_STRESS_CONCURRENCY"] ?? "4") ?? 4)
        let repetitions = max(1, Int(environment["SMBEE_STRESS_REPETITIONS"] ?? "10") ?? 10)
        let prefixLength = max(1, UInt64(environment["SMBEE_STRESS_PREFIX_LENGTH"] ?? "65536") ?? 65536)
        let session = try await SMBee.connect(host: host, port: port, credential: credential, share: share)
        let path = "smbee-wire-stress-\(UUID().uuidString).bin"
        let payload = (0..<Int(max(prefixLength, 65536))).map { UInt8($0 % 251) }
        let counters = StressCounters()

        do {
            try await session.upload(path: path, data: payload)
            for wave in 0..<repetitions {
                if await counters.connectionLossDetected {
                    await counters.abortWaves(count: repetitions - wave)
                    break
                }
                await withTaskGroup(of: Void.self) { group in
                    for _ in 0..<concurrency {
                        group.addTask {
                            await counters.operationStarted()
                            do {
                                _ = try await session.readPrefix(path: path, maxLength: prefixLength)
                            } catch {
                                await counters.record(error: error)
                            }
                        }
                    }
                    group.addTask {
                        await counters.operationStarted()
                        do {
                            _ = try await session.list()
                        } catch {
                            await counters.record(error: error)
                        }
                    }
                }
            }
        } catch {
            try? await session.delete(path: path)
            await session.close()
            throw error
        }

        let summary = await counters.summary
        print("[wire-stress] operations-before-fault=\(summary.operationsBeforeFault) connection-loss=\(summary.connectionLossOccurred) connection-losses=\(summary.connectionLosses) waves-aborted-after-fault=\(summary.wavesAbortedAfterFault)")
        XCTAssertTrue(summary.unexpected.isEmpty, summary.unexpected.joined(separator: "; "))
        if environment["SMBEE_STRESS_FAIL_ON_CONNECTION_LOSS"] == "1" {
            if summary.connectionLosses > 0 {
                XCTFail("wire stress detected \(summary.connectionLosses) connection-loss operation(s)")
            }
        }
        try? await session.delete(path: path)
        await session.close()
    }

    func testCreditFIFOHeadOfLineBlockingMeasurement() async throws {
        let environment = ProcessInfo.processInfo.environment
        guard environment["SMBEE_E2E"] == "1" else {
            throw XCTSkip("Set SMBEE_E2E=1 to run Samba-backed E2E tests")
        }
        guard environment["SMBEE_E2E_STRESS"] == "1" else {
            throw XCTSkip("Set SMBEE_E2E_STRESS=1 to run wire stress E2E tests")
        }

        let host = environment["SMBEE_E2E_HOST"] ?? "127.0.0.1"
        let port = try XCTUnwrap(UInt16(environment["SMBEE_E2E_PORT"] ?? "445"))
        let share = environment["SMBEE_E2E_SHARE"] ?? "public"
        let credential = SMBCredential(
            username: environment["SMBEE_E2E_USERNAME"] ?? "smbee",
            password: environment["SMBEE_E2E_PASSWORD"] ?? "smbee"
        )
        let iterations = max(1, Int(environment["SMBEE_CREDIT_FIFO_ITERATIONS"] ?? "20") ?? 20)
        let writeSizeMiB = max(1, Int(environment["SMBEE_CREDIT_FIFO_WRITE_MIB"] ?? "32") ?? 32)
        let writeSizeProduct = writeSizeMiB.multipliedReportingOverflow(by: 1_048_576)
        let writeSize = try XCTUnwrap(
            writeSizeProduct.overflow ? nil : writeSizeProduct.partialValue,
            "SMBEE_CREDIT_FIFO_WRITE_MIB is too large"
        )
        let prefixLength = UInt64(64 * 1_024)
        let suffix = UUID().uuidString
        let readPath = "smbee-credit-fifo-read-\(suffix).bin"
        let writePath = "smbee-credit-fifo-write-\(suffix).bin"
        let readPayload = (0..<Int(prefixLength)).map { UInt8(truncatingIfNeeded: $0) }
        let writePayload = (0..<writeSize).map { UInt8(truncatingIfNeeded: $0) }
        let session = try await SMBee.connect(
            host: host,
            port: port,
            credential: credential,
            share: share
        )
        let perfCapture = CreditWaitCapture()
        let capturesCreditWaits = environment["SMBEE_PERF"] == "1"
        let previousPerfSink = SMBPerfLog.testSink
        if capturesCreditWaits {
            SMBPerfLog.testSink = { perfCapture.append($0) }
        }
        defer {
            if capturesCreditWaits {
                SMBPerfLog.testSink = previousPerfSink
            }
        }

        var baselineMilliseconds: [Double] = []
        var competingMilliseconds: [Double] = []
        var baselineCreditWaits = CreditWaitCounts()
        var competingCreditWaits = CreditWaitCounts()
        var competingOverlaps = WriteOverlapCounts()

        do {
            try await session.upload(path: readPath, data: readPayload)
            _ = try await session.readPrefix(path: readPath, maxLength: prefixLength)

            for iteration in 0..<iterations {
                if iteration.isMultiple(of: 2) {
                    let baseline = try await measurePrefixRead(
                        session: session,
                        path: readPath,
                        maxLength: prefixLength,
                        perfCapture: capturesCreditWaits ? perfCapture : nil
                    )
                    baselineMilliseconds.append(baseline.milliseconds)
                    baselineCreditWaits += baseline.creditWaits
                    printCreditFIFOSample(
                        condition: "baseline",
                        iteration: iteration,
                        observation: baseline,
                        capturesCreditWaits: capturesCreditWaits
                    )

                    let competing = try await measurePrefixReadDuringWrite(
                        session: session,
                        readPath: readPath,
                        writePath: writePath,
                        maxLength: prefixLength,
                        writePayload: writePayload,
                        perfCapture: capturesCreditWaits ? perfCapture : nil
                    )
                    competingMilliseconds.append(competing.milliseconds)
                    competingCreditWaits += competing.creditWaits
                    competingOverlaps.record(competing.writeOverlap)
                    printCreditFIFOSample(
                        condition: "competing",
                        iteration: iteration,
                        observation: competing,
                        capturesCreditWaits: capturesCreditWaits
                    )
                } else {
                    let competing = try await measurePrefixReadDuringWrite(
                        session: session,
                        readPath: readPath,
                        writePath: writePath,
                        maxLength: prefixLength,
                        writePayload: writePayload,
                        perfCapture: capturesCreditWaits ? perfCapture : nil
                    )
                    competingMilliseconds.append(competing.milliseconds)
                    competingCreditWaits += competing.creditWaits
                    competingOverlaps.record(competing.writeOverlap)
                    printCreditFIFOSample(
                        condition: "competing",
                        iteration: iteration,
                        observation: competing,
                        capturesCreditWaits: capturesCreditWaits
                    )

                    let baseline = try await measurePrefixRead(
                        session: session,
                        path: readPath,
                        maxLength: prefixLength,
                        perfCapture: capturesCreditWaits ? perfCapture : nil
                    )
                    baselineMilliseconds.append(baseline.milliseconds)
                    baselineCreditWaits += baseline.creditWaits
                    printCreditFIFOSample(
                        condition: "baseline",
                        iteration: iteration,
                        observation: baseline,
                        capturesCreditWaits: capturesCreditWaits
                    )
                }
            }

            printCreditFIFOSummary(
                condition: "baseline",
                milliseconds: baselineMilliseconds,
                prefixLength: prefixLength,
                writeSize: writeSize
            )
            printCreditFIFOSummary(
                condition: "competing",
                milliseconds: competingMilliseconds,
                prefixLength: prefixLength,
                writeSize: writeSize,
                overlaps: competingOverlaps
            )
            printCreditFIFORatios(
                baseline: baselineMilliseconds,
                competing: competingMilliseconds
            )
            printCreditWaitCounts(
                condition: "baseline",
                counts: baselineCreditWaits,
                captured: capturesCreditWaits
            )
            printCreditWaitCounts(
                condition: "competing",
                counts: competingCreditWaits,
                captured: capturesCreditWaits
            )
            printReadTimingAvailability(
                condition: "baseline",
                capturesWireEvents: capturesCreditWaits
            )
            printReadTimingAvailability(
                condition: "competing",
                capturesWireEvents: capturesCreditWaits
            )

            try await session.delete(path: readPath)
            try await session.delete(path: writePath)
            await session.close()
        } catch {
            try? await session.delete(path: readPath)
            try? await session.delete(path: writePath)
            await session.close()
            throw error
        }
    }

    private func measurePrefixRead(
        session: SMBClientSession,
        path: String,
        maxLength: UInt64,
        perfCapture: CreditWaitCapture?
    ) async throws -> CreditFIFOObservation {
        let creditWaitsBefore = perfCapture?.counts ?? CreditWaitCounts()
        let start = ContinuousClock.now
        let data = try await session.readPrefix(path: path, maxLength: maxLength)
        let elapsed = milliseconds(start.duration(to: .now))
        XCTAssertEqual(data.count, Int(maxLength))
        let creditWaitsAfter = perfCapture?.counts ?? CreditWaitCounts()
        return CreditFIFOObservation(
            milliseconds: elapsed,
            creditWaits: creditWaitsAfter - creditWaitsBefore,
            writeOverlap: .none
        )
    }

    private func measurePrefixReadDuringWrite(
        session: SMBClientSession,
        readPath: String,
        writePath: String,
        maxLength: UInt64,
        writePayload: [UInt8],
        perfCapture: CreditWaitCapture?
    ) async throws -> CreditFIFOObservation {
        let creditWaitsBefore = perfCapture?.counts ?? CreditWaitCounts()
        let writeStarted = WriteProgressSignal()
        let writeTask = Task {
            do {
                try await session.upload(
                    path: writePath,
                    data: writePayload,
                    onProgress: { _ in
                        writeStarted.signalProgress()
                    }
                )
                writeStarted.complete()
            } catch {
                writeStarted.fail(error)
                throw error
            }
        }

        do {
            try await writeStarted.waitForProgress()
            guard writeStarted.isWriteActive else {
                try await writeTask.value
                throw CreditFIFOMeasurementError.writeCompletedBeforeRead
            }
            let start = ContinuousClock.now
            let data = try await session.readPrefix(path: readPath, maxLength: maxLength)
            let writeOverlap: WriteOverlap = writeStarted.isWriteActive ? .full : .partial
            let elapsed = milliseconds(start.duration(to: .now))
            XCTAssertEqual(data.count, Int(maxLength))
            try await writeTask.value
            let creditWaitsAfter = perfCapture?.counts ?? CreditWaitCounts()
            return CreditFIFOObservation(
                milliseconds: elapsed,
                creditWaits: creditWaitsAfter - creditWaitsBefore,
                writeOverlap: writeOverlap
            )
        } catch {
            writeTask.cancel()
            _ = try? await writeTask.value
            throw error
        }
    }

    private func printCreditFIFOSummary(
        condition: String,
        milliseconds: [Double],
        prefixLength: UInt64,
        writeSize: Int,
        overlaps: WriteOverlapCounts? = nil
    ) {
        let overlapField = overlaps.map {
            " write_active_samples=\($0.full + $0.partial)" +
                " write_overlap_full=\($0.full)" +
                " write_overlap_partial=\($0.partial)" +
                " write_overlap_none=\($0.none)"
        } ?? ""
        print(
            "CREDIT_FIFO_HOL condition=\(condition) iterations=\(milliseconds.count) " +
                "prefix_bytes=\(prefixLength) write_bytes=\(writeSize)\(overlapField) " +
                "latency_p50_ms=\(format(percentile(milliseconds, 0.50))) " +
                "latency_p95_ms=\(format(percentile(milliseconds, 0.95))) " +
                "latency_max_ms=\(format(milliseconds.max() ?? 0))"
        )
    }

    private func printCreditFIFORatios(baseline: [Double], competing: [Double]) {
        let baselineP50 = percentile(baseline, 0.50)
        let baselineP95 = percentile(baseline, 0.95)
        let baselineMax = baseline.max() ?? 0
        print(
            "CREDIT_FIFO_HOL_RATIO competing_over_baseline " +
                "p50=\(format(ratio(percentile(competing, 0.50), baselineP50))) " +
                "p95=\(format(ratio(percentile(competing, 0.95), baselineP95))) " +
                "max=\(format(ratio(competing.max() ?? 0, baselineMax)))"
        )
    }

    private func printCreditFIFOSample(
        condition: String,
        iteration: Int,
        observation: CreditFIFOObservation,
        capturesCreditWaits: Bool
    ) {
        print(
            "CREDIT_FIFO_HOL_SAMPLE condition=\(condition) iteration=\(iteration + 1) " +
                "latency_ms=\(format(observation.milliseconds)) " +
                "write_overlap=\(observation.writeOverlap.rawValue) " +
                "credit_wait_capture=\(capturesCreditWaits ? "enabled" : "disabled") " +
                "credit_wait_total=\(observation.creditWaits.total) " +
                "credit_wait_read=\(observation.creditWaits.read) " +
                "credit_wait_write=\(observation.creditWaits.write) " +
                "credit_wait_other=\(observation.creditWaits.other)"
        )
    }

    private func printCreditWaitCounts(
        condition: String,
        counts: CreditWaitCounts,
        captured: Bool
    ) {
        print(
            "CREDIT_FIFO_HOL_CREDIT_WAIT condition=\(condition) " +
                "capture=\(captured ? "enabled" : "disabled") total=\(counts.total) " +
                "read=\(counts.read) write=\(counts.write) other=\(counts.other)"
        )
    }

    private func printReadTimingAvailability(condition: String, capturesWireEvents: Bool) {
        let reason = capturesWireEvents
            ? "wire_events_have_no_request_timestamps"
            : "SMBEE_PERF_disabled"
        print(
            "CREDIT_FIFO_HOL_READ_TIMING condition=\(condition) available=false reason=\(reason)"
        )
    }

    private func percentile(_ values: [Double], _ quantile: Double) -> Double {
        let sorted = values.sorted()
        let rank = max(1, Int(ceil(quantile * Double(sorted.count))))
        return sorted[min(rank - 1, sorted.count - 1)]
    }

    private func milliseconds(_ duration: Duration) -> Double {
        let components = duration.components
        return Double(components.seconds) * 1_000 +
            Double(components.attoseconds) / 1_000_000_000_000_000
    }

    private func ratio(_ numerator: Double, _ denominator: Double) -> Double {
        denominator > 0 ? numerator / denominator : 0
    }

    private func format(_ value: Double) -> String {
        String(format: "%.3f", value)
    }
}

private struct CreditFIFOObservation {
    let milliseconds: Double
    let creditWaits: CreditWaitCounts
    let writeOverlap: WriteOverlap
}

private enum WriteOverlap: String {
    case full
    case partial
    case none
}

private struct WriteOverlapCounts {
    private(set) var full = 0
    private(set) var partial = 0
    private(set) var none = 0

    mutating func record(_ overlap: WriteOverlap) {
        switch overlap {
        case .full:
            full += 1
        case .partial:
            partial += 1
        case .none:
            none += 1
        }
    }
}

private struct CreditWaitCounts {
    var total = 0
    var read = 0
    var write = 0

    var other: Int {
        total - read - write
    }

    static func += (lhs: inout Self, rhs: Self) {
        lhs.total += rhs.total
        lhs.read += rhs.read
        lhs.write += rhs.write
    }

    static func - (lhs: Self, rhs: Self) -> Self {
        Self(
            total: lhs.total - rhs.total,
            read: lhs.read - rhs.read,
            write: lhs.write - rhs.write
        )
    }
}

private final class CreditWaitCapture: @unchecked Sendable {
    private let lock = NSLock()
    private var storage = CreditWaitCounts()

    var counts: CreditWaitCounts {
        lock.withLock { storage }
    }

    func append(_ message: String) {
        guard message.hasPrefix("[wire] credit_wait ") else { return }
        lock.withLock {
            storage.total += 1
            if message.contains(" command=8 ") {
                storage.read += 1
            } else if message.contains(" command=9 ") {
                storage.write += 1
            }
        }
    }
}

private final class WriteProgressSignal: @unchecked Sendable {
    private let lock = NSLock()
    private var result: Result<Void, Error>?
    private var continuation: CheckedContinuation<Void, Error>?
    private var writeCompleted = false

    var isWriteActive: Bool {
        lock.withLock { !writeCompleted }
    }

    func waitForProgress() async throws {
        try await withCheckedThrowingContinuation { continuation in
            lock.lock()
            if let result {
                lock.unlock()
                continuation.resume(with: result)
            } else {
                self.continuation = continuation
                lock.unlock()
            }
        }
    }

    func signalProgress() {
        resolve(with: .success(()))
    }

    func complete() {
        lock.withLock {
            writeCompleted = true
        }
        // A completed upload with no progress callback must fail the overlap guard instead
        // of leaving the measurement suspended forever.
        resolve(with: .success(()))
    }

    func fail(_ error: Error) {
        lock.withLock {
            writeCompleted = true
        }
        resolve(with: .failure(error))
    }

    private func resolve(with result: Result<Void, Error>) {
        lock.lock()
        guard self.result == nil else {
            lock.unlock()
            return
        }
        self.result = result
        let continuation = continuation
        self.continuation = nil
        lock.unlock()
        continuation?.resume(with: result)
    }
}

private enum CreditFIFOMeasurementError: LocalizedError {
    case writeCompletedBeforeRead

    var errorDescription: String? {
        "WRITE completed after its first progress callback but before the competing READ started"
    }
}

private actor StressCounters {
    private(set) var operations = 0
    private(set) var connectionLosses = 0
    private(set) var operationsBeforeFault = 0
    private(set) var connectionLossOccurred = false
    private(set) var wavesAbortedAfterFault = 0
    private(set) var unexpected: [String] = []

    func operationStarted() { operations += 1 }

    var connectionLossDetected: Bool { connectionLossOccurred }

    func record(error: Error) {
        if error is SMBTransportError {
            if !connectionLossOccurred {
                connectionLossOccurred = true
                operationsBeforeFault = operations
            }
            connectionLosses += 1
        } else if let error = error as? SMBError, case .connectionLost = error {
            if !connectionLossOccurred {
                connectionLossOccurred = true
                operationsBeforeFault = operations
            }
            connectionLosses += 1
        } else {
            unexpected.append("\(String(reflecting: type(of: error))): \(error)")
        }
    }

    func abortWaves(count: Int) {
        wavesAbortedAfterFault += count
    }

    var summary: (
        operationsBeforeFault: Int,
        connectionLossOccurred: Bool,
        connectionLosses: Int,
        wavesAbortedAfterFault: Int,
        unexpected: [String]
    ) {
        (
            connectionLossOccurred ? operationsBeforeFault : operations,
            connectionLossOccurred,
            connectionLosses,
            wavesAbortedAfterFault,
            unexpected
        )
    }
}
