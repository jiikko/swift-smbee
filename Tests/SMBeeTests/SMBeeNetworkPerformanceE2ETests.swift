import Foundation
import XCTest
@testable import SMBee

final class SMBeeNetworkPerformanceE2ETests: XCTestCase {
    private let measuredIterations = 100
    private let warmupIterations = 5
    private let payloadSize = 1024 * 1024

    func testPersistentSessionReadWriteLatencyAndThroughput() async throws {
        guard ProcessInfo.processInfo.environment["SMBEE_NETWORK_PERFORMANCE"] == "1" else {
            throw XCTSkip("Set SMBEE_NETWORK_PERFORMANCE=1 to run the Samba network benchmark")
        }

        let environment = ProcessInfo.processInfo.environment
        let host = environment["SMBEE_E2E_HOST"] ?? "127.0.0.1"
        let port = try XCTUnwrap(UInt16(environment["SMBEE_E2E_PORT"] ?? "445"))
        let share = environment["SMBEE_E2E_SHARE"] ?? "public"
        let credential = SMBCredential(
            username: environment["SMBEE_E2E_USERNAME"] ?? "smbee",
            password: environment["SMBEE_E2E_PASSWORD"] ?? "smbee"
        )
        let suffix = UUID().uuidString
        let readPath = "network-perf-read-\(suffix).bin"
        let writePath = "network-perf-write-\(suffix).bin"
        let payload = (0..<payloadSize).map { UInt8(truncatingIfNeeded: $0) }
        let session = try await SMBee.connect(
            host: host,
            port: port,
            credential: credential,
            share: share
        )

        do {
            try await session.upload(path: readPath, data: payload)
            for _ in 0..<warmupIterations {
                _ = try await session.read(path: readPath)
                try await session.upload(path: writePath, data: payload)
            }

            var readMilliseconds: [Double] = []
            var writeMilliseconds: [Double] = []
            for iteration in 1...measuredIterations {
                let readStart = ContinuousClock.now
                let received = try await session.read(path: readPath)
                let readElapsed = milliseconds(readStart.duration(to: .now))
                XCTAssertEqual(received.count, payloadSize)
                readMilliseconds.append(readElapsed)
                printSample(operation: "read", iteration: iteration, milliseconds: readElapsed)

                let writeStart = ContinuousClock.now
                try await session.upload(path: writePath, data: payload)
                let writeElapsed = milliseconds(writeStart.duration(to: .now))
                writeMilliseconds.append(writeElapsed)
                printSample(operation: "write", iteration: iteration, milliseconds: writeElapsed)
            }

            printSummary(operation: "read", milliseconds: readMilliseconds)
            printSummary(operation: "write", milliseconds: writeMilliseconds)
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

    private func printSample(operation: String, iteration: Int, milliseconds: Double) {
        print(
            "PERF_NETWORK_SAMPLE operation=\(operation) iteration=\(iteration) " +
                "latency_ms=\(format(milliseconds))"
        )
    }

    private func printSummary(operation: String, milliseconds: [Double]) {
        let totalSeconds = milliseconds.reduce(0, +) / 1_000
        let transferredMiB = Double(payloadSize * milliseconds.count) / 1_048_576
        print(
            "PERF_NETWORK operation=\(operation) iterations=\(milliseconds.count) " +
                "size_bytes=\(payloadSize) throughput_mib_s=\(format(transferredMiB / totalSeconds)) " +
                "latency_p50_ms=\(format(percentile(milliseconds, 0.50))) " +
                "latency_p95_ms=\(format(percentile(milliseconds, 0.95))) " +
                "latency_p99_ms=\(format(percentile(milliseconds, 0.99)))"
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

    private func format(_ value: Double) -> String {
        String(format: "%.3f", value)
    }
}
