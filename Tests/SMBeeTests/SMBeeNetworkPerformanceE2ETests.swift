import Crypto
import Foundation
import XCTest
@testable import SMBee
#if canImport(Glibc)
import Glibc
#endif

// Real-Samba transfer benchmark. With no SMBEE_NETWORK_PERF_* overrides it keeps the contract of the
// samba-network-performance job (1 MiB, 5 warm-ups, 100 samples, two PERF_NETWORK summary lines).
//
// Issue 097 also copies this file into worktrees of older commits (e91809a^ / e91809a) to A/B them with
// the same harness, so it may only use the public API (SMBee.connect / read / upload / delete) and
// SMBTransportTestOverride, which both exist there. Those commits predate SMBTransport.send(_ segments:);
// the study workflow compiles them with -DSMBEE_LEGACY_TRANSPORT_API.
final class SMBeeNetworkPerformanceE2ETests: XCTestCase {
    func testPersistentSessionReadWriteLatencyAndThroughput() async throws {
        let environment = ProcessInfo.processInfo.environment
        guard environment["SMBEE_NETWORK_PERFORMANCE"] == "1" else {
            throw XCTSkip("Set SMBEE_NETWORK_PERFORMANCE=1 to run the Samba network benchmark")
        }
        let configuration = try NetworkPerformanceConfiguration(environment: environment)
        let host = environment["SMBEE_E2E_HOST"] ?? "127.0.0.1"
        let port = try XCTUnwrap(UInt16(environment["SMBEE_E2E_PORT"] ?? "445"))
        let share = environment["SMBEE_E2E_SHARE"] ?? "public"
        let credential = SMBCredential(
            username: environment["SMBEE_E2E_USERNAME"] ?? "smbee",
            password: environment["SMBEE_E2E_PASSWORD"] ?? "smbee"
        )
        let recorder = try NetworkPerformanceRecorder(configuration: configuration)

        // The override is a process-wide static; this benchmark must run alone in its process
        // (the workflows filter to this single test).
        let counter = TransportCounter()
        SMBTransportTestOverride.factory = { CountingTransport(inner: POSIXSocketTransport(), counter: counter) }
        defer { SMBTransportTestOverride.factory = nil }

        let session = try await SMBee.connect(host: host, port: port, credential: credential, share: share)
        let suffix = UUID().uuidString
        var created: [String] = []
        do {
            for sizeBytes in configuration.sizesBytes {
                let payload = NetworkPerformancePayload.bytes(count: sizeBytes)
                let payloadDigest = NetworkPerformancePayload.sha256(payload)
                let readPath = "network-perf-read-\(sizeBytes)-\(suffix).bin"
                let writePath = "network-perf-write-\(sizeBytes)-\(suffix).bin"
                created += [readPath, writePath]

                // Fresh server files for every size and invocation; warm-ups then leave the page cache warm.
                try await session.upload(path: readPath, data: payload)
                for _ in 0..<configuration.warmupIterations {
                    _ = try await session.read(path: readPath)
                    try await session.upload(path: writePath, data: payload)
                }

                var readMilliseconds: [Double] = []
                var writeMilliseconds: [Double] = []
                for iteration in 1...configuration.measuredIterations {
                    // SHA-256 only on the first and last sample: hashing every sample would add client CPU
                    // to the measured interval's neighbourhood.
                    let verifyDigest = iteration == 1 || iteration == configuration.measuredIterations

                    let readStart = NetworkPerformanceSnapshot.take(counter: counter)
                    let received = try await session.read(path: readPath)
                    let readEnd = NetworkPerformanceSnapshot.take(counter: counter)
                    XCTAssertEqual(received.count, sizeBytes)
                    let readDigestMatches: Bool? = verifyDigest
                        ? NetworkPerformancePayload.sha256(received) == payloadDigest : nil
                    if let readDigestMatches { XCTAssertTrue(readDigestMatches, "read SHA-256 mismatch") }
                    let readSample = readEnd.sample(since: readStart)
                    readMilliseconds.append(readSample.wallMilliseconds)
                    try recorder.record(
                        operation: "read", sizeBytes: sizeBytes, iteration: iteration,
                        sample: readSample, sizeMatches: received.count == sizeBytes, digestMatches: readDigestMatches
                    )

                    let writeStart = NetworkPerformanceSnapshot.take(counter: counter)
                    try await session.upload(path: writePath, data: payload)
                    let writeEnd = NetworkPerformanceSnapshot.take(counter: counter)
                    let writeSample = writeEnd.sample(since: writeStart)
                    var writeDigestMatches: Bool?
                    var writeSizeMatches = true
                    if verifyDigest {
                        // Read the file back from the server (outside the measured interval).
                        let stored = try await session.read(path: writePath)
                        writeSizeMatches = stored.count == sizeBytes
                        writeDigestMatches = NetworkPerformancePayload.sha256(stored) == payloadDigest
                        XCTAssertEqual(stored.count, sizeBytes)
                        XCTAssertEqual(writeDigestMatches, true, "write read-back SHA-256 mismatch")
                    }
                    writeMilliseconds.append(writeSample.wallMilliseconds)
                    try recorder.record(
                        operation: "write", sizeBytes: sizeBytes, iteration: iteration,
                        sample: writeSample, sizeMatches: writeSizeMatches, digestMatches: writeDigestMatches
                    )
                }
                recorder.summary(operation: "read", sizeBytes: sizeBytes, milliseconds: readMilliseconds)
                recorder.summary(operation: "write", sizeBytes: sizeBytes, milliseconds: writeMilliseconds)
            }
            for path in created { try await session.delete(path: path) }
            await session.close()
        } catch {
            for path in created { try? await session.delete(path: path) }
            await session.close()
            throw error
        }
    }
}

struct NetworkPerformanceConfiguration {
    var sizesBytes: [Int]
    var warmupIterations: Int
    var measuredIterations: Int
    var jsonlPath: String?
    var metadata: [String: Any]

    init(environment: [String: String]) throws {
        let sizes = (environment["SMBEE_NETWORK_PERF_SIZES_MIB"] ?? "1")
            .split(separator: ",")
            .map { $0.trimmingCharacters(in: .whitespaces) }
        sizesBytes = try sizes.map { value in
            guard let mib = Int(value), mib > 0, mib <= 4096 else {
                throw NetworkPerformanceError.invalidEnvironment("SMBEE_NETWORK_PERF_SIZES_MIB: \(value)")
            }
            return mib * 1_048_576
        }
        warmupIterations = try Self.count(environment, "SMBEE_NETWORK_PERF_WARMUP", default: 5, minimum: 0)
        measuredIterations = try Self.count(environment, "SMBEE_NETWORK_PERF_SAMPLES", default: 100, minimum: 1)
        jsonlPath = environment["SMBEE_NETWORK_PERF_JSONL"].flatMap { $0.isEmpty ? nil : $0 }
        if let raw = environment["SMBEE_NETWORK_PERF_METADATA_JSON"], !raw.isEmpty {
            guard let object = try JSONSerialization.jsonObject(with: Data(raw.utf8)) as? [String: Any] else {
                throw NetworkPerformanceError.invalidEnvironment("SMBEE_NETWORK_PERF_METADATA_JSON must be an object")
            }
            metadata = object
        } else {
            metadata = [:]
        }
    }

    private static func count(_ environment: [String: String], _ key: String, default value: Int, minimum: Int) throws -> Int {
        guard let raw = environment[key] else { return value }
        guard let parsed = Int(raw), parsed >= minimum, parsed <= 10_000 else {
            throw NetworkPerformanceError.invalidEnvironment("\(key): \(raw)")
        }
        return parsed
    }
}

enum NetworkPerformanceError: Error {
    case invalidEnvironment(String)
}

enum NetworkPerformancePayload {
    /// Deterministic content (xorshift64*, fixed seed) so every invocation and commit transfers the same bytes.
    static func bytes(count: Int) -> [UInt8] {
        var state: UInt64 = 0x9E37_79B9_7F4A_7C15
        var bytes = [UInt8](repeating: 0, count: count)
        var index = 0
        while index < count {
            state ^= state >> 12
            state ^= state << 25
            state ^= state >> 27
            var word = state &* 0x2545_F491_4F6C_DD1D
            for _ in 0..<8 where index < count {
                bytes[index] = UInt8(truncatingIfNeeded: word)
                word >>= 8
                index += 1
            }
        }
        return bytes
    }

    static func sha256(_ bytes: [UInt8]) -> String {
        SHA256.hash(data: bytes).map { String(format: "%02x", $0) }.joined()
    }
}

/// Counts what crosses the SMBTransport API. Byte and call counts are exact; SMB2 command counts are only
/// available for plaintext (signed or unsigned) frames. Encrypted frames hide the command inside the
/// TRANSFORM payload, so the counter reports the command counts as unavailable instead of guessing.
final class TransportCounter: @unchecked Sendable {
    struct Values {
        var sentBytes = 0
        var receivedBytes = 0
        var sendCalls = 0
        var receiveCalls = 0
        var readCommands = 0
        var writeCommands = 0
        var sawEncryptedFrame = false
        var sawUnparsedSend = false
    }

    private let lock = NSLock()
    private var values = Values()

    func snapshot() -> Values {
        lock.lock()
        defer { lock.unlock() }
        return values
    }

    func recordSend(_ stream: [UInt8]) {
        let parsed = Self.parseCommands(stream)
        lock.lock()
        defer { lock.unlock() }
        values.sentBytes += stream.count
        values.sendCalls += 1
        switch parsed {
        case let .plaintext(reads, writes):
            values.readCommands += reads
            values.writeCommands += writes
        case .encrypted:
            values.sawEncryptedFrame = true
        case .unparsed:
            values.sawUnparsedSend = true
        }
    }

    func recordReceive(_ bytes: [UInt8]) {
        lock.lock()
        defer { lock.unlock() }
        values.receivedBytes += bytes.count
        values.receiveCalls += 1
    }

    private enum ParsedSend {
        case plaintext(reads: Int, writes: Int)
        case encrypted
        case unparsed
    }

    private static let smb2ReadCommand: UInt16 = 0x0008
    private static let smb2WriteCommand: UInt16 = 0x0009

    /// Walks the direct-TCP frames in one send call (the SMBTransport contract keeps each call's bytes
    /// together) and the SMB2 NextCommand chain inside each frame.
    private static func parseCommands(_ stream: [UInt8]) -> ParsedSend {
        var reads = 0
        var writes = 0
        var offset = 0
        while offset < stream.count {
            guard offset + 4 <= stream.count else { return .unparsed }
            let length = Int(stream[offset + 1]) << 16 | Int(stream[offset + 2]) << 8 | Int(stream[offset + 3])
            let frameStart = offset + 4
            let frameEnd = frameStart + length
            guard frameEnd <= stream.count, length >= 4 else { return .unparsed }
            if stream[frameStart] == 0xFD { return .encrypted }
            var header = frameStart
            while true {
                guard header + 64 <= frameEnd, stream[header] == 0xFE, stream[header + 1] == 0x53 else { return .unparsed }
                let command = UInt16(stream[header + 12]) | UInt16(stream[header + 13]) << 8
                if command == smb2ReadCommand { reads += 1 }
                if command == smb2WriteCommand { writes += 1 }
                let next = Int(stream[header + 20]) | Int(stream[header + 21]) << 8 |
                    Int(stream[header + 22]) << 16 | Int(stream[header + 23]) << 24
                if next == 0 { break }
                header += next
            }
            offset = frameEnd
        }
        return .plaintext(reads: reads, writes: writes)
    }
}

final class CountingTransport: SMBTransport, @unchecked Sendable {
    private let inner: POSIXSocketTransport
    private let counter: TransportCounter

    init(inner: POSIXSocketTransport, counter: TransportCounter) {
        self.inner = inner
        self.counter = counter
    }

    func connect(host: String, port: UInt16) async throws {
        try await inner.connect(host: host, port: port)
    }

    func send(_ bytes: [UInt8]) async throws {
        counter.recordSend(bytes)
        try await inner.send(bytes)
    }

#if !SMBEE_LEGACY_TRANSPORT_API
    // Forward the segmented form so the inner transport keeps its vectored I/O; the protocol default
    // would join the segments first and change what is being measured.
    func send(_ segments: [[UInt8]]) async throws {
        counter.recordSend(segments.flatMap { $0 })
        try await inner.send(segments)
    }
#endif

    func receive(maxLength: Int) async throws -> [UInt8] {
        let bytes = try await inner.receive(maxLength: maxLength)
        counter.recordReceive(bytes)
        return bytes
    }

    func close() {
        inner.close()
    }
}

struct NetworkPerformanceSample {
    var wallMilliseconds: Double
    var userCPUMilliseconds: Double
    var systemCPUMilliseconds: Double
    var maxRSSKiB: Int
    var transport: TransportCounter.Values
}

struct NetworkPerformanceSnapshot {
    var instant: ContinuousClock.Instant
    var usage: rusage
    var transport: TransportCounter.Values

    static func take(counter: TransportCounter) -> NetworkPerformanceSnapshot {
        var usage = rusage()
#if os(Linux)
        _ = getrusage(__rusage_who_t(RUSAGE_SELF.rawValue), &usage)
#else
        _ = getrusage(RUSAGE_SELF, &usage)
#endif
        return NetworkPerformanceSnapshot(instant: .now, usage: usage, transport: counter.snapshot())
    }

    func sample(since start: NetworkPerformanceSnapshot) -> NetworkPerformanceSample {
        let wall = start.instant.duration(to: instant)
        var delta = TransportCounter.Values()
        delta.sentBytes = transport.sentBytes - start.transport.sentBytes
        delta.receivedBytes = transport.receivedBytes - start.transport.receivedBytes
        delta.sendCalls = transport.sendCalls - start.transport.sendCalls
        delta.receiveCalls = transport.receiveCalls - start.transport.receiveCalls
        delta.readCommands = transport.readCommands - start.transport.readCommands
        delta.writeCommands = transport.writeCommands - start.transport.writeCommands
        // Sticky flags: once an encrypted or unparsed send appears, command counts stay unavailable.
        delta.sawEncryptedFrame = transport.sawEncryptedFrame
        delta.sawUnparsedSend = transport.sawUnparsedSend
        return NetworkPerformanceSample(
            wallMilliseconds: Self.milliseconds(wall),
            userCPUMilliseconds: Self.milliseconds(usage.ru_utime) - Self.milliseconds(start.usage.ru_utime),
            systemCPUMilliseconds: Self.milliseconds(usage.ru_stime) - Self.milliseconds(start.usage.ru_stime),
            maxRSSKiB: Self.maxRSSKiB(usage),
            transport: delta
        )
    }

    private static func milliseconds(_ duration: Duration) -> Double {
        let components = duration.components
        return Double(components.seconds) * 1_000 + Double(components.attoseconds) / 1_000_000_000_000_000
    }

    private static func milliseconds(_ time: timeval) -> Double {
        Double(time.tv_sec) * 1_000 + Double(time.tv_usec) / 1_000
    }

    private static func maxRSSKiB(_ usage: rusage) -> Int {
#if os(Linux)
        return Int(usage.ru_maxrss) // KiB on Linux
#else
        return Int(usage.ru_maxrss) / 1_024 // bytes on Darwin
#endif
    }
}

final class NetworkPerformanceRecorder {
    private let configuration: NetworkPerformanceConfiguration
    private let handle: FileHandle?

    init(configuration: NetworkPerformanceConfiguration) throws {
        self.configuration = configuration
        if let path = configuration.jsonlPath {
            if !FileManager.default.fileExists(atPath: path) {
                FileManager.default.createFile(atPath: path, contents: nil)
            }
            let handle = try FileHandle(forWritingTo: URL(fileURLWithPath: path))
            try handle.seekToEnd()
            self.handle = handle
        } else {
            handle = nil
        }
    }

    deinit {
        try? handle?.close()
    }

    func record(
        operation: String, sizeBytes: Int, iteration: Int,
        sample: NetworkPerformanceSample, sizeMatches: Bool, digestMatches: Bool?
    ) throws {
        print(
            "PERF_NETWORK_SAMPLE operation=\(operation) size_bytes=\(sizeBytes) iteration=\(iteration) " +
                "latency_ms=\(format(sample.wallMilliseconds))"
        )
        guard let handle else { return }
        var line = configuration.metadata
        line["operation"] = operation
        line["size_bytes"] = sizeBytes
        line["iteration"] = iteration
        line["warmup_iterations"] = configuration.warmupIterations
        line["measured_iterations"] = configuration.measuredIterations
        line["wall_ms"] = sample.wallMilliseconds
        line["throughput_mib_s"] = Double(sizeBytes) / 1_048_576 / (sample.wallMilliseconds / 1_000)
        line["client_user_cpu_ms"] = sample.userCPUMilliseconds
        line["client_system_cpu_ms"] = sample.systemCPUMilliseconds
        line["client_max_rss_kib"] = sample.maxRSSKiB
        line["sent_bytes"] = sample.transport.sentBytes
        line["received_bytes"] = sample.transport.receivedBytes
        line["send_calls"] = sample.transport.sendCalls
        line["receive_calls"] = sample.transport.receiveCalls
        let commandsAvailable = !sample.transport.sawEncryptedFrame && !sample.transport.sawUnparsedSend
        line["read_commands"] = commandsAvailable ? sample.transport.readCommands : NSNull()
        line["write_commands"] = commandsAvailable ? sample.transport.writeCommands : NSNull()
        line["size_matches"] = sizeMatches
        line["sha256_matches"] = digestMatches.map { $0 as Any } ?? NSNull()
        let data = try JSONSerialization.data(withJSONObject: line, options: [.sortedKeys])
        try handle.write(contentsOf: data + Data("\n".utf8))
    }

    func summary(operation: String, sizeBytes: Int, milliseconds: [Double]) {
        let totalSeconds = milliseconds.reduce(0, +) / 1_000
        let transferredMiB = Double(sizeBytes * milliseconds.count) / 1_048_576
        print(
            "PERF_NETWORK operation=\(operation) iterations=\(milliseconds.count) " +
                "size_bytes=\(sizeBytes) throughput_mib_s=\(format(transferredMiB / totalSeconds)) " +
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

    private func format(_ value: Double) -> String {
        String(format: "%.3f", value)
    }
}
