import Foundation
import XCTest
@testable import SMBee
#if os(Linux)
import Glibc
#else
import Darwin
#endif

final class SMBeePerformanceRegressionTests: XCTestCase {
    // This fixture represents a server after negotiation with ample credits.
    fileprivate let negotiatedServerCredits: UInt32 = 64
    private let credential = SMBCredential(username: "user", password: "pass")
    private let fileId = Array(UInt8(0)..<UInt8(16))
    private let treeId: UInt32 = 0x3344
    private let signingKey = Array(repeating: UInt8(0x11), count: 16)

    func testReadStreamingUsesExpectedReadCommandChunkAndByteCounts() async throws {
        let fileSize = 64 * 1024 * 2 + 123
        let effectiveReadChunkSize = SMBTransferLimits.negotiatedChunkSize(
            localLimit: SMBSession.localReadChunkLimit,
            negotiatedLimit: UInt32.max,
            transformOverhead: 0
        )
        let expectedChunks = ceilDiv(fileSize, effectiveReadChunkSize)
        let inbound = try framed(
            [try smb2CreateResponse(fileId: fileId, messageId: 0, treeId: treeId),
             try smb2QueryInfoResponse(size: UInt64(fileSize), messageId: 1, treeId: treeId)]
                + readResponses(fileSize: fileSize, chunkSize: effectiveReadChunkSize, firstMessageId: 2)
                + [try smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.close, messageId: UInt64(2 + expectedChunks), treeId: treeId)]
        )
        let transport = PerformanceInMemoryTransport(inbound: inbound)
        let clientSession = makeClientSession(transport: transport, initialCredits: negotiatedServerCredits)
        let sink = CountingChunkSink()

        try await clientSession.withReadStream(path: "large.bin") { chunk in
            sink.record(chunk)
        }

        let counter = try SMBCommandCounter(outbound: transport.outbound)
        counter.assertMetric("read_stream.commands.READ", command: SMB2Commands.read, expected: expectedChunks)
        sink.assertMetric("read_stream.chunks", actual: sink.chunkCount, expected: expectedChunks)
        sink.assertMetric("read_stream.bytes", actual: sink.byteCount, expected: fileSize)
    }

    func testWriteStreamingUsesExpectedWriteCommandAndByteCounts() async throws {
        XCTAssertEqual(SMBClientSession.localWriteChunkLimit, 1024 * 1024)
        let fileSize = 64 * 1024 * 2 + 321
        let effectiveWriteChunkSize = SMBTransferLimits.negotiatedChunkSize(
            localLimit: 64 * 1024,
            negotiatedLimit: UInt32.max,
            transformOverhead: 0
        )
        let expectedChunks = ceilDiv(fileSize, effectiveWriteChunkSize)
        let inbound = try framed(
            [
                try negotiateResponse(messageId: 0),
                try sessionSetupChallengeResponse(messageId: 1, sessionId: 0x1122_3344_5566_7788),
                try smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.sessionSetup, messageId: 2, treeId: 0),
                try smb2TreeConnectResponse(treeId: treeId),
                try smb2CreateResponse(fileId: fileId, messageId: 4, treeId: treeId)
            ]
                + writeResponses(fileSize: fileSize, chunkSize: effectiveWriteChunkSize, firstMessageId: 5)
                + [
                    try smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.flush, messageId: UInt64(5 + expectedChunks), treeId: treeId),
                    try smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.close, messageId: UInt64(6 + expectedChunks), treeId: treeId)
                ]
        )
        let transport = PerformanceInMemoryTransport(inbound: inbound)
        let source = try TemporaryCountingFile(byteCount: fileSize)
        defer { source.remove() }

        try await SMBClient.upload(
            host: "server",
            share: "share",
            path: "large.bin",
            localFile: source.url,
            credential: credential,
            makeTransport: { transport }
        )

        let counter = try SMBCommandCounter(outbound: transport.outbound)
        counter.assertMetric("write_stream.commands.WRITE", command: SMB2Commands.write, expected: expectedChunks)
        counter.assertMetric("write_stream.bytes", actual: try counter.totalWritePayloadBytes(), expected: fileSize)
    }

    func testPersistentSessionReusesNegotiationSessionSetupAndTreeConnect() async throws {
        let statFileId = Array(UInt8(16)..<UInt8(32))
        let directoryFileId = Array(UInt8(32)..<UInt8(48))
        let readFileId = Array(UInt8(48)..<UInt8(64))
        let inbound = try framed([
            try negotiateResponse(messageId: 0),
            try sessionSetupChallengeResponse(messageId: 1, sessionId: 0x1122_3344_5566_7788),
            try smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.sessionSetup, messageId: 2, treeId: 0),
            try smb2TreeConnectResponse(treeId: treeId),
            try smb2CreateResponse(fileId: statFileId, messageId: 4, treeId: treeId),
            try smb2QueryInfoResponse(size: 3, messageId: 5, treeId: treeId),
            try smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.close, messageId: 6, treeId: treeId),
            try smb2CreateResponse(fileId: readFileId, messageId: 7, treeId: treeId),
            try smb2QueryInfoResponse(size: 3, messageId: 8, treeId: treeId),
            try smb2ReadResponse(Array("abc".utf8), messageId: 9, treeId: treeId),
            try smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.close, messageId: 10, treeId: treeId),
            try smb2CreateResponse(fileId: directoryFileId, messageId: 11, treeId: treeId),
            try smb2QueryDirectoryResponse(
                entries: [makeDirectoryEntry(name: "a.txt", isDirectory: false, fileSize: 3, nextOffset: 0)],
                messageId: 12,
                treeId: treeId
            ),
            try smb2StatusResponse(status: SMB2Status.noMoreFiles, command: SMB2Commands.queryDirectory, messageId: 13, treeId: treeId),
            try smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.close, messageId: 14, treeId: treeId)
        ])
        let transport = PerformanceInMemoryTransport(inbound: inbound)
        let session = try await SMBClient.connect(
            host: "server",
            share: "share",
            credential: credential,
            makeTransport: { transport }
        )

        _ = try await session.stat(path: "a.txt")
        try await session.withReadStream(path: "a.txt") { _ in }
        _ = try await session.list(path: "")

        let counter = try SMBCommandCounter(outbound: transport.outbound)
        counter.assertMetric("persistent_session.commands.NEGOTIATE", command: SMBNegotiateConstants.commandNegotiate, expected: 1)
        counter.assertMetric("persistent_session.commands.SESSION_SETUP", actual: counter.count(SMB2Commands.sessionSetup), expected: 2)
        counter.assertMetric("persistent_session.commands.TREE_CONNECT", command: SMB2Commands.treeConnect, expected: 1)
    }

    func testPreauthMessagesAreSentWithUnpatchedCreditRequest() async throws {
        let inbound = try framed([
            try negotiateResponse(messageId: 0),
            try sessionSetupChallengeResponse(messageId: 1, sessionId: 0x1122_3344_5566_7788),
            try smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.sessionSetup, messageId: 2, treeId: 0),
            try smb2TreeConnectResponse(treeId: treeId),
            try smb2CreateResponse(fileId: fileId, messageId: 4, treeId: treeId),
            try smb2QueryInfoResponse(size: 3, messageId: 5, treeId: treeId),
            try smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.close, messageId: 6, treeId: treeId)
        ])
        let transport = PerformanceInMemoryTransport(inbound: inbound)
        let session = try await SMBClient.connect(
            host: "server",
            share: "share",
            credential: credential,
            makeTransport: { transport }
        )

        _ = try await session.stat(path: "a.txt")

        let headers = try unframed(transport.outbound).map { try SMB2Header.decode($0) }
        let preauthHeaders = headers.filter {
            $0.command == SMBNegotiateConstants.commandNegotiate || $0.command == SMB2Commands.sessionSetup
        }
        XCTAssertFalse(preauthHeaders.isEmpty)
        let preauthDefaultCredits = preauthHeaders[0].credits

        // Preauth bytes feed the SMB 3.1.1 integrity hash, so credit patching here
        // would desynchronize the signing key. This is a Docker-free regression guard.
        XCTAssertTrue(preauthHeaders.allSatisfy { $0.credits == preauthDefaultCredits })
        XCTAssertEqual(preauthDefaultCredits, 1)

        let treeConnect = try XCTUnwrap(headers.first { $0.command == SMB2Commands.treeConnect })
        XCTAssertGreaterThan(treeConnect.credits, preauthDefaultCredits)
    }

    private func makeClientSession(transport: PerformanceInMemoryTransport, initialCredits: UInt32 = 1) -> SMBClientSession {
        let session = SMBSession(host: "server", port: 445, credential: credential, transport: transport, signingKey: signingKey, initialCredits: initialCredits)
        return SMBClientSession(session: session, treeId: treeId)
    }

    private func readResponses(fileSize: Int, chunkSize: Int, firstMessageId: UInt64) throws -> [[UInt8]] {
        try chunkLengths(fileSize: fileSize, chunkSize: chunkSize).enumerated().map { index, length in
            try smb2ReadResponse(Array(repeating: UInt8(index & 0xff), count: length), messageId: firstMessageId + UInt64(index), treeId: treeId)
        }
    }

    private func writeResponses(fileSize: Int, chunkSize: Int, firstMessageId: UInt64) throws -> [[UInt8]] {
        try chunkLengths(fileSize: fileSize, chunkSize: chunkSize).enumerated().map { index, length in
            try smb2WriteResponse(count: length, messageId: firstMessageId + UInt64(index), treeId: treeId)
        }
    }
}

final class SMBeeResourcePerformanceTests: XCTestCase {
    private let measuredRuns = 5
    private let payloadSize = 8 * 1024 * 1024
    private let readIterationsPerSample = 20
    private let writeIterationsPerSample = 14
    private let treeId: UInt32 = 0x3344
    private let fileId = Array(UInt8(0)..<UInt8(16))
    private let credential = SMBCredential(username: "user", password: "pass")
    private let signingKey = Array(repeating: UInt8(0x11), count: 16)
    private let initialCredits: UInt32 = 1

    func testSyntheticReadStreamResourceUsage() async throws {
        try requireReleaseConfiguration()
        print("PERF_FORMAT version=1")
        _ = try await measureRead(size: 1024 * 1024)
        var samples: [ResourcePerformanceSample] = []
        for _ in 0..<measuredRuns {
            var iterations: [ResourcePerformanceSample] = []
            for _ in 0..<readIterationsPerSample {
                iterations.append(try await measureRead(size: payloadSize))
            }
            samples.append(ResourcePerformanceSample.combining(iterations))
        }
        assertAndPrint(samples: samples, operation: "read_stream", iterationsPerSample: readIterationsPerSample)
        print("PERF_RUN_COMPLETE operation=read_stream")
    }

    func testSyntheticWriteStreamResourceUsage() async throws {
        try requireReleaseConfiguration()
        print("PERF_FORMAT version=1")
        _ = try await measureWrite(size: 1024 * 1024)
        var samples: [ResourcePerformanceSample] = []
        for _ in 0..<measuredRuns {
            var iterations: [ResourcePerformanceSample] = []
            for _ in 0..<writeIterationsPerSample {
                iterations.append(try await measureWrite(size: payloadSize))
            }
            samples.append(ResourcePerformanceSample.combining(iterations))
        }
        assertAndPrint(samples: samples, operation: "write_stream", iterationsPerSample: writeIterationsPerSample)
        print("PERF_RUN_COMPLETE operation=write_stream")
    }

    func testSyntheticWriteStageProfile() async throws {
        try requireReleaseConfiguration()
        let chunkSize = 64 * 1024
        let chunks = chunkLengths(fileSize: payloadSize, chunkSize: chunkSize)
        let payload = Array(repeating: UInt8(0xa5), count: chunkSize)
        let packets = try chunks.enumerated().map { index, length in
            try SMB2Write.encodeRequest(
                messageId: UInt64(index), sessionId: 1, treeId: treeId, fileId: fileId,
                offset: UInt64(index * chunkSize), data: length == chunkSize ? payload : Array(payload.prefix(length))
            )
        }

        // Warm every measured path with the complete workload before collecting samples.
        _ = try signPackets(packets, usingPureSwiftBackend: false)
        _ = try signPackets(packets, usingPureSwiftBackend: true)
        _ = try await measureWriteSample(size: 1024 * 1024, retainOutbound: false)
        _ = try await measureWriteSample(size: 1024 * 1024, retainOutbound: true)

        var codecSamples: [Double] = []
        var signingSamples: [Double] = []
        var pureSwiftSigningSamples: [Double] = []
        var sessionSamples: [Double] = []
        var fullSamples: [Double] = []
        for run in 0..<measuredRuns {
            var encodedBytes = 0
            var start = ContinuousClock.now
            for (index, length) in chunks.enumerated() {
                encodedBytes += try SMB2Write.encodeRequest(
                    messageId: UInt64(index), sessionId: 1, treeId: treeId, fileId: fileId,
                    offset: UInt64(index * chunkSize), data: length == chunkSize ? payload : Array(payload.prefix(length))
                ).count
            }
            codecSamples.append(start.duration(to: ContinuousClock.now).secondsAsDouble * 1000)
            XCTAssertGreaterThan(encodedBytes, payloadSize)

            sessionSamples.append(
                try await measureWriteSample(size: payloadSize, retainOutbound: false).elapsedMilliseconds
            )
            fullSamples.append(
                try await measureWriteSample(size: payloadSize, retainOutbound: true).elapsedMilliseconds
            )

            // Alternate the backend order so clock/thermal drift is not assigned to one side.
            let backendOrder = run.isMultiple(of: 2) ? [false, true] : [true, false]
            for usePureSwift in backendOrder {
                start = ContinuousClock.now
                let signatureBytes = try signPackets(packets, usingPureSwiftBackend: usePureSwift)
                let elapsed = start.duration(to: ContinuousClock.now).secondsAsDouble * 1000
                XCTAssertEqual(signatureBytes, chunks.count * 16)
                if usePureSwift {
                    pureSwiftSigningSamples.append(elapsed)
                } else {
                    signingSamples.append(elapsed)
                }
            }
        }

        printWriteProfile(stage: "codec_only", samples: codecSamples)
        printWriteProfile(stage: "signing_only", samples: signingSamples)
        printWriteProfile(stage: "pure_swift_signing_only", samples: pureSwiftSigningSamples)
        printWriteProfile(stage: "session_no_outbound_retention", samples: sessionSamples)
        printWriteProfile(stage: "full_synthetic", samples: fullSamples)
    }

    func testSyntheticCMACScalingProfile() throws {
        try requireReleaseConfiguration()
        let chunkSize = 64 * 1024
        for sizeMiB in [4, 8, 16] {
            let size = sizeMiB * 1024 * 1024
            let payload = Array(repeating: UInt8(0xa5), count: chunkSize)
            let packets = try chunkLengths(fileSize: size, chunkSize: chunkSize).enumerated().map { index, length in
                try SMB2Write.encodeRequest(
                    messageId: UInt64(index), sessionId: 1, treeId: treeId, fileId: fileId,
                    offset: UInt64(index * chunkSize), data: length == chunkSize ? payload : Array(payload.prefix(length))
                )
            }
            let iterations = 512 / sizeMiB
            _ = try signPackets(packets, usingPureSwiftBackend: false)
            var samples: [CMACScalingSample] = []
            for run in 1...measuredRuns {
                let rssBefore = ResourceUsageSnapshot.currentRSSKilobytes()
                let before = ResourceUsageSnapshot.current()
                let start = ContinuousClock.now
                var signatureBytes = 0
                for _ in 0..<iterations {
                    signatureBytes += try signPackets(packets, usingPureSwiftBackend: false)
                }
                let elapsed = start.duration(to: ContinuousClock.now).secondsAsDouble * 1000
                let after = ResourceUsageSnapshot.current()
                let rssAfter = ResourceUsageSnapshot.currentRSSKilobytes()
                XCTAssertEqual(signatureBytes, packets.count * 16 * iterations)
                let sample = CMACScalingSample(
                    elapsedMilliseconds: elapsed,
                    userCPUMilliseconds: Double(after.userMicroseconds - before.userMicroseconds) / 1000,
                    currentRSSBeforeKilobytes: rssBefore,
                    currentRSSAfterKilobytes: rssAfter,
                    maxRSSKilobytes: after.maxRSSKilobytes
                )
                samples.append(sample)
                let totalSizeMiB = sizeMiB * iterations
                print(
                    "PERF_CMAC_SCALING_SAMPLE size_mib=\(sizeMiB) chunks=\(packets.count) "
                        + "iterations=\(iterations) run=\(run) elapsed_ms=\(format(sample.elapsedMilliseconds)) "
                        + "throughput_mib_s=\(format(Double(totalSizeMiB) / (sample.elapsedMilliseconds / 1000))) "
                        + "user_cpu_ms=\(format(sample.userCPUMilliseconds)) "
                        + "current_rss_before_kb=\(sample.currentRSSBeforeKilobytes) "
                        + "current_rss_after_kb=\(sample.currentRSSAfterKilobytes) max_rss_kb=\(sample.maxRSSKilobytes)"
                )
            }
            let elapsed = median(samples.map(\.elapsedMilliseconds))
            let userCPU = median(samples.map(\.userCPUMilliseconds))
            let rssBefore = median(samples.map { Double($0.currentRSSBeforeKilobytes) })
            let rssAfter = median(samples.map { Double($0.currentRSSAfterKilobytes) })
            let peakRSS = samples.map(\.maxRSSKilobytes).max() ?? 0
            let throughput = Double(sizeMiB * iterations) / (elapsed / 1000)
            print(
                "PERF_CMAC_SCALING size_mib=\(sizeMiB) chunks=\(packets.count) iterations=\(iterations) "
                    + "runs=\(measuredRuns) median_ms=\(format(elapsed)) throughput_mib_s=\(format(throughput)) "
                    + "user_cpu_ms=\(format(userCPU)) current_rss_before_kb=\(Int64(rssBefore)) "
                    + "current_rss_after_kb=\(Int64(rssAfter)) max_rss_kb=\(peakRSS)"
            )
        }
    }

    private func signPackets(_ packets: [[UInt8]], usingPureSwiftBackend: Bool) throws -> Int {
        var signatureBytes = 0
        for packet in packets {
            if usingPureSwiftBackend {
                var normalized = packet
                for index in 48..<64 { normalized[index] = 0 }
                signatureBytes += try AESCMAC.pureSwiftAuthenticationCode(
                    key: signingKey, message: normalized
                ).count
            } else {
                var normalized = packet
                for index in 48..<64 { normalized[index] = 0 }
                signatureBytes += try SMBSessionSigning.signatureForNormalizedPacket(
                    algorithm: .aesCMAC, key: signingKey, packet: normalized, sender: .client
                ).count
            }
        }
        return signatureBytes
    }

    private func measureRead(size: Int) async throws -> ResourcePerformanceSample {
        let chunkSize = 64 * 1024
        let lengths = chunkLengths(fileSize: size, chunkSize: chunkSize)
        let inbound = try framed(
            [
                try smb2CreateResponse(fileId: fileId, messageId: 0, treeId: treeId),
                try smb2QueryInfoResponse(size: UInt64(size), messageId: 1, treeId: treeId)
            ] + lengths.enumerated().map { index, length in
                try smb2ReadResponse(
                    Array(repeating: UInt8(index & 0xff), count: length),
                    messageId: UInt64(index + 2),
                    treeId: treeId
                )
            } + [
                try smb2StatusResponse(
                    status: SMB2Status.success,
                    command: SMB2Commands.close,
                    messageId: UInt64(lengths.count + 2),
                    treeId: treeId
                )
            ]
        )
        let transport = PerformanceInMemoryTransport(inbound: inbound)
        let session = SMBSession(
            host: "server", port: 445, credential: credential, transport: transport,
            signingKey: signingKey, initialCredits: initialCredits
        )
        let client = SMBClientSession(session: session, treeId: treeId)
        let sink = CountingChunkSink()
        let before = ResourceUsageSnapshot.current()
        let start = ContinuousClock.now
        try await client.withReadStream(path: "resource.bin") { sink.record($0) }
        let elapsed = start.duration(to: ContinuousClock.now).secondsAsDouble
        let after = ResourceUsageSnapshot.current()
        XCTAssertEqual(sink.byteCount, size)
        return ResourcePerformanceSample(size: size, elapsedSeconds: elapsed, before: before, after: after)
    }

    private func requireReleaseConfiguration() throws {
        if _isDebugAssertConfiguration() {
            throw XCTSkip("Resource performance metrics run only with swift test -c release")
        }
    }

    private func measureWrite(size: Int) async throws -> ResourcePerformanceSample {
        try await measureWriteSample(size: size, retainOutbound: true)
    }

    private func measureWriteSample(size: Int, retainOutbound: Bool) async throws -> ResourcePerformanceSample {
        let chunkSize = 64 * 1024
        let lengths = chunkLengths(fileSize: size, chunkSize: chunkSize)
        let inbound = try framed(
            [try smb2CreateResponse(fileId: fileId, messageId: 0, treeId: treeId)]
                + lengths.enumerated().map { index, length in
                    try smb2WriteResponse(count: length, messageId: UInt64(index + 1), treeId: treeId)
                } + [
                    try smb2StatusResponse(
                        status: SMB2Status.success,
                        command: SMB2Commands.flush,
                        messageId: UInt64(lengths.count + 1),
                        treeId: treeId
                    ),
                    try smb2StatusResponse(
                        status: SMB2Status.success,
                        command: SMB2Commands.close,
                        messageId: UInt64(lengths.count + 2),
                        treeId: treeId
                    )
                ]
        )
        let transport = PerformanceInMemoryTransport(inbound: inbound, retainOutbound: retainOutbound)
        let session = SMBSession(
            host: "server", port: 445, credential: credential, transport: transport,
            signingKey: signingKey, initialCredits: initialCredits
        )
        let client = SMBClientSession(session: session, treeId: treeId)
        let payload = Array(repeating: UInt8(0xa5), count: size)
        let before = ResourceUsageSnapshot.current()
        let start = ContinuousClock.now
        try await client.upload(path: "resource.bin", data: payload)
        let elapsed = start.duration(to: ContinuousClock.now).secondsAsDouble
        let after = ResourceUsageSnapshot.current()
        XCTAssertGreaterThan(transport.sentByteCount, size)
        return ResourcePerformanceSample(size: size, elapsedSeconds: elapsed, before: before, after: after)
    }

    private func printWriteProfile(stage: String, samples: [Double]) {
        let value = median(samples)
        let throughput = Double(payloadSize) / (value / 1000) / 1024 / 1024
        print(
            "PERF_WRITE_PROFILE stage=\(stage) median_ms=\(format(value)) "
                + "throughput_mib_s=\(format(throughput)) size_mib=8 runs=\(measuredRuns) chunks=128"
        )
    }

    private func assertAndPrint(samples: [ResourcePerformanceSample], operation: String, iterationsPerSample: Int) {
        let throughput = median(samples.map(\.throughputMiBPerSecond))
        let userCPU = median(samples.map(\.userCPUMilliseconds))
        let systemCPU = median(samples.map(\.systemCPUMilliseconds))
        let elapsed = median(samples.map(\.elapsedMilliseconds))
        let maxRSS = samples.map(\.maxRSSKilobytes).max() ?? 0
        let totalSizeMiB = (samples.first?.size ?? 0) / (1024 * 1024)
        let throughputFloor = operation == "read_stream" ? 400 : 5
        for (index, sample) in samples.enumerated() {
            print(
                "PERF_RESOURCE_SAMPLE operation=\(operation) run=\(index + 1) "
                    + "elapsed_ms=\(format(sample.elapsedMilliseconds)) throughput_mib_s=\(format(sample.throughputMiBPerSecond)) "
                    + "user_cpu_ms=\(format(sample.userCPUMilliseconds)) system_cpu_ms=\(format(sample.systemCPUMilliseconds)) "
                    + "max_rss_kb=\(sample.maxRSSKilobytes) total_size_mib=\(totalSizeMiB) iterations=\(iterationsPerSample)"
            )
        }
        let common = "size_mib=\(totalSizeMiB) runs=\(measuredRuns) iterations=\(iterationsPerSample) throughput_floor_mib_s=\(throughputFloor) config=release"
        print("PERF_RESOURCE \(operation).throughput_mib_s value=\(format(throughput)) \(common)")
        print("PERF_RESOURCE \(operation).user_cpu_ms value=\(format(userCPU)) \(common)")
        print("PERF_RESOURCE \(operation).system_cpu_ms value=\(format(systemCPU)) \(common)")
        print("PERF_RESOURCE \(operation).sample_elapsed_ms value=\(format(elapsed)) \(common)")
        print("PERF_RESOURCE \(operation).max_rss_kb value=\(maxRSS) \(common)")
        XCTAssertGreaterThan(throughput, Double(throughputFloor), "catastrophic synthetic \(operation) throughput regression")
        XCTAssertGreaterThanOrEqual(elapsed, 200, "synthetic \(operation) sample is too short for stable timing")
        XCTAssertLessThan(maxRSS, 512 * 1024, "catastrophic synthetic \(operation) RSS regression")
    }

    private func median(_ values: [Double]) -> Double {
        let sorted = values.sorted()
        return sorted[sorted.count / 2]
    }

    private func format(_ value: Double) -> String {
        String(format: "%.3f", value)
    }
}

private struct ResourceUsageSnapshot {
    let userMicroseconds: Int64
    let systemMicroseconds: Int64
    let maxRSSKilobytes: Int64

    static func current() -> ResourceUsageSnapshot {
        var usage = rusage()
#if os(Linux)
        _ = getrusage(__rusage_who_t(RUSAGE_SELF.rawValue), &usage)
        let maxRSS = Int64(usage.ru_maxrss)
#else
        _ = getrusage(RUSAGE_SELF, &usage)
        let maxRSS = Int64(usage.ru_maxrss) / 1024
#endif
        return ResourceUsageSnapshot(
            userMicroseconds: micros(usage.ru_utime),
            systemMicroseconds: micros(usage.ru_stime),
            maxRSSKilobytes: maxRSS
        )
    }

    static func currentRSSKilobytes() -> Int64 {
#if os(Linux)
        guard
            let statm = try? String(contentsOfFile: "/proc/self/statm", encoding: .utf8),
            let residentPages = Int64(statm.split(separator: " ").dropFirst().first ?? ""),
            residentPages >= 0
        else { return 0 }
        return residentPages * Int64(sysconf(Int32(_SC_PAGESIZE))) / 1024
#else
        var info = mach_task_basic_info()
        var count = mach_msg_type_number_t(
            MemoryLayout<mach_task_basic_info>.size / MemoryLayout<integer_t>.size
        )
        let result = withUnsafeMutablePointer(to: &info) { infoPointer in
            infoPointer.withMemoryRebound(to: integer_t.self, capacity: Int(count)) { integerPointer in
                task_info(
                    mach_task_self_,
                    task_flavor_t(MACH_TASK_BASIC_INFO),
                    integerPointer,
                    &count
                )
            }
        }
        return result == KERN_SUCCESS ? Int64(info.resident_size) / 1024 : 0
#endif
    }

    private static func micros(_ value: timeval) -> Int64 {
        Int64(value.tv_sec) * 1_000_000 + Int64(value.tv_usec)
    }
}

private struct CMACScalingSample {
    let elapsedMilliseconds: Double
    let userCPUMilliseconds: Double
    let currentRSSBeforeKilobytes: Int64
    let currentRSSAfterKilobytes: Int64
    let maxRSSKilobytes: Int64
}

private struct ResourcePerformanceSample {
    let size: Int
    let elapsedSeconds: Double
    let userMicroseconds: Int64
    let systemMicroseconds: Int64
    let maxRSSKilobytes: Int64

    init(size: Int, elapsedSeconds: Double, before: ResourceUsageSnapshot, after: ResourceUsageSnapshot) {
        self.size = size
        self.elapsedSeconds = elapsedSeconds
        self.userMicroseconds = after.userMicroseconds - before.userMicroseconds
        self.systemMicroseconds = after.systemMicroseconds - before.systemMicroseconds
        self.maxRSSKilobytes = after.maxRSSKilobytes
    }

    private init(size: Int, elapsedSeconds: Double, userMicroseconds: Int64, systemMicroseconds: Int64, maxRSSKilobytes: Int64) {
        self.size = size
        self.elapsedSeconds = elapsedSeconds
        self.userMicroseconds = userMicroseconds
        self.systemMicroseconds = systemMicroseconds
        self.maxRSSKilobytes = maxRSSKilobytes
    }

    static func combining(_ samples: [ResourcePerformanceSample]) -> ResourcePerformanceSample {
        precondition(!samples.isEmpty)
        return ResourcePerformanceSample(
            size: samples.reduce(0) { $0 + $1.size },
            elapsedSeconds: samples.reduce(0) { $0 + $1.elapsedSeconds },
            userMicroseconds: samples.reduce(0) { $0 + $1.userMicroseconds },
            systemMicroseconds: samples.reduce(0) { $0 + $1.systemMicroseconds },
            maxRSSKilobytes: samples.map(\.maxRSSKilobytes).max() ?? 0
        )
    }

    var throughputMiBPerSecond: Double {
        Double(size) / elapsedSeconds / 1024 / 1024
    }

    var userCPUMilliseconds: Double {
        Double(userMicroseconds) / 1000
    }

    var systemCPUMilliseconds: Double {
        Double(systemMicroseconds) / 1000
    }

    var elapsedMilliseconds: Double { elapsedSeconds * 1000 }
}

private extension Duration {
    var secondsAsDouble: Double {
        let parts = components
        return Double(parts.seconds) + Double(parts.attoseconds) / 1e18
    }
}

private final class PerformanceInMemoryTransport: SMBTransport, @unchecked Sendable {
    private let lock = NSLock()
    private var inbound: [UInt8]
    private var inboundOffset = 0
    private var outboundStorage: [UInt8] = []
    private var sentBytes = 0
    private let retainOutbound: Bool

    var outbound: [UInt8] {
        lock.lock()
        defer { lock.unlock() }
        return outboundStorage
    }

    var sentByteCount: Int {
        lock.withLock { sentBytes }
    }

    init(inbound: [UInt8], retainOutbound: Bool = true) {
        self.inbound = inbound
        self.retainOutbound = retainOutbound
    }

    func connect(host: String, port: UInt16) async throws {
        try Task.checkCancellation()
        _ = host
        _ = port
    }

    func send(_ bytes: [UInt8]) async throws {
        try Task.checkCancellation()
        lock.withLock {
            sentBytes += bytes.count
            if retainOutbound {
                outboundStorage.append(contentsOf: bytes)
            }
        }
    }

    func receive(maxLength: Int) async throws -> [UInt8] {
        try Task.checkCancellation()
        return try lock.withLock {
            guard inboundOffset < inbound.count else { throw SMBTransportError.connectionClosed }
            let count = min(maxLength, inbound.count - inboundOffset)
            let chunk = Array(inbound[inboundOffset..<(inboundOffset + count)])
            inboundOffset += count
            return chunk
        }
    }

    func close() {}
}

private struct SMBCommandCounter {
    private let requests: [[UInt8]]
    private let histogram: [UInt16: Int]

    init(outbound: [UInt8]) throws {
        let requests = try unframed(outbound)
        self.requests = requests
        self.histogram = try requests.reduce(into: [:]) { result, request in
            let command = try SMB2Header.decode(request).command
            result[command, default: 0] += 1
        }
    }

    func count(_ command: UInt16) -> Int {
        histogram[command, default: 0]
    }

    func assertMetric(_ name: String, command: UInt16, expected: Int, file: StaticString = #filePath, line: UInt = #line) {
        assertMetric(name, actual: count(command), expected: expected, file: file, line: line)
    }

    func assertMetric(_ name: String, actual: Int, expected: Int, file: StaticString = #filePath, line: UInt = #line) {
        print("PERF_METRIC \(name) actual=\(actual) expected=\(expected)")
        XCTAssertEqual(actual, expected, file: file, line: line)
    }

    func totalWritePayloadBytes() throws -> Int {
        try requests.reduce(0) { total, request in
            guard try SMB2Header.decode(request).command == SMB2Commands.write else { return total }
            return total + Int(readUInt32LE(request, at: 68))
        }
    }
}

private final class CountingChunkSink: @unchecked Sendable {
    private let lock = NSLock()
    private var chunks = 0
    private var bytes = 0

    var chunkCount: Int {
        lock.lock()
        defer { lock.unlock() }
        return chunks
    }

    var byteCount: Int {
        lock.lock()
        defer { lock.unlock() }
        return bytes
    }

    func record(_ chunk: [UInt8]) {
        lock.lock()
        chunks += 1
        bytes += chunk.count
        lock.unlock()
    }

    func assertMetric(_ name: String, actual: Int, expected: Int, file: StaticString = #filePath, line: UInt = #line) {
        print("PERF_METRIC \(name) actual=\(actual) expected=\(expected)")
        XCTAssertEqual(actual, expected, file: file, line: line)
    }
}

private struct TemporaryCountingFile {
    let url: URL

    init(byteCount: Int) throws {
        url = FileManager.default.temporaryDirectory.appendingPathComponent("smbee-perf-\(UUID().uuidString).bin")
        FileManager.default.createFile(atPath: url.path, contents: nil)
        let handle = try FileHandle(forWritingTo: url)
        defer { try? handle.close() }
        var remaining = byteCount
        let block = Data(repeating: 0xa5, count: 16 * 1024)
        while remaining > 0 {
            let count = min(remaining, block.count)
            try handle.write(contentsOf: block.prefix(count))
            remaining -= count
        }
    }

    func remove() {
        try? FileManager.default.removeItem(at: url)
    }
}

private func ceilDiv(_ lhs: Int, _ rhs: Int) -> Int {
    precondition(lhs >= 0)
    precondition(rhs > 0)
    return (lhs + rhs - 1) / rhs
}

private func chunkLengths(fileSize: Int, chunkSize: Int) -> [Int] {
    stride(from: 0, to: fileSize, by: chunkSize).map { offset in
        min(chunkSize, fileSize - offset)
    }
}

private func readUInt32LE(_ bytes: [UInt8], at offset: Int) -> UInt32 {
    UInt32(bytes[offset])
        | (UInt32(bytes[offset + 1]) << 8)
        | (UInt32(bytes[offset + 2]) << 16)
        | (UInt32(bytes[offset + 3]) << 24)
}

private func writeUInt16LE(_ value: UInt16, to bytes: inout [UInt8], at offset: Int) {
    bytes[offset] = UInt8(value & 0xff)
    bytes[offset + 1] = UInt8((value >> 8) & 0xff)
}

private func writeUInt32LE(_ value: UInt32, to bytes: inout [UInt8], at offset: Int) {
    bytes[offset] = UInt8(value & 0xff)
    bytes[offset + 1] = UInt8((value >> 8) & 0xff)
    bytes[offset + 2] = UInt8((value >> 16) & 0xff)
    bytes[offset + 3] = UInt8((value >> 24) & 0xff)
}

private func writeUInt64LE(_ value: UInt64, to bytes: inout [UInt8], at offset: Int) {
    for index in 0..<8 {
        bytes[offset + index] = UInt8((value >> UInt64(index * 8)) & 0xff)
    }
}

private func hexBytes(_ string: String) -> [UInt8] {
    precondition(string.count.isMultiple(of: 2))
    var bytes: [UInt8] = []
    var index = string.startIndex
    while index < string.endIndex {
        let next = string.index(index, offsetBy: 2)
        bytes.append(UInt8(string[index..<next], radix: 16)!)
        index = next
    }
    return bytes
}

private func smb2CreateResponse(fileId: [UInt8], messageId: UInt64, treeId: UInt32) throws -> [UInt8] {
    var response = try SMB2Header(command: SMB2Commands.create, messageId: messageId, treeId: treeId).encode()
    response.append(contentsOf: Array(repeating: UInt8(0), count: 88))
    writeUInt16LE(89, to: &response, at: 64)
    response.replaceSubrange(128..<144, with: fileId)
    return response
}

private func smb2ReadResponse(_ payload: [UInt8], messageId: UInt64, treeId: UInt32) throws -> [UInt8] {
    var response = try SMB2Header(command: SMB2Commands.read, messageId: messageId, treeId: treeId).encode()
    response.append(contentsOf: Array(repeating: UInt8(0), count: 16))
    writeUInt16LE(17, to: &response, at: 64)
    response[66] = 80
    writeUInt32LE(UInt32(payload.count), to: &response, at: 68)
    response.append(contentsOf: payload)
    return response
}

private func smb2WriteResponse(count: Int, messageId: UInt64, treeId: UInt32) throws -> [UInt8] {
    var response = try SMB2Header(command: SMB2Commands.write, messageId: messageId, treeId: treeId).encode()
    response.append(contentsOf: Array(repeating: UInt8(0), count: 16))
    writeUInt16LE(17, to: &response, at: 64)
    writeUInt32LE(UInt32(count), to: &response, at: 68)
    return response
}

private func smb2QueryInfoResponse(size: UInt64, messageId: UInt64, treeId: UInt32) throws -> [UInt8] {
    var payload = Array(repeating: UInt8(0), count: 56)
    writeUInt64LE(size, to: &payload, at: 40)
    var response = try SMB2Header(command: SMB2Commands.queryInfo, messageId: messageId, treeId: treeId).encode()
    response.append(contentsOf: Array(repeating: UInt8(0), count: 8))
    writeUInt16LE(9, to: &response, at: 64)
    writeUInt16LE(72, to: &response, at: 66)
    writeUInt32LE(UInt32(payload.count), to: &response, at: 68)
    response.append(contentsOf: payload)
    return response
}

private func smb2StatusResponse(status: UInt32, command: UInt16, messageId: UInt64, treeId: UInt32) throws -> [UInt8] {
    try SMB2Header(status: status, command: command, messageId: messageId, treeId: treeId).encode()
}

private func negotiateResponse(messageId: UInt64) throws -> [UInt8] {
    var response = try SMB2Header(command: SMBNegotiateConstants.commandNegotiate, messageId: messageId).encode()
    response.append(contentsOf: Array(repeating: UInt8(0), count: 65))
    writeUInt16LE(65, to: &response, at: 64)
    writeUInt16LE(SMBNegotiateConstants.signingEnabled, to: &response, at: 66)
    writeUInt16LE(SMBNegotiateConstants.dialect311, to: &response, at: 68)
    writeUInt16LE(2, to: &response, at: 70)
    response.replaceSubrange(72..<88, with: Array(repeating: UInt8(0x42), count: 16))
    writeUInt32LE(1_048_576, to: &response, at: 92)
    writeUInt32LE(1_048_576, to: &response, at: 96)
    // Keep this fixture credit/negotiation constrained; the assertion above covers
    // the production write limit while this test remains focused on accounting.
    writeUInt32LE(65_536, to: &response, at: 100)
    writeUInt16LE(UInt16(response.count), to: &response, at: 120)
    writeUInt16LE(0, to: &response, at: 122)
    writeUInt32LE(136, to: &response, at: 124)
    response.append(contentsOf: Array(repeating: UInt8(0), count: 7))
    response.append(contentsOf: negotiateContext(
        type: SMBNegotiateConstants.preauthContext,
        data: [0x01, 0x00, 0x00, 0x00, UInt8(SMBNegotiateConstants.sha512), 0x00],
        padTo8: true
    ))
    response.append(contentsOf: negotiateContext(
        type: SMBNegotiateConstants.signingContext,
        data: [0x01, 0x00, UInt8(SMBNegotiateConstants.aesGMAC), 0x00],
        padTo8: false
    ))
    return response
}

private func negotiateContext(type: UInt16, data: [UInt8], padTo8: Bool) -> [UInt8] {
    var writer = SMBByteWriter()
    writer.writeUInt16LE(type)
    writer.writeUInt16LE(UInt16(data.count))
    writer.writeUInt32LE(0)
    writer.writeBytes(data)
    if padTo8 {
        writer.padTo8()
    }
    return writer.bytes
}

private func sessionSetupChallengeResponse(messageId: UInt64, sessionId: UInt64) throws -> [UInt8] {
    let targetInfo = hexBytes("070008000090d336b734c30100000000")
    let blob = SPNEGO.wrapNegTokenResp(makeNTLMChallengeMessage(targetInfo: targetInfo))
    var response = try SMB2Header(
        status: SMB2Status.moreProcessingRequired,
        command: SMB2Commands.sessionSetup,
        messageId: messageId,
        sessionId: sessionId
    ).encode()
    response.append(contentsOf: Array(repeating: UInt8(0), count: 8))
    writeUInt16LE(9, to: &response, at: 64)
    writeUInt16LE(72, to: &response, at: 68)
    writeUInt16LE(UInt16(blob.count), to: &response, at: 70)
    response.append(contentsOf: blob)
    return response
}

private func smb2TreeConnectResponse(treeId: UInt32) throws -> [UInt8] {
    var response = try SMB2Header(command: SMB2Commands.treeConnect, messageId: 3, treeId: treeId).encode()
    response.append(contentsOf: Array(repeating: UInt8(0), count: 16))
    writeUInt16LE(16, to: &response, at: 64)
    response[66] = 1
    writeUInt32LE(0, to: &response, at: 68)
    writeUInt32LE(0, to: &response, at: 72)
    writeUInt32LE(0x001f_01ff, to: &response, at: 76)
    return response
}

private func smb2QueryDirectoryResponse(entries: [[UInt8]], messageId: UInt64, treeId: UInt32) throws -> [UInt8] {
    let payload = entries.flatMap { $0 }
    var response = try SMB2Header(command: SMB2Commands.queryDirectory, messageId: messageId, treeId: treeId).encode()
    response.append(contentsOf: Array(repeating: UInt8(0), count: 8))
    writeUInt16LE(9, to: &response, at: 64)
    writeUInt16LE(72, to: &response, at: 66)
    writeUInt32LE(UInt32(payload.count), to: &response, at: 68)
    response.append(contentsOf: payload)
    return response
}

private func makeDirectoryEntry(name: String, isDirectory: Bool, fileSize: UInt64 = 0, nextOffset: UInt32) -> [UInt8] {
    let nameBytes = NTLM.utf16le(name)
    var writer = SMBByteWriter()
    writer.writeUInt32LE(nextOffset)
    writer.writeUInt32LE(0)
    writer.writeUInt64LE(0)
    writer.writeUInt64LE(0)
    writer.writeUInt64LE(0)
    writer.writeUInt64LE(0)
    writer.writeUInt64LE(fileSize)
    writer.writeUInt64LE(fileSize)
    writer.writeUInt32LE(isDirectory ? 0x10 : 0x80)
    writer.writeUInt32LE(UInt32(nameBytes.count))
    writer.writeBytes(nameBytes)
    return writer.bytes
}

private func makeNTLMChallengeMessage(targetInfo: [UInt8]) -> [UInt8] {
    let targetName = NTLM.utf16le("Server")
    let targetNameOffset = UInt32(48)
    let targetInfoOffset = targetNameOffset + UInt32(targetName.count)
    var writer = SMBByteWriter()
    writer.writeBytes(Array("NTLMSSP\0".utf8))
    writer.writeUInt32LE(2)
    writer.writeUInt16LE(UInt16(targetName.count))
    writer.writeUInt16LE(UInt16(targetName.count))
    writer.writeUInt32LE(targetNameOffset)
    writer.writeUInt32LE(NTLM.negotiateFlags)
    writer.writeBytes(hexBytes("0123456789abcdef"))
    writer.writeBytes(Array(repeating: 0, count: 8))
    writer.writeUInt16LE(UInt16(targetInfo.count))
    writer.writeUInt16LE(UInt16(targetInfo.count))
    writer.writeUInt32LE(targetInfoOffset)
    writer.writeBytes(targetName)
    writer.writeBytes(targetInfo)
    return writer.bytes
}

private func framed(_ messages: [[UInt8]]) throws -> [UInt8] {
    try messages.reduce(into: []) { result, message in
        result.append(contentsOf: try DirectTCPFraming.frame(message))
    }
}

private func unframed(_ bytes: [UInt8]) throws -> [[UInt8]] {
    var frames: [[UInt8]] = []
    var cursor = 0
    while cursor < bytes.count {
        let length = try DirectTCPFraming.length(from: Array(bytes[cursor..<cursor + 4]))
        let start = cursor + 4
        let end = start + length
        frames.append(Array(bytes[start..<end]))
        cursor = end
    }
    return frames
}
