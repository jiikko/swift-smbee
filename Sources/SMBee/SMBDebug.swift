import Dispatch
import Foundation

enum SMBWireDataProvenance: Equatable, Sendable {
    case plaintext
    case ciphertext
    case metadata
}

struct SMBSessionDebugConfiguration: Sendable {
    let enabled: Bool
    let traceWire: Bool
    let traceWireFull: Bool

    static var environment: Self {
        Self(
            enabled: ProcessInfo.processInfo.environment["SMBEE_DEBUG"] == "1",
            traceWire: ProcessInfo.processInfo.environment["SMBEE_TRACE_WIRE"] == "1",
            traceWireFull: ProcessInfo.processInfo.environment["SMBEE_TRACE_WIRE_FULL"] == "1"
        )
    }
}

struct SMBSessionDebugLogger: Sendable {
#if DEBUG
    private static let outputQueue = DispatchQueue(label: "SMBee.debug-output")
#endif

    private let configurationProvider: @Sendable () -> SMBSessionDebugConfiguration
    private let sink: @Sendable (String) -> Void

    init(
        configuration: SMBSessionDebugConfiguration,
        sink: @escaping @Sendable (String) -> Void
    ) {
        self.configurationProvider = { configuration }
        self.sink = sink
    }

    private init(
        configurationProvider: @escaping @Sendable () -> SMBSessionDebugConfiguration,
        sink: @escaping @Sendable (String) -> Void
    ) {
        self.configurationProvider = configurationProvider
        self.sink = sink
    }

    static var environment: Self {
        // Snapshot once per logger (one per session): building ProcessInfo.environment on every
        // packet dump cost ~40% of read_stream throughput in the resource benchmark.
        let configuration = SMBSessionDebugConfiguration.environment
        return Self(
            configurationProvider: { configuration },
            sink: { message in FileHandle.standardError.write(Data("\(message)\n".utf8)) }
        )
    }

    func dump(
        _ label: String,
        bytes: [UInt8],
        provenance: SMBWireDataProvenance,
        encryptedSession: Bool
    ) {
        let configuration = configurationProvider()
        guard configuration.enabled else { return }
        let summary = SMBDebug.packetSummary(
            bytes,
            traceWire: configuration.traceWire,
            traceWireFull: configuration.traceWireFull,
            provenance: provenance,
            encryptedSession: encryptedSession
        )
        sink("\(label) (\(bytes.count) bytes): \(summary)")
    }

    /// Lets hot paths skip building dump inputs (for example a re-created frame header) when
    /// debugging is off.
    var isEnabled: Bool { configurationProvider().enabled }

    func line(_ message: String) {
        guard configurationProvider().enabled else { return }
        sink(message)
    }

#if DEBUG
    /// Queues diagnostics from latency-sensitive session work so a blocked stderr sink
    /// cannot occupy the session executor.
    func enqueueLine(_ message: String) {
        Self.outputQueue.async { self.line(message) }
    }
#endif
}

/// Measures a callback in place, without changing the task's executor. Only debug builds
/// read the clock; diagnostic output is queued away from the session executor.
struct SMBCallbackDurationMeasurement: Sendable {
#if DEBUG
    private let logger: SMBSessionDebugLogger
    private let sessionID: String
    private let label: String
    private let startedAt: ContinuousClock.Instant?

    init(logger: SMBSessionDebugLogger, sessionID: String, label: String) {
        self.logger = logger
        self.sessionID = sessionID
        self.label = label
        self.startedAt = logger.isEnabled ? ContinuousClock.now : nil
    }

    func finish() {
        guard let startedAt else { return }
        let duration = ContinuousClock.now - startedAt
        guard duration >= .milliseconds(100) else { return }
        logger.enqueueLine(
            "[callback] slow session=\(sessionID) name=\(label) " +
                "duration_ms=\(SMBPerfLog.milliseconds(duration)) threshold_ms=100"
        )
    }
#else
    init(logger: SMBSessionDebugLogger, sessionID: String, label: String) {
        _ = logger
        _ = sessionID
        _ = label
    }

    @inline(__always)
    func finish() {}
#endif
}

@concurrent
func runSMBUserSyncCallbackOnPreferredExecutor(
    _ operation: @escaping @Sendable () -> Void,
    label: String,
    logger: SMBSessionDebugLogger,
    sessionID: String
) async {
    let measurement = SMBCallbackDurationMeasurement(logger: logger, sessionID: sessionID, label: label)
    operation()
    measurement.finish()
}

@concurrent
func runSMBUserAsyncCallbackOnPreferredExecutor<Result: Sendable>(
    _ operation: @escaping @Sendable () async throws -> Result,
    label: String,
    logger: SMBSessionDebugLogger,
    sessionID: String
) async throws -> Result {
    let measurement = SMBCallbackDurationMeasurement(logger: logger, sessionID: sessionID, label: label)
    defer { measurement.finish() }
    return try await operation()
}

enum SMBDebug {
    private static let defaultDumpPrefixByteCount = 64
    private static let redactedPacketSummary = "<redacted; set SMBEE_TRACE_WIRE=1 to dump raw packet hex>"
    private static let encryptedPlaintextSummary = "<redacted; encrypted session plaintext>"

    static func hex(_ bytes: [UInt8]) -> String {
        bytes.map { String(format: "%02x", $0) }.joined()
    }

    static func hexPrefix(_ bytes: [UInt8], count: Int) -> String {
        hex(Array(bytes.prefix(count)))
    }

    static func hexSummary(_ bytes: [UInt8], prefixByteCount: Int = defaultDumpPrefixByteCount) -> String {
        let prefixCount = max(0, min(prefixByteCount, bytes.count))
        let prefix = hexPrefix(bytes, count: prefixCount)
        if prefixCount == bytes.count {
            return prefix
        }
        return "\(prefix)... totalBytes=\(bytes.count)"
    }

    static func packetSummary(_ bytes: [UInt8], traceWire: Bool) -> String {
        packetSummary(
            bytes,
            traceWire: traceWire,
            traceWireFull: ProcessInfo.processInfo.environment["SMBEE_TRACE_WIRE_FULL"] == "1",
            provenance: .plaintext,
            encryptedSession: false
        )
    }

    static func packetSummary(
        _ bytes: [UInt8],
        traceWire: Bool,
        traceWireFull: Bool,
        provenance: SMBWireDataProvenance,
        encryptedSession: Bool
    ) -> String {
        guard traceWire else { return redactedPacketSummary }
        if encryptedSession, provenance == .plaintext { return encryptedPlaintextSummary }
        if traceWireFull { return hex(bytes) }
        return hexSummary(bytes)
    }
}
