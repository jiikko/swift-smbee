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

    func line(_ message: String) {
        guard configurationProvider().enabled else { return }
        sink(message)
    }
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
