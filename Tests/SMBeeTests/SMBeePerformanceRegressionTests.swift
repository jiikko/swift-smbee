import Foundation
import XCTest
@testable import SMBee

final class SMBeePerformanceRegressionTests: XCTestCase {
    private let credential = SMBCredential(username: "user", password: "pass")
    private let fileId = Array(UInt8(0)..<UInt8(16))
    private let treeId: UInt32 = 0x3344
    private let signingKey = Array(repeating: UInt8(0x11), count: 16)

    func testReadStreamingUsesExpectedReadCommandChunkAndByteCounts() async throws {
        let fileSize = 64 * 1024 * 2 + 123
        let effectiveReadChunkSize = SMBTransferLimits.negotiatedChunkSize(
            localLimit: 64 * 1024,
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
        let clientSession = makeClientSession(transport: transport)
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
                try smb2CreateResponse(fileId: fileId, messageId: 4, treeId: treeId),
            ]
                + writeResponses(fileSize: fileSize, chunkSize: effectiveWriteChunkSize, firstMessageId: 5)
                + [
                    try smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.flush, messageId: UInt64(5 + expectedChunks), treeId: treeId),
                    try smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.close, messageId: UInt64(6 + expectedChunks), treeId: treeId),
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
            try smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.close, messageId: 14, treeId: treeId),
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

    private func makeClientSession(transport: PerformanceInMemoryTransport) -> SMBClientSession {
        let session = SMBSession(host: "server", port: 445, credential: credential, transport: transport, signingKey: signingKey)
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

private final class PerformanceInMemoryTransport: SMBTransport, @unchecked Sendable {
    private let lock = NSLock()
    private var inbound: [UInt8]
    private var outboundStorage: [UInt8] = []

    var outbound: [UInt8] {
        lock.lock()
        defer { lock.unlock() }
        return outboundStorage
    }

    init(inbound: [UInt8]) {
        self.inbound = inbound
    }

    func connect(host: String, port: UInt16) async throws {
        try Task.checkCancellation()
        _ = host
        _ = port
    }

    func send(_ bytes: [UInt8]) async throws {
        try Task.checkCancellation()
        lock.withLock {
            outboundStorage.append(contentsOf: bytes)
        }
    }

    func receive(maxLength: Int) async throws -> [UInt8] {
        try Task.checkCancellation()
        return try lock.withLock {
            guard !inbound.isEmpty else { throw SMBTransportError.connectionClosed }
            let count = min(maxLength, inbound.count)
            let chunk = Array(inbound.prefix(count))
            inbound.removeFirst(count)
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
    writeUInt32LE(1_048_576, to: &response, at: 100)
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
