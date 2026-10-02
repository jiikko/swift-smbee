import Foundation
@testable import SMBee

enum SMBIssue102WireFixtures {
    static func anonymousSessionResponses() throws -> [[UInt8]] {
        [
            try negotiateResponse(),
            try sessionSetupChallengeResponse(),
            try sessionSetupSuccessResponse(),
            try treeConnectResponse()
        ]
    }

    static func anonymousReconnectResponsesWithCleanup() throws -> [[UInt8]] {
        try anonymousSessionResponses() + [
            SMB2Header(
                command: SMB2Commands.treeDisconnect,
                messageId: 4,
                treeId: 0x3344,
                sessionId: 0x1122_3344_5566_7788
            ).encode(),
            SMB2Header(
                command: SMB2Commands.logoff,
                messageId: 5,
                sessionId: 0x1122_3344_5566_7788
            ).encode()
        ]
    }

    static func framed(_ packets: [[UInt8]]) throws -> [UInt8] {
        try packets.reduce(into: []) { result, packet in
            result.append(contentsOf: try DirectTCPFraming.frame(packet))
        }
    }

    private static func negotiateResponse() throws -> [UInt8] {
        var response = try SMB2Header(command: SMBNegotiateConstants.commandNegotiate, messageId: 0).encode()
        response.append(contentsOf: Array(repeating: 0, count: 65))
        writeUInt16LE(65, to: &response, at: 64)
        writeUInt16LE(SMBNegotiateConstants.signingEnabled, to: &response, at: 66)
        writeUInt16LE(SMBNegotiateConstants.dialect302, to: &response, at: 68)
        response.replaceSubrange(72..<88, with: Array(repeating: 0x42, count: 16))
        writeUInt32LE(0, to: &response, at: 88)
        writeUInt32LE(1_048_576, to: &response, at: 92)
        writeUInt32LE(1_048_576, to: &response, at: 96)
        writeUInt32LE(1_048_576, to: &response, at: 100)
        return response
    }

    private static func sessionSetupChallengeResponse() throws -> [UInt8] {
        let targetInfo: [UInt8] = [7, 0, 8, 0, 0, 0x90, 0xd3, 0x36, 0xb7, 0x34, 0xc3, 1, 0, 0, 0, 0]
        let challenge = makeNTLMChallengeMessage(targetInfo: targetInfo)
        let blob = SPNEGO.wrapNegTokenResp(challenge)
        var response = try SMB2Header(
            status: SMB2Status.moreProcessingRequired,
            command: SMB2Commands.sessionSetup,
            messageId: 1,
            sessionId: 0x1122_3344_5566_7788
        ).encode()
        response.append(contentsOf: Array(repeating: 0, count: 8))
        writeUInt16LE(9, to: &response, at: 64)
        writeUInt16LE(72, to: &response, at: 68)
        writeUInt16LE(UInt16(blob.count), to: &response, at: 70)
        response.append(contentsOf: blob)
        return response
    }

    private static func sessionSetupSuccessResponse() throws -> [UInt8] {
        var response = try SMB2Header(
            command: SMB2Commands.sessionSetup,
            messageId: 2,
            sessionId: 0x1122_3344_5566_7788
        ).encode()
        response.append(contentsOf: [9, 0, 0, 0, 72, 0, 0, 0])
        return response
    }

    private static func treeConnectResponse() throws -> [UInt8] {
        var response = try SMB2Header(
            command: SMB2Commands.treeConnect,
            messageId: 3,
            treeId: 0x3344,
            sessionId: 0x1122_3344_5566_7788
        ).encode()
        response.append(contentsOf: Array(repeating: 0, count: 16))
        writeUInt16LE(16, to: &response, at: 64)
        response[66] = 1
        writeUInt32LE(0, to: &response, at: 68)
        writeUInt32LE(0, to: &response, at: 72)
        writeUInt32LE(0x001f_01ff, to: &response, at: 76)
        return response
    }

    private static func makeNTLMChallengeMessage(targetInfo: [UInt8]) -> [UInt8] {
        let targetName = NTLM.utf16le("Server")
        let targetNameOffset: UInt32 = 48
        let targetInfoOffset = targetNameOffset + UInt32(targetName.count)
        var writer = SMBByteWriter()
        writer.writeBytes(Array("NTLMSSP\0".utf8))
        writer.writeUInt32LE(2)
        writer.writeUInt16LE(UInt16(targetName.count))
        writer.writeUInt16LE(UInt16(targetName.count))
        writer.writeUInt32LE(targetNameOffset)
        writer.writeUInt32LE(NTLM.negotiateFlags)
        writer.writeBytes(Array("0123456789abcdef".utf8))
        writer.writeBytes(Array(repeating: 0, count: 8))
        writer.writeUInt16LE(UInt16(targetInfo.count))
        writer.writeUInt16LE(UInt16(targetInfo.count))
        writer.writeUInt32LE(targetInfoOffset)
        writer.writeBytes(targetName)
        writer.writeBytes(targetInfo)
        return writer.bytes
    }
}

private func smbPacketInDirectTCPStream(_ bytes: [UInt8]) throws -> [UInt8]? {
    guard bytes.count >= 68,
          Array(bytes[4..<8]) == [0xfe, 0x53, 0x4d, 0x42]
    else {
        return nil
    }
    let payloadLength = try DirectTCPFraming.length(from: Array(bytes.prefix(4)))
    guard payloadLength == bytes.count - 4 else { return nil }
    return Array(bytes.dropFirst(4))
}

final class SMBContinuationCountBarrier: @unchecked Sendable {
    private let lock = NSLock()
    private var count = 0
    private var waiters: [(target: Int, continuation: CheckedContinuation<Void, Never>)] = []

    func signal() {
        let ready = lock.withLock { () -> [CheckedContinuation<Void, Never>] in
            count += 1
            let ready = waiters.filter { count >= $0.target }.map(\.continuation)
            waiters.removeAll { count >= $0.target }
            return ready
        }
        ready.forEach { $0.resume() }
    }

    func waitForCount(_ target: Int) async {
        await withCheckedContinuation { continuation in
            let resumeNow = lock.withLock { () -> Bool in
                guard count < target else { return true }
                waiters.append((target, continuation))
                return false
            }
            if resumeNow { continuation.resume() }
        }
    }
}

final class SMBContinuationCredentialGate: @unchecked Sendable {
    private let lock = NSLock()
    private let credential: SMBCredential
    private var released = false
    private var continuations: [CheckedContinuation<SMBCredential, Error>] = []
    private var callCountStorage = 0
    private var callWaiters: [(target: Int, continuation: CheckedContinuation<Void, Never>)] = []

    init(credential: SMBCredential) {
        self.credential = credential
    }

    var callCount: Int {
        lock.withLock { callCountStorage }
    }

    func getCredential() async throws -> SMBCredential {
        try await withCheckedThrowingContinuation { continuation in
            let state = lock.withLock { () -> (Bool, [CheckedContinuation<Void, Never>]) in
                callCountStorage += 1
                let ready = callWaiters.filter { callCountStorage >= $0.target }.map(\.continuation)
                callWaiters.removeAll { callCountStorage >= $0.target }
                if !released {
                    continuations.append(continuation)
                }
                return (released, ready)
            }
            state.1.forEach { $0.resume() }
            if state.0 { continuation.resume(returning: credential) }
        }
    }

    func waitForCallCount(_ target: Int) async {
        await withCheckedContinuation { continuation in
            let resumeNow = lock.withLock { () -> Bool in
                guard callCountStorage < target else { return true }
                callWaiters.append((target, continuation))
                return false
            }
            if resumeNow { continuation.resume() }
        }
    }

    func release() {
        let pending = lock.withLock { () -> [CheckedContinuation<SMBCredential, Error>] in
            released = true
            let pending = continuations
            continuations.removeAll()
            return pending
        }
        pending.forEach { $0.resume(returning: credential) }
    }
}

final class SMBContinuationTransportFactory: @unchecked Sendable {
    private let lock = NSLock()
    private var transports: [SMBTransport]
    private var makeCountStorage = 0

    init(transports: [SMBTransport]) {
        self.transports = transports
    }

    var makeCount: Int {
        lock.withLock { makeCountStorage }
    }

    func makeTransport() -> SMBTransport {
        lock.withLock {
            makeCountStorage += 1
            return transports.removeFirst()
        }
    }
}

private struct SMBContinuationPendingReceive {
    let maxLength: Int
    let continuation: CheckedContinuation<[UInt8], Error>
}

class SMBContinuationScriptTransport: SMBTransport, @unchecked Sendable {
    private let lock = NSLock()
    private var inbound: [UInt8]
    private var pendingReceive: SMBContinuationPendingReceive?
    private var closed = false
    private var treeConnectRequest: SMB2Header?
    private var closeCountStorage = 0
    private var commandCounts: [UInt16: Int] = [:]
    private var commandWaiters: [(command: UInt16, target: Int, continuation: CheckedContinuation<Void, Never>)] = []

    init(inbound: [UInt8]) {
        self.inbound = inbound
    }

    var closeCount: Int {
        lock.withLock { closeCountStorage }
    }

    func connect(host: String, port: UInt16) async throws {
        try Task.checkCancellation()
        _ = host
        _ = port
    }

    func send(_ bytes: [UInt8]) async throws {
        try Task.checkCancellation()
        guard let packet = try smbPacketInDirectTCPStream(bytes) else { return }
        let header = try SMB2Header.decode(packet)
        let ready = lock.withLock { () -> [CheckedContinuation<Void, Never>] in
            commandCounts[header.command, default: 0] += 1
            if header.command == SMB2Commands.treeConnect { treeConnectRequest = header }
            let ready = commandWaiters
                .filter { $0.command == header.command && commandCounts[header.command, default: 0] >= $0.target }
                .map(\.continuation)
            commandWaiters.removeAll {
                $0.command == header.command && commandCounts[header.command, default: 0] >= $0.target
            }
            return ready
        }
        ready.forEach { $0.resume() }
    }

    func receive(maxLength: Int) async throws -> [UInt8] {
        try Task.checkCancellation()
        return try await withCheckedThrowingContinuation { continuation in
            let decision = lock.withLock { () -> (bytes: [UInt8]?, closed: Bool) in
                if !inbound.isEmpty {
                    let count = min(maxLength, inbound.count)
                    let bytes = Array(inbound.prefix(count))
                    inbound.removeFirst(count)
                    return (bytes, false)
                }
                if closed { return (nil, true) }
                pendingReceive = SMBContinuationPendingReceive(maxLength: maxLength, continuation: continuation)
                return (nil, false)
            }
            if decision.closed {
                continuation.resume(throwing: SMBTransportError.connectionClosed)
            } else if let bytes = decision.bytes {
                continuation.resume(returning: bytes)
            }
        }
    }

    func waitForCommand(_ command: UInt16, occurrence: Int = 1) async {
        await withCheckedContinuation { continuation in
            let resumeNow = lock.withLock { () -> Bool in
                guard commandCounts[command, default: 0] < occurrence else { return true }
                commandWaiters.append((command, occurrence, continuation))
                return false
            }
            if resumeNow { continuation.resume() }
        }
    }

    func completeTreeConnect() throws {
        guard let request = lock.withLock({ treeConnectRequest }) else {
            throw SMBCodecError.invalidValue("test transport has no TREE_CONNECT request")
        }
        var response = try SMB2Header(
            command: SMB2Commands.treeConnect,
            messageId: request.messageId,
            treeId: 0x3344,
            sessionId: request.sessionId
        ).encode()
        response.append(contentsOf: Array(repeating: 0, count: 16))
        writeUInt16LE(16, to: &response, at: 64)
        response[66] = 1
        writeUInt32LE(0x001f_01ff, to: &response, at: 76)
        try enqueue(response)
    }

    func close() {
        let pending = lock.withLock { () -> SMBContinuationPendingReceive? in
            closed = true
            closeCountStorage += 1
            let pending = pendingReceive
            pendingReceive = nil
            return pending
        }
        pending?.continuation.resume(throwing: SMBTransportError.connectionClosed)
    }

    func failConnection() {
        close()
    }

    fileprivate func enqueue(_ packet: [UInt8]) throws {
        let bytes = try DirectTCPFraming.frame(packet)
        let delivery = lock.withLock { () -> (SMBContinuationPendingReceive, [UInt8])? in
            inbound.append(contentsOf: bytes)
            guard let pendingReceive else { return nil }
            let count = min(pendingReceive.maxLength, inbound.count)
            let chunk = Array(inbound.prefix(count))
            inbound.removeFirst(count)
            self.pendingReceive = nil
            return (pendingReceive, chunk)
        }
        if let delivery {
            delivery.0.continuation.resume(returning: delivery.1)
        }
    }
}

final class SMBContinuationWatchTransport: SMBContinuationScriptTransport, @unchecked Sendable {
    private let watchLock = NSLock()
    private let autoRespondChangeNotify: Bool
    private var createRequest: SMB2Header?
    private var treeDisconnectRequest: SMB2Header?
    private var watchedCommands: [UInt16] = []

    init(autoRespondChangeNotify: Bool = false) {
        self.autoRespondChangeNotify = autoRespondChangeNotify
        super.init(inbound: [])
    }

    override func send(_ bytes: [UInt8]) async throws {
        try await super.send(bytes)
        guard let packet = try smbPacketInDirectTCPStream(bytes) else { return }
        let header = try SMB2Header.decode(packet)
        watchLock.withLock {
            watchedCommands.append(header.command)
            switch header.command {
            case SMB2Commands.create: createRequest = header
            case SMB2Commands.treeDisconnect: treeDisconnectRequest = header
            default: break
            }
        }
        switch header.command {
        case SMB2Commands.close, SMB2Commands.logoff:
            try respond(status: SMB2Status.success, to: header)
        case SMB2Commands.changeNotify where autoRespondChangeNotify:
            try respond(status: SMB2Status.accessDenied, to: header)
        default: break
        }
    }

    var sentCommands: [UInt16] {
        watchLock.withLock { watchedCommands }
    }

    func completeCreate() throws {
        guard let request = watchLock.withLock({ createRequest }) else {
            throw SMBCodecError.invalidValue("test transport has no CREATE request")
        }
        var response = try SMB2Header(
            command: SMB2Commands.create,
            messageId: request.messageId,
            treeId: request.treeId,
            sessionId: request.sessionId
        ).encode()
        response.append(contentsOf: Array(repeating: 0, count: 88))
        writeUInt16LE(89, to: &response, at: 64)
        response.replaceSubrange(128..<144, with: Array(repeating: 0x55, count: 16))
        try enqueue(response)
    }

    func completeTreeDisconnect() throws {
        guard let request = watchLock.withLock({ treeDisconnectRequest }) else {
            throw SMBCodecError.invalidValue("test transport has no TREE_DISCONNECT request")
        }
        try respond(status: SMB2Status.success, to: request)
    }

    private func respond(status: UInt32, to request: SMB2Header) throws {
        let response = try SMB2Header(
            status: status,
            command: request.command,
            messageId: request.messageId,
            treeId: request.treeId,
            sessionId: request.sessionId
        ).encode()
        try enqueue(response)
    }
}
