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

    static func anonymousReconnectCancelledAtSessionSetupResponses() throws -> [[UInt8]] {
        [
            try negotiateResponse(),
            try SMB2Header(
                status: SMB2Status.cancelled,
                command: SMB2Commands.sessionSetup,
                messageId: 1
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
    private struct Waiter {
        let id: UUID
        let target: Int
        let continuation: CheckedContinuation<Void, Error>
        var timeoutTask: Task<Void, Never>?
    }

    private let lock = NSLock()
    private var count = 0
    private var waiters: [Waiter] = []

    var waiterCount: Int {
        lock.withLock { waiters.count }
    }

    var currentCount: Int {
        lock.withLock { count }
    }

    func signal() {
        let ready = lock.withLock { () -> [Waiter] in
            count += 1
            let ready = waiters.filter { count >= $0.target }
            waiters.removeAll { count >= $0.target }
            return ready
        }
        ready.forEach {
            $0.timeoutTask?.cancel()
            $0.continuation.resume()
        }
    }

    /// For callers already wrapped in `smbIssue102AwaitWithTimeout`: that wrapper is the hang
    /// guard, so this timeout is only a backstop longer than any wrapper deadline.
    func waitForCount(_ target: Int) async throws {
        try await waitForCount(target, timeout: .seconds(60), sleeper: { try await Task.sleep(for: $0) })
    }

    func waitForCount(
        _ target: Int,
        timeout: Duration,
        sleeper: @escaping @Sendable (Duration) async throws -> Void
    ) async throws {
        let waiterID = UUID()
        try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                let result = lock.withLock { () -> Int in
                    if Task.isCancelled { return -1 }
                    guard count < target else { return 1 }
                    waiters.append(Waiter(id: waiterID, target: target, continuation: continuation))
                    return 0
                }
                if result < 0 { continuation.resume(throwing: CancellationError()) }
                if result > 0 { continuation.resume() }
                if result == 0 {
                    let timeoutTask = Task { [weak self] in
                        do {
                            try await sleeper(timeout)
                        } catch {
                            return
                        }
                        self?.timeoutWaiter(waiterID)
                    }
                    let shouldCancel = lock.withLock { () -> Bool in
                        guard let index = waiters.firstIndex(where: { $0.id == waiterID }) else { return true }
                        waiters[index].timeoutTask = timeoutTask
                        return false
                    }
                    if shouldCancel { timeoutTask.cancel() }
                }
            }
        } onCancel: {
            cancelWaiter(waiterID)
        }
    }

    func reset() {
        let drained = lock.withLock { () -> [Waiter] in
            count = 0
            defer { waiters.removeAll() }
            return waiters
        }
        drained.forEach {
            $0.timeoutTask?.cancel()
            $0.continuation.resume(throwing: CancellationError())
        }
    }

    private func timeoutWaiter(_ waiterID: UUID) {
        let waiter = lock.withLock { () -> Waiter? in
            guard let index = waiters.firstIndex(where: { $0.id == waiterID }) else { return nil }
            return waiters.remove(at: index)
        }
        waiter?.continuation.resume(throwing: SMBContinuationWaitTimedOut())
    }

    private func cancelWaiter(_ waiterID: UUID) {
        let waiter = lock.withLock { () -> Waiter? in
            guard let index = waiters.firstIndex(where: { $0.id == waiterID }) else { return nil }
            return waiters.remove(at: index)
        }
        waiter?.timeoutTask?.cancel()
        waiter?.continuation.resume(throwing: CancellationError())
    }
}

struct SMBContinuationWaitTimedOut: Error {}

/// Holds reader tasks after their receive loop exits so lifecycle overlap and shutdown joins
/// can be tested at an exact event boundary. Cancellation intentionally does not release a
/// held task; the test must release it explicitly after proving the join behavior.
final class SMBReaderTaskExitGate: @unchecked Sendable {
    private let lock = NSLock()
    private var enteredHandles: [UUID] = []
    private var continuations: [UUID: CheckedContinuation<Void, Never>] = [:]
    private var releasedHandles = Set<UUID>()
    private var releaseAllRequested = false
    private let enteredBarrier = SMBContinuationCountBarrier()

    func hold(_ handle: UUID) async {
        await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
            let shouldResume = lock.withLock { () -> Bool in
                enteredHandles.append(handle)
                guard !releaseAllRequested, !releasedHandles.contains(handle) else { return true }
                continuations[handle] = continuation
                return false
            }
            enteredBarrier.signal()
            if shouldResume { continuation.resume() }
        }
    }

    func waitForCount(
        _ count: Int,
        timeout: Duration,
        sleeper: @escaping @Sendable (Duration) async throws -> Void
    ) async throws {
        try await enteredBarrier.waitForCount(count, timeout: timeout, sleeper: sleeper)
    }

    func release(_ handle: UUID) {
        let continuation = lock.withLock { () -> CheckedContinuation<Void, Never>? in
            releasedHandles.insert(handle)
            return continuations.removeValue(forKey: handle)
        }
        continuation?.resume()
    }

    func releaseAll() {
        let pending = lock.withLock { () -> [CheckedContinuation<Void, Never>] in
            releaseAllRequested = true
            defer { continuations.removeAll() }
            return Array(continuations.values)
        }
        pending.forEach { $0.resume() }
    }
}

final class SMBContinuationCredentialGate: @unchecked Sendable {
    private let lock = NSLock()
    private let credential: SMBCredential
    private var released = false
    private var continuations: [(id: UUID, continuation: CheckedContinuation<SMBCredential, Error>)] = []
    private var callCountStorage = 0
    private var callWaiters: [(id: UUID, target: Int, continuation: CheckedContinuation<Void, Error>)] = []

    init(credential: SMBCredential) {
        self.credential = credential
    }

    var callCount: Int {
        lock.withLock { callCountStorage }
    }

    var isReleased: Bool {
        lock.withLock { released }
    }

    func getCredential() async throws -> SMBCredential {
        let waiterID = UUID()
        return try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                let state = lock.withLock { () -> (released: Bool, cancelled: Bool, ready: [CheckedContinuation<Void, Error>]) in
                    callCountStorage += 1
                    let ready = callWaiters.filter { callCountStorage >= $0.target }.map(\.continuation)
                    callWaiters.removeAll { callCountStorage >= $0.target }
                    if Task.isCancelled { return (false, true, ready) }
                    if !released {
                        continuations.append((waiterID, continuation))
                    }
                    return (released, false, ready)
                }
                state.ready.forEach { $0.resume() }
                if state.cancelled {
                    continuation.resume(throwing: CancellationError())
                } else if state.released {
                    continuation.resume(returning: credential)
                }
            }
        } onCancel: {
            cancelCredentialWaiter(waiterID)
        }
    }

    func getCredentialIgnoringCancellation() async throws -> SMBCredential {
        try await withCheckedThrowingContinuation { continuation in
            let state = lock.withLock { () -> (
                released: Bool,
                ready: [CheckedContinuation<Void, Error>]
            ) in
                callCountStorage += 1
                let ready = callWaiters
                    .filter { callCountStorage >= $0.target }
                    .map(\.continuation)
                callWaiters.removeAll { callCountStorage >= $0.target }
                if !released {
                    continuations.append((UUID(), continuation))
                }
                return (released, ready)
            }
            state.ready.forEach { $0.resume() }
            if state.released {
                continuation.resume(returning: credential)
            }
        }
    }

    func waitForCallCount(_ target: Int) async throws {
        let waiterID = UUID()
        try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                let result = lock.withLock { () -> Int in
                    if Task.isCancelled { return -1 }
                    guard callCountStorage < target else { return 1 }
                    callWaiters.append((waiterID, target, continuation))
                    return 0
                }
                if result < 0 { continuation.resume(throwing: CancellationError()) }
                if result > 0 { continuation.resume() }
            }
        } onCancel: {
            cancelCallWaiter(waiterID)
        }
    }

    func release() {
        let pending = lock.withLock { () -> [CheckedContinuation<SMBCredential, Error>] in
            released = true
            let pending = continuations.map(\.continuation)
            continuations.removeAll()
            return pending
        }
        pending.forEach { $0.resume(returning: credential) }
    }

    private func cancelCredentialWaiter(_ waiterID: UUID) {
        let continuation = lock.withLock { () -> CheckedContinuation<SMBCredential, Error>? in
            guard let index = continuations.firstIndex(where: { $0.id == waiterID }) else { return nil }
            return continuations.remove(at: index).continuation
        }
        continuation?.resume(throwing: CancellationError())
    }

    private func cancelCallWaiter(_ waiterID: UUID) {
        let continuation = lock.withLock { () -> CheckedContinuation<Void, Error>? in
            guard let index = callWaiters.firstIndex(where: { $0.id == waiterID }) else { return nil }
            return callWaiters.remove(at: index).continuation
        }
        continuation?.resume(throwing: CancellationError())
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
    private var preloadedResponses: [[UInt8]]
    private var pendingReceive: SMBContinuationPendingReceive?
    private var closed = false
    private var closeCountStorage = 0
    private let closeCountBarrier = SMBContinuationCountBarrier()
    private var commandCounts: [UInt16: Int] = [:]
    private var commandWaiters: [(id: UUID, command: UInt16, target: Int, continuation: CheckedContinuation<Void, Error>)] = []

    init(inbound: [UInt8]) {
        self.inbound = []
        self.preloadedResponses = Self.directTCPFrames(inbound)
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
        let result = lock.withLock { () -> ([CheckedContinuation<Void, Error>], (SMBContinuationPendingReceive, [UInt8])?) in
            commandCounts[header.command, default: 0] += 1
            let ready = commandWaiters
                .filter { $0.command == header.command && commandCounts[header.command, default: 0] >= $0.target }
                .map(\.continuation)
            commandWaiters.removeAll {
                $0.command == header.command && commandCounts[header.command, default: 0] >= $0.target
            }
            if header.command != SMB2Commands.cancel, !preloadedResponses.isEmpty {
                inbound.append(contentsOf: preloadedResponses.removeFirst())
            }
            return (ready, takePendingReceiveLocked())
        }
        result.0.forEach { $0.resume() }
        result.1?.0.continuation.resume(returning: result.1?.1 ?? [])
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

    func waitForCommand(_ command: UInt16, occurrence: Int = 1) async throws {
        let waiterID = UUID()
        try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                let resumeNow = lock.withLock { () -> Int in
                    if Task.isCancelled { return -1 }
                    guard commandCounts[command, default: 0] < occurrence else { return 1 }
                    commandWaiters.append((waiterID, command, occurrence, continuation))
                    return 0
                }
                if resumeNow < 0 { continuation.resume(throwing: CancellationError()) }
                if resumeNow > 0 { continuation.resume() }
            }
        } onCancel: {
            cancelCommandWaiter(waiterID)
        }
    }

    private func cancelCommandWaiter(_ waiterID: UUID) {
        let continuation = lock.withLock { () -> CheckedContinuation<Void, Error>? in
            guard let index = commandWaiters.firstIndex(where: { $0.id == waiterID }) else { return nil }
            return commandWaiters.remove(at: index).continuation
        }
        continuation?.resume(throwing: CancellationError())
    }

    func close() {
        let result = lock.withLock { () -> (SMBContinuationPendingReceive?, [CheckedContinuation<Void, Error>]) in
            closed = true
            closeCountStorage += 1
            let pending = pendingReceive
            pendingReceive = nil
            preloadedResponses.removeAll()
            let waiters = commandWaiters.map(\.continuation)
            commandWaiters.removeAll()
            return (pending, waiters)
        }
        result.0?.continuation.resume(throwing: SMBTransportError.connectionClosed)
        result.1.forEach { $0.resume(throwing: SMBTransportError.connectionClosed) }
        closeCountBarrier.signal()
    }

    func failConnection() {
        close()
    }

    func waitForCloseCount(_ target: Int) async throws {
        try await closeCountBarrier.waitForCount(target)
    }

    fileprivate func enqueue(_ packet: [UInt8]) throws {
        let bytes = try DirectTCPFraming.frame(packet)
        let delivery = lock.withLock { () -> (SMBContinuationPendingReceive, [UInt8])? in
            inbound.append(contentsOf: bytes)
            return takePendingReceiveLocked()
        }
        if let delivery {
            delivery.0.continuation.resume(returning: delivery.1)
        }
    }

    private func takePendingReceiveLocked() -> (SMBContinuationPendingReceive, [UInt8])? {
        guard let pendingReceive, !inbound.isEmpty else { return nil }
        let count = min(pendingReceive.maxLength, inbound.count)
        let chunk = Array(inbound.prefix(count))
        inbound.removeFirst(count)
        self.pendingReceive = nil
        return (pendingReceive, chunk)
    }

    private static func directTCPFrames(_ bytes: [UInt8]) -> [[UInt8]] {
        var frames: [[UInt8]] = []
        var offset = 0
        while offset + 4 <= bytes.count {
            guard let payloadLength = try? DirectTCPFraming.length(from: Array(bytes[offset..<(offset + 4)])) else {
                return []
            }
            let end = offset + 4 + payloadLength
            guard bytes[offset] == 0, end <= bytes.count else { return [] }
            frames.append(Array(bytes[offset..<end]))
            offset = end
        }
        return offset == bytes.count ? frames : []
    }
}

class SMBContinuationWatchTransport: SMBContinuationScriptTransport, @unchecked Sendable {
    private let watchLock = NSLock()
    private let autoRespondChangeNotify: Bool
    private var createRequests: [SMB2Header] = []
    private var completedCreateCount = 0
    private var treeConnectRequest: SMB2Header?
    private var treeDisconnectRequest: SMB2Header?
    private var changeNotifyRequest: SMB2Header?
    private var watchedCommands: [UInt16] = []
    private var treeDisconnectTreeIDs: [UInt32] = []
    private var afterCommandSignalHook: (@Sendable (UInt16) async -> Void)?

    init(autoRespondChangeNotify: Bool = false) {
        self.autoRespondChangeNotify = autoRespondChangeNotify
        super.init(inbound: [])
    }

    override func send(_ bytes: [UInt8]) async throws {
        guard let packet = try smbPacketInDirectTCPStream(bytes) else {
            try await super.send(bytes)
            return
        }
        let header = try SMB2Header.decode(packet)
        watchLock.withLock {
            watchedCommands.append(header.command)
            switch header.command {
            case SMB2Commands.create: createRequests.append(header)
            case SMB2Commands.treeConnect: treeConnectRequest = header
            case SMB2Commands.treeDisconnect:
                treeDisconnectRequest = header
                treeDisconnectTreeIDs.append(header.treeId)
            case SMB2Commands.changeNotify: changeNotifyRequest = header
            default: break
            }
        }
        try await super.send(bytes)
        let hook = watchLock.withLock { afterCommandSignalHook }
        await hook?(header.command)
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

    var sentTreeDisconnectTreeIDs: [UInt32] {
        watchLock.withLock { treeDisconnectTreeIDs }
    }

    func installAfterCommandSignalHook(_ hook: (@Sendable (UInt16) async -> Void)?) {
        watchLock.withLock { afterCommandSignalHook = hook }
    }

    func completeCreate(credits: UInt16 = 1) throws {
        guard let request = watchLock.withLock({ () -> SMB2Header? in
            guard createRequests.indices.contains(completedCreateCount) else { return nil }
            defer { completedCreateCount += 1 }
            return createRequests[completedCreateCount]
        }) else {
            throw SMBCodecError.invalidValue("test transport has no CREATE request")
        }
        var response = try SMB2Header(
            command: SMB2Commands.create,
            credits: credits,
            messageId: request.messageId,
            treeId: request.treeId,
            sessionId: request.sessionId
        ).encode()
        response.append(contentsOf: Array(repeating: 0, count: 88))
        writeUInt16LE(89, to: &response, at: 64)
        response.replaceSubrange(128..<144, with: Array(repeating: 0x55, count: 16))
        try enqueue(response)
    }

    func completeTreeConnect(status: UInt32 = SMB2Status.success, treeId: UInt32 = 0x5566) throws {
        guard let request = watchLock.withLock({ treeConnectRequest }) else {
            throw SMBCodecError.invalidValue("test transport has no TREE_CONNECT request")
        }
        var response = try SMB2Header(
            status: status,
            command: SMB2Commands.treeConnect,
            messageId: request.messageId,
            treeId: treeId,
            sessionId: request.sessionId
        ).encode()
        if status == SMB2Status.success {
            response.append(contentsOf: Array(repeating: 0, count: 16))
            writeUInt16LE(16, to: &response, at: 64)
            response[66] = 1
        }
        try enqueue(response)
    }

    func completeTreeDisconnect() throws {
        guard let request = watchLock.withLock({ treeDisconnectRequest }) else {
            throw SMBCodecError.invalidValue("test transport has no TREE_DISCONNECT request")
        }
        try respond(status: SMB2Status.success, to: request)
    }

    func completeChangeNotify(status: UInt32 = SMB2Status.notifyEnumDir) throws {
        guard let request = watchLock.withLock({ changeNotifyRequest }) else {
            throw SMBCodecError.invalidValue("test transport has no CHANGE_NOTIFY request")
        }
        try respond(status: status, to: request)
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

class SMBReadPipelineScriptTransport: SMBContinuationWatchTransport, @unchecked Sendable {
    struct ReadRequest: Equatable, Sendable {
        let header: SMB2Header
        let offset: UInt64
        let length: UInt32
    }

    private let readLock = NSLock()
    private var readRequestsStorage: [ReadRequest] = []
    private var errorResponseBodiesStorage: [[UInt8]] = []
    private let readRequestBarrier = SMBContinuationCountBarrier()

    override func send(_ bytes: [UInt8]) async throws {
        if let packet = try smbPacketInDirectTCPStream(bytes) {
            let header = try SMB2Header.decode(packet)
            if header.command == SMB2Commands.read {
                var lengthReader = SMBByteReader(bytes: Array(packet[68..<72]))
                var offsetReader = SMBByteReader(bytes: Array(packet[72..<80]))
                let request = ReadRequest(
                    header: header,
                    offset: try offsetReader.readUInt64LE(),
                    length: try lengthReader.readUInt32LE()
                )
                readLock.withLock { readRequestsStorage.append(request) }
                readRequestBarrier.signal()
            }
        }
        try await super.send(bytes)
    }

    /// Ordered by MessageId, i.e. commit order. Concurrent full sends reach the transport in an
    /// unspecified order (`SMBTransport.send` contract), so arrival order is not deterministic.
    var readRequests: [ReadRequest] {
        readLock.withLock { readRequestsStorage }.sorted { $0.header.messageId < $1.header.messageId }
    }

    var errorResponseBodies: [[UInt8]] {
        readLock.withLock { errorResponseBodiesStorage }
    }

    func waitForReadCount(_ count: Int) async throws {
        try await readRequestBarrier.waitForCount(count)
    }

    func respond(
        to request: ReadRequest,
        payload: [UInt8] = [],
        status: UInt32 = SMB2Status.success,
        credits: UInt16 = 1
    ) throws {
        var response = try SMB2Header(
            status: status,
            command: SMB2Commands.read,
            credits: credits,
            messageId: request.header.messageId,
            treeId: request.header.treeId,
            sessionId: request.header.sessionId
        ).encode()
        if status == SMB2Status.success {
            response.append(contentsOf: [17, 0, 80, 0])
            response.append(contentsOf: Self.littleEndian(UInt32(payload.count)))
            response.append(contentsOf: [0, 0, 0, 0, 0, 0, 0, 0])
            response.append(contentsOf: payload)
        } else {
            let errorBody: [UInt8] = [9, 0, 0, 0, 0, 0, 0, 0]
            readLock.withLock { errorResponseBodiesStorage.append(errorBody) }
            response.append(contentsOf: errorBody)
        }
        try enqueue(response)
    }

    func respondTogether(_ responses: [(request: ReadRequest, payload: [UInt8])]) throws {
        var packet: [UInt8] = []
        for (index, item) in responses.enumerated() {
            let start = packet.count
            var response = try SMB2Header(
                command: SMB2Commands.read,
                credits: 1,
                messageId: item.request.header.messageId,
                treeId: item.request.header.treeId,
                sessionId: item.request.header.sessionId
            ).encode()
            response.append(contentsOf: [17, 0, 80, 0])
            response.append(contentsOf: Self.littleEndian(UInt32(item.payload.count)))
            response.append(contentsOf: [0, 0, 0, 0, 0, 0, 0, 0])
            response.append(contentsOf: item.payload)

            if index < responses.count - 1 {
                let nextStart = (start + response.count + 7) & ~7
                writeUInt32LE(UInt32(nextStart - start), to: &response, at: 20)
                packet.append(contentsOf: response)
                packet.append(contentsOf: Array(repeating: 0, count: nextStart - start - response.count))
            } else {
                packet.append(contentsOf: response)
            }
        }
        try enqueue(packet)
    }

    private static func littleEndian(_ value: UInt32) -> [UInt8] {
        [
            UInt8(truncatingIfNeeded: value),
            UInt8(truncatingIfNeeded: value >> 8),
            UInt8(truncatingIfNeeded: value >> 16),
            UInt8(truncatingIfNeeded: value >> 24)
        ]
    }
}

final class SMBReadPipelineCancellationSendTransport: SMBReadPipelineScriptTransport, @unchecked Sendable {
    private let failureLock = NSLock()
    private var didFailReadSend = false

    override func send(_ bytes: [UInt8]) async throws {
        let header = try smbPacketInDirectTCPStream(bytes).flatMap { try? SMB2Header.decode($0) }
        try await super.send(bytes)
        let shouldFail = failureLock.withLock { () -> Bool in
            guard header?.command == SMB2Commands.read, !didFailReadSend else { return false }
            didFailReadSend = true
            return true
        }
        if shouldFail { throw CancellationError() }
    }
}

final class SMBContinuationAsyncGate: @unchecked Sendable {
    private struct Waiter {
        let id: UUID
        let continuation: CheckedContinuation<Void, Error>
        var timeoutTask: Task<Void, Never>?
    }

    private let lock = NSLock()
    private var released = false
    private var waiters: [UUID: Waiter] = [:]
    private let suspended = SMBContinuationCountBarrier()
    private var suspensionSignalCount = 0

    var waiterCount: Int {
        lock.withLock { waiters.count }
    }

    func suspend(
        timeout: Duration,
        sleeper: @escaping @Sendable (Duration) async throws -> Void
    ) async throws {
        let id = UUID()
        try await withTaskCancellationHandler {
            try Task.checkCancellation()
            try await withCheckedThrowingContinuation { continuation in
                let shouldWait = lock.withLock { () -> Bool in
                    guard !released, !Task.isCancelled else { return false }
                    waiters[id] = Waiter(id: id, continuation: continuation)
                    suspensionSignalCount += 1
                    suspended.signal()
                    return true
                }
                guard shouldWait else {
                    if Task.isCancelled {
                        continuation.resume(throwing: CancellationError())
                    } else {
                        continuation.resume()
                    }
                    return
                }
                let timeoutTask = Task { [weak self] in
                    do {
                        try await sleeper(timeout)
                    } catch {
                        return
                    }
                    self?.timeout(id: id)
                }
                let shouldCancel = lock.withLock { () -> Bool in
                    guard var waiter = waiters[id] else { return true }
                    waiter.timeoutTask = timeoutTask
                    waiters[id] = waiter
                    return false
                }
                if shouldCancel { timeoutTask.cancel() }
            }
        } onCancel: {
            self.cancel(id: id)
        }
    }

    func waitUntilSuspended(
        timeout: Duration,
        sleeper: @escaping @Sendable (Duration) async throws -> Void
    ) async throws {
        let nextSignal = lock.withLock { () -> Int? in
            guard waiters.isEmpty else { return nil }
            return suspensionSignalCount + 1
        }
        if let nextSignal {
            try await suspended.waitForCount(nextSignal, timeout: timeout, sleeper: sleeper)
        }
    }

    func release() {
        let pending = lock.withLock { () -> [Waiter] in
            released = true
            let pending = Array(waiters.values)
            waiters.removeAll()
            return pending
        }
        pending.forEach {
            $0.timeoutTask?.cancel()
            $0.continuation.resume()
        }
    }

    func reset() {
        let pending = lock.withLock { () -> [Waiter] in
            released = false
            suspensionSignalCount = 0
            let pending = Array(waiters.values)
            waiters.removeAll()
            suspended.reset()
            return pending
        }
        pending.forEach {
            $0.timeoutTask?.cancel()
            $0.continuation.resume(throwing: CancellationError())
        }
    }

    private func timeout(id: UUID) {
        let waiter = lock.withLock { waiters.removeValue(forKey: id) }
        waiter?.continuation.resume(throwing: SMBContinuationWaitTimedOut())
    }

    private func cancel(id: UUID) {
        let waiter = lock.withLock { waiters.removeValue(forKey: id) }
        waiter?.timeoutTask?.cancel()
        waiter?.continuation.resume(throwing: CancellationError())
    }
}

final class SMBContinuationCloseEventLatch: @unchecked Sendable {
    private struct Waiter {
        let id: UUID
        let continuation: CheckedContinuation<SMBClientCloseEvent, Error>
    }

    private let lock = NSLock()
    private var eventStorage: SMBClientCloseEvent?
    private var waiters: [Waiter] = []

    var pendingWaiterCount: Int {
        lock.withLock { waiters.count }
    }

    func signal(_ event: SMBClientCloseEvent) {
        let continuations = lock.withLock { () -> [CheckedContinuation<SMBClientCloseEvent, Error>] in
            guard eventStorage == nil else { return [] }
            eventStorage = event
            let continuations = waiters.map(\.continuation)
            waiters.removeAll()
            return continuations
        }
        continuations.forEach { $0.resume(returning: event) }
    }

    func wait() async throws -> SMBClientCloseEvent {
        let waiterID = UUID()
        return try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                let state = lock.withLock { () -> (event: SMBClientCloseEvent?, cancelled: Bool) in
                    if Task.isCancelled { return (nil, true) }
                    if let eventStorage { return (eventStorage, false) }
                    waiters.append(Waiter(id: waiterID, continuation: continuation))
                    return (nil, false)
                }
                if state.cancelled {
                    continuation.resume(throwing: CancellationError())
                } else if let event = state.event {
                    continuation.resume(returning: event)
                }
            }
        } onCancel: {
            self.cancelWaiter(waiterID)
        }
    }

    func reset() {
        let continuations = lock.withLock { () -> [CheckedContinuation<SMBClientCloseEvent, Error>] in
            eventStorage = nil
            let continuations = waiters.map(\.continuation)
            waiters.removeAll()
            return continuations
        }
        continuations.forEach { $0.resume(throwing: CancellationError()) }
    }

    private func cancelWaiter(_ waiterID: UUID) {
        let continuation = lock.withLock { () -> CheckedContinuation<SMBClientCloseEvent, Error>? in
            guard let index = waiters.firstIndex(where: { $0.id == waiterID }) else { return nil }
            return waiters.remove(at: index).continuation
        }
        continuation?.resume(throwing: CancellationError())
    }
}

final class SMBContinuationSleeperGate: @unchecked Sendable {
    private struct SleepWaiter {
        let id: UUID
        let continuation: CheckedContinuation<Void, Error>
    }

    private struct CallWaiter {
        let id: UUID
        let target: Int
        let continuation: CheckedContinuation<Void, Error>
    }

    private let lock = NSLock()
    private var callCountStorage = 0
    private var sleepWaiters: [SleepWaiter] = []
    private var callWaiters: [CallWaiter] = []

    var callCount: Int {
        lock.withLock { callCountStorage }
    }

    var pendingSleepCount: Int {
        lock.withLock { sleepWaiters.count }
    }

    var pendingCallWaiterCount: Int {
        lock.withLock { callWaiters.count }
    }

    func sleep(for duration: Duration) async throws {
        _ = duration
        let waiterID = UUID()
        try await withTaskCancellationHandler {
            try Task.checkCancellation()
            try await withCheckedThrowingContinuation { continuation in
                let state = lock.withLock { () -> (readyCallWaiters: [CheckedContinuation<Void, Error>], cancelled: Bool) in
                    callCountStorage += 1
                    let ready = callWaiters
                        .filter { callCountStorage >= $0.target }
                        .map(\.continuation)
                    callWaiters.removeAll { callCountStorage >= $0.target }
                    if Task.isCancelled {
                        return (ready, true)
                    }
                    sleepWaiters.append(SleepWaiter(id: waiterID, continuation: continuation))
                    return (ready, false)
                }
                state.readyCallWaiters.forEach { $0.resume() }
                if state.cancelled {
                    continuation.resume(throwing: CancellationError())
                }
            }
        } onCancel: {
            self.cancelSleepWaiter(waiterID)
        }
    }

    func waitForCallCount(_ target: Int) async throws {
        let waiterID = UUID()
        try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                let state = lock.withLock { () -> (ready: Bool, cancelled: Bool) in
                    if Task.isCancelled { return (false, true) }
                    guard callCountStorage < target else { return (true, false) }
                    callWaiters.append(CallWaiter(id: waiterID, target: target, continuation: continuation))
                    return (false, false)
                }
                if state.cancelled {
                    continuation.resume(throwing: CancellationError())
                } else if state.ready {
                    continuation.resume()
                }
            }
        } onCancel: {
            self.cancelCallWaiter(waiterID)
        }
    }

    func fireNext() {
        let continuation = lock.withLock { sleepWaiters.isEmpty ? nil : sleepWaiters.removeFirst().continuation }
        continuation?.resume()
    }

    func fireAll() {
        let continuations = lock.withLock { () -> [CheckedContinuation<Void, Error>] in
            let continuations = sleepWaiters.map(\.continuation)
            sleepWaiters.removeAll()
            return continuations
        }
        continuations.forEach { $0.resume() }
    }

    func reset() {
        let pending = lock.withLock { () -> (
            sleeps: [CheckedContinuation<Void, Error>],
            calls: [CheckedContinuation<Void, Error>]
        ) in
            let sleeps = sleepWaiters.map(\.continuation)
            let calls = callWaiters.map(\.continuation)
            sleepWaiters.removeAll()
            callWaiters.removeAll()
            callCountStorage = 0
            return (sleeps, calls)
        }
        pending.sleeps.forEach { $0.resume(throwing: CancellationError()) }
        pending.calls.forEach { $0.resume(throwing: CancellationError()) }
    }

    private func cancelSleepWaiter(_ waiterID: UUID) {
        let continuation = lock.withLock { () -> CheckedContinuation<Void, Error>? in
            guard let index = sleepWaiters.firstIndex(where: { $0.id == waiterID }) else { return nil }
            return sleepWaiters.remove(at: index).continuation
        }
        continuation?.resume(throwing: CancellationError())
    }

    private func cancelCallWaiter(_ waiterID: UUID) {
        let continuation = lock.withLock { () -> CheckedContinuation<Void, Error>? in
            guard let index = callWaiters.firstIndex(where: { $0.id == waiterID }) else { return nil }
            return callWaiters.remove(at: index).continuation
        }
        continuation?.resume(throwing: CancellationError())
    }
}

struct SMBIssue102WaitTimeout: Error, CustomStringConvertible {
    let label: String

    var description: String { "Timed out waiting for \(label)" }
}

private final class SMBIssue102WaitResult<T: Sendable>: @unchecked Sendable {
    private let lock = NSLock()
    private var completed = false
    private var continuation: CheckedContinuation<T, Error>?
    private var pendingResult: Result<T, Error>?

    func install(_ continuation: CheckedContinuation<T, Error>) {
        let result = lock.withLock { () -> Result<T, Error>? in
            if completed {
                let result = pendingResult
                pendingResult = nil
                return result
            }
            self.continuation = continuation
            return nil
        }
        if let result { continuation.resume(with: result) }
    }

    func finish(_ result: Result<T, Error>) {
        let continuation = lock.withLock { () -> CheckedContinuation<T, Error>? in
            guard !completed else { return nil }
            completed = true
            guard let continuation = self.continuation else {
                pendingResult = result
                return nil
            }
            self.continuation = nil
            return continuation
        }
        continuation?.resume(with: result)
    }
}

func smbIssue102AwaitWithTimeout<T: Sendable>(
    _ label: String,
    timeout: Duration = .seconds(3),
    operation: @escaping @Sendable () async throws -> T
) async throws -> T {
    let result = SMBIssue102WaitResult<T>()
    let operationTask = Task {
        do {
            result.finish(.success(try await operation()))
        } catch {
            result.finish(.failure(error))
        }
    }
    let timeoutTask = Task {
        do {
            try await Task.sleep(for: timeout)
        } catch {
            return
        }
        result.finish(.failure(SMBIssue102WaitTimeout(label: label)))
        operationTask.cancel()
    }
    defer { timeoutTask.cancel() }
    return try await withCheckedThrowingContinuation { continuation in
        result.install(continuation)
    }
}
