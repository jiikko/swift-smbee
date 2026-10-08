import Crypto
import Foundation
import XCTest
@testable import SMBee

#if os(Linux)
import Glibc
#else
import Darwin
#endif

#if canImport(Network)
import Network
#endif

private final class RecursiveActionRecorder: @unchecked Sendable {
    private let lock = NSLock()
    private var storage: [SMBRecursiveAction] = []

    func append(_ action: SMBRecursiveAction) {
        lock.lock()
        storage.append(action)
        lock.unlock()
    }

    var actions: [SMBRecursiveAction] {
        lock.lock()
        defer { lock.unlock() }
        return storage
    }
}

final class SMBTraceLogCapture: @unchecked Sendable {
    private let lock = NSLock()
    private var storage: [String] = []

    var messages: [String] {
        lock.withLock { storage }
    }

    func append(_ message: String) {
        lock.withLock { storage.append(message) }
    }
}

private struct SMBTestTimeoutError: Error, CustomStringConvertible {
    let label: String
    let seconds: Double
    var description: String { "test await '\(label)' timed out after \(seconds)s (likely wire-transaction ordering deadlock)" }
}

private struct SMBTestEventWaitTimedOut: Error {}

private final class TransferProgressCollector: @unchecked Sendable {
    private let lock = NSLock()
    private var storage: [SMBTransferProgress] = []

    var snapshots: [SMBTransferProgress] {
        lock.lock()
        defer { lock.unlock() }
        return storage
    }

    func append(_ progress: SMBTransferProgress) {
        lock.lock()
        storage.append(progress)
        lock.unlock()
    }
}

private final class AsyncChunkSupplierRecorder: @unchecked Sendable {
    private let lock = NSLock()
    private let chunks: [[UInt8]]
    private var nextChunkIndex = 0
    private var requestedSizesStorage: [Int] = []

    init(chunks: [[UInt8]]) {
        self.chunks = chunks
    }

    var requestedSizes: [Int] {
        lock.lock()
        defer { lock.unlock() }
        return requestedSizesStorage
    }

    @discardableResult
    func recordRequest(maxLength: Int) -> Int {
        lock.lock()
        requestedSizesStorage.append(maxLength)
        let callNumber = requestedSizesStorage.count
        lock.unlock()
        return callNumber
    }

    func nextChunk(maxLength: Int) -> [UInt8] {
        lock.lock()
        defer { lock.unlock() }
        requestedSizesStorage.append(maxLength)
        guard nextChunkIndex < chunks.count else { return [] }
        defer { nextChunkIndex += 1 }
        return chunks[nextChunkIndex]
    }
}

private final class PrefixChunkCollector: @unchecked Sendable {
    private let lock = NSLock()
    private var storage: [[UInt8]] = []

    func append(_ chunk: [UInt8]) {
        lock.lock()
        storage.append(chunk)
        lock.unlock()
    }

    var chunks: [[UInt8]] {
        lock.lock()
        defer { lock.unlock() }
        return storage
    }
}

private final class SMBReceiveRegistrationGate: @unchecked Sendable {
    private let entered = DispatchSemaphore(value: 0)
    private let released = DispatchSemaphore(value: 0)

    func blockBeforeRegistration() {
        entered.signal()
        released.wait()
    }

    func waitUntilEntered() {
        _ = entered.wait(timeout: .now() + 5)
    }

    func release() {
        released.signal()
    }
}

private final class POSIXAsyncCounter: @unchecked Sendable {
    private struct Waiter {
        let target: Int
        let continuation: CheckedContinuation<Void, Never>
    }

    private let lock = NSLock()
    private var value = 0
    private var waiters: [Waiter] = []

    func increment() {
        lock.lock()
        value += 1
        var ready: [CheckedContinuation<Void, Never>] = []
        var pending: [Waiter] = []
        for waiter in waiters {
            if waiter.target <= value {
                ready.append(waiter.continuation)
            } else {
                pending.append(waiter)
            }
        }
        waiters = pending
        lock.unlock()

        for continuation in ready {
            continuation.resume()
        }
    }

    func wait(until target: Int) async {
        await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
            lock.lock()
            if value >= target {
                lock.unlock()
                continuation.resume()
            } else {
                waiters.append(Waiter(target: target, continuation: continuation))
                lock.unlock()
            }
        }
    }
}

private final class BlockingReceiveTransport: SMBTransport, @unchecked Sendable {
    private let receiveState = ReceiveState()

    func connect(host: String, port: UInt16) async throws {
        try Task.checkCancellation()
        _ = host
        _ = port
    }

    func send(_ bytes: [UInt8]) async throws {
        try Task.checkCancellation()
        _ = bytes
    }

    func receive(maxLength: Int) async throws -> [UInt8] {
        try Task.checkCancellation()
        _ = maxLength

        return try await withTaskCancellationHandler {
            try await receiveState.waitForCancellation()
        } onCancel: {
            receiveState.cancel()
        }
    }

    func close() {
        receiveState.cancel()
    }
}

private final class ScriptedBlockingReceiveTransport: SMBTransport, @unchecked Sendable {
    private let lock = NSLock()
    private let receiveState = ReceiveState()
    private var inbound: [UInt8]
    private var outboundStorage: [UInt8] = []
    private var blocked = false
    private var blockedWaiters: [CheckedContinuation<Void, Never>] = []
    private var closeCountStorage = 0

    init(inbound: [UInt8]) {
        self.inbound = inbound
    }

    var didBlockAfterScript: Bool {
        lock.withLock { blocked }
    }

    var outbound: [UInt8] {
        lock.withLock { outboundStorage }
    }

    var closeCount: Int {
        lock.withLock { closeCountStorage }
    }

    func waitUntilBlockedAfterScript() async {
        await withCheckedContinuation { continuation in
            lock.lock()
            if blocked {
                lock.unlock()
                continuation.resume()
            } else {
                blockedWaiters.append(continuation)
                lock.unlock()
            }
        }
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
        let state = lock.withLock { () -> ([UInt8]?, [CheckedContinuation<Void, Never>]) in
            guard !inbound.isEmpty else {
                blocked = true
                let waiters = blockedWaiters
                blockedWaiters.removeAll()
                return (nil, waiters)
            }
            let count = min(maxLength, inbound.count)
            let chunk = Array(inbound.prefix(count))
            inbound.removeFirst(count)
            return (chunk, [])
        }
        for waiter in state.1 { waiter.resume() }
        if let chunk = state.0 {
            return chunk
        }
        return try await withTaskCancellationHandler {
            try await receiveState.waitForCancellation()
        } onCancel: {
            receiveState.cancel()
        }
    }

    func close() {
        lock.withLock { closeCountStorage += 1 }
        receiveState.cancel()
    }
}

private final class BlockingSendTransport: SMBTransport, @unchecked Sendable {
    private let lock = NSLock()
    private var inbound: [UInt8]
    private var sendContinuation: CheckedContinuation<Void, Error>?
    private var firstSend = true
    private var sendStarted = false
    private var sendCancellationObserved = false
    private var outboundStorage: [UInt8] = []
    private var receiveContinuation: CheckedContinuation<[UInt8], Error>?
    private var receiveLimit = 0

    init(inbound: [UInt8]) {
        self.inbound = inbound
    }

    var isSendStarted: Bool { lock.withLock { sendStarted } }
    var didObserveSendCancellation: Bool { lock.withLock { sendCancellationObserved } }
    var outbound: [UInt8] { lock.withLock { outboundStorage } }

    func connect(host: String, port: UInt16) async throws {
        _ = host
        _ = port
    }

    func send(_ bytes: [UInt8]) async throws {
        let shouldBlock = lock.withLock { () -> Bool in
            sendStarted = true
            if firstSend {
                firstSend = false
                return true
            }
            return false
        }
        if shouldBlock {
            try await withCheckedThrowingContinuation { continuation in
                lock.withLock { sendContinuation = continuation }
            }
            if Task.isCancelled {
                lock.withLock { sendCancellationObserved = true }
                throw CancellationError()
            }
        }
        lock.withLock { outboundStorage.append(contentsOf: bytes) }
    }

    func releaseBlockedSend() {
        let continuation = lock.withLock { () -> CheckedContinuation<Void, Error>? in
            let continuation = sendContinuation
            sendContinuation = nil
            return continuation
        }
        continuation?.resume()
    }

    func appendInbound(_ bytes: [UInt8]) {
        let result = lock.withLock { () -> (CheckedContinuation<[UInt8], Error>?, [UInt8]?) in
            inbound.append(contentsOf: bytes)
            let continuation = receiveContinuation
            receiveContinuation = nil
            guard let continuation else { return (nil, nil) }
            let count = min(receiveLimit, inbound.count)
            let chunk = Array(inbound.prefix(count))
            inbound.removeFirst(count)
            receiveLimit = 0
            return (continuation, chunk)
        }
        if let continuation = result.0, let chunk = result.1 {
            continuation.resume(returning: chunk)
        }
    }

    func receive(maxLength: Int) async throws -> [UInt8] {
        try Task.checkCancellation()
        return try await withCheckedThrowingContinuation { continuation in
            let chunk = lock.withLock { () -> [UInt8]? in
                guard !inbound.isEmpty else {
                    receiveContinuation = continuation
                    receiveLimit = maxLength
                    return nil
                }
                let count = min(maxLength, inbound.count)
                let chunk = Array(inbound.prefix(count))
                inbound.removeFirst(count)
                return chunk
            }
            if let chunk {
                continuation.resume(returning: chunk)
            }
        }
    }

    func close() {}
}

private final class InterleavingPOSIXWriter: @unchecked Sendable {
    private let lock = NSLock()
    private let aRestGate = DispatchSemaphore(value: 0)
    private let aRestCounter = POSIXAsyncCounter()
    private let enqueueCounter = POSIXAsyncCounter()
    private var didEnterARest = false
    private var enqueueCount = 0
    private var outboundStorage: [UInt8] = []

    var outbound: [UInt8] { lock.withLock { outboundStorage } }
    var isARestBlocked: Bool { lock.withLock { didEnterARest } }
    var didEnqueueBothSends: Bool { lock.withLock { enqueueCount >= 2 } }

    func markEnqueued() {
        lock.withLock { enqueueCount += 1 }
        enqueueCounter.increment()
    }

    func write(_ descriptor: Int32, _ bytes: [UInt8], _ offset: Int) -> Int {
        _ = descriptor
        if bytes == [1, 2, 3], offset == 0 {
            lock.withLock { outboundStorage.append(1) }
            return 1
        }
        if bytes == [1, 2, 3], offset == 1 {
            lock.withLock { didEnterARest = true }
            aRestCounter.increment()
            aRestGate.wait()
            lock.withLock { outboundStorage.append(contentsOf: [2, 3]) }
            return 2
        }
        if bytes == [9, 9] {
            lock.withLock {
                outboundStorage.append(contentsOf: bytes[offset...])
            }
            return bytes.count - offset
        }
        lock.withLock { outboundStorage.append(contentsOf: bytes[offset...]) }
        return bytes.count - offset
    }

    func releaseA() {
        aRestGate.signal()
    }

    func waitForARest() async {
        await aRestCounter.wait(until: 1)
    }

    func waitForEnqueues(_ count: Int) async {
        await enqueueCounter.wait(until: count)
    }
}

private final class BlockingPOSIXWriter: @unchecked Sendable {
    private let lock = NSLock()
    private let gate = DispatchSemaphore(value: 0)
    private let startedCounter = POSIXAsyncCounter()
    private var started = false
    private var callCountStorage = 0
    private var outboundStorage: [UInt8] = []
    private var descriptorsStorage: [Int32] = []
    private var didBlockStorage = false

    var isStarted: Bool { lock.withLock { started } }
    var callCount: Int { lock.withLock { callCountStorage } }
    var outbound: [UInt8] { lock.withLock { outboundStorage } }
    var descriptors: [Int32] { lock.withLock { descriptorsStorage } }

    func write(_ descriptor: Int32, _ bytes: [UInt8], _ offset: Int) -> Int {
        lock.withLock {
            started = true
            callCountStorage += 1
            descriptorsStorage.append(descriptor)
        }
        let shouldBlock = lock.withLock { () -> Bool in
            guard offset == 0, !didBlockStorage else { return false }
            didBlockStorage = true
            return true
        }
        if shouldBlock {
            lock.withLock { outboundStorage.append(bytes[0]) }
            // Signal only after the partial byte is visible: waitForStart() callers assert
            // on `outbound`, and incrementing earlier lets a slow runner observe an empty
            // buffer between the signal and the append (observed on Linux CI).
            startedCounter.increment()
            gate.wait()
            return 1
        }
        lock.withLock { outboundStorage.append(contentsOf: bytes[offset...]) }
        startedCounter.increment()
        return bytes.count - offset
    }

    func release() {
        gate.signal()
    }

    func waitForStart() async {
        await startedCounter.wait(until: 1)
    }
}

private final class BlockingPOSIXReader: @unchecked Sendable {
    private let lock = NSLock()
    private let gate = DispatchSemaphore(value: 0)
    private let startedCounter = POSIXAsyncCounter()
    private var callCountStorage = 0
    private var descriptorsStorage: [Int32] = []

    var callCount: Int { lock.withLock { callCountStorage } }
    var descriptors: [Int32] { lock.withLock { descriptorsStorage } }

    func read(_ descriptor: Int32, _ buffer: UnsafeMutableRawPointer?, _ maxLength: Int) -> Int {
        lock.withLock {
            callCountStorage += 1
            descriptorsStorage.append(descriptor)
        }
        startedCounter.increment()
        gate.wait()
        guard maxLength > 0 else { return 0 }
        buffer?.storeBytes(of: UInt8(1), as: UInt8.self)
        return 1
    }

    func release() {
        gate.signal()
    }

    func waitForStart() async {
        await startedCounter.wait(until: 1)
    }
}

/// Wraps the live send / recv / shutdown / close so a test can put a real syscall into a
/// kernel-blocked state and see what the transport did around it (issues/073): whether the
/// shutdown reached a syscall that was still inside the kernel, and whether the physical close
/// waited until that syscall had returned.
private final class LivePOSIXSyscallProbe: @unchecked Sendable {
    private let lock = NSLock()
    private var enteredStorage = 0
    private var returnedStorage = 0
    private var insideAtShutdownStorage: [Bool] = []
    private var insideAtCloseStorage: [Bool] = []

    /// (calls entered, whether one is still inside the syscall)
    var snapshot: (entered: Int, inside: Bool) {
        lock.withLock { (enteredStorage, enteredStorage > returnedStorage) }
    }
    var insideAtShutdown: [Bool] { lock.withLock { insideAtShutdownStorage } }
    var insideAtClose: [Bool] { lock.withLock { insideAtCloseStorage } }

    func write(_ descriptor: Int32, _ bytes: [UInt8], _ offset: Int) throws -> Int {
        lock.withLock { enteredStorage += 1 }
        defer { lock.withLock { returnedStorage += 1 } }
        return try POSIXSocketTransport.liveWriter(descriptor, bytes, offset)
    }

    func read(_ descriptor: Int32, _ buffer: UnsafeMutableRawPointer?, _ maxLength: Int) -> Int {
        lock.withLock { enteredStorage += 1 }
        defer { lock.withLock { returnedStorage += 1 } }
        return POSIXSocketTransport.liveReader(descriptor, buffer, maxLength)
    }

    func shutdown(_ descriptor: Int32) {
        lock.withLock { insideAtShutdownStorage.append(enteredStorage > returnedStorage) }
        POSIXSocketTransport.liveShutdown(descriptor)
    }

    func close(_ descriptor: Int32) {
        lock.withLock { insideAtCloseStorage.append(enteredStorage > returnedStorage) }
        POSIXSocketTransport.liveClose(descriptor)
    }
}

private final class POSIXSendEnqueueRecorder: @unchecked Sendable {
    private let lock = NSLock()
    private let counter = POSIXAsyncCounter()
    private var countStorage = 0

    var count: Int { lock.withLock { countStorage } }

    func mark() {
        lock.withLock { countStorage += 1 }
        counter.increment()
    }

    func waitForCount(_ count: Int) async {
        await counter.wait(until: count)
    }
}

private final class FailingPOSIXWriter: @unchecked Sendable {
    private let lock = NSLock()
    private var callCountStorage = 0

    var callCount: Int { lock.withLock { callCountStorage } }

    func write(_ descriptor: Int32, _ bytes: [UInt8], _ offset: Int) throws -> Int {
        _ = descriptor
        _ = bytes
        _ = offset
        let callCount = lock.withLock { () -> Int in
            callCountStorage += 1
            return callCountStorage
        }
        if callCount == 1 {
            return 1
        }
        throw SMBTransportError.socketFailure("injected send failure")
    }
}

private final class EINTRPOSIXWriter: @unchecked Sendable {
    private let lock = NSLock()
    private var callCountStorage = 0

    var callCount: Int { lock.withLock { callCountStorage } }

    func write(_ descriptor: Int32, _ bytes: [UInt8], _ offset: Int) -> Int {
        _ = descriptor
        let callCount = lock.withLock { () -> Int in
            callCountStorage += 1
            return callCountStorage
        }
        if callCount == 1 {
            setPOSIXErrno(EINTR)
            return -1
        }
        return bytes.count - offset
    }
}

private func setPOSIXErrno(_ value: Int32) {
#if os(Linux)
    Glibc.errno = value
#else
    Darwin.errno = value
#endif
}

private enum POSIXLifecycleOperation: Equatable {
    case shutdown
    case close
}

private struct POSIXLifecycleEvent: Equatable {
    let operation: POSIXLifecycleOperation
    let descriptor: Int32
}

private final class POSIXLifecycleRecorder: @unchecked Sendable {
    private let lock = NSLock()
    private let shutdownCounter = POSIXAsyncCounter()
    private let closeCounter = POSIXAsyncCounter()
    private var shutdownCountStorage = 0
    private var closeCountStorage = 0
    private var eventsStorage: [POSIXLifecycleEvent] = []

    var shutdownCount: Int { lock.withLock { shutdownCountStorage } }
    var closeCount: Int { lock.withLock { closeCountStorage } }
    var events: [POSIXLifecycleEvent] { lock.withLock { eventsStorage } }

    func shutdown(_ descriptor: Int32) {
        lock.withLock {
            shutdownCountStorage += 1
            eventsStorage.append(POSIXLifecycleEvent(operation: .shutdown, descriptor: descriptor))
        }
        shutdownCounter.increment()
    }

    func close(_ descriptor: Int32) {
        lock.withLock {
            closeCountStorage += 1
            eventsStorage.append(POSIXLifecycleEvent(operation: .close, descriptor: descriptor))
        }
        closeCounter.increment()
    }

    func waitForClose() async {
        await closeCounter.wait(until: 1)
    }

    func waitForShutdown() async {
        await shutdownCounter.wait(until: 1)
    }
}

private struct POSIXConnectFakeSocketOption: Equatable {
    let level: Int32
    let option: Int32
    let value: Int32?
    let length: socklen_t
}

private enum POSIXConnectFakeEvent: Equatable {
    case connect(result: Int32, errno: Int32)
    case connectReady
    case setSocketOption(POSIXConnectFakeSocketOption)
    case connectReturned
    case pollStarted
    case shutdown
    case pollReturned
    case restoreStarted
    case restoreReturned
    case close
}

private final class POSIXConnectFakeEventRecorder: @unchecked Sendable {
    private let lock = NSLock()
    private var storage: [POSIXConnectFakeEvent] = []

    var events: [POSIXConnectFakeEvent] { lock.withLock { storage } }

    func append(_ event: POSIXConnectFakeEvent) {
        lock.withLock { storage.append(event) }
    }
}

private struct POSIXConnectFakePollStep {
    let result: Int32
    let errno: Int32
    let revents: Int16
    let clockAdvance: Duration

    init(
        result: Int32,
        errno: Int32 = 0,
        revents: Int16 = 0,
        clockAdvance: Duration = .zero
    ) {
        self.result = result
        self.errno = errno
        self.revents = revents
        self.clockAdvance = clockAdvance
    }
}

private final class POSIXConnectSyscallFake: @unchecked Sendable {
    let descriptor: Int32 = 73
    let originalFlags: Int32 = 0
    let events = POSIXConnectFakeEventRecorder()
    let syscallEvents = POSIXConnectFakeEventRecorder()

    private let lock = NSLock()
    private let pollCondition = NSCondition()
    private let restoreCondition = NSCondition()
    private let pollStartCounter = POSIXAsyncCounter()
    private let restoreStartCounter = POSIXAsyncCounter()
    private var nowStorage = ContinuousClock().now
    private var connectResults: [POSIXSocketCallResult<Int32>]
    private var pollSteps: [POSIXConnectFakePollStep]
    private var socketErrors: [POSIXSocketCallResult<Int32>]
    private var restoreResult: POSIXSocketCallResult<Int32>
    private var shouldBlockPoll = false
    private var shouldBlockRestore = false
    private var releasePoll = false
    private var releaseRestore = false
    private var pollTimeoutStorage: [Int32] = []
    private var connectCountStorage = 0
    private var getSocketErrorCountStorage = 0
    private var restoreCountStorage = 0
    private var socketOptionCallsStorage: [POSIXConnectFakeSocketOption] = []
    private var failedSocketOptionCountStorage = 0
    private let failingSocketOption: Int32?
    private let socketOptionFailureErrno: Int32

    init(
        connectResults: [POSIXSocketCallResult<Int32>] = [POSIXSocketCallResult(-1, errno: EINPROGRESS)],
        pollSteps: [POSIXConnectFakePollStep] = [
            POSIXConnectFakePollStep(result: 1, revents: Int16(POLLOUT))
        ],
        socketErrors: [POSIXSocketCallResult<Int32>] = [POSIXSocketCallResult(0)],
        restoreResult: POSIXSocketCallResult<Int32> = POSIXSocketCallResult(0),
        failingSocketOption: Int32? = nil,
        socketOptionFailureErrno: Int32 = EINVAL,
        blockPoll: Bool = false,
        blockRestore: Bool = false
    ) {
        self.connectResults = connectResults
        self.pollSteps = pollSteps
        self.socketErrors = socketErrors
        self.restoreResult = restoreResult
        self.failingSocketOption = failingSocketOption
        self.socketOptionFailureErrno = socketOptionFailureErrno
        self.shouldBlockPoll = blockPoll
        self.shouldBlockRestore = blockRestore
    }

    var pollTimeouts: [Int32] { lock.withLock { pollTimeoutStorage } }
    var connectCount: Int { lock.withLock { connectCountStorage } }
    var getSocketErrorCount: Int { lock.withLock { getSocketErrorCountStorage } }
    var restoreCount: Int { lock.withLock { restoreCountStorage } }
    var socketOptionCalls: [POSIXConnectFakeSocketOption] { lock.withLock { socketOptionCallsStorage } }
    var failedSocketOptionCount: Int { lock.withLock { failedSocketOptionCountStorage } }

    private func validateDescriptor(_ actual: Int32, operation: String) -> Bool {
        guard actual == descriptor else {
            XCTFail("\(operation) used descriptor \(actual), expected \(descriptor)")
            return false
        }
        return true
    }

    var syscalls: POSIXSocketSyscalls {
        POSIXSocketSyscalls(
            socket: { [self] _, _, _ in POSIXSocketCallResult(descriptor) },
            connect: { [self] actualDescriptor, _, _ in
                guard validateDescriptor(actualDescriptor, operation: "connect") else {
                    return POSIXSocketCallResult<Int32>(-1, errno: EIO)
                }
                let result = lock.withLock {
                    connectCountStorage += 1
                    guard !connectResults.isEmpty else {
                        XCTFail("connectResults script exhausted")
                        return POSIXSocketCallResult<Int32>(-1, errno: EIO)
                    }
                    return connectResults.removeFirst()
                }
                syscallEvents.append(.connect(result: result.value, errno: result.errno))
                return result
            },
            fcntl: { [self] actualDescriptor, command, value in
                guard validateDescriptor(actualDescriptor, operation: "fcntl") else {
                    return POSIXSocketCallResult<Int32>(-1, errno: EIO)
                }
                if command == F_GETFL { return POSIXSocketCallResult(originalFlags) }
                guard command == F_SETFL else {
                    XCTFail("fcntl used command \(command), expected F_GETFL or F_SETFL")
                    return POSIXSocketCallResult<Int32>(-1, errno: EIO)
                }
                if value != originalFlags { return POSIXSocketCallResult(0) }

                lock.withLock { restoreCountStorage += 1 }
                events.append(.restoreStarted)
                restoreStartCounter.increment()
                restoreCondition.lock()
                while shouldBlockRestore && !releaseRestore {
                    restoreCondition.wait()
                }
                restoreCondition.unlock()
                events.append(.restoreReturned)
                if restoreResult.value >= 0 {
                    syscallEvents.append(.connectReady)
                }
                return restoreResult
            },
            poll: { [self] actualDescriptor, requestedEvents, timeout in
                guard validateDescriptor(actualDescriptor, operation: "poll") else {
                    return POSIXSocketCallResult(
                        POSIXSocketPollValue(result: -1, revents: 0),
                        errno: EIO
                    )
                }
                guard requestedEvents == Int16(POLLOUT) else {
                    XCTFail("poll requested events \(requestedEvents), expected POLLOUT")
                    return POSIXSocketCallResult(
                        POSIXSocketPollValue(result: -1, revents: 0),
                        errno: EIO
                    )
                }
                let step = lock.withLock { () -> POSIXConnectFakePollStep in
                    pollTimeoutStorage.append(timeout)
                    guard !pollSteps.isEmpty else {
                        XCTFail("pollSteps script exhausted")
                        return POSIXConnectFakePollStep(result: -1, errno: EIO)
                    }
                    return pollSteps.removeFirst()
                }
                events.append(.pollStarted)
                pollStartCounter.increment()
                pollCondition.lock()
                while shouldBlockPoll && !releasePoll {
                    pollCondition.wait()
                }
                pollCondition.unlock()
                lock.withLock { nowStorage = nowStorage.advanced(by: step.clockAdvance) }
                events.append(.pollReturned)
                return POSIXSocketCallResult(
                    POSIXSocketPollValue(result: step.result, revents: step.revents),
                    errno: step.errno
                )
            },
            getSocketError: { [self] actualDescriptor in
                guard validateDescriptor(actualDescriptor, operation: "getsockopt(SO_ERROR)") else {
                    return POSIXSocketCallResult(
                        POSIXSocketErrorValue(result: -1, socketError: 0),
                        errno: EIO
                    )
                }
                return lock.withLock {
                    getSocketErrorCountStorage += 1
                    guard !socketErrors.isEmpty else {
                        XCTFail("socketErrors script exhausted")
                        return POSIXSocketCallResult(
                            POSIXSocketErrorValue(result: -1, socketError: 0),
                            errno: EIO
                        )
                    }
                    let entry = socketErrors.removeFirst()
                    return POSIXSocketCallResult(
                        POSIXSocketErrorValue(
                            result: entry.errno == 0 ? 0 : -1,
                            socketError: entry.value
                        ),
                        errno: entry.errno
                    )
                }
            },
            setSocketOption: { [self] actualDescriptor, level, option, value, length in
                guard validateDescriptor(actualDescriptor, operation: "setsockopt") else {
                    return POSIXSocketCallResult<Int32>(-1, errno: EIO)
                }
                let call = POSIXConnectFakeSocketOption(
                    level: level,
                    option: option,
                    value: value?.load(as: Int32.self),
                    length: length
                )
                lock.withLock { socketOptionCallsStorage.append(call) }
                syscallEvents.append(.setSocketOption(call))
                if let failingSocketOption, option == failingSocketOption {
                    lock.withLock { failedSocketOptionCountStorage += 1 }
                    return POSIXSocketCallResult<Int32>(-1, errno: socketOptionFailureErrno)
                }
                return POSIXSocketCallResult(0)
            },
            now: { [self] in lock.withLock { nowStorage } }
        )
    }

    func shutdown(_ descriptor: Int32) {
        XCTAssertEqual(descriptor, self.descriptor)
        events.append(.shutdown)
    }

    func close(_ descriptor: Int32) {
        XCTAssertEqual(descriptor, self.descriptor)
        events.append(.close)
    }

    func waitForPollStart() async {
        await pollStartCounter.wait(until: 1)
    }

    func waitForRestoreStart() async {
        await restoreStartCounter.wait(until: 1)
    }

    func unblockPoll() {
        pollCondition.lock()
        releasePoll = true
        pollCondition.broadcast()
        pollCondition.unlock()
    }

    func unblockRestore() {
        restoreCondition.lock()
        releaseRestore = true
        restoreCondition.broadcast()
        restoreCondition.unlock()
    }
}

private final class FailingReceiveTransport: SMBTransport, @unchecked Sendable {
    let failure: Error

    init(failure: Error) {
        self.failure = failure
    }

    func connect(host: String, port: UInt16) async throws {
        try Task.checkCancellation()
        _ = host
        _ = port
    }

    func send(_ bytes: [UInt8]) async throws {
        try Task.checkCancellation()
        _ = bytes
    }

    func receive(maxLength: Int) async throws -> [UInt8] {
        try Task.checkCancellation()
        _ = maxLength
        throw failure
    }

    func close() {}
}

private final class FailingSendTransport: SMBTransport, @unchecked Sendable {
    let failure: Error
    // Recorded so tests can prove the session actually closed the transport (not just
    // failed the pending requests) after a non-cancellation send failure.
    private let lock = NSLock()
    private var closeCallCount = 0

    var closeCount: Int { lock.withLock { closeCallCount } }

    init(failure: Error) {
        self.failure = failure
    }

    func connect(host: String, port: UInt16) async throws {
        try Task.checkCancellation()
        _ = host
        _ = port
    }

    func send(_ bytes: [UInt8]) async throws {
        try Task.checkCancellation()
        _ = bytes
        throw failure
    }

    func receive(maxLength: Int) async throws -> [UInt8] {
        try Task.checkCancellation()
        _ = maxLength
        return []
    }

    func close() {
        lock.withLock { closeCallCount += 1 }
    }
}

private final class FailingConnectTransport: SMBTransport, @unchecked Sendable {
    let failure: Error

    init(failure: Error) {
        self.failure = failure
    }

    func connect(host: String, port: UInt16) async throws {
        try Task.checkCancellation()
        _ = host
        _ = port
        throw failure
    }

    func send(_ bytes: [UInt8]) async throws {
        try Task.checkCancellation()
        _ = bytes
    }

    func receive(maxLength: Int) async throws -> [UInt8] {
        try Task.checkCancellation()
        _ = maxLength
        return []
    }

    func close() {}
}

private actor ChangeNotifyEventAccumulator {
    private(set) var sawOverflow = false
    private var changeNames: [String] = []

    func record(_ event: SMBChangeNotifyEvent) {
        switch event {
        case .overflow:
            sawOverflow = true
        case .changes(let changes):
            changeNames.append(contentsOf: changes.map(\.name))
        }
    }

    func containsChange(named name: String) -> Bool {
        changeNames.contains(name)
    }
}

private final class TransportFactorySequence: @unchecked Sendable {
    private let lock = NSLock()
    private var transports: [SMBTransport]
    private(set) var makeCount = 0

    init(_ transports: [SMBTransport]) {
        self.transports = transports
    }

    func make() -> SMBTransport {
        lock.lock()
        defer { lock.unlock() }
        makeCount += 1
        return transports.removeFirst()
    }
}

private final class ControlledReceiveTransport: SMBTransport, @unchecked Sendable {
    private struct PendingReceive {
        let id: UUID
        var maxLength: Int
        var continuation: CheckedContinuation<[UInt8], Error>
    }

    private struct ReceiveCountWaiter {
        let target: Int
        let continuation: CheckedContinuation<Void, Error>
        var timeoutTask: Task<Void, Never>?
    }

    private struct PendingSend {
        let id: UUID
        let bytes: [UInt8]
        let continuation: CheckedContinuation<Void, Error>
    }

    private enum WaitEvent {
        case sendAttempt(Int)
        case outboundFrames(Int)
        case blockedSendCount(Int)
        case receiveBlocked
    }

    private let lock = NSLock()
    private var inbound: [UInt8] = []
    private var pending: PendingReceive?
    private var outboundStorage: [UInt8] = []
    private var closeCountStorage = 0
    private var receiveCountStorage = 0
    private var sendAttemptCountStorage = 0
    private var outboundFrameCountStorage = 0
    private var activeReceiveCountStorage = 0
    private var maxConcurrentReceiveCountStorage = 0
    private var receiveCountWaiters: [UUID: ReceiveCountWaiter] = [:]
    private var receiveBlockedWaiters: [UUID: ReceiveCountWaiter] = [:]
    private var sendAttemptWaiters: [UUID: ReceiveCountWaiter] = [:]
    private var outboundFrameWaiters: [UUID: ReceiveCountWaiter] = [:]
    private var blockedSendCountWaiters: [UUID: ReceiveCountWaiter] = [:]
    private var blockedSends: [PendingSend] = []
    private var blockNextSendCount = 0
    private var isInputFinished = false
    private var isClosed = false

    var outbound: [UInt8] {
        lock.lock()
        defer { lock.unlock() }
        return outboundStorage
    }

    var closeCount: Int {
        lock.withLock { closeCountStorage }
    }

    var receiveCount: Int {
        lock.withLock { receiveCountStorage }
    }

    var maxConcurrentReceiveCount: Int {
        lock.withLock { maxConcurrentReceiveCountStorage }
    }

    var activeReceiveCount: Int {
        lock.withLock { activeReceiveCountStorage }
    }

    var sendAttemptCount: Int {
        lock.withLock { sendAttemptCountStorage }
    }

    var blockedSendCount: Int {
        lock.withLock { blockedSends.count }
    }

    var hasPendingReceive: Bool {
        lock.withLock { pending != nil }
    }

    var firstBlockedSendBytes: [UInt8]? {
        lock.withLock { blockedSends.first?.bytes }
    }

    func connect(host: String, port: UInt16) async throws {
        try Task.checkCancellation()
        _ = host
        _ = port
        try lock.withLock {
            guard !isClosed else { throw SMBTransportError.connectionClosed }
        }
    }

    func send(_ bytes: [UInt8]) async throws {
        try Task.checkCancellation()
        let sendID = UUID()
        let shouldBlock = try lock.withLock { () throws -> Bool in
            guard !isClosed else { throw SMBTransportError.connectionClosed }
            sendAttemptCountStorage += 1
            if blockNextSendCount > 0 {
                blockNextSendCount -= 1
                return true
            }
            return false
        }
        signalSatisfiedSendAttemptWaiters()
        if shouldBlock {
            try await withTaskCancellationHandler {
                try await withCheckedThrowingContinuation { continuation in
                    let failure: Error? = lock.withLock {
                        if Task.isCancelled { return CancellationError() }
                        if isClosed { return SMBTransportError.connectionClosed }
                        blockedSends.append(PendingSend(id: sendID, bytes: bytes, continuation: continuation))
                        return nil
                    }
                    if let failure {
                        continuation.resume(throwing: failure)
                    } else {
                        signalSatisfiedBlockedSendCountWaiters()
                    }
                }
            } onCancel: {
                self.cancelBlockedSend(id: sendID)
            }
            try Task.checkCancellation()
        }
        try lock.withLock {
            guard !isClosed else { throw SMBTransportError.connectionClosed }
            outboundStorage.append(contentsOf: bytes)
            outboundFrameCountStorage += 1
        }
        signalSatisfiedOutboundFrameWaiters()
    }

    func blockNextSend() {
        lock.withLock { blockNextSendCount += 1 }
    }

    func releaseBlockedSend() {
        let send = lock.withLock { blockedSends.isEmpty ? nil : blockedSends.removeFirst() }
        send?.continuation.resume()
    }

    func waitForSendAttemptCount(
        atLeast target: Int,
        timeout: Duration,
        sleeper: @escaping @Sendable (Duration) async throws -> Void
    ) async throws {
        try await waitForEvent(
            event: .sendAttempt(target),
            timeout: timeout,
            sleeper: sleeper,
            timeoutHandler: { self.timeoutSendAttemptWaiter(id: $0) },
            cancelHandler: { self.cancelSendAttemptWaiter(id: $0) }
        )
    }

    func waitForOutboundFrameCount(
        atLeast target: Int,
        timeout: Duration,
        sleeper: @escaping @Sendable (Duration) async throws -> Void
    ) async throws {
        try await waitForEvent(
            event: .outboundFrames(target),
            timeout: timeout,
            sleeper: sleeper,
            timeoutHandler: { self.timeoutOutboundFrameWaiter(id: $0) },
            cancelHandler: { self.cancelOutboundFrameWaiter(id: $0) }
        )
    }

    /// Unlike the attempt counter, this event fires only after `blockedSends` owns the send continuation.
    func waitForBlockedSendCount(
        atLeast target: Int,
        timeout: Duration,
        sleeper: @escaping @Sendable (Duration) async throws -> Void
    ) async throws {
        try await waitForEvent(
            event: .blockedSendCount(target),
            timeout: timeout,
            sleeper: sleeper,
            timeoutHandler: { self.timeoutBlockedSendCountWaiter(id: $0) },
            cancelHandler: { self.cancelBlockedSendCountWaiter(id: $0) }
        )
    }

    func receive(maxLength: Int) async throws -> [UInt8] {
        try Task.checkCancellation()
        let receiveID = UUID()
        lock.withLock {
            receiveCountStorage += 1
            activeReceiveCountStorage += 1
            maxConcurrentReceiveCountStorage = max(maxConcurrentReceiveCountStorage, activeReceiveCountStorage)
        }
        signalSatisfiedReceiveCountWaiters()
        defer { lock.withLock { activeReceiveCountStorage -= 1 } }
        return try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                let chunk: [UInt8]?
                let closed: Bool
                let alreadyPending: Bool
                let cancelled: Bool
                let didBlock: Bool

                lock.lock()
                if Task.isCancelled {
                    closed = false
                    chunk = nil
                    alreadyPending = false
                    cancelled = true
                    didBlock = false
                } else if isClosed {
                    closed = true
                    chunk = nil
                    alreadyPending = false
                    cancelled = false
                    didBlock = false
                } else if let pending {
                    closed = false
                    chunk = nil
                    alreadyPending = pending.id != receiveID
                    cancelled = false
                    didBlock = false
                } else if inbound.isEmpty {
                    closed = false
                    chunk = isInputFinished ? [] : nil
                    alreadyPending = false
                    cancelled = false
                    if chunk == nil {
                        pending = PendingReceive(id: receiveID, maxLength: maxLength, continuation: continuation)
                        didBlock = true
                    } else {
                        didBlock = false
                    }
                } else {
                    closed = false
                    alreadyPending = false
                    cancelled = false
                    didBlock = false
                    let count = min(maxLength, inbound.count)
                    chunk = Array(inbound.prefix(count))
                    inbound.removeFirst(count)
                }
                lock.unlock()

                if didBlock { signalReceiveBlockedWaiters() }

                if cancelled {
                    continuation.resume(throwing: CancellationError())
                } else if closed {
                    continuation.resume(throwing: SMBTransportError.connectionClosed)
                } else if alreadyPending {
                    continuation.resume(throwing: SMBCodecError.invalidValue("concurrent receive on one-reader test transport"))
                } else if let chunk {
                    continuation.resume(returning: chunk)
                }
            }
        } onCancel: {
            self.cancelPendingReceive(id: receiveID)
        }
    }

    func enqueueInbound(_ bytes: [UInt8]) {
        let pendingReceive: PendingReceive?
        let chunk: [UInt8]?

        lock.lock()
        inbound.append(contentsOf: bytes)
        if let pending {
            let count = min(pending.maxLength, inbound.count)
            chunk = Array(inbound.prefix(count))
            inbound.removeFirst(count)
            pendingReceive = pending
            self.pending = nil
        } else {
            chunk = nil
            pendingReceive = nil
        }
        lock.unlock()

        if let pendingReceive, let chunk {
            pendingReceive.continuation.resume(returning: chunk)
        }
    }

    func close() {
        let teardown = lock.withLock { () -> (PendingReceive?, [PendingSend]) in
            closeCountStorage += 1
            isClosed = true
            let receive = pending
            pending = nil
            let sends = blockedSends
            blockedSends.removeAll()
            return (receive, sends)
        }
        teardown.0?.continuation.resume(throwing: SMBTransportError.connectionClosed)
        teardown.1.forEach { $0.continuation.resume(throwing: SMBTransportError.connectionClosed) }
        drainReceiveCountWaiters(error: SMBTransportError.connectionClosed)
        drainSendAttemptWaiters(error: SMBTransportError.connectionClosed)
        drainOutboundFrameWaiters(error: SMBTransportError.connectionClosed)
        drainBlockedSendCountWaiters(error: SMBTransportError.connectionClosed)
        drainReceiveBlockedWaiters(error: SMBTransportError.connectionClosed)
    }

    func reset() {
        let pendingReceive = lock.withLock { () -> (PendingReceive?, [PendingSend]) in
            let result = pending
            pending = nil
            inbound.removeAll()
            outboundStorage.removeAll()
            closeCountStorage = 0
            receiveCountStorage = 0
            maxConcurrentReceiveCountStorage = 0
            sendAttemptCountStorage = 0
            outboundFrameCountStorage = 0
            blockNextSendCount = 0
            isInputFinished = false
            isClosed = false
            let sends = blockedSends
            blockedSends.removeAll()
            return (result, sends)
        }
        pendingReceive.0?.continuation.resume(throwing: CancellationError())
        pendingReceive.1.forEach { $0.continuation.resume(throwing: CancellationError()) }
        drainReceiveCountWaiters(error: CancellationError())
        drainSendAttemptWaiters(error: CancellationError())
        drainOutboundFrameWaiters(error: CancellationError())
        drainBlockedSendCountWaiters(error: CancellationError())
        drainReceiveBlockedWaiters(error: CancellationError())
    }

    func finishInput() {
        let receive = lock.withLock { () -> PendingReceive? in
            isInputFinished = true
            guard inbound.isEmpty else { return nil }
            defer { pending = nil }
            return pending
        }
        receive?.continuation.resume(returning: [])
    }

    func waitForReceiveCount(
        atLeast target: Int,
        timeout: Duration,
        sleeper: @escaping @Sendable (Duration) async throws -> Void
    ) async throws {
        let waiterID = UUID()
        try await withTaskCancellationHandler(operation: {
            try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
                lock.lock()
                if Task.isCancelled {
                    lock.unlock()
                    continuation.resume(throwing: CancellationError())
                    return
                }
                if receiveCountStorage >= target {
                    lock.unlock()
                    continuation.resume()
                    return
                }
                if isClosed {
                    lock.unlock()
                    continuation.resume(throwing: SMBTransportError.connectionClosed)
                    return
                }
                receiveCountWaiters[waiterID] = ReceiveCountWaiter(target: target, continuation: continuation)
                lock.unlock()

                let timeoutTask = Task { [weak self] in
                    do {
                        try await sleeper(timeout)
                    } catch {
                        return
                    }
                    self?.timeoutReceiveCountWaiter(id: waiterID)
                }
                lock.lock()
                if var waiter = receiveCountWaiters[waiterID] {
                    waiter.timeoutTask = timeoutTask
                    receiveCountWaiters[waiterID] = waiter
                    lock.unlock()
                } else {
                    lock.unlock()
                    timeoutTask.cancel()
                }
            }
        }, onCancel: {
            self.cancelReceiveCountWaiter(id: waiterID)
        })
    }

    func waitUntilReceiveIsBlocked(
        timeout: Duration,
        sleeper: @escaping @Sendable (Duration) async throws -> Void
    ) async throws {
        try await waitForEvent(
            event: .receiveBlocked,
            timeout: timeout,
            sleeper: sleeper,
            timeoutHandler: { self.timeoutReceiveBlockedWaiter(id: $0) },
            cancelHandler: { self.cancelReceiveBlockedWaiter(id: $0) }
        )
    }

    private func cancelPendingReceive(id: UUID) {
        let pendingReceive = lock.withLock { () -> PendingReceive? in
            guard pending?.id == id else { return nil }
            defer { pending = nil }
            return pending
        }
        pendingReceive?.continuation.resume(throwing: CancellationError())
    }

    private func signalSatisfiedReceiveCountWaiters() {
        let satisfied = lock.withLock { () -> [ReceiveCountWaiter] in
            let ids = receiveCountWaiters.filter { receiveCountStorage >= $0.value.target }.map(\.key)
            return ids.compactMap { receiveCountWaiters.removeValue(forKey: $0) }
        }
        for waiter in satisfied {
            waiter.timeoutTask?.cancel()
            waiter.continuation.resume()
        }
    }

    private func timeoutReceiveCountWaiter(id: UUID) {
        let waiter = lock.withLock { receiveCountWaiters.removeValue(forKey: id) }
        waiter?.continuation.resume(throwing: SMBTestEventWaitTimedOut())
    }

    private func cancelReceiveCountWaiter(id: UUID) {
        let waiter = lock.withLock { receiveCountWaiters.removeValue(forKey: id) }
        waiter?.timeoutTask?.cancel()
        waiter?.continuation.resume(throwing: CancellationError())
    }

    private func drainReceiveCountWaiters(error: Error) {
        let waiters = lock.withLock { () -> [ReceiveCountWaiter] in
            let values = Array(receiveCountWaiters.values)
            receiveCountWaiters.removeAll()
            return values
        }
        for waiter in waiters {
            waiter.timeoutTask?.cancel()
            waiter.continuation.resume(throwing: error)
        }
    }

    private func cancelBlockedSend(id: UUID) {
        let send = lock.withLock { () -> PendingSend? in
            guard let index = blockedSends.firstIndex(where: { $0.id == id }) else { return nil }
            return blockedSends.remove(at: index)
        }
        send?.continuation.resume(throwing: CancellationError())
    }

    private func signalSatisfiedSendAttemptWaiters() {
        let satisfied = lock.withLock { () -> [ReceiveCountWaiter] in
            let ids = sendAttemptWaiters.filter { sendAttemptCountStorage >= $0.value.target }.map(\.key)
            return ids.compactMap { sendAttemptWaiters.removeValue(forKey: $0) }
        }
        for waiter in satisfied {
            waiter.timeoutTask?.cancel()
            waiter.continuation.resume()
        }
    }

    private func signalSatisfiedOutboundFrameWaiters() {
        let satisfied = lock.withLock { () -> [ReceiveCountWaiter] in
            let ids = outboundFrameWaiters.filter { outboundFrameCountStorage >= $0.value.target }.map(\.key)
            return ids.compactMap { outboundFrameWaiters.removeValue(forKey: $0) }
        }
        for waiter in satisfied {
            waiter.timeoutTask?.cancel()
            waiter.continuation.resume()
        }
    }

    private func signalSatisfiedBlockedSendCountWaiters() {
        let satisfied = lock.withLock { () -> [ReceiveCountWaiter] in
            let ids = blockedSendCountWaiters.filter { blockedSends.count >= $0.value.target }.map(\.key)
            return ids.compactMap { blockedSendCountWaiters.removeValue(forKey: $0) }
        }
        for waiter in satisfied {
            waiter.timeoutTask?.cancel()
            waiter.continuation.resume()
        }
    }

    private func timeoutBlockedSendCountWaiter(id: UUID) {
        let waiter = lock.withLock { blockedSendCountWaiters.removeValue(forKey: id) }
        waiter?.continuation.resume(throwing: SMBTestEventWaitTimedOut())
    }

    private func cancelBlockedSendCountWaiter(id: UUID) {
        let waiter = lock.withLock { blockedSendCountWaiters.removeValue(forKey: id) }
        waiter?.timeoutTask?.cancel()
        waiter?.continuation.resume(throwing: CancellationError())
    }

    private func drainBlockedSendCountWaiters(error: Error) {
        let waiters = lock.withLock { () -> [ReceiveCountWaiter] in
            let values = Array(blockedSendCountWaiters.values)
            blockedSendCountWaiters.removeAll()
            return values
        }
        for waiter in waiters {
            waiter.timeoutTask?.cancel()
            waiter.continuation.resume(throwing: error)
        }
    }

    private func timeoutOutboundFrameWaiter(id: UUID) {
        let waiter = lock.withLock { outboundFrameWaiters.removeValue(forKey: id) }
        waiter?.continuation.resume(throwing: SMBTestEventWaitTimedOut())
    }

    private func cancelOutboundFrameWaiter(id: UUID) {
        let waiter = lock.withLock { outboundFrameWaiters.removeValue(forKey: id) }
        waiter?.timeoutTask?.cancel()
        waiter?.continuation.resume(throwing: CancellationError())
    }

    private func drainOutboundFrameWaiters(error: Error) {
        let waiters = lock.withLock { () -> [ReceiveCountWaiter] in
            let values = Array(outboundFrameWaiters.values)
            outboundFrameWaiters.removeAll()
            return values
        }
        for waiter in waiters {
            waiter.timeoutTask?.cancel()
            waiter.continuation.resume(throwing: error)
        }
    }

    private func drainSendAttemptWaiters(error: Error) {
        let waiters = lock.withLock { () -> [ReceiveCountWaiter] in
            let values = Array(sendAttemptWaiters.values)
            sendAttemptWaiters.removeAll()
            return values
        }
        for waiter in waiters {
            waiter.timeoutTask?.cancel()
            waiter.continuation.resume(throwing: error)
        }
    }

    private func timeoutSendAttemptWaiter(id: UUID) {
        let waiter = lock.withLock { sendAttemptWaiters.removeValue(forKey: id) }
        waiter?.continuation.resume(throwing: SMBTestEventWaitTimedOut())
    }

    private func cancelSendAttemptWaiter(id: UUID) {
        let waiter = lock.withLock { sendAttemptWaiters.removeValue(forKey: id) }
        waiter?.timeoutTask?.cancel()
        waiter?.continuation.resume(throwing: CancellationError())
    }

    private func waitForEvent(
        event: WaitEvent,
        timeout: Duration,
        sleeper: @escaping @Sendable (Duration) async throws -> Void,
        timeoutHandler: @escaping @Sendable (UUID) -> Void,
        cancelHandler: @escaping @Sendable (UUID) -> Void
    ) async throws {
        let waiterID = UUID()
        try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
                lock.lock()
                if Task.isCancelled {
                    lock.unlock()
                    continuation.resume(throwing: CancellationError())
                    return
                }
                let ready: Bool
                switch event {
                case .sendAttempt(let target):
                    ready = sendAttemptCountStorage >= target
                case .outboundFrames(let target):
                    ready = outboundFrameCountStorage >= target
                case .blockedSendCount(let target):
                    ready = blockedSends.count >= target
                case .receiveBlocked:
                    ready = pending != nil
                }
                if ready {
                    lock.unlock()
                    continuation.resume()
                    return
                }
                if isClosed {
                    lock.unlock()
                    continuation.resume(throwing: SMBTransportError.connectionClosed)
                    return
                }
                switch event {
                case .sendAttempt(let target):
                    sendAttemptWaiters[waiterID] = ReceiveCountWaiter(target: target, continuation: continuation)
                case .outboundFrames(let target):
                    outboundFrameWaiters[waiterID] = ReceiveCountWaiter(target: target, continuation: continuation)
                case .blockedSendCount(let target):
                    blockedSendCountWaiters[waiterID] = ReceiveCountWaiter(target: target, continuation: continuation)
                case .receiveBlocked:
                    receiveBlockedWaiters[waiterID] = ReceiveCountWaiter(target: 0, continuation: continuation)
                }
                lock.unlock()

                let timeoutTask = Task {
                    do {
                        try await sleeper(timeout)
                    } catch {
                        return
                    }
                    timeoutHandler(waiterID)
                }
                lock.lock()
                let shouldCancelTimeout: Bool
                switch event {
                case .sendAttempt:
                    if var waiter = sendAttemptWaiters[waiterID] {
                        waiter.timeoutTask = timeoutTask
                        sendAttemptWaiters[waiterID] = waiter
                        shouldCancelTimeout = false
                    } else {
                        shouldCancelTimeout = true
                    }
                case .outboundFrames:
                    if var waiter = outboundFrameWaiters[waiterID] {
                        waiter.timeoutTask = timeoutTask
                        outboundFrameWaiters[waiterID] = waiter
                        shouldCancelTimeout = false
                    } else {
                        shouldCancelTimeout = true
                    }
                case .blockedSendCount:
                    if var waiter = blockedSendCountWaiters[waiterID] {
                        waiter.timeoutTask = timeoutTask
                        blockedSendCountWaiters[waiterID] = waiter
                        shouldCancelTimeout = false
                    } else {
                        shouldCancelTimeout = true
                    }
                case .receiveBlocked:
                    if var waiter = receiveBlockedWaiters[waiterID] {
                        waiter.timeoutTask = timeoutTask
                        receiveBlockedWaiters[waiterID] = waiter
                        shouldCancelTimeout = false
                    } else {
                        shouldCancelTimeout = true
                    }
                }
                lock.unlock()
                if shouldCancelTimeout {
                    timeoutTask.cancel()
                }
            }
        } onCancel: {
            cancelHandler(waiterID)
        }
    }

    private func signalReceiveBlockedWaiters() {
        let waiters = lock.withLock { () -> [ReceiveCountWaiter] in
            let values = Array(receiveBlockedWaiters.values)
            receiveBlockedWaiters.removeAll()
            return values
        }
        for waiter in waiters {
            waiter.timeoutTask?.cancel()
            waiter.continuation.resume()
        }
    }

    private func timeoutReceiveBlockedWaiter(id: UUID) {
        let waiter = lock.withLock { receiveBlockedWaiters.removeValue(forKey: id) }
        waiter?.continuation.resume(throwing: SMBTestEventWaitTimedOut())
    }

    private func cancelReceiveBlockedWaiter(id: UUID) {
        let waiter = lock.withLock { receiveBlockedWaiters.removeValue(forKey: id) }
        waiter?.timeoutTask?.cancel()
        waiter?.continuation.resume(throwing: CancellationError())
    }

    private func drainReceiveBlockedWaiters(error: Error) {
        let waiters = lock.withLock { () -> [ReceiveCountWaiter] in
            let values = Array(receiveBlockedWaiters.values)
            receiveBlockedWaiters.removeAll()
            return values
        }
        for waiter in waiters {
            waiter.timeoutTask?.cancel()
            waiter.continuation.resume(throwing: error)
        }
    }

}

private final class WeakSMBSessionReference {
    weak var value: SMBSession?

    init(_ value: SMBSession) {
        self.value = value
    }
}

private final class LateConnectPublicationTransport: SMBTransport, @unchecked Sendable {
    private let lock = NSLock()
    private let connectGate = SMBContinuationAsyncGate()
    private let connectGateClock = ManualSMBSleeper()
    let connectEntered = SMBContinuationCountBarrier()
    let closeObserved = SMBContinuationCountBarrier()
    private var closed = false
    private var publishedAfterCloseStorage = false
    private var resourceOpenStorage = false
    private var closeCountStorage = 0

    var publishedAfterClose: Bool { lock.withLock { publishedAfterCloseStorage } }
    var resourceIsOpen: Bool { lock.withLock { resourceOpenStorage } }
    var closeCount: Int { lock.withLock { closeCountStorage } }

    func connect(host: String, port: UInt16) async throws {
        _ = host
        _ = port
        connectEntered.signal()
        try await connectGate.suspend(
            timeout: .seconds(3),
            sleeper: { [connectGateClock] in try await connectGateClock.sleep(for: $0) }
        )
        lock.withLock {
            publishedAfterCloseStorage = closed
            resourceOpenStorage = true
        }
    }

    func releaseConnect() {
        connectGate.release()
    }

    func resetConnectGate() {
        connectGate.reset()
    }

    func send(_ bytes: [UInt8]) async throws {
        _ = bytes
        throw SMBTransportError.connectionClosed
    }

    func receive(maxLength: Int) async throws -> [UInt8] {
        _ = maxLength
        throw SMBTransportError.connectionClosed
    }

    func close() {
        lock.withLock {
            closed = true
            closeCountStorage += 1
            if resourceOpenStorage { resourceOpenStorage = false }
        }
        closeObserved.signal()
    }
}

private final class TestTransportResource {}

private final class RequestTimeoutSleeperGate: @unchecked Sendable {
    private let lock = NSLock()
    private var callCountStorage = 0
    private var order: [UUID] = []
    private var waiters: [UUID: CheckedContinuation<Void, Error>] = [:]
    private let callCountBarrier = SMBContinuationCountBarrier()

    var callCount: Int {
        lock.withLock { callCountStorage }
    }

    var pendingCount: Int {
        lock.withLock { waiters.count }
    }

    func waitUntilCallCount(
        atLeast target: Int,
        timeout: Duration,
        sleeper: @escaping @Sendable (Duration) async throws -> Void
    ) async throws {
        try await callCountBarrier.waitForCount(target, timeout: timeout, sleeper: sleeper)
    }

    func sleep(for duration: Duration) async throws {
        let id = UUID()
        try await withTaskCancellationHandler {
            try Task.checkCancellation()
            try await withCheckedThrowingContinuation { continuation in
                let cancelled: Bool = lock.withLock {
                    callCountStorage += 1
                    callCountBarrier.signal()
                    guard !Task.isCancelled else { return true }
                    order.append(id)
                    waiters[id] = continuation
                    return false
                }
                if cancelled {
                    continuation.resume(throwing: CancellationError())
                }
            }
        } onCancel: {
            self.cancel(id: id)
        }
    }

    func fireNext() {
        let continuation: CheckedContinuation<Void, Error>? = lock.withLock {
            while let id = order.first {
                order.removeFirst()
                if let continuation = waiters.removeValue(forKey: id) {
                    return continuation
                }
            }
            return nil
        }
        continuation?.resume()
    }

    func reset() {
        let pending: [CheckedContinuation<Void, Error>] = lock.withLock {
            let continuations = Array(waiters.values)
            callCountStorage = 0
            order.removeAll()
            waiters.removeAll()
            callCountBarrier.reset()
            return continuations
        }
        pending.forEach { $0.resume(throwing: CancellationError()) }
    }

    private func cancel(id: UUID) {
        let continuation = lock.withLock { waiters.removeValue(forKey: id) }
        continuation?.resume(throwing: CancellationError())
    }
}

private final class ReceiveState: @unchecked Sendable {
    private let lock = NSLock()
    private var continuation: CheckedContinuation<[UInt8], Error>?
    private var isCancelled = false

    func waitForCancellation() async throws -> [UInt8] {
        try await withCheckedThrowingContinuation { continuation in
            let continuationToResume: CheckedContinuation<[UInt8], Error>?

            lock.lock()
            if isCancelled {
                continuationToResume = continuation
            } else {
                self.continuation = continuation
                continuationToResume = nil
            }
            lock.unlock()

            continuationToResume?.resume(throwing: CancellationError())
        }
    }

    func cancel() {
        let continuationToResume: CheckedContinuation<[UInt8], Error>?

        lock.lock()
        isCancelled = true
        continuationToResume = continuation
        continuation = nil
        lock.unlock()

        continuationToResume?.resume(throwing: CancellationError())
    }
}

private final class TestDirectoryEntryCollector: @unchecked Sendable {
    private let lock = NSLock()
    private var storage: [SMBDirectoryEntry] = []

    var entries: [SMBDirectoryEntry] {
        lock.lock()
        defer { lock.unlock() }
        return storage
    }

    func append(_ entry: SMBDirectoryEntry) {
        lock.lock()
        storage.append(entry)
        lock.unlock()
    }
}

private final class ChangeNotifyCollector: @unchecked Sendable {
    private let lock = NSLock()
    private var storage: [SMBChangeNotifyEvent] = []

    var events: [SMBChangeNotifyEvent] {
        lock.lock()
        defer { lock.unlock() }
        return storage
    }

    func append(_ event: SMBChangeNotifyEvent) {
        lock.lock()
        storage.append(event)
        lock.unlock()
    }
}

private func awaitResult(_ operation: @Sendable () async throws -> Void) async -> Result<Void, Error> {
    do {
        try await operation()
        return .success(())
    } catch {
        return .failure(error)
    }
}

private final class LockedCounter: @unchecked Sendable {
    private let lock = NSLock()
    private var storage = 0

    var value: Int {
        lock.lock()
        defer { lock.unlock() }
        return storage
    }

    func increment() {
        lock.lock()
        storage += 1
        lock.unlock()
    }
}

#if canImport(Network)
final class LoopbackNWServer: @unchecked Sendable {
    private let listener: NWListener
    private let queue = DispatchQueue(label: "dev.smbee.tests.nwserver")
    private let state = LoopbackNWServerState()
    private let echo: Bool

    var port: UInt16 {
        guard let port = listener.port?.rawValue else {
            fatalError("listener port is only available after the listener is ready")
        }
        return port
    }

    init(echo: Bool) throws {
        self.echo = echo
        listener = try NWListener(using: .tcp, on: .any)
    }

    func start() async throws {
        try await withCheckedThrowingContinuation { continuation in
            let resumer = TestContinuationResumer<Void>()
            listener.stateUpdateHandler = { state in
                switch state {
                case .ready:
                    resumer.resume(continuation, with: .success(()))
                case .failed(let error):
                    resumer.resume(continuation, with: .failure(error))
                case .cancelled:
                    resumer.resume(continuation, with: .failure(CancellationError()))
                default:
                    break
                }
            }
            listener.newConnectionHandler = { [weak self] connection in
                self?.accept(connection)
            }
            listener.start(queue: queue)
        }
    }

    func waitForConnection() async -> NWConnection {
        await state.waitForConnection()
    }

    func waitForReceivedBytes(atLeast count: Int) async -> [UInt8] {
        await state.waitForReceivedBytes(atLeast: count)
    }

    func receivedBytes() async -> [UInt8] {
        await state.receivedBytes()
    }

    func didPeerCloseSendDirection() async -> Bool {
        await state.didPeerCloseSendDirection()
    }

    func stop() {
        listener.cancel()
        Task { await state.cancelConnections() }
    }

    private func accept(_ connection: NWConnection) {
        Task { await state.accept(connection) }
        connection.start(queue: queue)
        receiveAndEcho(connection)
    }

    private func receiveAndEcho(_ connection: NWConnection) {
        connection.receive(minimumIncompleteLength: 1, maximumLength: 65_536) { [weak self] data, context, isComplete, error in
            guard let self else { return }
            guard error == nil else {
                Task { await self.state.markPeerClosed() }
                return
            }
            let peerSendDirectionClosed = isComplete && (context?.isFinal ?? false)
            if let data, !data.isEmpty {
                Task {
                    await self.state.recordReceived(data)
                    if self.echo {
                        connection.send(content: data, completion: .contentProcessed { sendError in
                            if sendError != nil || peerSendDirectionClosed {
                                Task { await self.state.markPeerClosed() }
                            } else {
                                self.receiveAndEcho(connection)
                            }
                        })
                    } else if peerSendDirectionClosed {
                        await self.state.markPeerClosed()
                    } else {
                        self.receiveAndEcho(connection)
                    }
                }
            } else if peerSendDirectionClosed {
                Task { await self.state.markPeerClosed() }
            } else {
                self.receiveAndEcho(connection)
            }
        }
    }
}

private actor LoopbackNWServerState {
    private struct ByteWaiter {
        let target: Int
        let continuation: CheckedContinuation<[UInt8], Never>
    }

    private var connections: [NWConnection] = []
    private var pendingConnectionWaiter: CheckedContinuation<NWConnection, Never>?
    private var received = Data()
    private var byteWaiters: [ByteWaiter] = []
    private var peerClosedSendDirection = false

    func accept(_ connection: NWConnection) {
        connections.append(connection)
        let waiter = pendingConnectionWaiter
        pendingConnectionWaiter = nil
        waiter?.resume(returning: connection)
    }

    func waitForConnection() async -> NWConnection {
        if let connection = connections.first {
            return connection
        }
        return await withCheckedContinuation { continuation in
            pendingConnectionWaiter = continuation
        }
    }

    func recordReceived(_ data: Data) {
        received.append(data)
        let ready = byteWaiters.filter { received.count >= $0.target }
        byteWaiters.removeAll { received.count >= $0.target }
        for waiter in ready {
            waiter.continuation.resume(returning: Array(received.prefix(waiter.target)))
        }
    }

    func waitForReceivedBytes(atLeast count: Int) async -> [UInt8] {
        if received.count >= count || peerClosedSendDirection { return Array(received.prefix(count)) }
        return await withCheckedContinuation { continuation in
            byteWaiters.append(ByteWaiter(target: count, continuation: continuation))
        }
    }

    func receivedBytes() -> [UInt8] { Array(received) }

    func markPeerClosed() {
        peerClosedSendDirection = true
        let waiters = byteWaiters
        byteWaiters.removeAll()
        for waiter in waiters {
            waiter.continuation.resume(returning: Array(received.prefix(waiter.target)))
        }
    }

    func didPeerCloseSendDirection() -> Bool { peerClosedSendDirection }

    func cancelConnections() {
        let currentConnections = connections
        connections.removeAll()
        pendingConnectionWaiter = nil
        currentConnections.forEach { $0.cancel() }
    }
}

private final class TestContinuationResumer<Success: Sendable>: @unchecked Sendable {
    private let lock = NSLock()
    private var didResume = false

    func resume(_ continuation: CheckedContinuation<Success, Error>, with result: Result<Success, Error>) {
        lock.lock()
        if didResume {
            lock.unlock()
            return
        }
        didResume = true
        lock.unlock()

        switch result {
        case .success(let value):
            continuation.resume(returning: value)
        case .failure(let error):
            continuation.resume(throwing: error)
        }
    }
}
#endif

// swiftlint:disable:next type_body_length
final class SMBeeTests: XCTestCase {
    // These tests model a server with enough negotiated credits for one large request.
    fileprivate let negotiatedServerCredits: UInt32 = 64
    func testVersionIsNotEmpty() {
        XCTAssertFalse(SMBee.version.isEmpty)
    }

    func testSessionReaderStartsAfterEachFullSendAndStopsWhenNoResponseIsOutstanding() async throws {
        let transport = ControlledReceiveTransport()
        transport.blockNextSend()
        let session = SMBSession(
            host: "test",
            port: 445,
            credential: .anonymous,
            transport: transport,
            initialCredits: 1
        )
        let clock = ManualSMBSleeper()
        let sendStarted = Task {
            try await transport.waitForSendAttemptCount(
                atLeast: 1,
                timeout: .seconds(1),
                sleeper: { try await clock.sleep(for: $0) }
            )
        }
        let echo = Task { try await session.echo() }
        try await awaitWithTimeout("blocked full-send entered") { try await sendStarted.value }
        XCTAssertEqual(transport.receiveCount, 0, "reader starts only after full-send success")

        transport.releaseBlockedSend()
        try await awaitWithTimeout("reader starts after full-send") {
            try await transport.waitForReceiveCount(
                atLeast: 1,
                timeout: .seconds(1),
                sleeper: { try await clock.sleep(for: $0) }
            )
        }
        let optionalFirstHandle = await session.readerHandleForTesting()
        let firstHandle = try XCTUnwrap(optionalFirstHandle)
        let optionalFirstReader = await session.readerTaskForTesting(handle: firstHandle)
        let firstReader = try XCTUnwrap(optionalFirstReader)
        let request = try XCTUnwrap(try unframed(transport.outbound).first)
        let messageId = try SMB2Header.decode(request).messageId
        transport.enqueueInbound(try framed([smb2EchoResponse(messageId: messageId)]))
        try await awaitWithTimeout("ECHO response") { try await echo.value }
        try await awaitWithTimeout("reader exits when the final response is dispatched") { await firstReader.value }
        let handleAtIdle = await session.readerHandleForTesting()
        let readerCountAtIdle = await session.readerTaskCountForTesting()
        XCTAssertNil(handleAtIdle)
        XCTAssertEqual(readerCountAtIdle, 0)
        XCTAssertEqual(transport.receiveCount, 2, "the idle session must not issue another receive")

        let secondEcho = Task { try await session.echo() }
        try await awaitWithTimeout("second request completes its full send") {
            await session.waitForRequestSentCountForTesting(atLeast: 2)
        }
        try await awaitWithTimeout("second request starts a new reader") {
            try await transport.waitForReceiveCount(
                atLeast: 3,
                timeout: .seconds(1),
                sleeper: { try await clock.sleep(for: $0) }
            )
        }
        let optionalSecondHandle = await session.readerHandleForTesting()
        let secondHandle = try XCTUnwrap(optionalSecondHandle)
        let optionalSecondReader = await session.readerTaskForTesting(handle: secondHandle)
        let secondReader = try XCTUnwrap(optionalSecondReader)
        XCTAssertNotEqual(secondHandle, firstHandle)
        let secondRequest = try XCTUnwrap(try unframed(transport.outbound).last)
        let secondMessageId = try SMB2Header.decode(secondRequest).messageId
        XCTAssertEqual(transport.maxConcurrentReceiveCount, 1)
        transport.enqueueInbound(try framed([smb2EchoResponse(messageId: secondMessageId)]))
        try await awaitWithTimeout("second ECHO response") { try await secondEcho.value }
        try await awaitWithTimeout("second reader exits at idle") { await secondReader.value }

        let pendingCount = await session.pendingCountForTesting()
        let readerRunning = await session.receiveLoopRunningForTesting()
        XCTAssertEqual(pendingCount, 0)
        XCTAssertFalse(readerRunning)
        XCTAssertEqual(transport.maxConcurrentReceiveCount, 1)
        XCTAssertEqual(transport.receiveCount, 4, "each response uses only the frame header and body receives")

        await session.closeTransportAndWait(cause: "test_idle_reader_join")
        XCTAssertEqual(transport.activeReceiveCount, 0)
        XCTAssertEqual(transport.closeCount, 1)
    }

    func testNextSendCanRestartReaderBeforeThePreviousTaskReturns() async throws {
        let transport = ControlledReceiveTransport()
        let session = SMBSession(
            host: "test",
            port: 445,
            credential: .anonymous,
            transport: transport,
            initialCredits: 1
        )
        let exitGate = SMBReaderTaskExitGate()
        defer { exitGate.releaseAll() }
        let exitCount = LockedCounter()
        await session.setReaderTaskExitHookForTesting { handle in
            exitCount.increment()
            if exitCount.value == 1 { await exitGate.hold(handle) }
        }

        let first = Task { try await session.echo() }
        try await awaitWithTimeout("first ECHO is sent") {
            await session.waitForRequestSentCountForTesting(atLeast: 1)
        }
        let optionalFirstHandle = await session.readerHandleForTesting()
        let firstHandle = try XCTUnwrap(optionalFirstHandle)
        let optionalFirstReader = await session.readerTaskForTesting(handle: firstHandle)
        let firstReader = try XCTUnwrap(optionalFirstReader)
        let firstRequest = try XCTUnwrap(try unframed(transport.outbound).first)
        let firstMessageId = try SMB2Header.decode(firstRequest).messageId
        transport.enqueueInbound(try framed([smb2EchoResponse(messageId: firstMessageId)]))

        let exitClock = ManualSMBSleeper()
        try await awaitWithTimeout("old reader has committed its dormant transition") {
            try await exitGate.waitForCount(
                1,
                timeout: .seconds(1),
                sleeper: { try await exitClock.sleep(for: $0) }
            )
        }
        try await awaitWithTimeout("first response reaches its caller") { try await first.value }
        let readerRunningWhileOldReturns = await session.receiveLoopRunningForTesting()
        let readerTaskCountWhileOldReturns = await session.readerTaskCountForTesting()
        XCTAssertFalse(readerRunningWhileOldReturns)
        XCTAssertEqual(readerTaskCountWhileOldReturns, 1, "the old task remains tracked while it returns")

        transport.blockNextSend()
        let second = Task { try await session.echo() }
        let sendClock = ManualSMBSleeper()
        try await awaitWithTimeout("second full-send is held after the old reader stopped") {
            try await transport.waitForSendAttemptCount(
                atLeast: 2,
                timeout: .seconds(1),
                sleeper: { try await sendClock.sleep(for: $0) }
            )
        }
        XCTAssertEqual(transport.receiveCount, 2, "the old reader must not enter an idle receive")

        transport.releaseBlockedSend()
        try await awaitWithTimeout("second send completes and wakes a replacement reader") {
            await session.waitForRequestSentCountForTesting(atLeast: 2)
        }
        let receiveClock = ManualSMBSleeper()
        try await awaitWithTimeout("replacement reader starts receiving") {
            try await transport.waitForReceiveCount(
                atLeast: 3,
                timeout: .seconds(1),
                sleeper: { try await receiveClock.sleep(for: $0) }
            )
        }
        let optionalSecondHandle = await session.readerHandleForTesting()
        let secondHandle = try XCTUnwrap(optionalSecondHandle)
        let optionalSecondReader = await session.readerTaskForTesting(handle: secondHandle)
        let secondReader = try XCTUnwrap(optionalSecondReader)
        XCTAssertNotEqual(secondHandle, firstHandle)
        let readerTaskCountWithOverlap = await session.readerTaskCountForTesting()
        XCTAssertEqual(readerTaskCountWithOverlap, 2)
        let secondRequest = try XCTUnwrap(try unframed(transport.outbound).last)
        let secondMessageId = try SMB2Header.decode(secondRequest).messageId
        transport.enqueueInbound(try framed([smb2EchoResponse(messageId: secondMessageId)]))

        try await awaitWithTimeout("replacement reader delivers the response") { try await second.value }
        try await awaitWithTimeout("replacement reader returns to dormant") { await secondReader.value }
        let readerTaskCountWithOldTask = await session.readerTaskCountForTesting()
        XCTAssertEqual(readerTaskCountWithOldTask, 1, "only the held old task remains")

        exitGate.release(firstHandle)
        try await awaitWithTimeout("old reader completes without clearing a newer lifecycle") { await firstReader.value }
        let finalReaderTaskCount = await session.readerTaskCountForTesting()
        let finalReaderRunning = await session.receiveLoopRunningForTesting()
        XCTAssertEqual(finalReaderTaskCount, 0)
        XCTAssertFalse(finalReaderRunning)
        await session.setReaderTaskExitHookForTesting(nil)
        await session.closeTransportAndWait(cause: "test_reader_restart_during_old_exit")
    }

    func testCloseJoinsOldAndReplacementReaderTasks() async throws {
        let transport = ControlledReceiveTransport()
        let session = SMBSession(
            host: "test",
            port: 445,
            credential: .anonymous,
            transport: transport,
            initialCredits: 1
        )
        let exitGate = SMBReaderTaskExitGate()
        defer { exitGate.releaseAll() }
        await session.setReaderTaskExitHookForTesting { handle in await exitGate.hold(handle) }

        let first = Task { try await session.echo() }
        try await awaitWithTimeout("first ECHO is sent") {
            await session.waitForRequestSentCountForTesting(atLeast: 1)
        }
        let optionalFirstHandle = await session.readerHandleForTesting()
        let firstHandle = try XCTUnwrap(optionalFirstHandle)
        let firstRequest = try XCTUnwrap(try unframed(transport.outbound).first)
        let firstMessageId = try SMB2Header.decode(firstRequest).messageId
        transport.enqueueInbound(try framed([smb2EchoResponse(messageId: firstMessageId)]))
        let firstExitClock = ManualSMBSleeper()
        try await awaitWithTimeout("old reader is retained after its final response") {
            try await exitGate.waitForCount(
                1,
                timeout: .seconds(1),
                sleeper: { try await firstExitClock.sleep(for: $0) }
            )
        }
        try await awaitWithTimeout("first ECHO completes") { try await first.value }

        let second = Task { try await session.echo() }
        try await awaitWithTimeout("second ECHO is sent") {
            await session.waitForRequestSentCountForTesting(atLeast: 2)
        }
        let receiveClock = ManualSMBSleeper()
        try await awaitWithTimeout("replacement reader parks in transport receive") {
            try await transport.waitUntilReceiveIsBlocked(
                timeout: .seconds(1),
                sleeper: { try await receiveClock.sleep(for: $0) }
            )
        }
        let optionalSecondHandle = await session.readerHandleForTesting()
        let secondHandle = try XCTUnwrap(optionalSecondHandle)
        let optionalSecondReader = await session.readerTaskForTesting(handle: secondHandle)
        let secondReader = try XCTUnwrap(optionalSecondReader)
        XCTAssertNotEqual(secondHandle, firstHandle)
        let readerTaskCountWithOverlap = await session.readerTaskCountForTesting()
        XCTAssertEqual(readerTaskCountWithOverlap, 2)

        await session.closeTransport(cause: "test_close_with_overlapping_readers")
        do {
            try await awaitWithTimeout("second ECHO fails with the closed transport") { try await second.value }
            XCTFail("closing the transport must fail the pending ECHO")
        } catch SMBTransportError.connectionClosed {
        }
        let bothExitClock = ManualSMBSleeper()
        try await awaitWithTimeout("both reader tasks reach their controlled exit gates") {
            try await exitGate.waitForCount(
                2,
                timeout: .seconds(1),
                sleeper: { try await bothExitClock.sleep(for: $0) }
            )
        }

        let joinSnapshot = SMBContinuationCountBarrier()
        let completeJoinSnapshotCount = LockedCounter()
        await session.setReaderTaskJoinSnapshotHookForTesting { count in
            if count == 2 { completeJoinSnapshotCount.increment() }
            joinSnapshot.signal()
        }
        let closeCompleted = SMBContinuationCountBarrier()
        let closing = Task {
            await session.closeTransportAndWait(cause: "test_join_both_reader_tasks")
            closeCompleted.signal()
        }
        let snapshotClock = ManualSMBSleeper()
        try await awaitWithTimeout("shutdown snapshots both reader tasks") {
            try await joinSnapshot.waitForCount(
                1,
                timeout: .seconds(1),
                sleeper: { try await snapshotClock.sleep(for: $0) }
            )
        }
        XCTAssertEqual(completeJoinSnapshotCount.value, 1, "shutdown must snapshot both reader tasks")

        let closeWaitClock = ManualSMBSleeper()
        let closeWait = Task {
            try await closeCompleted.waitForCount(
                1,
                timeout: .seconds(1),
                sleeper: { try await closeWaitClock.sleep(for: $0) }
            )
        }
        let timerGuardClock = ManualSMBSleeper()
        try await awaitWithTimeout("install close-join absence guard") {
            try await closeWaitClock.waitUntilCallCount(
                atLeast: 1,
                timeout: .seconds(1),
                sleeper: { try await timerGuardClock.sleep(for: $0) }
            )
        }
        exitGate.release(secondHandle)
        try await awaitWithTimeout("replacement reader exits after close") { await secondReader.value }
        closeWaitClock.fireNext()
        do {
            try await awaitWithTimeout("close still waits for the old reader") { try await closeWait.value }
            XCTFail("closeTransportAndWait returned while the old reader was held")
        } catch is SMBContinuationWaitTimedOut {
            // The replacement exited, while the old task is still part of the join set.
        }

        exitGate.release(firstHandle)
        try await awaitWithTimeout("shutdown joins both reader tasks") { await closing.value }
        let readerTaskCountAfterClose = await session.readerTaskCountForTesting()
        XCTAssertEqual(readerTaskCountAfterClose, 0)
        XCTAssertEqual(transport.activeReceiveCount, 0)
        XCTAssertEqual(transport.closeCount, 1)
        await session.setReaderTaskExitHookForTesting(nil)
        await session.setReaderTaskJoinSnapshotHookForTesting(nil)
    }

    func testCloseJoinsReplacementAfterOldReaderExits() async throws {
        let transport = ControlledReceiveTransport()
        let session = SMBSession(
            host: "test",
            port: 445,
            credential: .anonymous,
            transport: transport,
            initialCredits: 1
        )
        let exitGate = SMBReaderTaskExitGate()
        defer { exitGate.releaseAll() }
        await session.setReaderTaskExitHookForTesting { handle in await exitGate.hold(handle) }

        let first = Task { try await session.echo() }
        try await awaitWithTimeout("first ECHO is sent before symmetric join case") {
            await session.waitForRequestSentCountForTesting(atLeast: 1)
        }
        let optionalFirstHandle = await session.readerHandleForTesting()
        let firstHandle = try XCTUnwrap(optionalFirstHandle)
        let optionalFirstReader = await session.readerTaskForTesting(handle: firstHandle)
        let firstReader = try XCTUnwrap(optionalFirstReader)
        let firstRequest = try XCTUnwrap(try unframed(transport.outbound).first)
        let firstMessageId = try SMB2Header.decode(firstRequest).messageId
        transport.enqueueInbound(try framed([smb2EchoResponse(messageId: firstMessageId)]))

        let firstExitClock = ManualSMBSleeper()
        try await awaitWithTimeout("old reader reaches its exit gate before replacement") {
            try await exitGate.waitForCount(
                1,
                timeout: .seconds(1),
                sleeper: { try await firstExitClock.sleep(for: $0) }
            )
        }
        try await awaitWithTimeout("first ECHO completes before replacement") { try await first.value }

        let second = Task { try await session.echo() }
        try await awaitWithTimeout("replacement ECHO is sent") {
            await session.waitForRequestSentCountForTesting(atLeast: 2)
        }
        let receiveClock = ManualSMBSleeper()
        try await awaitWithTimeout("replacement reader blocks in receive") {
            try await transport.waitUntilReceiveIsBlocked(
                timeout: .seconds(1),
                sleeper: { try await receiveClock.sleep(for: $0) }
            )
        }
        let optionalSecondHandle = await session.readerHandleForTesting()
        let secondHandle = try XCTUnwrap(optionalSecondHandle)
        let optionalSecondReader = await session.readerTaskForTesting(handle: secondHandle)
        let secondReader = try XCTUnwrap(optionalSecondReader)
        XCTAssertNotEqual(secondHandle, firstHandle)

        await session.closeTransport(cause: "test_close_with_replacement_joined_last")
        do {
            try await awaitWithTimeout("replacement ECHO fails with closed transport") { try await second.value }
            XCTFail("closing the transport must fail the pending replacement ECHO")
        } catch SMBTransportError.connectionClosed {
        }
        let bothExitClock = ManualSMBSleeper()
        try await awaitWithTimeout("both old and replacement readers reach their exit gates") {
            try await exitGate.waitForCount(
                2,
                timeout: .seconds(1),
                sleeper: { try await bothExitClock.sleep(for: $0) }
            )
        }

        let joinSnapshot = SMBContinuationCountBarrier()
        let snapshotCount = LockedCounter()
        await session.setReaderTaskJoinSnapshotHookForTesting { count in
            if count == 2 { snapshotCount.increment() }
            joinSnapshot.signal()
        }
        // firstReader.value completing does not prove the close task has moved past its join
        // of that Task, so the absence check below waits for close to report that it is now
        // awaiting the replacement.
        let awaitingReplacement = SMBContinuationCountBarrier()
        await session.setReaderTaskJoinWillAwaitHookForTesting { handle in
            if handle == secondHandle { awaitingReplacement.signal() }
        }
        let closeCompleted = SMBContinuationCountBarrier()
        let closing = Task {
            await session.closeTransportAndWait(cause: "test_join_replacement_after_old")
            closeCompleted.signal()
        }
        let snapshotClock = ManualSMBSleeper()
        try await awaitWithTimeout("shutdown snapshots both reader tasks in symmetric case") {
            try await joinSnapshot.waitForCount(
                1,
                timeout: .seconds(1),
                sleeper: { try await snapshotClock.sleep(for: $0) }
            )
        }
        XCTAssertEqual(snapshotCount.value, 1, "shutdown must snapshot both readers")

        let closeWaitClock = ManualSMBSleeper()
        let closeWait = Task {
            try await closeCompleted.waitForCount(
                1,
                timeout: .seconds(1),
                sleeper: { try await closeWaitClock.sleep(for: $0) }
            )
        }
        let timerGuardClock = ManualSMBSleeper()
        try await awaitWithTimeout("install close-join guard for the replacement") {
            try await closeWaitClock.waitUntilCallCount(
                atLeast: 1,
                timeout: .seconds(1),
                sleeper: { try await timerGuardClock.sleep(for: $0) }
            )
        }

        exitGate.release(firstHandle)
        try await awaitWithTimeout("old reader exits while replacement remains gated") { await firstReader.value }
        let awaitingClock = ManualSMBSleeper()
        try await awaitWithTimeout("close begins awaiting the replacement reader") {
            try await awaitingReplacement.waitForCount(
                1,
                timeout: .seconds(1),
                sleeper: { try await awaitingClock.sleep(for: $0) }
            )
        }
        closeWaitClock.fireNext()
        do {
            try await awaitWithTimeout("close still waits for the replacement reader") { try await closeWait.value }
            XCTFail("closeTransportAndWait returned while only the replacement reader was held")
        } catch is SMBContinuationWaitTimedOut {
            // The old reader exited; the replacement remains in the close join set.
        }

        exitGate.release(secondHandle)
        try await awaitWithTimeout("replacement reader exits after its gate opens") { await secondReader.value }
        try await awaitWithTimeout("shutdown joins the replacement reader") { await closing.value }
        let taskCountAfterClose = await session.readerTaskCountForTesting()
        XCTAssertEqual(taskCountAfterClose, 0)
        XCTAssertEqual(transport.activeReceiveCount, 0)
        XCTAssertEqual(transport.closeCount, 1)
        await session.setReaderTaskExitHookForTesting(nil)
        await session.setReaderTaskJoinSnapshotHookForTesting(nil)
        await session.setReaderTaskJoinWillAwaitHookForTesting(nil)
    }

    func testConnectionSlotRejectsCandidatePublishedAfterClose() {
        let slot = SMBTransportConnectionSlot<TestTransportResource>()
        let candidate = TestTransportResource()

        XCTAssertNil(slot.close())
        XCTAssertFalse(slot.install(candidate))
        XCTAssertNil(slot.value)
        XCTAssertNil(slot.close(), "close is idempotent")
    }

    func testRetiredPendingFullSendDoesNotStartAnIdleReceive() async throws {
        let transport = ControlledReceiveTransport()
        let session = SMBSession(
            host: "test",
            port: 445,
            credential: .anonymous,
            transport: transport,
            initialCredits: 1
        )
        let retiredPending = Task {
            try await session.parkPendingForTesting(messageId: 0x77, command: SMB2Commands.echo)
        }
        try await awaitWithTimeout("pending record installed for retired-send model") {
            await session.waitForPendingCountForTesting(atLeast: 1)
        }
        await session.failPendingResponseForTesting(messageId: 0x77)
        do {
            try await awaitWithTimeout("retired pending continuation") { try await retiredPending.value }
            XCTFail("retired pending record should resume its waiter")
        } catch is CancellationError {
        }

        await session.sendDidSucceedForTesting(messageId: 0x77)
        let readerRunningBeforeClose = await session.receiveLoopRunningForTesting()
        XCTAssertFalse(readerRunningBeforeClose, "a send with no remaining wire response must leave the reader dormant")
        await session.closeTransportAndWait(cause: "test_retired_pending_send_bootstrap_join")
        let readerTaskCountAfterClose = await session.readerTaskCountForTesting()
        XCTAssertEqual(readerTaskCountAfterClose, 0)
        XCTAssertEqual(transport.receiveCount, 0, "idle completion must not enter transport.receive")
    }

    func testUnsentResponseIsDiscardedAndReaderRemainsSingle() async throws {
        let transport = ControlledReceiveTransport()
        let session = SMBSession(
            host: "test",
            port: 445,
            credential: .anonymous,
            transport: transport,
            initialCredits: 1
        )
        defer { transport.close() }

        let requestB = Task {
            try await session.parkPendingForTesting(messageId: 0xB0, command: SMB2Commands.echo)
        }
        let requestC = Task {
            try await session.parkPendingForTesting(messageId: 0xC0, command: SMB2Commands.echo)
        }
        try await awaitWithTimeout("both unsent ECHOs are registered") {
            await session.waitForPendingCountForTesting(atLeast: 2)
        }
        try await session.dispatchReceivedPacketForTesting(smb2EchoResponse(messageId: 0xB0))
        let orphanCountBeforeSend = await session.orphanResponseCountForTesting()
        XCTAssertEqual(orphanCountBeforeSend, 0, "a response for a registered but unsent request is discarded")

        let taskCountAfterBootstrap = await session.sendDidSucceedInOrderForTesting([0xB0, 0xC0])
        XCTAssertEqual(taskCountAfterBootstrap, 1, "both sent requests share one reader")
        let pendingAfterBootstrap = await session.pendingCountForTesting()
        XCTAssertEqual(pendingAfterBootstrap, 2, "the discarded response is not replayed after send completion")

        let receiveClock = ManualSMBSleeper()
        try await awaitWithTimeout("single reader waits for C's final") {
            try await transport.waitUntilReceiveIsBlocked(
                timeout: .seconds(1),
                sleeper: { try await receiveClock.sleep(for: $0) }
            )
        }
        XCTAssertEqual(
            transport.maxConcurrentReceiveCount,
            1,
            "send completion and orphan replay must never leave two readers in transport.receive"
        )
        let optionalCurrentHandle = await session.readerHandleForTesting()
        let currentHandle = try XCTUnwrap(optionalCurrentHandle)
        let optionalCurrentReader = await session.readerTaskForTesting(handle: currentHandle)
        let currentReader = try XCTUnwrap(optionalCurrentReader)
        transport.enqueueInbound(try framed([
            smb2EchoResponse(messageId: 0xB0),
            smb2EchoResponse(messageId: 0xC0)
        ]))
        try await awaitWithTimeout("fresh B and C finals are delivered by the sole reader") {
            _ = try await requestB.value
            _ = try await requestC.value
        }
        try await awaitWithTimeout("sole reader becomes dormant after both finals") { await currentReader.value }
        XCTAssertEqual(transport.maxConcurrentReceiveCount, 1)
        await session.closeTransportAndWait(cause: "test_orphan_replay_reader_join")
    }

    func testStaleCallbacksCannotMutateAClosedGeneration() async throws {
        let transport = ControlledReceiveTransport()
        let session = SMBSession(
            host: "test",
            port: 445,
            credential: .anonymous,
            transport: transport,
            initialCredits: 1
        )
        await session.closeTransportAndWait(cause: "test_stale_callback_setup_close")

        // A terminal wire makes the pending-count helper return before this Task registers.
        // Synchronize on the insertion callback so the stale callbacks have a record to test.
        let registration = POSIXAsyncCounter()
        let responseWaiter = Task {
            try await session.parkPendingForTesting(
                messageId: 0x88,
                command: SMB2Commands.echo,
                sent: true,
                onRegistered: { registration.increment() }
            )
        }
        try await awaitWithTimeout("sent record installed behind terminal fence") {
            await registration.wait(until: 1)
        }
        try await session.dispatchReceivedPacketForTesting(smb2EchoResponse(messageId: 0x88))
        let pendingAfterStaleReceive = await session.wirePendingRecordCountForTesting()
        XCTAssertEqual(pendingAfterStaleReceive, 1, "a stale receive cannot remove a terminal-generation record")
        if let handle = await session.readerHandleForTesting() {
            await session.readerDidExitForTesting(
                generation: 1,
                handle: handle,
                error: SMBTransportError.socketFailure("stale reader completion")
            )
        } else {
            await session.readerDidExitForTesting(
                generation: 1,
                handle: UUID(),
                error: SMBTransportError.socketFailure("stale reader completion")
            )
        }
        let pendingAfterStaleReaderExit = await session.wirePendingRecordCountForTesting()
        XCTAssertEqual(pendingAfterStaleReaderExit, 1, "a stale reader exit cannot remove a terminal-generation record")
        await session.sendDidSucceedForTesting(messageId: 0x88)
        let pendingAfterStaleSend = await session.wirePendingRecordCountForTesting()
        XCTAssertEqual(pendingAfterStaleSend, 1, "a stale send completion cannot remove a terminal-generation record")

        let pending = await session.wirePendingRecordCountForTesting()
        let orphanCount = await session.orphanResponseCountForTesting()
        let readerRunning = await session.receiveLoopRunningForTesting()
        let readerTask = await session.readerTaskForTesting()
        XCTAssertEqual(pending, 1)
        XCTAssertEqual(orphanCount, 0)
        XCTAssertFalse(readerRunning)
        XCTAssertNil(readerTask)
        XCTAssertEqual(transport.receiveCount, 0)

        await session.failPendingResponseForTesting(messageId: 0x88)
        do {
            try await awaitWithTimeout("stale callback waiter cleanup") { try await responseWaiter.value }
            XCTFail("the stale frame must not complete a terminal-generation request")
        } catch is CancellationError {
        }
    }

    func testRequestTimerCannotMutateAClosedGeneration() async throws {
        let transport = ControlledReceiveTransport()
        let session = SMBSession(
            host: "test",
            port: 445,
            credential: .anonymous,
            transport: transport,
            initialCredits: 1
        )
        await session.closeTransportAndWait(cause: "test_stale_timer_setup_close")

        let messageId: UInt64 = 0x89
        // A terminal wire makes the pending-count helper return before this Task registers
        // (same race as testStaleCallbacksCannotMutateAClosedGeneration). Wait for insertion.
        let registration = POSIXAsyncCounter()
        let pending = Task {
            try await session.parkPendingForTesting(
                messageId: messageId,
                command: SMB2Commands.echo,
                sent: true,
                onRegistered: { registration.increment() }
            )
        }
        try await awaitWithTimeout("terminal-generation test record installed") {
            await registration.wait(until: 1)
        }
        let identity = UUID()
        await session.setRequestTimeoutIdentityForTesting(messageId: messageId, identity: identity)
        await session.requestDidTimeOutForTesting(
            messageId: messageId,
            command: SMB2Commands.echo,
            generation: 1,
            identity: identity
        )

        let pendingAfterStaleTimer = await session.wirePendingRecordCountForTesting()
        XCTAssertEqual(pendingAfterStaleTimer, 1, "a timer from a terminal generation cannot retire a record")
        await session.failPendingResponseForTesting(messageId: messageId)
        do {
            try await awaitWithTimeout("terminal-generation timer fixture drains") { try await pending.value }
            XCTFail("fixture record should be released")
        } catch is CancellationError {
        }
    }

    func testWrongReaderCompletionHandleIsIgnoredAndStoppingHandleIsAcknowledged() async throws {
        let transport = ControlledReceiveTransport()
        let session = SMBSession(
            host: "test",
            port: 445,
            credential: .anonymous,
            transport: transport,
            initialCredits: 1
        )
        let echo = Task { try await session.echo() }
        try await awaitWithTimeout("ECHO send starts the reader") {
            await session.waitForRequestSentCountForTesting(atLeast: 1)
        }
        let actualHandle = await session.readerHandleForTesting()
        XCTAssertNotNil(actualHandle)
        await session.readerDidExitForTesting(
            generation: 1,
            handle: UUID(),
            error: SMBTransportError.socketFailure("wrong handle")
        )
        let readerStillRunning = await session.receiveLoopRunningForTesting()
        XCTAssertTrue(readerStillRunning)
        XCTAssertEqual(transport.closeCount, 0)

        let request = try XCTUnwrap(try unframed(transport.outbound).first)
        let messageId = try SMB2Header.decode(request).messageId
        transport.enqueueInbound(try framed([smb2EchoResponse(messageId: messageId)]))
        try await awaitWithTimeout("ECHO after stale completion") { try await echo.value }
        await session.closeTransportAndWait(cause: "test_reader_ack_join")
        let stoppedHandle = await session.readerHandleForTesting()
        XCTAssertNil(stoppedHandle, "the matching stop acknowledgement clears the handle")
    }

    func testCloseWhileCreditGrantHookIsSuspendedPreservesAcceptedFinal() async throws {
        let transport = ControlledReceiveTransport()
        let session = SMBSession(
            host: "test",
            port: 445,
            credential: .anonymous,
            transport: transport,
            initialCredits: 1
        )
        let grantGate = SMBContinuationAsyncGate()
        let gateClock = ManualSMBSleeper()
        let hookEntered = SMBContinuationCountBarrier()
        await session.setCreditGrantAfterAwaitHookForTesting {
            hookEntered.signal()
            try? await grantGate.suspend(
                timeout: .seconds(2),
                sleeper: { try await gateClock.sleep(for: $0) }
            )
        }
        let echo = Task { try await session.echo() }
        try await awaitWithTimeout("ECHO sent before suspended grant") {
            await session.waitForRequestSentCountForTesting(atLeast: 1)
        }
        let request = try XCTUnwrap(try unframed(transport.outbound).first)
        let messageId = try SMB2Header.decode(request).messageId
        transport.enqueueInbound(try framed([smb2EchoResponse(messageId: messageId)]))
        let eventClock = ManualSMBSleeper()
        try await awaitWithTimeout("credit grant reached the injected await") {
            try await hookEntered.waitForCount(
                1,
                timeout: .seconds(1),
                sleeper: { try await eventClock.sleep(for: $0) }
            )
        }
        try await awaitWithTimeout("accepted ECHO completes while credit acknowledgement is paused") {
            try await echo.value
        }

        await session.closeTransport(cause: "test_close_during_credit_ack")
        grantGate.release()
        await session.closeTransportAndWait(cause: "test_credit_ack_post_close_join")
        let dispatchCount = await session.receivedPacketDispatchCountForTesting()
        let pending = await session.pendingCountForTesting()
        XCTAssertEqual(dispatchCount, 1, "final acceptance precedes the delayed credit acknowledgement")
        XCTAssertEqual(pending, 0)
        XCTAssertEqual(transport.closeCount, 1)
        await session.setCreditGrantAfterAwaitHookForTesting(nil)
        grantGate.reset()
        hookEntered.reset()
    }

    func testReaderDropsRemainingFramesAfterGenerationChanges() async throws {
        let transport = ControlledReceiveTransport()
        let session = SMBSession(
            host: "test",
            port: 445,
            credential: .anonymous,
            transport: transport,
            initialCredits: 2
        )
        let grantGate = SMBContinuationAsyncGate()
        let gateClock = ManualSMBSleeper()
        let hookEntered = SMBContinuationCountBarrier()
        let hookCount = LockedCounter()
        await session.setCreditGrantAfterAwaitHookForTesting {
            hookCount.increment()
            if hookCount.value == 2 {
                hookEntered.signal()
                try? await grantGate.suspend(
                    timeout: .seconds(2),
                    sleeper: { try await gateClock.sleep(for: $0) }
                )
            }
        }

        let firstEcho = Task { try await session.echo() }
        try await awaitWithTimeout("first ECHO sent before generation test") {
            await session.waitForRequestSentCountForTesting(atLeast: 1)
        }
        let firstRequest = try XCTUnwrap(try unframed(transport.outbound).first)
        let firstMessageId = try SMB2Header.decode(firstRequest).messageId
        let secondEcho = Task { try await session.echo() }
        try await awaitWithTimeout("second ECHO sent before generation test") {
            await session.waitForRequestSentCountForTesting(atLeast: 2)
        }
        let secondRequest = try XCTUnwrap(try unframed(transport.outbound).last)
        let secondMessageId = try SMB2Header.decode(secondRequest).messageId
        transport.enqueueInbound(try framed([
            smb2EchoResponse(messageId: firstMessageId),
            smb2EchoResponse(messageId: secondMessageId),
            smb2EchoResponse(messageId: 0x2222)
        ]))

        let eventClock = ManualSMBSleeper()
        try await awaitWithTimeout("second accepted response reached the suspended credit grant") {
            try await hookEntered.waitForCount(
                1,
                timeout: .seconds(1),
                sleeper: { try await eventClock.sleep(for: $0) }
            )
        }
        try await awaitWithTimeout("first frame was processed before the generation changed") {
            try await firstEcho.value
        }
        try await awaitWithTimeout("second final completes before its credit acknowledgement") {
            try await secondEcho.value
        }
        let dispatchCountBeforeClose = await session.receivedPacketDispatchCountForTesting()
        XCTAssertEqual(dispatchCountBeforeClose, 2)

        await session.closeTransport(cause: "test_close_during_reader_generation")
        grantGate.release()
        await session.closeTransportAndWait(cause: "test_reader_generation_join")
        XCTAssertEqual(hookCount.value, 2, "the third frame must not start credit processing")
        let dispatchCountAfterClose = await session.receivedPacketDispatchCountForTesting()
        let orphanCountAfterClose = await session.orphanResponseCountForTesting()
        XCTAssertEqual(dispatchCountAfterClose, 2)
        XCTAssertEqual(orphanCountAfterClose, 0)
        XCTAssertEqual(transport.closeCount, 1)
        await session.setCreditGrantAfterAwaitHookForTesting(nil)
        grantGate.reset()
        hookEntered.reset()
    }

    func testStaleFrameGenerationCannotGrantCreditDispatchOrQueueOrphan() async throws {
        let transport = ControlledReceiveTransport()
        let session = SMBSession(
            host: "test",
            port: 445,
            credential: .anonymous,
            transport: transport,
            initialCredits: 2
        )
        defer { transport.close() }

        let activeRequest = Task {
            try await session.parkPendingForTesting(messageId: 0x140, command: SMB2Commands.echo)
        }
        try await awaitWithTimeout("generation 1 request is registered") {
            await session.waitForPendingCountForTesting(atLeast: 1)
        }
        await session.sendDidSucceedForTesting(messageId: 0x140, generation: 1)
        let receiveClock = ManualSMBSleeper()
        try await awaitWithTimeout("generation 1 reader becomes active") {
            try await transport.waitUntilReceiveIsBlocked(
                timeout: .seconds(1),
                sleeper: { try await receiveClock.sleep(for: $0) }
            )
        }

        let creditBefore = await session.creditBalanceForTesting()
        let dispatchBefore = await session.receivedPacketDispatchCountForTesting()
        let orphanBefore = await session.orphanResponseCountForTesting()
        let staleFrame = try smb2EchoResponse(messageId: 0x240, credits: 7)
        let shouldContinue = try await session.processRawFrameForTesting(
            staleFrame,
            generation: 2,
            handle: UUID()
        )
        XCTAssertFalse(shouldContinue, "generation 2 frame must be fenced from active generation 1")

        let creditAfter = await session.creditBalanceForTesting()
        let dispatchAfter = await session.receivedPacketDispatchCountForTesting()
        let orphanAfter = await session.orphanResponseCountForTesting()
        XCTAssertEqual(creditAfter, creditBefore, "stale frame credits must not change the window")
        XCTAssertEqual(dispatchAfter, dispatchBefore, "stale frame must not reach response dispatch")
        XCTAssertEqual(orphanAfter, orphanBefore, "stale frame must not become an orphan response")

        await session.closeTransportAndWait(cause: "test_stale_frame_generation_join")
        do {
            try await awaitWithTimeout("generation test pending request closes") { try await activeRequest.value }
            XCTFail("close should fail the active generation 1 request")
        } catch SMBTransportError.connectionClosed {
        }
    }

    func testSessionCloseReclaimsTransportPublishedAfterConnectClose() async throws {
        let transport = LateConnectPublicationTransport()
        defer { transport.resetConnectGate() }
        let session = SMBSession(
            host: "test",
            port: 445,
            credential: .anonymous,
            transport: transport,
            initialCredits: 1
        )
        let enteredClock = ManualSMBSleeper()
        let connecting = Task { try await session.connect() }
        try await smbIssue102AwaitWithTimeout("transport connect entered") {
            try await transport.connectEntered.waitForCount(
                1,
                timeout: .seconds(1),
                sleeper: { try await enteredClock.sleep(for: $0) }
            )
        }

        let closing = Task { await session.closeTransportAndWait(cause: "test_connect_close_publication_race") }
        let closeClock = ManualSMBSleeper()
        try await smbIssue102AwaitWithTimeout("session closed transport before candidate publication") {
            try await transport.closeObserved.waitForCount(
                1,
                timeout: .seconds(1),
                sleeper: { try await closeClock.sleep(for: $0) }
            )
        }
        transport.releaseConnect()
        do {
            try await smbIssue102AwaitWithTimeout("stale connect fails after close") { try await connecting.value }
            XCTFail("close must prevent the session from continuing after connect")
        } catch SMBTransportError.connectionClosed {
            // Expected: the stale connect completion is rejected and closes its candidate.
        }
        try await smbIssue102AwaitWithTimeout("close joins connect and late candidate cleanup") {
            await closing.value
        }

        XCTAssertTrue(transport.publishedAfterClose)
        XCTAssertFalse(transport.resourceIsOpen)
        XCTAssertEqual(transport.closeCount, 2, "the late candidate is re-closed after connect unwinds")
        let terminal = await session.isTransportClosedForTesting()
        XCTAssertTrue(terminal)
    }

    func testIdleEOFIsObservedOnlyWhenTheNextRequestStartsAReader() async throws {
        let transport = ControlledReceiveTransport()
        let session = SMBSession(
            host: "test",
            port: 445,
            credential: .anonymous,
            transport: transport,
            initialCredits: 1
        )
        let clock = ManualSMBSleeper()
        let echo = Task { try await session.echo() }
        try await awaitWithTimeout("reader started") {
            try await transport.waitForReceiveCount(
                atLeast: 1,
                timeout: .seconds(1),
                sleeper: { try await clock.sleep(for: $0) }
            )
        }
        let request = try XCTUnwrap(try unframed(transport.outbound).first)
        let messageId = try SMB2Header.decode(request).messageId
        let optionalReaderHandle = await session.readerHandleForTesting()
        let readerHandle = try XCTUnwrap(optionalReaderHandle)
        let optionalReader = await session.readerTaskForTesting(handle: readerHandle)
        let reader = try XCTUnwrap(optionalReader)
        transport.enqueueInbound(try framed([smb2EchoResponse(messageId: messageId)]))
        try await awaitWithTimeout("ECHO response before idle EOF") { try await echo.value }
        try await awaitWithTimeout("reader stops at pending zero") { await reader.value }
        XCTAssertEqual(transport.receiveCount, 2)
        let readerRunningAtIdle = await session.receiveLoopRunningForTesting()
        let isClosedAtIdle = await session.isTransportClosedForTesting()
        XCTAssertFalse(readerRunningAtIdle)
        XCTAssertFalse(isClosedAtIdle)
        XCTAssertEqual(transport.closeCount, 0)

        transport.finishInput()
        let nextEcho = Task { try await session.echo() }
        do {
            try await awaitWithTimeout("EOF after the next send") { try await nextEcho.value }
            XCTFail("the next demand should observe the finished transport")
        } catch SMBTransportError.connectionClosed {
        }
        let isClosed = await session.isTransportClosedForTesting()
        let readerRunning = await session.receiveLoopRunningForTesting()
        XCTAssertTrue(isClosed)
        XCTAssertFalse(readerRunning)
        XCTAssertEqual(transport.closeCount, 1)
        await session.closeTransportAndWait(cause: "test_idle_eof_join")
    }

    func testControlledReceiveWaitersTimeoutCancelAndResetDrain() async throws {
        let transport = ControlledReceiveTransport()
        let timeoutClock = ManualSMBSleeper()
        let timedWait = Task {
            try await transport.waitForReceiveCount(
                atLeast: 1,
                timeout: .seconds(1),
                sleeper: { try await timeoutClock.sleep(for: $0) }
            )
        }
        try await timeoutClock.waitUntilCallCount(atLeast: 1, timeout: .seconds(1), sleeper: { try await ManualSMBSleeper().sleep(for: $0) })
        timeoutClock.fireNext()
        do {
            try await awaitWithTimeout("event waiter injected timeout") { try await timedWait.value }
            XCTFail("event wait should time out")
        } catch is SMBTestEventWaitTimedOut {
        }

        let outboundTimeoutClock = ManualSMBSleeper()
        let outboundTimedWait = Task {
            try await transport.waitForOutboundFrameCount(
                atLeast: 1,
                timeout: .seconds(1),
                sleeper: { try await outboundTimeoutClock.sleep(for: $0) }
            )
        }
        try await awaitWithTimeout("outbound frame timeout sleeper registration") {
            try await outboundTimeoutClock.waitUntilCallCount(atLeast: 1, timeout: .seconds(1), sleeper: { try await ManualSMBSleeper().sleep(for: $0) })
        }
        outboundTimeoutClock.fireNext()
        do {
            try await awaitWithTimeout("outbound frame waiter timeout") { try await outboundTimedWait.value }
            XCTFail("outbound frame event should time out")
        } catch is SMBTestEventWaitTimedOut {
        }

        let outboundCancelClock = ManualSMBSleeper()
        let outboundCancelledWait = Task {
            try await transport.waitForOutboundFrameCount(
                atLeast: 2,
                timeout: .seconds(1),
                sleeper: { try await outboundCancelClock.sleep(for: $0) }
            )
        }
        try await awaitWithTimeout("outbound frame cancellation sleeper registration") {
            try await outboundCancelClock.waitUntilCallCount(atLeast: 1, timeout: .seconds(1), sleeper: { try await ManualSMBSleeper().sleep(for: $0) })
        }
        outboundCancelledWait.cancel()
        do {
            try await awaitWithTimeout("outbound frame waiter cancellation") {
                try await outboundCancelledWait.value
            }
            XCTFail("cancelled outbound frame wait should throw")
        } catch is CancellationError {
        }

        let cancelClock = ManualSMBSleeper()
        let cancelledWait = Task {
            try await transport.waitForReceiveCount(
                atLeast: 2,
                timeout: .seconds(1),
                sleeper: { try await cancelClock.sleep(for: $0) }
            )
        }
        try await cancelClock.waitUntilCallCount(atLeast: 1, timeout: .seconds(1), sleeper: { try await ManualSMBSleeper().sleep(for: $0) })
        cancelledWait.cancel()
        do {
            try await awaitWithTimeout("event waiter cancellation") { try await cancelledWait.value }
            XCTFail("cancelled event wait should throw")
        } catch is CancellationError {
        }

        let receiveBlockClock = ManualSMBSleeper()
        let receive = Task { try await transport.receive(maxLength: 4) }
        try await awaitWithTimeout("receive fixture blocked event") {
            try await transport.waitUntilReceiveIsBlocked(
                timeout: .seconds(1),
                sleeper: { try await receiveBlockClock.sleep(for: $0) }
            )
        }
        let resetClock = ManualSMBSleeper()
        let drainedWait = Task {
            try await transport.waitForReceiveCount(
                atLeast: Int.max,
                timeout: .seconds(1),
                sleeper: { try await resetClock.sleep(for: $0) }
            )
        }
        let outboundResetClock = ManualSMBSleeper()
        let outboundDrainedWait = Task {
            try await transport.waitForOutboundFrameCount(
                atLeast: Int.max,
                timeout: .seconds(1),
                sleeper: { try await outboundResetClock.sleep(for: $0) }
            )
        }
        try await resetClock.waitUntilCallCount(atLeast: 1, timeout: .seconds(1), sleeper: { try await ManualSMBSleeper().sleep(for: $0) })
        try await awaitWithTimeout("outbound reset waiter sleeper registration") {
            try await outboundResetClock.waitUntilCallCount(atLeast: 1, timeout: .seconds(1), sleeper: { try await ManualSMBSleeper().sleep(for: $0) })
        }
        transport.reset()
        do {
            _ = try await awaitWithTimeout("reset drains receive") { try await receive.value }
            XCTFail("reset receive should be cancelled")
        } catch is CancellationError {
        }
        do {
            try await awaitWithTimeout("reset drains outbound event waiter") {
                try await outboundDrainedWait.value
            }
            XCTFail("reset should drain outbound frame waiter")
        } catch is CancellationError {
        }
        do {
            try await awaitWithTimeout("reset drains event waiter") { try await drainedWait.value }
            XCTFail("reset event waiter should be cancelled")
        } catch is CancellationError {
        }
        XCTAssertEqual(transport.activeReceiveCount, 0)
        XCTAssertEqual(transport.receiveCount, 0)
    }

    func testManualSleeperResetDrainsSleepAndCallCountWaiters() async throws {
        let clock = ManualSMBSleeper()
        let sleep = Task { try await clock.sleep(for: .seconds(1)) }
        let countEventClock = ManualSMBSleeper()
        try await clock.waitUntilCallCount(
            atLeast: 1,
            timeout: .seconds(1),
            sleeper: { try await countEventClock.sleep(for: $0) }
        )

        let timeoutClock = ManualSMBSleeper()
        let timeoutStarted = SMBContinuationCountBarrier()
        let countWait = Task {
            try await clock.waitUntilCallCount(
                atLeast: 2,
                timeout: .seconds(1),
                sleeper: { duration in
                    timeoutStarted.signal()
                    try await timeoutClock.sleep(for: duration)
                }
            )
        }
        let eventWaitClock = ManualSMBSleeper()
        try await awaitWithTimeout("manual sleeper count timeout starts") {
            try await timeoutStarted.waitForCount(
                1,
                timeout: .seconds(1),
                sleeper: { try await eventWaitClock.sleep(for: $0) }
            )
        }

        clock.reset()
        do {
            try await awaitWithTimeout("manual sleeper reset cancels time wait") { try await sleep.value }
            XCTFail("reset should cancel a parked sleep")
        } catch is CancellationError {
        }
        do {
            try await awaitWithTimeout("manual sleeper reset drains count waiter") { try await countWait.value }
            XCTFail("reset should drain a parked call-count waiter")
        } catch is CancellationError {
        }
        timeoutStarted.reset()
        eventWaitClock.reset()
    }

    func testAsyncBarrierTimeoutCancellationAndResetDrain() async throws {
        let gate = SMBContinuationAsyncGate()
        let timeoutClock = ManualSMBSleeper()
        let timeoutWait = Task {
            try await gate.suspend(
                timeout: .seconds(1),
                sleeper: { try await timeoutClock.sleep(for: $0) }
            )
        }
        let eventClock = ManualSMBSleeper()
        try await gate.waitUntilSuspended(
            timeout: .seconds(1),
            sleeper: { try await eventClock.sleep(for: $0) }
        )
        try await timeoutClock.waitUntilCallCount(atLeast: 1, timeout: .seconds(1), sleeper: { try await ManualSMBSleeper().sleep(for: $0) })
        timeoutClock.fireNext()
        do {
            try await awaitWithTimeout("barrier injected timeout") { try await timeoutWait.value }
            XCTFail("barrier timeout should fail")
        } catch is SMBContinuationWaitTimedOut {
        }
        XCTAssertEqual(gate.waiterCount, 0)

        let cancelClock = ManualSMBSleeper()
        let cancelled = Task {
            try await gate.suspend(
                timeout: .seconds(1),
                sleeper: { try await cancelClock.sleep(for: $0) }
            )
        }
        try await gate.waitUntilSuspended(
            timeout: .seconds(1),
            sleeper: { try await eventClock.sleep(for: $0) }
        )
        cancelled.cancel()
        do {
            try await awaitWithTimeout("barrier cancellation") { try await cancelled.value }
            XCTFail("cancelled barrier should throw")
        } catch is CancellationError {
        }
        XCTAssertEqual(gate.waiterCount, 0)

        let resetClock = ManualSMBSleeper()
        let drained = Task {
            try await gate.suspend(
                timeout: .seconds(1),
                sleeper: { try await resetClock.sleep(for: $0) }
            )
        }
        try await gate.waitUntilSuspended(
            timeout: .seconds(1),
            sleeper: { try await eventClock.sleep(for: $0) }
        )
        gate.reset()
        do {
            try await awaitWithTimeout("barrier reset drain") { try await drained.value }
            XCTFail("reset should drain the barrier waiter")
        } catch is CancellationError {
        }
        XCTAssertEqual(gate.waiterCount, 0)
    }

    func testCreditWaiterProgressesThroughTheResidentReader() async throws {
        let transport = ControlledReceiveTransport()
        let fileId = hexBytes("00112233445566778899aabbccddeeff")
        let session = SMBSession(
            host: "test",
            port: 445,
            credential: .anonymous,
            transport: transport,
            initialCredits: 2
        )
        let first = Task {
            try await session.readChunk(treeId: 0x3344, fileId: fileId, offset: 0, length: 131_072)
        }
        try await awaitWithTimeout("first request sent") {
            await session.waitForRequestSentCountForTesting(atLeast: 1)
        }
        let second = Task {
            try await session.readChunk(treeId: 0x3344, fileId: fileId, offset: 131_072, length: 131_072)
        }
        try await awaitWithTimeout("second request parked on credit") {
            await session.waitForCreditWaiterCountForTesting(atLeast: 1)
        }
        XCTAssertEqual(transport.sendAttemptCount, 1)

        let firstRequest = try XCTUnwrap(try unframed(transport.outbound).first)
        let firstHeader = try SMB2Header.decode(firstRequest)
        XCTAssertEqual(firstHeader.command, SMB2Commands.read)
        XCTAssertEqual(firstHeader.creditCharge, 2)
        XCTAssertEqual(readUInt32LE(firstRequest, at: 68), 131_072)
        transport.enqueueInbound(try framed([
            smb2ReadResponse([0x41], messageId: firstHeader.messageId, treeId: 0x3344, credits: 1)
        ]))
        try await awaitWithTimeout("grant releases second request") {
            await session.waitForRequestSentCountForTesting(atLeast: 2)
        }
        let requests = try unframed(transport.outbound).filter {
            try SMB2Header.decode($0).command == SMB2Commands.read
        }
        let secondRequest = try XCTUnwrap(requests.last)
        let secondHeader = try SMB2Header.decode(secondRequest)
        XCTAssertEqual(secondHeader.creditCharge, 1, "the queued READ is resized to the one granted credit")
        XCTAssertEqual(readUInt32LE(secondRequest, at: 68), UInt32(SMB2Credit.unitSize))
        transport.enqueueInbound(try framed([
            smb2ReadResponse([0x42], messageId: secondHeader.messageId, treeId: 0x3344, credits: 1)
        ]))
        _ = try await awaitWithTimeout("first READ completes") { try await first.value }
        _ = try await awaitWithTimeout("second READ completes") { try await second.value }
        let pendingCount = await session.pendingCountForTesting()
        XCTAssertEqual(pendingCount, 0)
        XCTAssertEqual(transport.maxConcurrentReceiveCount, 1)
        await session.closeTransportAndWait(cause: "test_credit_progress_reader_join")
    }

    func testSendingResponsesAreFIFOBufferedAndCreditIsNotGrantedTwice() async throws {
        let transport = ControlledReceiveTransport()
        let session = SMBSession(
            host: "test",
            port: 445,
            credential: .anonymous,
            transport: transport,
            initialCredits: 2
        )
        let clock = ManualSMBSleeper()

        let first = Task { try await session.echo() }
        try await awaitWithTimeout("first ECHO sent") {
            await session.waitForRequestSentCountForTesting(atLeast: 1)
        }
        let firstID = try SMB2Header.decode(try XCTUnwrap(try unframed(transport.outbound).first)).messageId
        transport.blockNextSend()
        let second = Task { try await session.echo() }
        try await awaitWithTimeout("second ECHO send blocks") {
            try await transport.waitForSendAttemptCount(
                atLeast: 2,
                timeout: .seconds(1),
                sleeper: { try await clock.sleep(for: $0) }
            )
        }
        let blockedSend = try XCTUnwrap(transport.firstBlockedSendBytes)
        let secondID = try SMB2Header.decode(Array(blockedSend.dropFirst(4))).messageId
        let asyncId: UInt64 = 0x1234_5678
        var asyncFinal = try SMB2Header.asyncHeader(
            command: SMB2Commands.echo,
            credits: 0,
            messageId: secondID,
            asyncId: asyncId
        ).encode()
        asyncFinal.append(contentsOf: [4, 0, 0, 0])
        transport.enqueueInbound(try framed([
            try smb2AsyncPendingResponse(
                command: SMB2Commands.echo,
                messageId: secondID,
                asyncId: asyncId,
                credits: 1
            ),
            asyncFinal,
            smb2EchoResponse(messageId: firstID)
        ]))
        try await awaitWithTimeout("pre-send interim, final and in-flight response reach the reader") {
            await session.waitForReceivedPacketDispatchCountForTesting(atLeast: 3)
        }
        _ = try await awaitWithTimeout("first ECHO completes while the second send remains blocked") {
            try await first.value
        }
        let pendingBeforeSendCompletion = await session.pendingCountForTesting()
        let asyncIdBeforeSendCompletion = await session.pendingAsyncIdForTesting(messageId: secondID)
        let finalSeenBeforeSendCompletion = await session.pendingFinalSeenForTesting(messageId: secondID)
        let callerResumedBeforeSendCompletion = await session.pendingContinuationResumedForTesting(messageId: secondID)
        XCTAssertEqual(pendingBeforeSendCompletion, 1, "response is gated until full-send completion")
        XCTAssertEqual(asyncIdBeforeSendCompletion, asyncId, "STATUS_PENDING correlation is committed while sending")
        XCTAssertTrue(finalSeenBeforeSendCompletion, "the final is accepted while sending")
        XCTAssertFalse(callerResumedBeforeSendCompletion, "the caller gate stays closed until full-send completion")

        transport.releaseBlockedSend()
        try await awaitWithTimeout("accepted ECHO final releases after send completion") { try await second.value }
        let pendingAfterReplay = await session.pendingCountForTesting()
        let creditBalance = await session.creditBalanceForTesting()
        let grantReceiptCount = await session.creditGrantReceiptCountForTesting()
        XCTAssertEqual(pendingAfterReplay, 0)
        XCTAssertEqual(creditBalance, 2, "the two interim grants are applied once; the legal async final grants zero")
        XCTAssertEqual(grantReceiptCount, 3, "each accepted slice grants once, including the zero-credit final")
        await session.closeTransportAndWait(cause: "test_fifo_orphan_reader_join")
    }

    func testUnknownPreSendResponsesDoNotOverflowOrReplay() async throws {
        let transport = ControlledReceiveTransport()
        let session = SMBSession(
            host: "test",
            port: 445,
            credential: .anonymous,
            transport: transport,
            initialCredits: 2
        )
        let firstEcho = Task { try await session.echo() }
        let clock = ManualSMBSleeper()
        try await awaitWithTimeout("first ECHO is sent") {
            await session.waitForRequestSentCountForTesting(atLeast: 1)
        }
        let firstID = try SMB2Header.decode(try XCTUnwrap(try unframed(transport.outbound).first)).messageId
        transport.blockNextSend()
        let blockedEcho = Task { try await session.echo() }
        defer { blockedEcho.cancel() }
        try await awaitWithTimeout("second ECHO is blocked before send completion") {
            try await transport.waitForSendAttemptCount(
                atLeast: 2,
                timeout: .seconds(1),
                sleeper: { try await clock.sleep(for: $0) }
            )
        }
        let blockedSend = try XCTUnwrap(transport.firstBlockedSendBytes)
        let messageId = try SMB2Header.decode(Array(blockedSend.dropFirst(4))).messageId
        let unknownMessageId = messageId &+ 1_000
        let unknownFrames = try (0..<65).map { _ in
            try DirectTCPFraming.frame(smb2EchoResponse(messageId: unknownMessageId))
        }.flatMap { $0 }
        transport.enqueueInbound(unknownFrames + (try DirectTCPFraming.frame(smb2EchoResponse(messageId: firstID))))
        try await awaitWithTimeout("first ECHO completes after unsolicited frames are discarded") {
            try await firstEcho.value
        }
        let closedAfterUnknowns = await session.isTransportClosedForTesting()
        let balanceAfterFirst = await session.creditBalanceForTesting()
        let grantsAfterFirst = await session.creditGrantReceiptCountForTesting()
        XCTAssertFalse(closedAfterUnknowns, "unknown MessageIds do not overflow or close the wire")
        XCTAssertEqual(balanceAfterFirst, 1, "only the known first response grants a credit")
        XCTAssertEqual(grantsAfterFirst, 1, "unknown response credits are discarded")

        transport.releaseBlockedSend()
        try await awaitWithTimeout("second ECHO completes its send") {
            await session.waitForRequestSentCountForTesting(atLeast: 2)
        }
        transport.enqueueInbound(try DirectTCPFraming.frame(smb2EchoResponse(messageId: messageId)))
        try await awaitWithTimeout("second ECHO receives a fresh response") { try await blockedEcho.value }
        let balanceAfterSecond = await session.creditBalanceForTesting()
        let grantsAfterSecond = await session.creditGrantReceiptCountForTesting()
        XCTAssertEqual(balanceAfterSecond, 2)
        XCTAssertEqual(grantsAfterSecond, 2)
        await session.closeTransportAndWait(cause: "test_unknown_unsent_frames_join")
    }

    func testCloseDrainsBlockedCancelSendAfterOriginalResponseIsCancelled() async throws {
        let transport = ControlledReceiveTransport()
        let session = SMBSession(
            host: "test",
            port: 445,
            credential: .anonymous,
            transport: transport,
            initialCredits: 1
        )
        let clock = ManualSMBSleeper()
        let echo = Task { try await session.echo() }
        try await awaitWithTimeout("ECHO full-send") {
            await session.waitForRequestSentCountForTesting(atLeast: 1)
        }
        let echoRequest = try XCTUnwrap(try unframed(transport.outbound).first)
        let echoMessageId = try SMB2Header.decode(echoRequest).messageId
        try await awaitWithTimeout("reader receive begins") {
            try await transport.waitForReceiveCount(
                atLeast: 1,
                timeout: .seconds(1),
                sleeper: { try await clock.sleep(for: $0) }
            )
        }
        transport.blockNextSend()
        echo.cancel()
        do {
            try await awaitWithTimeout("cancelled ECHO caller") { try await echo.value }
            XCTFail("cancelled ECHO should throw CancellationError")
        } catch is CancellationError {
        }
        try await awaitWithTimeout("CANCEL send is registered as blocked") {
            try await transport.waitForBlockedSendCount(
                atLeast: 1,
                timeout: .seconds(1),
                sleeper: { try await clock.sleep(for: $0) }
            )
        }
        XCTAssertEqual(transport.blockedSendCount, 1, "the CANCEL send waiter returns only after blocked registration")

        transport.enqueueInbound(try framed([smb2EchoResponse(messageId: echoMessageId)]))
        try await awaitWithTimeout("late final retires the cancellation record") {
            await session.waitForReceivedPacketDispatchCountForTesting(atLeast: 1)
        }
        let retiredRecordCount = await session.wirePendingRecordCountForTesting()
        XCTAssertEqual(retiredRecordCount, 0, "the blocked CANCEL must outlive its pending record")

        await session.closeTransportAndWait(cause: "test_blocked_cancel_send_drain")
        XCTAssertEqual(transport.blockedSendCount, 0)
        let wireRecordCount = await session.wirePendingRecordCountForTesting()
        XCTAssertEqual(wireRecordCount, 0)
    }

    func testOrdinaryCancellationTombstonesCloseOnTheSixtyFifth() async throws {
        let transport = ControlledReceiveTransport()
        let session = SMBSession(
            host: "test",
            port: 445,
            credential: .anonymous,
            transport: transport,
            initialCredits: 1
        )
        let clock = ManualSMBSleeper()

        for index in 1...65 {
            let echo = Task { try await session.echo() }
            try await awaitWithTimeout("ECHO \(index) sent") {
                await session.waitForRequestSentCountForTesting(atLeast: index)
            }
            let request = try XCTUnwrap(try unframed(transport.outbound).last {
                try SMB2Header.decode($0).command == SMB2Commands.echo
            })
            let messageId = try SMB2Header.decode(request).messageId
            transport.enqueueInbound(try framed([
                try smb2AsyncPendingResponse(
                    command: SMB2Commands.echo,
                    messageId: messageId,
                    asyncId: UInt64(index),
                    credits: 1
                )
            ]))
            try await awaitWithTimeout("ECHO \(index) interim dispatch") {
                await session.waitForReceivedPacketDispatchCountForTesting(atLeast: index)
            }
            echo.cancel()
            do {
                try await awaitWithTimeout("cancelled ECHO \(index)") { try await echo.value }
                XCTFail("cancelled ECHO should throw CancellationError")
            } catch is CancellationError {
            }
            if index < 65 {
                let tombstoneCount = await session.ordinaryCancellationTombstoneCountForTesting()
                XCTAssertEqual(tombstoneCount, index)
                try await awaitWithTimeout("CANCEL \(index) send") {
                    try await transport.waitForSendAttemptCount(
                        atLeast: index * 2,
                        timeout: .seconds(1),
                        sleeper: { try await clock.sleep(for: $0) }
                    )
                }
            }
        }

        let terminal = await session.isTransportClosedForTesting()
        let tombstones = await session.ordinaryCancellationTombstoneCountForTesting()
        XCTAssertTrue(terminal)
        XCTAssertEqual(tombstones, 0, "wire-fatal overflow drains all tombstones")
        await session.closeTransportAndWait(cause: "test_cancellation_tombstone_bound_join")
    }

    func testIdleSessionHasNoReaderAndCanDeinit() async throws {
        let transport = ControlledReceiveTransport()
        let weakSession = try await completeIdleRequestAndReleaseSession(transport: transport)
        XCTAssertNil(weakSession.value, "an idle session has no reader task retaining it")
        XCTAssertEqual(transport.closeCount, 1)
        XCTAssertFalse(transport.hasPendingReceive)
        XCTAssertEqual(transport.activeReceiveCount, 0)
    }

    private func completeIdleRequestAndReleaseSession(
        transport: ControlledReceiveTransport
    ) async throws -> WeakSMBSessionReference {
        var session: SMBSession? = SMBSession(
            host: "test",
            port: 445,
            credential: .anonymous,
            transport: transport,
            initialCredits: 1
        )
        let weakSession = WeakSMBSessionReference(session!)
        let activeSession = session!
        let echo = Task { try await activeSession.echo() }
        let receiveClock = ManualSMBSleeper()
        try await awaitWithTimeout("reader starts after the complete send") {
            try await transport.waitForReceiveCount(
                atLeast: 1,
                timeout: .seconds(1),
                sleeper: { try await receiveClock.sleep(for: $0) }
            )
        }
        let optionalHandle = await activeSession.readerHandleForTesting()
        let handle = try XCTUnwrap(optionalHandle)
        let optionalReader = await activeSession.readerTaskForTesting(handle: handle)
        let reader = try XCTUnwrap(optionalReader)
        let request = try XCTUnwrap(try unframed(transport.outbound).first)
        let messageId = try SMB2Header.decode(request).messageId
        transport.enqueueInbound(try framed([smb2EchoResponse(messageId: messageId)]))
        try await awaitWithTimeout("ECHO completes") { try await echo.value }
        try await awaitWithTimeout("response completion makes the reader dormant") { await reader.value }
        let readerTaskCount = await activeSession.readerTaskCountForTesting()
        XCTAssertEqual(readerTaskCount, 0)
        XCTAssertEqual(transport.receiveCount, 2)
        XCTAssertFalse(transport.hasPendingReceive)
        XCTAssertEqual(transport.activeReceiveCount, 0)

        await activeSession.waitForActiveSendTasksForTesting()
        session = nil
        return weakSession
    }

    func testRequestTimerSleeperDoesNotRetainSession() async throws {
        let clock = ManualSMBSleeper()
        var session: SMBSession? = SMBSession(
            host: "test",
            port: 445,
            credential: .anonymous,
            transport: ControlledReceiveTransport(),
            requestTimeoutSleeper: { try await clock.sleep(for: $0) }
        )
        let weakSession = WeakSMBSessionReference(session!)
        let timer = await session!.startRequestTimeoutForTesting()
        try await clock.waitUntilCallCount(atLeast: 1, timeout: .seconds(1), sleeper: { try await ManualSMBSleeper().sleep(for: $0) })

        session = nil
        XCTAssertNil(weakSession.value, "detached timer sleeper must hold only weak session")
        clock.fireNext()
        try await awaitWithTimeout("timer callback exits after weak session disappears") {
            await timer.value
        }
    }

    func testQueuedNormalTimeoutCannotEraseCancellationTombstone() async throws {
        let transport = ControlledReceiveTransport()
        let timerSleeper = ManualSMBSleeper()
        let session = SMBSession(
            host: "test",
            port: 445,
            credential: .anonymous,
            transport: transport,
            initialCredits: 1,
            requestTimeout: .seconds(5),
            requestTimeoutSleeper: { try await timerSleeper.sleep(for: $0) }
        )
        let echo = Task { try await session.echo() }
        try await awaitWithTimeout("ECHO sent before cancellation") {
            await session.waitForRequestSentCountForTesting(atLeast: 1)
        }
        let request = try XCTUnwrap(try unframed(transport.outbound).first)
        let header = try SMB2Header.decode(request)
        let optionalTimeoutIdentity = await session.requestTimeoutIdentityForTesting(messageId: header.messageId)
        let timeoutIdentity = try XCTUnwrap(optionalTimeoutIdentity)
        try await awaitWithTimeout("normal timeout sleeper installed") {
            try await timerSleeper.waitUntilCallCount(atLeast: 1, timeout: .seconds(1), sleeper: { try await ManualSMBSleeper().sleep(for: $0) })
        }

        echo.cancel()
        do {
            try await awaitWithTimeout("cancelled ECHO caller") { try await echo.value }
            XCTFail("cancelled ECHO should throw")
        } catch is CancellationError {
        }
        let tombstoneCount = await session.ordinaryCancellationTombstoneCountForTesting()
        XCTAssertEqual(tombstoneCount, 1)
        await session.setRequestTimeoutIdentityForTesting(messageId: header.messageId, identity: timeoutIdentity)

        await session.requestDidTimeOutForTesting(
            messageId: header.messageId,
            command: SMB2Commands.echo,
            generation: 1,
            identity: timeoutIdentity
        )
        let pendingAfterStaleTimeout = await session.wirePendingRecordCountForTesting()
        let orphanAfterStaleTimeout = await session.orphanResponseCountForTesting()
        XCTAssertEqual(pendingAfterStaleTimeout, 1, "queued stale timeout must preserve correlation")
        XCTAssertEqual(orphanAfterStaleTimeout, 0)

        transport.enqueueInbound(try framed([smb2EchoResponse(messageId: header.messageId)]))
        try await awaitWithTimeout("late final drains cancellation tombstone") {
            await session.waitForReceivedPacketDispatchCountForTesting(atLeast: 1)
        }
        let pendingAfterFinal = await session.wirePendingRecordCountForTesting()
        let orphanAfterFinal = await session.orphanResponseCountForTesting()
        XCTAssertEqual(pendingAfterFinal, 0)
        XCTAssertEqual(orphanAfterFinal, 0)
        await session.closeTransportAndWait(cause: "test_stale_request_timeout_join")
    }

    func testPOSIXSocketTransportLoopbackRoundTrip() async throws {
        let server = try POSIXLoopbackServer(mode: .echoOnce)
        server.start()
        defer { server.close() }

        let transport = POSIXSocketTransport(timeout: .seconds(1))
        defer { transport.close() }

        try await awaitWithTimeout("connect POSIXSocketTransport") {
            try await transport.connect(host: "127.0.0.1", port: server.port)
        }
        try await awaitWithTimeout("send POSIXSocketTransport payload") {
            try await transport.send([0xde, 0xad, 0xbe, 0xef])
        }
        let received = try await awaitWithTimeout("receive POSIXSocketTransport payload") {
            try await transport.receive(maxLength: 4)
        }

        XCTAssertEqual(received, [0xde, 0xad, 0xbe, 0xef])
    }

    func testPOSIXConnectNilTimeoutCloseInterruptsLiveBlackholeConnect() async throws {
        let transport = POSIXSocketTransport()
        let connectTask = Task {
            try await transport.connect(host: "10.255.255.1", port: 445)
        }
        defer {
            connectTask.cancel()
            transport.close()
        }

        var earlyCompletion: Result<Void, Error>?
        do {
            try await awaitWithTimeout(seconds: 0.4, "live blackhole connect remains pending") {
                try await connectTask.value
            }
            earlyCompletion = .success(())
        } catch is SMBTestTimeoutError {
            // Expected: the live connect is still parked in the OS after several heartbeats.
        } catch {
            earlyCompletion = .failure(error)
        }

        if let earlyCompletion {
            transport.close()
            switch earlyCompletion {
            case .success:
                throw XCTSkip("10.255.255.1:445 accepted the connection before close; no blackhole path")
            case .failure(let error):
                throw XCTSkip("10.255.255.1:445 failed before close (\(error)); no blackhole path")
            }
        }

        transport.close()
        do {
            try await awaitWithTimeout(seconds: 5, "live nil-timeout connect completion after close") {
                try await connectTask.value
            }
            XCTFail("live blackhole connect unexpectedly succeeded after close")
        } catch SMBTransportError.connectionClosed {
        }

        // A second operation must observe the terminal state; the connecting descriptor must
        // not have been promoted or left usable after its lease drained and was closed.
        do {
            try await transport.send([0])
            XCTFail("closed live transport remained usable after connect retirement")
        } catch SMBTransportError.connectionClosed {
        }
    }

    func testPOSIXConnectNilTimeoutCloseDrainsCandidateLeaseAfterPollReturns() async throws {
        let fake = POSIXConnectSyscallFake(
            pollSteps: [POSIXConnectFakePollStep(result: 0)],
            blockPoll: true
        )
        let transport = POSIXSocketTransport(
            timeout: nil,
            syscalls: fake.syscalls,
            shutdown: fake.shutdown,
            close: fake.close
        )
        let connectTask = Task { try await transport.connect(host: "127.0.0.1", port: 445) }
        defer {
            fake.unblockPoll()
            connectTask.cancel()
            transport.close()
        }

        try await awaitWithTimeout("fake poll start before close") {
            await fake.waitForPollStart()
        }
        transport.close()
        XCTAssertEqual(fake.events.events, [.pollStarted, .shutdown])
        XCTAssertEqual(fake.restoreCount, 0)
        XCTAssertEqual(fake.getSocketErrorCount, 0)

        fake.unblockPoll()
        do {
            try await awaitWithTimeout("connect completion after close") {
                try await connectTask.value
            }
            XCTFail("connect unexpectedly succeeded after close")
        } catch SMBTransportError.connectionClosed {
        }
        XCTAssertEqual(fake.events.events, [.pollStarted, .shutdown, .pollReturned, .close])
    }

    func testPOSIXConnectNilTimeoutCancellationDrainsCandidateLeaseAfterPollReturns() async throws {
        let fake = POSIXConnectSyscallFake(
            pollSteps: [POSIXConnectFakePollStep(result: 0)],
            blockPoll: true
        )
        let transport = POSIXSocketTransport(
            timeout: nil,
            syscalls: fake.syscalls,
            shutdown: fake.shutdown,
            close: fake.close
        )
        let connectTask = Task { try await transport.connect(host: "127.0.0.1", port: 445) }
        defer {
            fake.unblockPoll()
            connectTask.cancel()
            transport.close()
        }

        try await awaitWithTimeout("fake poll start before cancellation") {
            await fake.waitForPollStart()
        }
        connectTask.cancel()
        XCTAssertEqual(fake.events.events, [.pollStarted, .shutdown])
        fake.unblockPoll()

        do {
            try await awaitWithTimeout("connect completion after cancellation") {
                try await connectTask.value
            }
            XCTFail("connect unexpectedly succeeded after cancellation")
        } catch is CancellationError {
        }
        XCTAssertEqual(fake.events.events, [.pollStarted, .shutdown, .pollReturned, .close])
        XCTAssertEqual(fake.restoreCount, 0)
        XCTAssertEqual(fake.getSocketErrorCount, 0)
    }

    func testPOSIXConnectCloseDuringFlagRestorationDoesNotPromoteCandidate() async throws {
        let fake = POSIXConnectSyscallFake(blockRestore: true)
        let transport = POSIXSocketTransport(
            timeout: nil,
            syscalls: fake.syscalls,
            shutdown: fake.shutdown,
            close: fake.close
        )
        let connectTask = Task { try await transport.connect(host: "127.0.0.1", port: 445) }
        defer {
            fake.unblockRestore()
            connectTask.cancel()
            transport.close()
        }

        try await awaitWithTimeout("fake flag restoration start before close") {
            await fake.waitForRestoreStart()
        }
        transport.close()
        XCTAssertEqual(
            fake.events.events,
            [.pollStarted, .pollReturned, .restoreStarted, .shutdown]
        )
        fake.unblockRestore()

        do {
            try await awaitWithTimeout("connect completion after close during restoration") {
                try await connectTask.value
            }
            XCTFail("connect unexpectedly promoted a retired candidate")
        } catch SMBTransportError.connectionClosed {
        }
        XCTAssertEqual(
            fake.events.events,
            [.pollStarted, .pollReturned, .restoreStarted, .shutdown, .restoreReturned, .close]
        )
        do {
            try await awaitWithTimeout("send after retired connect candidate") {
                try await transport.send([1])
            }
            XCTFail("retired candidate remained usable")
        } catch SMBTransportError.connectionClosed {
        }
    }

    func testPOSIXConnectErrnoTransitionsUsePollWithoutReissuingConnect() async throws {
        let cases: [(name: String, result: POSIXSocketCallResult<Int32>, expectedPolls: Int)] = [
            ("success", POSIXSocketCallResult(0), 0),
            ("EINTR", POSIXSocketCallResult(-1, errno: EINTR), 1),
            ("EINPROGRESS", POSIXSocketCallResult(-1, errno: EINPROGRESS), 1),
            ("EALREADY", POSIXSocketCallResult(-1, errno: EALREADY), 1),
            ("EISCONN", POSIXSocketCallResult(-1, errno: EISCONN), 0)
        ]

        for testCase in cases {
            let fake = POSIXConnectSyscallFake(connectResults: [testCase.result])
            let transport = POSIXSocketTransport(
                timeout: nil,
                syscalls: fake.syscalls,
                shutdown: fake.shutdown,
                close: fake.close
            )
            try await transport.connect(host: "127.0.0.1", port: 445)
            XCTAssertEqual(fake.pollTimeouts.count, testCase.expectedPolls, testCase.name)
            XCTAssertEqual(fake.connectCount, 1, testCase.name)
            XCTAssertEqual(fake.restoreCount, 1, testCase.name)
            XCTAssertEqual(
                fake.socketOptionCalls.filter {
                    $0.level == Int32(IPPROTO_TCP) && $0.option == Int32(TCP_NODELAY)
                },
                [POSIXConnectFakeSocketOption(
                    level: Int32(IPPROTO_TCP),
                    option: Int32(TCP_NODELAY),
                    value: 1,
                    length: socklen_t(4)
                )],
                testCase.name
            )
            transport.close()
        }
    }

    // This test does not pin promotion order: observing it would require a test-only production seam for issue 099.
    func testPOSIXConnectSetsTCPNoDelayAfterConnectReady() async throws {
        let fake = POSIXConnectSyscallFake()
        let transport = POSIXSocketTransport(
            timeout: .seconds(1),
            syscalls: fake.syscalls,
            shutdown: fake.shutdown,
            close: fake.close
        )

        try await transport.connect(host: "127.0.0.1", port: 445)
        fake.syscallEvents.append(.connectReturned)

        let tcpNoDelay = POSIXConnectFakeSocketOption(
            level: Int32(IPPROTO_TCP),
            option: Int32(TCP_NODELAY),
            value: 1,
            length: socklen_t(4)
        )
        XCTAssertEqual(
            fake.socketOptionCalls.filter {
                $0.level == Int32(IPPROTO_TCP) && $0.option == Int32(TCP_NODELAY)
            },
            [tcpNoDelay]
        )

        let events = fake.syscallEvents.events
        let connectIndex = try XCTUnwrap(events.firstIndex { event in
            if case .connect = event { return true }
            return false
        })
        let connectReadyIndex = try XCTUnwrap(events.firstIndex(of: .connectReady))
        let tcpNoDelayIndex = try XCTUnwrap(events.firstIndex(of: .setSocketOption(tcpNoDelay)))
        let receiveTimeoutIndex = try XCTUnwrap(events.firstIndex { event in
            guard case .setSocketOption(let call) = event else { return false }
            return call.level == Int32(SOL_SOCKET) && call.option == Int32(SO_RCVTIMEO)
        })
        let sendTimeoutIndex = try XCTUnwrap(events.firstIndex { event in
            guard case .setSocketOption(let call) = event else { return false }
            return call.level == Int32(SOL_SOCKET) && call.option == Int32(SO_SNDTIMEO)
        })
        let connectReturnedIndex = try XCTUnwrap(events.firstIndex(of: .connectReturned))

        XCTAssertLessThan(connectIndex, tcpNoDelayIndex)
        XCTAssertLessThan(connectReadyIndex, tcpNoDelayIndex)
        XCTAssertLessThan(tcpNoDelayIndex, receiveTimeoutIndex)
        XCTAssertLessThan(receiveTimeoutIndex, sendTimeoutIndex)
        XCTAssertLessThan(sendTimeoutIndex, connectReturnedIndex)
        transport.close()
    }

    func testPOSIXConnectContinuesWhenTCPNoDelayFails() async throws {
        let cases: [(name: String, errno: Int32)] = [
            ("EINVAL", EINVAL),
            ("EAGAIN", EAGAIN)
        ]

        for testCase in cases {
            let fake = POSIXConnectSyscallFake(
                failingSocketOption: Int32(TCP_NODELAY),
                socketOptionFailureErrno: testCase.errno
            )
            let transport = POSIXSocketTransport(
                timeout: nil,
                syscalls: fake.syscalls,
                shutdown: fake.shutdown,
                close: fake.close
            )

            do {
                try await transport.connect(host: "127.0.0.1", port: 445)
            } catch {
                XCTFail("TCP_NODELAY failure with \(testCase.name) failed the connection: \(error)")
                continue
            }
            XCTAssertEqual(fake.failedSocketOptionCount, 1, testCase.name)
            XCTAssertEqual(fake.connectCount, 1, testCase.name)
            XCTAssertEqual(fake.restoreCount, 1, testCase.name)
            XCTAssertEqual(
                fake.socketOptionCalls.filter {
                    $0.level == Int32(IPPROTO_TCP) && $0.option == Int32(TCP_NODELAY)
                },
                [POSIXConnectFakeSocketOption(
                    level: Int32(IPPROTO_TCP),
                    option: Int32(TCP_NODELAY),
                    value: 1,
                    length: socklen_t(4)
                )],
                testCase.name
            )
            transport.close()
        }
    }

    func testPOSIXConnectPollHeartbeatAndEINTRRetryUntilReady() async throws {
        let fake = POSIXConnectSyscallFake(
            pollSteps: [
                POSIXConnectFakePollStep(result: 0),
                POSIXConnectFakePollStep(result: -1, errno: EINTR),
                POSIXConnectFakePollStep(result: 1, revents: Int16(POLLERR | POLLHUP))
            ]
        )
        let transport = POSIXSocketTransport(
            timeout: nil,
            syscalls: fake.syscalls,
            shutdown: fake.shutdown,
            close: fake.close
        )

        try await transport.connect(host: "127.0.0.1", port: 445)

        XCTAssertEqual(fake.pollTimeouts, [100, 100, 100])
        XCTAssertEqual(fake.getSocketErrorCount, 1, "SO_ERROR must only follow positive poll readiness")
        XCTAssertEqual(fake.restoreCount, 1)
        transport.close()
    }

    func testPOSIXConnectAbsoluteDeadlineIsNotExtendedByPollEINTR() async throws {
        let fake = POSIXConnectSyscallFake(
            pollSteps: [
                POSIXConnectFakePollStep(
                    result: -1,
                    errno: EINTR,
                    clockAdvance: .milliseconds(60)
                ),
                POSIXConnectFakePollStep(result: 0, clockAdvance: .milliseconds(90))
            ]
        )
        let transport = POSIXSocketTransport(
            timeout: .milliseconds(150),
            syscalls: fake.syscalls,
            shutdown: fake.shutdown,
            close: fake.close
        )

        do {
            try await transport.connect(host: "127.0.0.1", port: 445)
            XCTFail("connect unexpectedly outlived its absolute deadline")
        } catch SMBTransportError.timedOut {
        }
        XCTAssertEqual(fake.pollTimeouts, [100, 90])
        XCTAssertEqual(fake.getSocketErrorCount, 0)
        XCTAssertEqual(fake.restoreCount, 0)
    }

    func testPOSIXConnectRoundsPositivePollRemainderUpToOneMillisecond() async throws {
        let fake = POSIXConnectSyscallFake()
        let transport = POSIXSocketTransport(
            timeout: .nanoseconds(1),
            syscalls: fake.syscalls,
            shutdown: fake.shutdown,
            close: fake.close
        )

        try await transport.connect(host: "127.0.0.1", port: 445)

        XCTAssertEqual(fake.pollTimeouts, [1])
        transport.close()
    }

    func testPOSIXConnectSocketErrorTable() async throws {
        let cases: [(name: String, socketError: Int32, timedOut: Bool)] = [
            ("success", 0, false),
            ("ECONNREFUSED", ECONNREFUSED, false),
            ("ETIMEDOUT", ETIMEDOUT, true)
        ]

        for testCase in cases {
            let fake = POSIXConnectSyscallFake(
                socketErrors: [POSIXSocketCallResult(testCase.socketError)]
            )
            let transport = POSIXSocketTransport(
                timeout: nil,
                syscalls: fake.syscalls,
                shutdown: fake.shutdown,
                close: fake.close
            )
            do {
                try await transport.connect(host: "127.0.0.1", port: 445)
                XCTAssertEqual(testCase.socketError, 0, testCase.name)
                transport.close()
            } catch SMBTransportError.timedOut {
                XCTAssertTrue(testCase.timedOut, testCase.name)
            } catch let error as SMBTransportError {
                guard case .socketFailure = error else {
                    XCTFail("\(testCase.name): unexpected error \(error)")
                    continue
                }
                XCTAssertEqual(testCase.socketError, ECONNREFUSED, testCase.name)
            }
            XCTAssertEqual(fake.getSocketErrorCount, 1, testCase.name)
        }
    }

    func testPOSIXConnectPollNVALIsNeverTreatedAsSuccess() async throws {
        let fake = POSIXConnectSyscallFake(
            pollSteps: [
                POSIXConnectFakePollStep(result: 1, revents: Int16(POLLOUT | POLLNVAL))
            ]
        )
        let transport = POSIXSocketTransport(
            timeout: nil,
            syscalls: fake.syscalls,
            shutdown: fake.shutdown,
            close: fake.close
        )

        do {
            try await transport.connect(host: "127.0.0.1", port: 445)
            XCTFail("POLLNVAL unexpectedly completed connect")
        } catch let error as SMBTransportError {
            guard case .socketFailure = error else {
                return XCTFail("unexpected error \(error)")
            }
        }
        XCTAssertEqual(fake.getSocketErrorCount, 0)
        XCTAssertEqual(fake.restoreCount, 0)
    }

    func testPOSIXConnectPollEAGAINIsSocketFailureNotTimeout() async throws {
        let fake = POSIXConnectSyscallFake(
            pollSteps: [POSIXConnectFakePollStep(result: -1, errno: EAGAIN)]
        )
        let transport = POSIXSocketTransport(
            timeout: .seconds(1),
            syscalls: fake.syscalls,
            shutdown: fake.shutdown,
            close: fake.close
        )

        do {
            try await transport.connect(host: "127.0.0.1", port: 445)
            XCTFail("poll EAGAIN unexpectedly completed connect")
        } catch SMBTransportError.timedOut {
            XCTFail("poll EAGAIN was incorrectly normalized to timedOut")
        } catch let error as SMBTransportError {
            guard case .socketFailure = error else {
                return XCTFail("unexpected error \(error)")
            }
        }
    }

    func testPOSIXConnectFlagRestorationFailureRetiresCandidate() async throws {
        let fake = POSIXConnectSyscallFake(
            restoreResult: POSIXSocketCallResult(-1, errno: EIO)
        )
        let transport = POSIXSocketTransport(
            timeout: nil,
            syscalls: fake.syscalls,
            shutdown: fake.shutdown,
            close: fake.close
        )

        do {
            try await transport.connect(host: "127.0.0.1", port: 445)
            XCTFail("connect unexpectedly promoted after restoration failure")
        } catch let error as SMBTransportError {
            guard case .socketFailure = error else {
                return XCTFail("unexpected error \(error)")
            }
        }
        XCTAssertEqual(fake.restoreCount, 1)
        XCTAssertEqual(fake.events.events.suffix(3), [.restoreStarted, .restoreReturned, .close])
    }

    func testPOSIXSocketTransportSendBeforeConnectDoesNotPoisonTransport() async throws {
        let server = try POSIXLoopbackServer(mode: .echoOnce)
        server.start()
        defer { server.close() }

        let transport = POSIXSocketTransport(timeout: .seconds(1))
        defer { transport.close() }

        do {
            try await transport.send([0x01])
            XCTFail("send before connect unexpectedly succeeded")
        } catch SMBTransportError.connectionClosed {
        }

        try await awaitWithTimeout("connect after pre-connect send") {
            try await transport.connect(host: "127.0.0.1", port: server.port)
        }
        try await awaitWithTimeout("send after pre-connect failure") {
            try await transport.send([0x01])
        }
        let received = try await awaitWithTimeout("receive after pre-connect failure") {
            try await transport.receive(maxLength: 1)
        }
        XCTAssertEqual(received, [0x01])
    }

    func testPOSIXSocketTransportRetriesInterruptedWriter() async throws {
        let writer = EINTRPOSIXWriter()
        let lifecycle = POSIXLifecycleRecorder()
        let transport = POSIXSocketTransport(
            writer: writer.write,
            shutdown: lifecycle.shutdown,
            close: lifecycle.close
        )

        try await awaitWithTimeout("retry interrupted POSIX send") {
            try await transport.send([1, 2, 3])
        }

        XCTAssertEqual(writer.callCount, 2)
        XCTAssertEqual(lifecycle.shutdownCount, 0)
        XCTAssertEqual(lifecycle.closeCount, 0)
    }

    func testPOSIXSocketTransportConcurrentSendsDoNotInterleave() async throws {
        let writer = InterleavingPOSIXWriter()
        let transport = POSIXSocketTransport(writer: writer.write, sendEnqueued: writer.markEnqueued)

        let first = Task { try await transport.send([[1, 2, 3], [4, 5, 6]]) }
        try await awaitWithTimeout("first POSIX writer rest") { await writer.waitForARest() }
        XCTAssertTrue(writer.isARestBlocked)

        let second = Task { try await transport.send([9, 9]) }
        try await awaitWithTimeout("both POSIX sends enqueued") { await writer.waitForEnqueues(2) }
        XCTAssertTrue(writer.didEnqueueBothSends)
        writer.releaseA()

        try await awaitWithTimeout("first POSIX concurrent send") { try await first.value }
        try await awaitWithTimeout("second POSIX concurrent send") { try await second.value }

        let firstThenSecond: [UInt8] = [1, 2, 3, 4, 5, 6, 9, 9]
        let secondThenFirst: [UInt8] = [9, 9, 1, 2, 3, 4, 5, 6]
        XCTAssertTrue(
            writer.outbound == firstThenSecond || writer.outbound == secondThenFirst,
            "concurrent sends interleaved: \(writer.outbound)"
        )
    }

    func testPOSIXSocketTransportQueuedSendCancellationIsIsolated() async throws {
        let writer = BlockingPOSIXWriter()
        let enqueueRecorder = POSIXSendEnqueueRecorder()
        let lifecycle = POSIXLifecycleRecorder()
        let transport = POSIXSocketTransport(
            writer: writer.write,
            shutdown: lifecycle.shutdown,
            close: lifecycle.close,
            sendEnqueued: enqueueRecorder.mark
        )

        let first = Task { try await transport.send([1, 2, 3]) }
        try await awaitWithTimeout("first POSIX writer start") { await writer.waitForStart() }
        XCTAssertTrue(writer.isStarted)

        let second = Task { try await transport.send([4, 5, 6]) }
        try await awaitWithTimeout("both POSIX sends enqueued") { await enqueueRecorder.waitForCount(2) }
        XCTAssertEqual(enqueueRecorder.count, 2)
        second.cancel()

        do {
            try await awaitWithTimeout("queued POSIX send cancellation") { try await second.value }
            XCTFail("queued send unexpectedly succeeded after cancellation")
        } catch is CancellationError {
        }
        XCTAssertEqual(writer.callCount, 1, "queued cancellation must not reach the writer")
        XCTAssertEqual(lifecycle.shutdownCount, 0)
        XCTAssertEqual(lifecycle.closeCount, 0)

        writer.release()
        try await awaitWithTimeout("active POSIX send after queued cancellation") { try await first.value }
        try await awaitWithTimeout("send after isolated queued cancellation") {
            try await transport.send([7, 8])
        }
        XCTAssertEqual(lifecycle.shutdownCount, 0)
        XCTAssertEqual(lifecycle.closeCount, 0)
    }

    func testPOSIXSocketTransportActiveSendCancellationPoisonsConnection() async throws {
        let writer = BlockingPOSIXWriter()
        let lifecycle = POSIXLifecycleRecorder()
        let transport = POSIXSocketTransport(
            writer: writer.write,
            shutdown: lifecycle.shutdown,
            close: lifecycle.close
        )

        let sendTask = Task { try await transport.send([1, 2, 3]) }
        try await awaitWithTimeout("active POSIX writer start") { await writer.waitForStart() }
        XCTAssertTrue(writer.isStarted)
        XCTAssertEqual(writer.outbound, [1], "the cancellation must exercise a partial write")
        let writerDescriptor = try XCTUnwrap(writer.descriptors.first)
        XCTAssertEqual(writer.descriptors, [writerDescriptor])

        sendTask.cancel()
        try await awaitWithTimeout("active POSIX send shutdown") { await lifecycle.waitForShutdown() }
        XCTAssertEqual(lifecycle.shutdownCount, 1)
        XCTAssertEqual(lifecycle.closeCount, 0, "physical close must wait for the writer lease")
        XCTAssertEqual(
            lifecycle.events,
            [POSIXLifecycleEvent(operation: .shutdown, descriptor: writerDescriptor)]
        )
        writer.release()

        do {
            try await awaitWithTimeout("active POSIX send cancellation") { try await sendTask.value }
            XCTFail("active send unexpectedly succeeded after cancellation")
        } catch is CancellationError {
        }
        try await awaitWithTimeout("active POSIX send lease drain") { await lifecycle.waitForClose() }
        XCTAssertEqual(lifecycle.shutdownCount, 1)
        XCTAssertEqual(lifecycle.closeCount, 1)
        XCTAssertEqual(
            lifecycle.events,
            [
                POSIXLifecycleEvent(operation: .shutdown, descriptor: writerDescriptor),
                POSIXLifecycleEvent(operation: .close, descriptor: writerDescriptor)
            ]
        )
        do {
            try await transport.send([9])
            XCTFail("send after poison unexpectedly succeeded")
        } catch SMBTransportError.connectionClosed {
        }
        do {
            _ = try await transport.receive(maxLength: 1)
            XCTFail("receive after poison unexpectedly succeeded")
        } catch SMBTransportError.connectionClosed {
        }
        transport.close()
        transport.close()
        XCTAssertEqual(lifecycle.shutdownCount, 1)
        XCTAssertEqual(lifecycle.closeCount, 1)
    }

    func testPOSIXSocketTransportCloseDuringActiveSendDefersCloseAndStopsNextWrite() async throws {
        let writer = BlockingPOSIXWriter()
        let lifecycle = POSIXLifecycleRecorder()
        let transport = POSIXSocketTransport(
            writer: writer.write,
            shutdown: lifecycle.shutdown,
            close: lifecycle.close
        )

        let sendTask = Task { try await transport.send([1, 2, 3]) }
        try await awaitWithTimeout("active POSIX writer before close") { await writer.waitForStart() }
        XCTAssertEqual(writer.outbound, [1])
        let writerDescriptor = try XCTUnwrap(writer.descriptors.first)
        XCTAssertEqual(writer.descriptors, [writerDescriptor])

        transport.close()
        XCTAssertEqual(lifecycle.shutdownCount, 1)
        XCTAssertEqual(lifecycle.closeCount, 0, "physical close must wait for the writer lease")
        XCTAssertEqual(
            lifecycle.events,
            [POSIXLifecycleEvent(operation: .shutdown, descriptor: writerDescriptor)]
        )
        writer.release()

        do {
            try await awaitWithTimeout("active POSIX send after close") { try await sendTask.value }
            XCTFail("active send unexpectedly succeeded after close")
        } catch SMBTransportError.connectionClosed {
        }
        try await awaitWithTimeout("active POSIX close lease drain") { await lifecycle.waitForClose() }
        XCTAssertEqual(writer.callCount, 1, "retired descriptors must be rechecked before the next write")
        XCTAssertEqual(lifecycle.shutdownCount, 1)
        XCTAssertEqual(lifecycle.closeCount, 1)
        XCTAssertEqual(
            lifecycle.events,
            [
                POSIXLifecycleEvent(operation: .shutdown, descriptor: writerDescriptor),
                POSIXLifecycleEvent(operation: .close, descriptor: writerDescriptor)
            ]
        )

        transport.close()
        XCTAssertEqual(lifecycle.shutdownCount, 1)
        XCTAssertEqual(lifecycle.closeCount, 1)
    }

    func testPOSIXSocketTransportPartialWriteErrorPoisonsConnection() async throws {
        let writer = FailingPOSIXWriter()
        let lifecycle = POSIXLifecycleRecorder()
        let transport = POSIXSocketTransport(
            writer: writer.write,
            shutdown: lifecycle.shutdown,
            close: lifecycle.close
        )

        do {
            try await transport.send([1, 2, 3])
            XCTFail("send unexpectedly succeeded after injected writer error")
        } catch SMBTransportError.socketFailure("injected send failure") {
        }
        XCTAssertEqual(writer.callCount, 2)
        XCTAssertEqual(lifecycle.shutdownCount, 1)
        XCTAssertEqual(lifecycle.closeCount, 1)

        do {
            try await transport.send([4])
            XCTFail("send after writer error unexpectedly succeeded")
        } catch SMBTransportError.connectionClosed {
        }
    }

    func testPOSIXSocketTransportSegmentedSendsDoNotInterleave() async throws {
        let writer = InterleavingPOSIXWriter()
        let transport = POSIXSocketTransport(writer: writer.write, sendEnqueued: writer.markEnqueued)

        let first = Task { try await transport.send([[1, 2, 3]]) }
        try await awaitWithTimeout("segmented POSIX writer rest") { await writer.waitForARest() }
        XCTAssertTrue(writer.isARestBlocked)
        let second = Task { try await transport.send([[9, 9]]) }
        try await awaitWithTimeout("both segmented POSIX sends enqueued") { await writer.waitForEnqueues(2) }
        XCTAssertTrue(writer.didEnqueueBothSends)
        writer.releaseA()

        try await awaitWithTimeout("first segmented POSIX send") { try await first.value }
        try await awaitWithTimeout("second segmented POSIX send") { try await second.value }
        let firstThenSecond: [UInt8] = [1, 2, 3, 9, 9]
        let secondThenFirst: [UInt8] = [9, 9, 1, 2, 3]
        XCTAssertTrue(writer.outbound == firstThenSecond || writer.outbound == secondThenFirst)
    }

    func testSessionSendFailureClosesTransportAndFailsOtherPendingRequests() async throws {
        let transport = FailingSendTransport(failure: SMBTransportError.socketFailure("send failed"))
        let session = SMBSession(
            host: "server",
            port: 445,
            credential: SMBCredential(username: "user", password: "pass"),
            transport: transport,
            initialCredits: 3
        )
        let firstPending = Task { try await session.parkPendingForTesting(messageId: 1, command: 8) }
        let secondPending = Task { try await session.parkPendingForTesting(messageId: 2, command: 9) }
        try await awaitWithTimeout("park pending session requests") {
            await session.waitForPendingCountForTesting(atLeast: 2)
        }
        let pendingBeforeSend = await session.pendingCountForTesting()
        XCTAssertEqual(pendingBeforeSend, 2)

        let sendFailure = Task { try await session.echo() }
        do {
            try await awaitWithTimeout("session send failure") { try await sendFailure.value }
            XCTFail("echo unexpectedly succeeded with a failing transport")
        } catch SMBTransportError.connectionClosed {
        }
        do {
            try await awaitWithTimeout("first pending failed by send_failure") { _ = try await firstPending.value }
            XCTFail("first pending unexpectedly succeeded")
        } catch SMBTransportError.connectionClosed {
        }
        do {
            try await awaitWithTimeout("second pending failed by send_failure") { _ = try await secondPending.value }
            XCTFail("second pending unexpectedly succeeded")
        } catch SMBTransportError.connectionClosed {
        }
        let pendingAfterSendFailure = await session.pendingCountForTesting()
        XCTAssertEqual(pendingAfterSendFailure, 0)
        // Pin the transport actually being closed: failing the pendings via failWire alone
        // (without closeTransport) would leave closeCount == 0 and must fail this test.
        XCTAssertEqual(transport.closeCount, 1)
    }

    func testPOSIXSocketTransportReceiveCancellationClosesSocket() async throws {
        let server = try POSIXLoopbackServer(mode: .acceptAndHold)
        server.start()
        defer { server.close() }

        let transport = POSIXSocketTransport()
        defer { transport.close() }
        try await awaitWithTimeout("connect POSIXSocketTransport to silent server") {
            try await transport.connect(host: "127.0.0.1", port: server.port)
        }

        let receiveTask = Task {
            try await transport.receive(maxLength: 1)
        }
        try await Task.sleep(nanoseconds: 50_000_000)
        receiveTask.cancel()

        do {
            _ = try await awaitWithTimeout(seconds: 2, "cancel POSIXSocketTransport receive") {
                try await receiveTask.value
            }
            XCTFail("receive unexpectedly succeeded after cancellation")
        } catch is CancellationError {
        }
    }

    func testPOSIXSocketTransportActiveReceiveCancellationDefersCloseUntilReaderReturns() async throws {
        let reader = BlockingPOSIXReader()
        let lifecycle = POSIXLifecycleRecorder()
        let transport = POSIXSocketTransport(
            writer: { _, bytes, offset in bytes.count - offset },
            reader: reader.read,
            shutdown: lifecycle.shutdown,
            close: lifecycle.close
        )

        let receiveTask = Task { try await transport.receive(maxLength: 1) }
        try await awaitWithTimeout("active POSIX reader start") { await reader.waitForStart() }
        XCTAssertEqual(reader.callCount, 1)
        let readerDescriptor = try XCTUnwrap(reader.descriptors.first)
        XCTAssertEqual(reader.descriptors, [readerDescriptor])

        receiveTask.cancel()
        try await awaitWithTimeout("active POSIX receive shutdown") { await lifecycle.waitForShutdown() }
        XCTAssertEqual(lifecycle.shutdownCount, 1)
        XCTAssertEqual(lifecycle.closeCount, 0, "physical close must wait for the reader lease")
        XCTAssertEqual(
            lifecycle.events,
            [POSIXLifecycleEvent(operation: .shutdown, descriptor: readerDescriptor)]
        )
        reader.release()

        do {
            _ = try await awaitWithTimeout("active POSIX receive cancellation") {
                try await receiveTask.value
            }
            XCTFail("active receive unexpectedly succeeded after cancellation")
        } catch is CancellationError {
        }
        try await awaitWithTimeout("active POSIX receive lease drain") { await lifecycle.waitForClose() }
        XCTAssertEqual(lifecycle.shutdownCount, 1)
        XCTAssertEqual(lifecycle.closeCount, 1)
        XCTAssertEqual(
            lifecycle.events,
            [
                POSIXLifecycleEvent(operation: .shutdown, descriptor: readerDescriptor),
                POSIXLifecycleEvent(operation: .close, descriptor: readerDescriptor)
            ]
        )

        transport.close()
        transport.close()
        XCTAssertEqual(lifecycle.shutdownCount, 1)
        XCTAssertEqual(lifecycle.closeCount, 1)
    }

    /// A send that is really blocked in the kernel (the peer never reads and the payload is far
    /// larger than the loopback socket buffers) must be woken by `close()`'s shutdown, and the
    /// physical close must wait until it has returned. Unlike the fake-writer tests above, this
    /// measures the OS contract the lease design relies on (issues/073: "shutdown wakes blocked
    /// send/recv"), on whichever platform runs it.
    func testPOSIXSocketTransportCloseWakesLiveKernelBlockedSend() async throws {
        let server = try POSIXLoopbackServer(mode: .acceptAndHold)
        server.start()
        defer { server.close() }
        let probe = LivePOSIXSyscallProbe()
        let transport = POSIXSocketTransport(
            timeout: nil,
            syscalls: .live,
            writer: probe.write,
            reader: probe.read,
            shutdown: probe.shutdown,
            close: probe.close
        )
        defer { transport.close() }
        try await awaitWithTimeout("connect POSIXSocketTransport to non-reading server") {
            try await transport.connect(host: "127.0.0.1", port: server.port)
        }

        let payload = [UInt8](repeating: 0x5A, count: 32 * 1024 * 1024)
        let sendTask = Task { try await transport.send(payload) }
        try await waitUntilBlockedInLiveSyscall(probe, "live send blocked on a full socket buffer")
        transport.close()

        do {
            try await awaitWithTimeout(seconds: 5, "kernel-blocked live send woken by close") {
                try await sendTask.value
            }
            XCTFail("send of a payload the peer never reads unexpectedly succeeded")
        } catch SMBTransportError.connectionClosed {
        }
        XCTAssertEqual(probe.insideAtShutdown, [true], "shutdown must reach the send blocked in the kernel")
        XCTAssertEqual(probe.insideAtClose, [false], "physical close must wait for the blocked send to return")
    }

    /// The receive counterpart: a recv blocked on a silent peer is woken by `close()`'s shutdown
    /// and only then physically closed (issues/073).
    func testPOSIXSocketTransportCloseWakesLiveKernelBlockedReceive() async throws {
        let server = try POSIXLoopbackServer(mode: .acceptAndHold)
        server.start()
        defer { server.close() }
        let probe = LivePOSIXSyscallProbe()
        let transport = POSIXSocketTransport(
            timeout: nil,
            syscalls: .live,
            writer: probe.write,
            reader: probe.read,
            shutdown: probe.shutdown,
            close: probe.close
        )
        defer { transport.close() }
        try await awaitWithTimeout("connect POSIXSocketTransport to silent server") {
            try await transport.connect(host: "127.0.0.1", port: server.port)
        }

        let receiveTask = Task { try await transport.receive(maxLength: 1) }
        try await waitUntilBlockedInLiveSyscall(probe, "live recv blocked on a silent peer")
        transport.close()

        do {
            _ = try await awaitWithTimeout(seconds: 5, "kernel-blocked live recv woken by close") {
                try await receiveTask.value
            }
            XCTFail("receive from a silent peer unexpectedly succeeded")
        } catch SMBTransportError.connectionClosed {
        }
        XCTAssertEqual(probe.insideAtShutdown, [true], "shutdown must reach the recv blocked in the kernel")
        XCTAssertEqual(probe.insideAtClose, [false], "physical close must wait for the blocked recv to return")
    }

    /// Waits until the probe has been inside the same syscall for 10 consecutive 20 ms polls.
    /// A send that is still filling the socket buffer returns quickly and re-enters, which
    /// resets the count; only a call that stays in the kernel gets through.
    private func waitUntilBlockedInLiveSyscall(
        _ probe: LivePOSIXSyscallProbe,
        _ label: String
    ) async throws {
        var lastEntered = -1
        var stablePolls = 0
        for _ in 0..<500 {
            let snapshot = probe.snapshot
            if snapshot.inside, snapshot.entered == lastEntered {
                stablePolls += 1
                if stablePolls >= 10 { return }
            } else {
                stablePolls = 0
            }
            lastEntered = snapshot.entered
            try await Task.sleep(nanoseconds: 20_000_000)
        }
        throw SMBTestTimeoutError(label: label, seconds: 10)
    }

    func testPOSIXSocketTransportReceiveTimeout() async throws {
        let server = try POSIXLoopbackServer(mode: .acceptAndHold)
        server.start()
        defer { server.close() }

        let transport = POSIXSocketTransport(timeout: .milliseconds(100))
        defer { transport.close() }
        try await awaitWithTimeout("connect POSIXSocketTransport to timeout server") {
            try await transport.connect(host: "127.0.0.1", port: server.port)
        }

        do {
            _ = try await awaitWithTimeout(seconds: 2, "timeout POSIXSocketTransport receive") {
                try await transport.receive(maxLength: 1)
            }
            XCTFail("receive unexpectedly succeeded without server response")
        } catch SMBTransportError.timedOut {
        }
    }

    func testSMBeeListSharesPassesTimeoutToDefaultTransport() async throws {
        let server = try POSIXLoopbackServer(mode: .acceptAndHold)
        server.start()
        defer { server.close() }

        do {
            _ = try await awaitWithTimeout(seconds: 2, "SMBee.listShares socket timeout") {
                try await SMBee.listShares(
                    host: "127.0.0.1",
                    port: server.port,
                    credential: SMBCredential(username: "user", password: "pass"),
                    timeout: .milliseconds(100)
                )
            }
            XCTFail("listShares unexpectedly succeeded without server response")
        } catch SMBTransportError.timedOut {
        }
    }

    func testOperationDeadlineTimesOut() async throws {
        do {
            _ = try await SMBOperationDeadline.run(timeout: .milliseconds(10)) {
                try await Task.sleep(for: .seconds(5))
                return 1
            }
            XCTFail("operation unexpectedly completed")
        } catch SMBTransportError.timedOut {
        }
    }

    func testOperationDeadlineCancelsTimedOutOperation() async throws {
        let operation = Task {
            try await SMBOperationDeadline.run(timeout: .milliseconds(10)) {
                while true {
                    try await Task.sleep(for: .seconds(5))
                }
                return 1
            }
        }

        do {
            _ = try await operation.value
            XCTFail("operation unexpectedly completed")
        } catch SMBTransportError.timedOut {
        } catch {
            XCTFail("unexpected deadline error: \(error)")
        }
    }

    func testBestEffortCloseTimeoutKeepsTransportOpenWithCleanupTombstone() async throws {
        // This previously asserted that the cleanup deadline itself invalidates the shared
        // transport. Issue 069 keeps the CLOSE correlated and leaves teardown to wire faults/bounds.
        let clock = ManualSMBSleeper()
        let transport = ScriptedBlockingReceiveTransport(inbound: [])
        let session = SMBSession(
            host: "server",
            port: 445,
            credential: .anonymous,
            transport: transport,
            cleanupTimeout: .seconds(5),
            cleanupTimeoutSleeper: { try await clock.sleep(for: $0) }
        )
        let closeTask = Task { await session.bestEffortClose(treeId: 1, fileId: [UInt8](repeating: 1, count: 16)) }
        try await awaitWithTimeout("receive blocked after script") { await transport.waitUntilBlockedAfterScript() }
        try await awaitWithTimeout("CLOSE reached production sent state") {
            await session.waitForRequestSentCountForTesting(atLeast: 1)
        }
        try await awaitWithTimeout("cleanup timer registered") {
            try await clock.waitUntilCallCount(atLeast: 1, timeout: .seconds(1), sleeper: { try await ManualSMBSleeper().sleep(for: $0) })
        }
        clock.fireNext()
        try await awaitWithTimeout("best-effort CLOSE returned") { await closeTask.value }

        XCTAssertTrue(transport.didBlockAfterScript)
        XCTAssertEqual(transport.closeCount, 0)
        let tombstoneCount = await session.cleanupTombstoneCountForTesting()
        let ledgerCount = await session.cleanupLedgerCountForTesting()
        XCTAssertEqual(tombstoneCount, 1)
        XCTAssertEqual(ledgerCount, 1)
    }

    func testDisconnectInvalidatesTransportWhenTreeDisconnectResponseIsMissing() async {
        let transport = ScriptedBlockingReceiveTransport(inbound: [])
        let session = SMBSession(
            host: "server",
            port: 445,
            credential: .anonymous,
            transport: transport,
            cleanupTimeout: .milliseconds(25)
        )

        await session.disconnect(treeId: 1)

        XCTAssertTrue(transport.didBlockAfterScript)
        XCTAssertEqual(transport.closeCount, 1)
    }

    func testCloseCreatedHandleTimeoutThrowsWithoutInvalidatingTransport() async throws {
        let clock = ManualSMBSleeper()
        let transport = ScriptedBlockingReceiveTransport(inbound: [])
        let session = SMBSession(
            host: "server",
            port: 445,
            credential: .anonymous,
            transport: transport,
            cleanupTimeout: .seconds(5),
            cleanupTimeoutSleeper: { try await clock.sleep(for: $0) }
        )
        let closeTask = Task {
            try await session.closeCreatedHandle(
                treeId: 1,
                fileId: [UInt8](repeating: 1, count: 16)
            )
        }
        try await awaitWithTimeout("receive blocked after script") { await transport.waitUntilBlockedAfterScript() }
        try await awaitWithTimeout("CLOSE reached production sent state") {
            await session.waitForRequestSentCountForTesting(atLeast: 1)
        }
        try await awaitWithTimeout("cleanup timer registered") {
            try await clock.waitUntilCallCount(atLeast: 1, timeout: .seconds(1), sleeper: { try await ManualSMBSleeper().sleep(for: $0) })
        }
        clock.fireNext()
        do {
            try await awaitWithTimeout("CLOSE timeout returned") { try await closeTask.value }
            XCTFail("CLOSE unexpectedly completed without a response")
        } catch SMBTransportError.timedOut {
        } catch {
            XCTFail("unexpected CLOSE error: \(error)")
        }

        XCTAssertTrue(transport.didBlockAfterScript)
        XCTAssertEqual(transport.closeCount, 0)
        let tombstoneCount = await session.cleanupTombstoneCountForTesting()
        let ledgerCount = await session.cleanupLedgerCountForTesting()
        XCTAssertEqual(tombstoneCount, 1)
        XCTAssertEqual(ledgerCount, 1)
    }

    func testSMBeeDownloadDirectoryOperationTimeout() async throws {
        let destination = FileManager.default.temporaryDirectory
            .appendingPathComponent("smbee-deadline-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: destination) }
        let transport = ScriptedBlockingReceiveTransport(inbound: try framed(authenticatedTreeResponses(credential: .anonymous)))
        SMBTransportTestOverride.factory = { transport }
        defer { SMBTransportTestOverride.factory = nil }

        do {
            try await SMBee.downloadDirectory(
                host: "server",
                credential: .anonymous,
                share: "share",
                path: "remote",
                localDirectory: destination,
                operationTimeout: .milliseconds(250)
            )
            XCTFail("recursive download unexpectedly completed")
        } catch SMBTransportError.timedOut {
        }
        XCTAssertTrue(transport.didBlockAfterScript)
        try assertOutboundContainsCreateRequest(transport)
    }

    func testSMBeeCopyDirectoryOperationTimeout() async throws {
        let transport = ScriptedBlockingReceiveTransport(inbound: try framed(authenticatedTreeResponses(credential: .anonymous)))
        SMBTransportTestOverride.factory = { transport }
        defer { SMBTransportTestOverride.factory = nil }

        do {
            try await SMBee.copyDirectory(
                host: "server",
                credential: .anonymous,
                share: "share",
                fromPath: "source",
                toPath: "destination",
                operationTimeout: .milliseconds(250)
            )
            XCTFail("recursive copy unexpectedly completed")
        } catch SMBTransportError.timedOut {
        }
        XCTAssertTrue(transport.didBlockAfterScript)
        try assertOutboundContainsCreateRequest(transport)
    }

    func testSMBeeRecursiveDeleteOperationTimeout() async throws {
        let transport = ScriptedBlockingReceiveTransport(inbound: try framed(authenticatedTreeResponses(credential: .anonymous)))
        SMBTransportTestOverride.factory = { transport }
        defer { SMBTransportTestOverride.factory = nil }

        do {
            try await SMBee.delete(
                host: "server",
                credential: .anonymous,
                share: "share",
                path: "directory",
                directory: true,
                recursive: true,
                operationTimeout: .milliseconds(250)
            )
            XCTFail("recursive delete unexpectedly completed")
        } catch SMBTransportError.timedOut {
        }
        XCTAssertTrue(transport.didBlockAfterScript)
        try assertOutboundContainsCreateRequest(transport)
    }

    func testSMBeeCredentialProviderUploadOperationTimeout() async throws {
        do {
            try await SMBee.upload(
                host: "server",
                credentialProvider: {
                    try await Task.sleep(for: .seconds(5))
                    return .anonymous
                },
                share: "share",
                path: "file.txt",
                data: [1, 2, 3],
                operationTimeout: .milliseconds(10)
            )
            XCTFail("upload unexpectedly completed")
        } catch SMBTransportError.timedOut {
        }
    }

    func testSMBeeUploadOperationTimeoutDuringIO() async throws {
        let transport = ScriptedBlockingReceiveTransport(inbound: try framed(authenticatedTreeResponses(credential: .anonymous)))
        SMBTransportTestOverride.factory = { transport }
        defer { SMBTransportTestOverride.factory = nil }

        do {
            try await SMBee.upload(
                host: "server",
                credential: .anonymous,
                share: "share",
                path: "file.txt",
                data: [1, 2, 3],
                operationTimeout: .milliseconds(250)
            )
            XCTFail("upload unexpectedly completed")
        } catch SMBTransportError.timedOut {
        }
        XCTAssertTrue(transport.didBlockAfterScript)
        try assertOutboundContainsCreateRequest(transport)
    }

    func testSMBeeUploadDirectoryOperationTimeoutDuringFileIO() async throws {
        let localDirectory = FileManager.default.temporaryDirectory
            .appendingPathComponent("smbee-deadline-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: localDirectory, withIntermediateDirectories: true)
        try Data([1, 2, 3]).write(to: localDirectory.appendingPathComponent("file.txt"))
        defer { try? FileManager.default.removeItem(at: localDirectory) }

        let transport = ScriptedBlockingReceiveTransport(inbound: try framed(authenticatedTreeResponses(credential: .anonymous)))
        SMBTransportTestOverride.factory = { transport }
        defer { SMBTransportTestOverride.factory = nil }

        do {
            try await SMBee.uploadDirectory(
                host: "server",
                credential: .anonymous,
                share: "share",
                path: "",
                localDirectory: localDirectory,
                operationTimeout: .milliseconds(250)
            )
            XCTFail("recursive upload unexpectedly completed")
        } catch SMBTransportError.timedOut {
        }
        XCTAssertTrue(transport.didBlockAfterScript)
        try assertOutboundContainsCreateRequest(transport)
    }

    func testSMBeeCredentialProviderReadOperationTimeout() async throws {
        do {
            _ = try await SMBee.read(
                host: "server",
                credentialProvider: {
                    try await Task.sleep(for: .seconds(5))
                    return .anonymous
                },
                share: "share",
                path: "file.txt",
                operationTimeout: .milliseconds(10)
            )
            XCTFail("read unexpectedly completed")
        } catch SMBTransportError.timedOut {
        }
    }

    func testReadURLParserKeepsUserInfoPassword() throws {
        let endpoint = try SMBURLParser.parseReadURL("smb://user:pass@server:1445/share/path/to/file.txt")

        XCTAssertEqual(endpoint.username, "user")
        XCTAssertEqual(endpoint.password, "pass")
        XCTAssertEqual(endpoint.host, "server")
        XCTAssertEqual(endpoint.port, 1445)
        XCTAssertEqual(endpoint.share, "share")
        XCTAssertEqual(endpoint.path, "path\\to\\file.txt")
    }

    func testReadURLParserDecodesPercentEncodedComponents() throws {
        let endpoint = try SMBURLParser.parseReadURL("smb://user%40domain:p%40ss@server/share%20name/dir%20one/file%23.txt")

        XCTAssertEqual(endpoint.username, "user@domain")
        XCTAssertEqual(endpoint.password, "p@ss")
        XCTAssertEqual(endpoint.share, "share name")
        XCTAssertEqual(endpoint.path, "dir one\\file#.txt")
    }

    func testReadURLParserRejectsDotDotAndSeparatorComponents() {
        XCTAssertThrowsError(try SMBURLParser.parseReadURL("smb://user@server/share/../file.txt"))
        XCTAssertThrowsError(try SMBURLParser.parseReadURL("smb://user@server/share/dir%2Ffile.txt"))
        XCTAssertThrowsError(try SMBURLParser.parseReadURL("smb://user@server/share/dir%5Cfile.txt"))
    }

    func testServerURLParserDecodesUserInfoWithoutShare() throws {
        let endpoint = try SMBURLParser.parseServerURL("smb://user%40domain:p%40ss@server:1445")

        XCTAssertEqual(endpoint.username, "user@domain")
        XCTAssertEqual(endpoint.password, "p@ss")
        XCTAssertEqual(endpoint.host, "server")
        XCTAssertEqual(endpoint.port, 1445)
        XCTAssertThrowsError(try SMBURLParser.parseServerURL("smb://user@server/share"))
    }

    func testSMBPathNormalizesPublicAPIPaths() throws {
        XCTAssertEqual(try SMBPath.normalize("\\dir/child\\"), "dir\\child")
        XCTAssertEqual(try SMBPath.normalize(""), "")
        XCTAssertEqual(try SMBPath.join("\\dir", "/child"), "dir\\child")
        XCTAssertThrowsError(try SMBPath.normalize("dir//child"))
        XCTAssertThrowsError(try SMBPath.normalize("dir/./child"))
        XCTAssertThrowsError(try SMBPath.normalize("dir/../child"))
    }

    func testSMBPathRejectsUnsafeDirectoryEntryNames() {
        for name in ["..", "../outside", "a/b", "a\\b", "/absolute", ""] {
            XCTAssertThrowsError(try SMBPath.validateDirectoryEntryName(name))
        }
        XCTAssertNoThrow(try SMBPath.validateDirectoryEntryName("日本語.txt"))
    }

    func testSMBPathRejectsRecursiveDirectoryCopyTargets() throws {
        XCTAssertThrowsError(try SMBPath.validateDirectoryCopyTarget(fromPath: "a", toPath: "a")) { error in
            XCTAssertEqual(error as? SMBError, .invalidRecursion("destination is inside source directory"))
        }
        XCTAssertThrowsError(try SMBPath.validateDirectoryCopyTarget(fromPath: "\\a", toPath: "/a/sub")) { error in
            XCTAssertEqual(error as? SMBError, .invalidRecursion("destination is inside source directory"))
        }
        XCTAssertThrowsError(try SMBPath.validateDirectoryCopyTarget(fromPath: "A/Mixed", toPath: "a/mixed/Child")) { error in
            XCTAssertEqual(error as? SMBError, .invalidRecursion("destination is inside source directory"))
        }
        XCTAssertThrowsError(try SMBPath.validateDirectoryCopyTarget(fromPath: "café", toPath: "cafe\u{301}/child")) { error in
            XCTAssertEqual(error as? SMBError, .invalidRecursion("destination is inside source directory"))
        }
        XCTAssertThrowsError(try SMBPath.validateDirectoryCopyTarget(fromPath: "Straße", toPath: "STRASSE/child")) { error in
            XCTAssertEqual(error as? SMBError, .invalidRecursion("destination is inside source directory"))
        }
    }

    func testSMBPathAllowsNonRecursiveDirectoryCopyTargets() throws {
        XCTAssertNoThrow(try SMBPath.validateDirectoryCopyTarget(fromPath: "a\\sub", toPath: "a"))
        XCTAssertNoThrow(try SMBPath.validateDirectoryCopyTarget(fromPath: "a", toPath: "ab"))
        XCTAssertNoThrow(try SMBPath.validateDirectoryCopyTarget(fromPath: "a", toPath: "b\\a"))
    }

    func testSMBPathRecursionDepthCap() throws {
        XCTAssertNoThrow(try SMBPath.validateRecursionDepth(0))
        XCTAssertNoThrow(try SMBPath.validateRecursionDepth(SMBPath.maxRecursionDepth))
        XCTAssertThrowsError(try SMBPath.validateRecursionDepth(SMBPath.maxRecursionDepth + 1)) { error in
            XCTAssertEqual(error as? SMBError, .invalidRecursion("recursion depth exceeded 64"))
        }
    }

    func testSMBShareNameRejectsPathSeparators() {
        XCTAssertThrowsError(try SMBShareName(""))
        XCTAssertThrowsError(try SMBShareName("a/b"))
        XCTAssertThrowsError(try SMBShareName("a\\b"))
        XCTAssertThrowsError(try SMBShareName(".."))
    }

    func testSMBErrorMapperMapsRepresentativeNTSTATUSValues() {
        XCTAssertEqual(
            SMBErrorMapper.map(status: SMB2Status.objectNameNotFound, operation: "CREATE"),
            .notFound(status: SMB2Status.objectNameNotFound, operation: "CREATE")
        )
        XCTAssertEqual(
            SMBErrorMapper.map(status: SMB2Status.objectPathNotFound, operation: "CREATE"),
            .notFound(status: SMB2Status.objectPathNotFound, operation: "CREATE")
        )
        XCTAssertEqual(
            SMBErrorMapper.map(status: SMB2Status.accessDenied, operation: "READ"),
            .accessDenied(status: SMB2Status.accessDenied, operation: "READ")
        )
        XCTAssertEqual(
            SMBErrorMapper.map(status: SMB2Status.sharingViolation, operation: "CREATE"),
            .sharingViolation(status: SMB2Status.sharingViolation, operation: "CREATE")
        )
        XCTAssertEqual(
            SMBErrorMapper.map(status: SMB2Status.objectNameCollision, operation: "CREATE"),
            .nameCollision(status: SMB2Status.objectNameCollision, operation: "CREATE")
        )
        XCTAssertEqual(
            SMBErrorMapper.map(status: SMB2Status.directoryNotEmpty, operation: "CLOSE"),
            .directoryNotEmpty(status: SMB2Status.directoryNotEmpty, operation: "CLOSE")
        )
        XCTAssertEqual(
            SMBErrorMapper.map(status: SMB2Status.fileIsADirectory, operation: "READ"),
            .fileIsADirectory(status: SMB2Status.fileIsADirectory, operation: "READ")
        )
        XCTAssertEqual(
            SMBErrorMapper.map(status: SMB2Status.notADirectory, operation: "QUERY_DIRECTORY"),
            .notADirectory(status: SMB2Status.notADirectory, operation: "QUERY_DIRECTORY")
        )
        XCTAssertEqual(
            SMBErrorMapper.map(status: SMB2Status.diskFull, operation: "WRITE"),
            .diskFull(status: SMB2Status.diskFull, operation: "WRITE")
        )
        XCTAssertEqual(
            SMBErrorMapper.map(status: SMB2Status.networkNameDeleted, operation: "TREE_CONNECT"),
            .networkNameDeleted(status: SMB2Status.networkNameDeleted, operation: "TREE_CONNECT")
        )
        XCTAssertEqual(
            SMBErrorMapper.map(status: SMB2Status.logonFailure, operation: "SESSION_SETUP"),
            .logonFailure(status: SMB2Status.logonFailure, operation: "SESSION_SETUP")
        )
        XCTAssertEqual(
            SMBErrorMapper.map(status: SMB2Status.objectNameInvalid, operation: "CREATE"),
            .objectNameInvalid(status: SMB2Status.objectNameInvalid, operation: "CREATE")
        )
        XCTAssertEqual(
            SMBErrorMapper.map(status: SMB2Status.endOfFile, operation: "READ"),
            .endOfFile(status: SMB2Status.endOfFile, operation: "READ")
        )
        XCTAssertEqual(
            SMBErrorMapper.map(status: SMB2Status.cancelled, operation: "CHANGE_NOTIFY"),
            .cancelled(status: SMB2Status.cancelled, operation: "CHANGE_NOTIFY")
        )
        XCTAssertThrowsError(try SMBErrorMapper.throwIfFailure(status: SMB2Status.cancelled, operation: "CHANGE_NOTIFY")) { error in
            XCTAssertTrue(error is CancellationError)
        }
        XCTAssertEqual(
            SMBErrorMapper.map(status: 0xc000_000d, operation: "QUERY_INFO"),
            .unsupported(status: 0xc000_000d, operation: "QUERY_INFO")
        )
    }

    func testTransportCancellationPropagatesCancellationError() async {
        let transport = BlockingReceiveTransport()
        let task = Task {
            try await transport.receive(maxLength: 1)
        }
        task.cancel()

        do {
            _ = try await task.value
            XCTFail("expected CancellationError")
        } catch is CancellationError {
        } catch {
            XCTFail("expected CancellationError, got \(error)")
        }
    }

    func testCancellingBlockedSendDoesNotCancelSharedSessionSendTask() async throws {
        let transport = BlockingSendTransport(inbound: [])
        let session = SMBSession(
            host: "server",
            port: 445,
            credential: SMBCredential(username: "user", password: "pass"),
            transport: transport,
            initialCredits: 2
        )

        let request = Task { try await session.echo() }
        for _ in 0..<100 where !transport.isSendStarted {
            try await Task.sleep(nanoseconds: 1_000_000)
        }
        XCTAssertTrue(transport.isSendStarted)

        request.cancel()
        XCTAssertTrue(transport.outbound.isEmpty, "cancel while transport.send is blocked must not emit a frame")
        do {
            try await awaitWithTimeout("cancelled blocked send") { try await request.value }
            XCTFail("expected CancellationError")
        } catch is CancellationError {
        }
        XCTAssertFalse(transport.didObserveSendCancellation)

        transport.releaseBlockedSend()
        for _ in 0..<100 where transport.outbound.isEmpty {
            try await Task.sleep(nanoseconds: 1_000_000)
        }
        XCTAssertFalse(transport.didObserveSendCancellation)

        var outboundFrames: [[UInt8]] = []
        for _ in 0..<100 {
            outboundFrames = try unframed(transport.outbound)
            if outboundFrames.count >= 2 { break }
            try await Task.sleep(nanoseconds: 1_000_000)
        }
        XCTAssertGreaterThanOrEqual(outboundFrames.count, 2)
        let requestHeader = try SMB2Header.decode(outboundFrames[0])
        let cancelHeader = try SMB2Header.decode(outboundFrames[1])
        XCTAssertEqual(requestHeader.command, SMB2Commands.echo)
        XCTAssertEqual(cancelHeader.command, SMB2Commands.cancel)
        XCTAssertEqual(cancelHeader.messageId, requestHeader.messageId)

        // Let the cancelled request's response drain, then satisfy the next request.
        transport.appendInbound(try framed([
            try smb2EchoResponse(messageId: requestHeader.messageId),
            try smb2EchoResponse(messageId: requestHeader.messageId + 1)
        ]))

        try await session.echo()
        XCTAssertFalse(transport.didObserveSendCancellation)
    }

    func testInMemoryTransportSupportsConcurrentSendAndReceive() async throws {
        let bytes = Array(UInt8(0)..<UInt8(128))
        let transport = InMemoryTransport(inbound: bytes, mode: .eofWhenDrained)

        async let sent: Void = withThrowingTaskGroup(of: Void.self) { group in
            for byte in bytes {
                group.addTask { try await transport.send([byte]) }
            }
            try await group.waitForAll()
        }
        async let received: [UInt8] = withThrowingTaskGroup(of: UInt8.self, returning: [UInt8].self) { group in
            for _ in bytes {
                group.addTask { try await transport.receive(maxLength: 1).first! }
            }
            var result: [UInt8] = []
            for try await byte in group {
                result.append(byte)
            }
            return result
        }

        try await sent
        let receivedBytes = try await received
        XCTAssertEqual(transport.outbound.sorted(), bytes)
        XCTAssertEqual(receivedBytes.sorted(), bytes)
    }

    func testInMemorySendGateReleasesAllResponsesForTheMatchingRequest() async throws {
        let firstId: UInt64 = 10
        let secondId: UInt64 = 11
        var final = try SMB2Header.asyncHeader(
            command: SMB2Commands.echo,
            credits: 0,
            messageId: firstId,
            asyncId: 0x1234
        ).encode()
        final.append(contentsOf: [4, 0, 0, 0])
        let transport = InMemoryTransport(inbound: try framed([
            try smb2AsyncPendingResponse(
                command: SMB2Commands.echo,
                messageId: firstId,
                asyncId: 0x1234,
                credits: 1
            ),
            final,
            try smb2EchoResponse(messageId: secondId)
        ]))
        defer { transport.close() }

        try await transport.send(try DirectTCPFraming.frame(
            SMB2Header(command: SMB2Commands.echo, messageId: firstId).encode()
        ))
        let interim = try await transport.receive(maxLength: 4096)
        XCTAssertEqual(try SMB2Header.decode(Array(interim.dropFirst(4))).messageId, firstId)
        let asyncFinal = try await awaitWithTimeout(seconds: 0.5, "same-request async final released") {
            try await transport.receive(maxLength: 4096)
        }
        let finalHeader = try SMB2Header.decode(Array(asyncFinal.dropFirst(4)))
        XCTAssertEqual(finalHeader.messageId, firstId)
        XCTAssertEqual(finalHeader.credits, 0)

        try await transport.send(try DirectTCPFraming.frame(
            SMB2Header(command: SMB2Commands.echo, messageId: secondId).encode()
        ))
        let secondResponse = try await transport.receive(maxLength: 4096)
        XCTAssertEqual(try SMB2Header.decode(Array(secondResponse.dropFirst(4))).messageId, secondId)
    }

    func testInMemorySendGateRejectsUnmatchedCommandAndExtraSend() async throws {
        let transport = InMemoryTransport(inbound: try framed([smb2EchoResponse(messageId: 20)]))
        defer { transport.close() }

        do {
            let wrongCommand = try SMB2Header(command: SMB2Commands.read, messageId: 20).encode()
            try await transport.send(try DirectTCPFraming.frame(wrongCommand))
            XCTFail("a response for ECHO must not be unlocked by READ with the same MessageId")
        } catch SMBCodecError.invalidValue(let message) {
            XCTAssertTrue(message.contains("unexpected SMB request"), message)
        }
        XCTAssertTrue(transport.outbound.isEmpty)

        let matchingRequest = try SMB2Header(command: SMB2Commands.echo, messageId: 20).encode()
        try await transport.send(try DirectTCPFraming.frame(matchingRequest))
        let response = try await transport.receive(maxLength: 4096)
        XCTAssertEqual(try SMB2Header.decode(Array(response.dropFirst(4))).messageId, 20)

        do {
            let extraRequest = try SMB2Header(command: SMB2Commands.echo, messageId: 21).encode()
            try await transport.send(try DirectTCPFraming.frame(extraRequest))
            XCTFail("the fixture must reject a send after all configured responses are consumed")
        } catch SMBCodecError.invalidValue(let message) {
            XCTAssertTrue(message.contains("unexpected SMB request"), message)
        }
    }

    func testInMemorySendGateClassifiesEncryptedRequestsAndCANCELDoesNotUnlockResponses() async throws {
        let echo42 = try SMBWireRequestDescriptor(packet: SMB2Header(
            command: SMB2Commands.echo,
            messageId: 42
        ).encode())
        let cancel42 = try SMBWireRequestDescriptor(packet: SMB2Header(
            command: SMB2Commands.cancel,
            messageId: 42
        ).encode())
        let echo43 = try SMBWireRequestDescriptor(packet: SMB2Header(
            command: SMB2Commands.echo,
            messageId: 43
        ).encode())
        let decoder: SMBWireRequestDecoder = { packet in
            guard packet.starts(with: SMB3TransformHeader.protocolId), let marker = packet.last else {
                return try SMBWireRequestDescriptor(packet: packet)
            }
            switch marker {
            case 0x42: return echo42
            case 0xc0: return cancel42
            case 0x43: return echo43
            default: throw SMBCodecError.invalidValue("unknown encrypted test request marker")
            }
        }
        let transport = InMemoryTransport(
            inbound: try framed([
                try smb2EchoResponse(messageId: 42),
                try smb2EchoResponse(messageId: 43)
            ]),
            mode: .sendGatedWaitUntilClosed,
            responseIdentityOverrides: nil,
            allowedUnansweredRequests: [],
            requestDecoder: decoder
        )
        defer { transport.close() }
        func encryptedRequest(_ marker: UInt8) throws -> [UInt8] {
            try DirectTCPFraming.frame(SMB3TransformHeader.protocolId + [marker])
        }

        try await transport.send(encryptedRequest(0x42))
        let firstResponse = try await transport.receive(maxLength: 4096)
        XCTAssertEqual(try SMB2Header.decode(Array(firstResponse.dropFirst(4))).messageId, 42)

        let waitingReceive = Task { try await transport.receive(maxLength: 4096) }
        try await awaitWithTimeout("receive waits for request 43") {
            while !transport.hasPendingReceiveForTesting { await Task.yield() }
        }
        try await transport.send(encryptedRequest(0xc0))
        XCTAssertTrue(transport.hasPendingReceiveForTesting, "encrypted CANCEL must not release an unrelated response")

        try await transport.send(encryptedRequest(0x43))
        let secondResponse = try await awaitWithTimeout(seconds: 0.5, "request 43 response released") {
            try await waitingReceive.value
        }
        XCTAssertEqual(try SMB2Header.decode(Array(secondResponse.dropFirst(4))).messageId, 43)

        do {
            try await transport.send(encryptedRequest(0x44))
            XCTFail("unexpected encrypted request should fail the scripted fixture")
        } catch SMBCodecError.invalidValue(let message) {
            XCTAssertTrue(message.contains("unknown encrypted test request marker"))
        }
    }

    func testVNITransportReceiveTokensAndTerminalClose() async throws {
        let response = try framed([
            try smb2EchoResponse(messageId: 0),
            try smb2EchoResponse(messageId: 1)
        ])
        let transport = SMBValidateNegotiateScriptTransport(inbound: response)
        try await transport.connect(host: "server", port: 445)

        let first = Task { try await transport.receive(maxLength: 4096) }
        try await awaitWithTimeout("first scripted receive registers") {
            while transport.pendingReceiveTokenForTesting == nil { await Task.yield() }
        }
        let firstToken = try XCTUnwrap(transport.pendingReceiveTokenForTesting)
        do {
            _ = try await transport.receive(maxLength: 4096)
            XCTFail("a second concurrent receive must fail explicitly")
        } catch SMBCodecError.invalidValue(let message) {
            XCTAssertTrue(message.contains("concurrent receive"))
        }

        let request0 = try SMB2Header(command: SMB2Commands.echo, messageId: 0).encode()
        try await transport.send(try DirectTCPFraming.frame(request0))
        let firstResponse = try await first.value
        XCTAssertEqual(try SMB2Header.decode(Array(firstResponse.dropFirst(4))).messageId, 0)

        let second = Task { try await transport.receive(maxLength: 4096) }
        try await awaitWithTimeout("second scripted receive registers") {
            while transport.pendingReceiveTokenForTesting == nil { await Task.yield() }
        }
        let secondToken = try XCTUnwrap(transport.pendingReceiveTokenForTesting)
        XCTAssertNotEqual(firstToken, secondToken)
        transport.cancelPendingReceiveForTesting(token: firstToken)
        XCTAssertTrue(transport.hasPendingReceiveForTesting, "an old cancellation token must leave the current receive alone")

        let request1 = try SMB2Header(command: SMB2Commands.echo, messageId: 1).encode()
        try await transport.send(try DirectTCPFraming.frame(request1))
        let secondResponse = try await second.value
        XCTAssertEqual(try SMB2Header.decode(Array(secondResponse.dropFirst(4))).messageId, 1)

        let pendingAfterAllScripts = Task { try await transport.receive(maxLength: 4096) }
        try await awaitWithTimeout("drained scripted receive registers") {
            while transport.pendingReceiveTokenForTesting == nil { await Task.yield() }
        }
        transport.close()
        do {
            _ = try await pendingAfterAllScripts.value
            XCTFail("close should finish an already registered receive with an error")
        } catch SMBTransportError.connectionClosed {
        }
        do {
            try await transport.connect(host: "server", port: 445)
            XCTFail("connect after close must fail")
        } catch SMBTransportError.connectionClosed {
        }
        do {
            try await transport.send(try DirectTCPFraming.frame(
                SMB2Header(command: SMB2Commands.echo, messageId: 2).encode()
            ))
            XCTFail("send after close must fail")
        } catch SMBTransportError.connectionClosed {
        }
        do {
            _ = try await transport.receive(maxLength: 16)
            XCTFail("receive after close must fail")
        } catch SMBTransportError.connectionClosed {
        }
    }

    func testVNITransportRechecksCancellationAtReceiveRegistration() async throws {
        let gate = SMBReceiveRegistrationGate()
        let transport = SMBValidateNegotiateScriptTransport(
            inbound: [],
            beforeReceiveRegistration: { gate.blockBeforeRegistration() }
        )
        let entered = Task.detached { gate.waitUntilEntered() }
        let receive = Task { try await transport.receive(maxLength: 256) }
        defer { gate.release(); transport.close() }
        try await awaitWithTimeout("receive reached registration gate") { await entered.value }

        receive.cancel()
        gate.release()
        do {
            _ = try await awaitWithTimeout(seconds: 0.5, "cancel-before-registration is observed") { try await receive.value }
            XCTFail("cancelled receive should not register after its cancellation handler has already run")
        } catch is CancellationError {
        }
        XCTAssertFalse(transport.hasPendingReceiveForTesting)
    }

    func testVNITransportRejectsUnexpectedRequestIdentity() async throws {
        let transport = SMBValidateNegotiateScriptTransport(
            inbound: try framed([smb2EchoResponse(messageId: 0)])
        )
        try await transport.connect(host: "server", port: 445)
        let wrongCommand = try SMB2Header(command: SMB2Commands.read, messageId: 0).encode()
        do {
            try await transport.send(try DirectTCPFraming.frame(wrongCommand))
            XCTFail("a response for ECHO must not be unlocked by READ with the same MessageId")
        } catch SMBCodecError.invalidValue(let message) {
            XCTAssertTrue(message.contains("unexpected SMB request"), message)
        }
        XCTAssertTrue(transport.outbound.isEmpty)

        let matchingRequest = try SMB2Header(command: SMB2Commands.echo, messageId: 0).encode()
        try await transport.send(try DirectTCPFraming.frame(matchingRequest))
        let matchingResponse = try await transport.receive(maxLength: 4096)
        XCTAssertEqual(try SMB2Header.decode(Array(matchingResponse.dropFirst(4))).messageId, 0)
        let matchedOutbound = transport.outbound

        let wrongRequest = try SMB2Header(command: SMB2Commands.echo, messageId: 1).encode()
        do {
            try await transport.send(try DirectTCPFraming.frame(wrongRequest))
            XCTFail("a response for another MessageId must not be unlocked by this extra send")
        } catch SMBCodecError.invalidValue(let message) {
            XCTAssertTrue(message.contains("unexpected SMB request"), message)
        }
        XCTAssertEqual(transport.outbound, matchedOutbound)
        transport.close()
    }

#if canImport(Network)
    func testNWConnectionTransportConnectSendReceiveOverLoopback() async throws {
        let server = try LoopbackNWServer(echo: true)
        try await awaitWithTimeout("start loopback NWListener") {
            try await server.start()
        }
        defer { server.stop() }

        let transport = NWConnectionTransport()
        try await awaitWithTimeout("connect NWConnectionTransport") {
            try await transport.connect(host: "127.0.0.1", port: server.port)
        }
        defer { transport.close() }

        let payload: [UInt8] = [0x01, 0x02, 0x03, 0x04]
        try await awaitWithTimeout("send loopback payload") {
            try await transport.send(payload)
        }
        let received = try await awaitWithTimeout("receive loopback payload") {
            try await transport.receive(maxLength: payload.count)
        }

        XCTAssertEqual(received, payload)
    }

    func testNWConnectionTransportConnectCancellationDoesNotCrash() async throws {
        let transport = NWConnectionTransport()
        let task = Task {
            try await transport.connect(host: "192.0.2.1", port: 445)
        }
        task.cancel()

        do {
            try await awaitWithTimeout("cancel NWConnectionTransport connect") {
                try await task.value
            }
            XCTFail("expected CancellationError")
        } catch is CancellationError {
        } catch {
            XCTFail("expected CancellationError, got \(error)")
        }
    }

    func testNWConnectionTransportReceiveCloseDoesNotCrash() async throws {
        let server = try LoopbackNWServer(echo: false)
        try await awaitWithTimeout("start loopback NWListener") {
            try await server.start()
        }
        defer { server.stop() }

        let transport = NWConnectionTransport()
        try await awaitWithTimeout("connect NWConnectionTransport") {
            try await transport.connect(host: "127.0.0.1", port: server.port)
        }
        _ = await server.waitForConnection()

        let task = Task {
            try await transport.receive(maxLength: 1)
        }
        transport.close()

        do {
            _ = try await awaitWithTimeout("receive after close") {
                try await task.value
            }
            XCTFail("expected receive to end after close")
        } catch {
            XCTAssertTrue(error is CancellationError || error is SMBTransportError || error is NWError)
        }
    }
#endif

    func testProbeRetriesConnectionLossOnceAndSucceedsWithNewTransport() async throws {
        let first = FailingReceiveTransport(failure: SMBTransportError.connectionClosed)
        let second = InMemoryTransport(inbound: try framed([negotiateResponse(messageId: 0)]))
        let factory = TransportFactorySequence([first, second])

        let result = try await SMBProbe.probe(host: "server", makeTransport: factory.make)

        XCTAssertEqual(result.dialect, SMBNegotiateConstants.dialect302)
        XCTAssertEqual(factory.makeCount, 2)
    }

    func testDeleteDoesNotRetryConnectionLossAndThrowsConnectionLost() async {
        let factory = TransportFactorySequence([
            FailingConnectTransport(failure: SMBTransportError.connectionClosed)
        ])

        do {
            try await SMBClient.delete(
                host: "server",
                share: "share",
                path: "dead.txt",
                credential: SMBCredential(username: "user", password: "pass"),
                makeTransport: factory.make
            )
            XCTFail("expected connectionLost")
        } catch SMBError.connectionLost(operation: "DELETE") {
            XCTAssertEqual(factory.makeCount, 1)
        } catch {
            XCTFail("expected connectionLost, got \(error)")
        }
    }

    func testSessionSetupLogonFailureDoesNotRetry() async throws {
        let inbound = try framed([
            negotiateResponse(messageId: 0),
            smb2StatusResponse(status: SMB2Status.logonFailure, command: SMB2Commands.sessionSetup, messageId: 1, treeId: 0)
        ])
        let factory = TransportFactorySequence([InMemoryTransport(inbound: inbound)])

        do {
            _ = try await SMBClient.list(
                host: "server",
                share: "share",
                credential: SMBCredential(username: "user", password: "pass"),
                makeTransport: factory.make
            )
            XCTFail("expected logonFailure")
        } catch SMBError.logonFailure(status: SMB2Status.logonFailure, operation: "SESSION_SETUP#1") {
            XCTAssertEqual(factory.makeCount, 1)
        } catch {
            XCTFail("expected logonFailure, got \(error)")
        }
    }

    func testAuthenticatedConnectRejectsSMB21OnlyServerWithDiagnostic() async throws {
        let inbound = try framed([
            negotiateResponse(messageId: 0, dialect: SMBNegotiateConstants.dialect210)
        ])
        let transport = InMemoryTransport(inbound: inbound)

        do {
            _ = try await SMBClient.connect(
                host: "server",
                share: "share",
                credential: SMBCredential(username: "user", password: "pass"),
                makeTransport: { transport }
            )
            XCTFail("expected SMB 2.1 authenticated connection to be rejected")
        } catch SMBError.protocolError(let message) {
            XCTAssertEqual(message, SMBNegotiateCodec.authenticatedUnsupportedMessage)
            let requests = try unframed(transport.outbound)
            XCTAssertEqual(requests.count, 1)
            let header = try SMB2Header.decode(requests[0])
            XCTAssertEqual(header.command, SMBNegotiateConstants.commandNegotiate)
        } catch {
            XCTFail("expected protocolError, got \(error)")
        }
    }

    func testNegotiateDecodeReportsServerCapabilitiesAndEncryptionSupport() throws {
        let plain = try SMBNegotiateCodec.decodeResponse(negotiateResponse(messageId: 0, capabilities: 0x0000_0007))
        XCTAssertEqual(plain.capabilities, 0x0000_0007)
        XCTAssertFalse(plain.supportsEncryption)

        let encrypting = try SMBNegotiateCodec.decodeResponse(
            negotiateResponse(messageId: 0, capabilities: SMBNegotiateConstants.globalCapEncryption))
        XCTAssertTrue(encrypting.supportsEncryption)

        // 2.x has no encryption even if a server sets the (3.x-only) capability bit.
        let smb21 = try SMBNegotiateCodec.decodeResponse(negotiateResponse(
            messageId: 0, dialect: SMBNegotiateConstants.dialect210, capabilities: SMBNegotiateConstants.globalCapEncryption))
        XCTAssertFalse(smb21.supportsEncryption)
    }

    // Issue 098: an SMB 3.0.x server without SMB2_GLOBAL_CAP_ENCRYPTION (Samba `smb encrypt = disabled`)
    // disconnects on TRANSFORM frames, so post-auth requests must go out as signed plaintext.
    func testSMB302WithoutServerEncryptionCapabilitySignsTreeConnectInsteadOfEncrypting() async throws {
        let requests = try await connectOutboundRequests(capabilities: 0, sessionFlags: 0)
        XCTAssertGreaterThanOrEqual(requests.count, 4)
        let treeConnect = requests[3]
        XCTAssertEqual(Array(treeConnect[0..<4]), [0xfe, 0x53, 0x4d, 0x42])
        let header = try SMB2Header.decode(treeConnect)
        XCTAssertEqual(header.command, SMB2Commands.treeConnect)
        XCTAssertNotEqual(header.flags & SMB2Flags.signed, 0)
        XCTAssertNotEqual(Array(treeConnect[48..<64]), Array(repeating: UInt8(0), count: 16))
    }

    func testSMB302WithServerEncryptionCapabilityEncryptsTreeConnect() async throws {
        let requests = try await connectOutboundRequests(
            capabilities: SMBNegotiateConstants.globalCapEncryption, sessionFlags: 0)
        XCTAssertGreaterThanOrEqual(requests.count, 4)
        XCTAssertEqual(Array(requests[3][0..<4]), SMB3TransformHeader.protocolId)
    }

    func testSessionSetupEncryptDataWithoutEncryptionCapabilityFailsClosed() async throws {
        try await assertSessionSetupEncryptDataFailsClosed(credential: SMBCredential(username: "user", password: "pass"))
    }

    // Anonymous NTLM yields no key material, so an ENCRYPT_DATA session must also fail closed rather than
    // continue in plaintext.
    func testAnonymousSessionSetupEncryptDataFailsClosed() async throws {
        try await assertSessionSetupEncryptDataFailsClosed(credential: .anonymous)
    }

    private func assertSessionSetupEncryptDataFailsClosed(credential: SMBCredential) async throws {
        let inbound = try framed([
            negotiateResponse(messageId: 0, capabilities: 0),
            sessionSetupChallengeResponse(messageId: 1, sessionId: 0x1122_3344_5566_7788),
            try sessionSetupSuccessResponse(messageId: 2, sessionFlags: SMB2SessionSetup.sessionFlagEncryptData)
        ])
        let transport = InMemoryTransport(inbound: inbound)
        do {
            let session = try await SMBClient.connect(
                host: "server", share: "share",
                credential: credential,
                makeTransport: { transport }
            )
            await session.close()
            XCTFail("expected SESSION_SETUP encryption requirement to fail closed")
        } catch let SMBError.protocolError(message) {
            XCTAssertTrue(message.contains("SESSION_SETUP requires encryption"), message)
        }
        let requests = try unframed(transport.outbound)
        XCTAssertFalse(requests.contains { (try? SMB2Header.decode($0).command) == SMB2Commands.treeConnect })
        XCTAssertFalse(requests.contains { Array($0[0..<4]) == SMB3TransformHeader.protocolId })
    }

    /// Connects over a synthetic 3.0.2 exchange and returns every request the client framed.
    /// The script supplies the required signed VALIDATE_NEGOTIATE_INFO response so connect can
    /// finish before this wire-shape assertion closes the transport directly.
    private func connectOutboundRequests(capabilities: UInt32, sessionFlags: UInt16) async throws -> [[UInt8]] {
        let inbound = try framed([
            negotiateResponse(messageId: 0, capabilities: capabilities),
            sessionSetupChallengeResponse(messageId: 1, sessionId: 0x1122_3344_5566_7788),
            try sessionSetupSuccessResponse(
                messageId: 2,
                sessionFlags: sessionFlags,
                sessionId: 0x1122_3344_5566_7788
            ),
            smb2TreeConnectResponse(treeId: 0x3344, shareType: 1, shareFlags: 0, capabilities: 0, maximalAccess: 0x001f_01ff),
            try SMBValidateNegotiateScript.responseTemplate(capabilities: capabilities)
        ])
        let credential = SMBCredential(username: "user", password: "pass")
        let transport = SMBValidateNegotiateScriptTransport(inbound: inbound, credential: credential)
        let session = try await SMBClient.connect(
            host: "server", share: "share",
            credential: credential,
            makeTransport: { transport }
        )
        let wireSession = await session.wireSessionForTesting()
        await wireSession.closeTransportAndWait(cause: "wire_shape_test_complete")
        return try unframed(transport.outbound)
    }

    func testCredentialProviderIsResolvedOnceWhenConnectingPersistentSession() async throws {
        let providerCredential = SMBCredential(
            username: "provider-user", password: "provider-pass", domain: "provider-domain"
        )
        let inbound = try framed([
            negotiateResponse(messageId: 0),
            sessionSetupChallengeResponse(messageId: 1, sessionId: 0x1122_3344_5566_7788),
            try sessionSetupSuccessResponse(messageId: 2),
            smb2TreeConnectResponse(treeId: 0x3344, shareType: 1, shareFlags: 0, capabilities: 0, maximalAccess: 0x001f_01ff),
            try SMBValidateNegotiateScript.responseTemplate(),
            try smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.treeDisconnect, messageId: 4, treeId: 0x3344),
            try smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.logoff, messageId: 5, treeId: 0)
        ])
        let transport = SMBValidateNegotiateScriptTransport(inbound: inbound, credential: providerCredential)
        let providerCalls = LockedCounter()

        let session = try await SMBClient.connect(
            host: "server",
            share: "share",
            credentialProvider: {
                providerCalls.increment()
                return providerCredential
            },
            makeTransport: { transport }
        )
        let retainsCredential = await session.retainsAuthenticationCredentialForTesting()
        XCTAssertFalse(retainsCredential)
        await session.close()

        XCTAssertEqual(providerCalls.value, 1)
        let requests = try unframed(transport.outbound)
        XCTAssertGreaterThanOrEqual(requests.count, 3)
        let type1 = try SPNEGO.unwrapNTLMToken(Array(requests[1][88..<requests[1].count]))
        XCTAssertEqual(String(bytes: readSecurityBuffer(type1, at: 16), encoding: .utf8), "PROVIDER-DOMAIN")
    }

    func testCredentialProviderIsResolvedOnceForOneShotStat() async throws {
        let fileId = hexBytes("00112233445566778899aabbccddeeff")
        let providerCredential = SMBCredential(
            username: "one-shot-user", password: "one-shot-pass", domain: "one-shot-domain"
        )
        let inbound = try framed([
            negotiateResponse(messageId: 0),
            sessionSetupChallengeResponse(messageId: 1, sessionId: 0x1122_3344_5566_7788),
            try sessionSetupSuccessResponse(messageId: 2),
            smb2TreeConnectResponse(treeId: 0x3344, shareType: 1, shareFlags: 0, capabilities: 0, maximalAccess: 0x001f_01ff),
            try SMBValidateNegotiateScript.responseTemplate(),
            smb2CreateResponse(fileId: fileId, messageId: 4, treeId: 0x3344),
            smb2QueryInfoResponse(size: 7, messageId: 5, treeId: 0x3344),
            smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.close, messageId: 6, treeId: 0x3344),
            smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.treeDisconnect, messageId: 7, treeId: 0x3344),
            smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.logoff, messageId: 8, treeId: 0)
        ])
        let transport = SMBValidateNegotiateScriptTransport(inbound: inbound, credential: providerCredential)
        let providerCalls = LockedCounter()

        let stat = try await SMBClient.stat(
            host: "server",
            share: "share",
            path: "known.txt",
            credentialProvider: {
                providerCalls.increment()
                return providerCredential
            },
            makeTransport: { transport }
        )

        XCTAssertEqual(stat.size, 7)
        XCTAssertEqual(providerCalls.value, 1)
        let requests = try unframed(transport.outbound)
        XCTAssertGreaterThanOrEqual(requests.count, 3)
        let type1 = try SPNEGO.unwrapNTLMToken(Array(requests[1][88..<requests[1].count]))
        XCTAssertEqual(String(bytes: readSecurityBuffer(type1, at: 16), encoding: .utf8), "ONE-SHOT-DOMAIN")
    }

    func testSMBeeFacadeStatUsesTransportOverride() async throws {
        let fileId = hexBytes("00112233445566778899aabbccddeeff")
        let transport = SMBValidateNegotiateScriptTransport(inbound: try framed(authenticatedTreeResponses() + [
            smb2CreateResponse(fileId: fileId, messageId: 4, treeId: 0x3344),
            smb2QueryInfoResponse(size: 7, messageId: 5, treeId: 0x3344),
            smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.close, messageId: 6, treeId: 0x3344),
            smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.treeDisconnect, messageId: 7, treeId: 0x3344),
            smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.logoff, messageId: 8, treeId: 0)
        ]))
        SMBTransportTestOverride.factory = { transport }
        defer { SMBTransportTestOverride.factory = nil }

        let stat = try await SMBee.stat(
            host: "server",
            credential: SMBCredential(username: "user", password: "pass"),
            share: "share",
            path: "known.txt"
        )

        XCTAssertEqual(stat.size, 7)
        let requests = try unframed(transport.outbound)
        XCTAssertEqual(requests.count, 10)
    }

    func testSMBeeFacadeCredentialProviderReadUsesTransportOverride() async throws {
        let fileId = hexBytes("00112233445566778899aabbccddeeff")
        let providerCredential = SMBCredential(username: "provider-user", password: "provider-pass")
        let transport = SMBValidateNegotiateScriptTransport(
            inbound: try framed(authenticatedTreeResponses(credential: providerCredential) + [
            smb2CreateResponse(fileId: fileId, messageId: 4, treeId: 0x3344),
            smb2QueryInfoResponse(size: 5, messageId: 5, treeId: 0x3344),
            smb2ReadResponse(Array("hello".utf8), messageId: 6, treeId: 0x3344),
            smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.close, messageId: 7, treeId: 0x3344),
            smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.treeDisconnect, messageId: 8, treeId: 0x3344),
            smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.logoff, messageId: 9, treeId: 0)
            ]),
            credential: providerCredential
        )
        SMBTransportTestOverride.factory = { transport }
        defer { SMBTransportTestOverride.factory = nil }
        let providerCalls = LockedCounter()

        let data = try await SMBee.read(
            host: "server",
            credentialProvider: {
                providerCalls.increment()
                return providerCredential
            },
            share: "share",
            path: "hello.txt"
        )

        XCTAssertEqual(data, Array("hello".utf8))
        XCTAssertEqual(providerCalls.value, 1)
        let requests = try unframed(transport.outbound)
        XCTAssertEqual(requests.count, 11)
    }

    func testSMBeeFacadeListStreamsDirectoryEntriesUsingTransportOverride() async throws {
        let fileId = hexBytes("00112233445566778899aabbccddeeff")
        let transport = SMBValidateNegotiateScriptTransport(inbound: try framed(authenticatedTreeResponses() + [
            smb2CreateResponse(fileId: fileId, messageId: 4, treeId: 0x3344),
            smb2QueryDirectoryResponse(entries: [
                makeDirectoryEntry(name: "a.txt", isDirectory: false, fileSize: 1, nextOffset: 0)
            ], messageId: 5, treeId: 0x3344),
            smb2StatusResponse(status: SMB2Status.noMoreFiles, command: SMB2Commands.queryDirectory, messageId: 6, treeId: 0x3344),
            smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.close, messageId: 7, treeId: 0x3344),
            smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.treeDisconnect, messageId: 8, treeId: 0x3344),
            smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.logoff, messageId: 9, treeId: 0)
        ]))
        SMBTransportTestOverride.factory = { transport }
        defer { SMBTransportTestOverride.factory = nil }

        let entries = try await SMBee.list(
            host: "server",
            credential: SMBCredential(username: "user", password: "pass"),
            share: "share",
            path: ""
        )

        XCTAssertEqual(entries, [SMBDirectoryEntry(name: "a.txt", fileSize: 1, isDirectory: false, attributes: 0x80)])
    }

    func testWatchAutoReconnectResubscribesAfterConnectionDropAndEmitsOverflow() async throws {
        let fileId = hexBytes("00112233445566778899aabbccddeeff")
        // Transport #1: auth + tree + CREATE for the watch, then drains — the CHANGE_NOTIFY
        // long-poll receive hits connectionClosed, triggering reconnect.
        // Transport #2: fresh auth + tree + CREATE + a real ADDED notification.
        // Transport #2 parks after delivering the notification (rather than draining) so the
        // resubscribed watch stays blocked on its next long-poll until the test cancels,
        // instead of looping into another reconnect.
        let secondTransport = ControlledReceiveTransport()
        secondTransport.enqueueInbound(try framed(authenticatedTreeResponses(credential: .anonymous) + [
            smb2CreateResponse(fileId: fileId, messageId: 4, treeId: 0x3344),
            smb2ChangeNotifyResponse(
                entries: [makeFileNotifyEntry(action: 1, name: "created.txt", nextOffset: 0)],
                messageId: 5,
                treeId: 0x3344
            )
        ]))
        let factory = TransportFactorySequence([
            SMBValidateNegotiateScriptTransport(
                inbound: try framed(authenticatedTreeResponses(credential: .anonymous) + [
                    smb2CreateResponse(fileId: fileId, messageId: 4, treeId: 0x3344)
                ]),
                blockWhenDrained: false
            ),
            secondTransport
        ])
        SMBTransportTestOverride.factory = factory.make
        defer { SMBTransportTestOverride.factory = nil }

        let session = try await SMBee.connect(host: "server", credential: .anonymous, share: "share")
        let events = ChangeNotifyEventAccumulator()
        let changeReceived = SMBContinuationCountBarrier()
        let changeReceivedClock = ManualSMBSleeper()
        let overflowReceived = SMBContinuationCountBarrier()
        let overflowReceivedClock = ManualSMBSleeper()
        let watcher = Task {
            try await session.withChangeNotifications(path: "dir", autoReconnect: true) { event in
                await events.record(event)
                switch event {
                case .overflow:
                    overflowReceived.signal()
                case .changes(let changes) where changes.contains(where: { $0.name == "created.txt" }):
                    changeReceived.signal()
                default:
                    break
                }
            }
        }

        try await smbIssue102AwaitWithTimeout("watch reconnect overflow event") {
            try await overflowReceived.waitForCount(
                1,
                timeout: .seconds(1),
                sleeper: { try await overflowReceivedClock.sleep(for: $0) }
            )
        }
        try await smbIssue102AwaitWithTimeout("watch reconnect change event") {
            try await changeReceived.waitForCount(
                1,
                timeout: .seconds(1),
                sleeper: { try await changeReceivedClock.sleep(for: $0) }
            )
        }
        watcher.cancel()
        let wireSession = await session.wireSessionForTesting()
        await wireSession.closeTransportAndWait(cause: "test_watch_reconnect_cancel")
        do {
            try await smbIssue102AwaitWithTimeout("watcher cancellation completes") { try await watcher.value }
        } catch is CancellationError {
            // Cancelling the watch must release its blocked transport receive.
        }

        let sawAdded = await events.containsChange(named: "created.txt")
        XCTAssertTrue(sawAdded, "expected the ADDED notification after reconnect")
        // Reconnect built a second transport, and an overflow was emitted before resubscribe.
        XCTAssertEqual(factory.makeCount, 2)
        let sawOverflow = await events.sawOverflow
        XCTAssertTrue(sawOverflow, "expected an overflow (full rescan) signal after reconnect")
    }

    func testSMBeeFacadeMutatingOperationsUseTransportOverride() async throws {
        let fileId = hexBytes("00112233445566778899aabbccddeeff")
        let factory = TransportFactorySequence([
            SMBValidateNegotiateScriptTransport(inbound: try framed(authenticatedTreeResponses(credential: .anonymous) + [
                smb2CreateResponse(fileId: fileId, messageId: 4, treeId: 0x3344),
                smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.close, messageId: 5, treeId: 0x3344),
                smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.treeDisconnect, messageId: 6, treeId: 0x3344),
                smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.logoff, messageId: 7, treeId: 0)
            ])),
            SMBValidateNegotiateScriptTransport(inbound: try framed(authenticatedTreeResponses(credential: .anonymous) + [
                smb2CreateResponse(fileId: fileId, messageId: 4, treeId: 0x3344),
                smb2WriteResponse(count: 3, messageId: 5, treeId: 0x3344),
                smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.flush, messageId: 6, treeId: 0x3344),
                smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.close, messageId: 7, treeId: 0x3344),
                smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.treeDisconnect, messageId: 8, treeId: 0x3344),
                smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.logoff, messageId: 9, treeId: 0)
            ])),
            SMBValidateNegotiateScriptTransport(inbound: try framed(authenticatedTreeResponses(credential: .anonymous) + [
                smb2CreateResponse(fileId: fileId, messageId: 4, treeId: 0x3344),
                smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.setInfo, messageId: 5, treeId: 0x3344),
                smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.close, messageId: 6, treeId: 0x3344),
                smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.treeDisconnect, messageId: 7, treeId: 0x3344),
                smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.logoff, messageId: 8, treeId: 0)
            ])),
            SMBValidateNegotiateScriptTransport(inbound: try framed(authenticatedTreeResponses(credential: .anonymous) + [
                smb2CreateResponse(fileId: fileId, messageId: 4, treeId: 0x3344),
                smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.close, messageId: 5, treeId: 0x3344),
                smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.treeDisconnect, messageId: 6, treeId: 0x3344),
                smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.logoff, messageId: 7, treeId: 0)
            ]))
        ])
        SMBTransportTestOverride.factory = factory.make
        defer { SMBTransportTestOverride.factory = nil }

        try await SMBee.makeDirectory(host: "server", credential: .anonymous, share: "share", path: "new")
        try await SMBee.upload(host: "server", credential: .anonymous, share: "share", path: "file.txt", data: Array("hey".utf8))
        try await SMBee.rename(host: "server", credentialProvider: { .anonymous }, share: "share", fromPath: "old.txt", toPath: "new.txt")
        try await SMBee.delete(host: "server", credentialProvider: { .anonymous }, share: "share", path: "new.txt")

        XCTAssertEqual(factory.makeCount, 4)
    }

    func testSMBeeFacadeConnectUsesTransportOverrideAndTeardown() async throws {
        let transport = SMBValidateNegotiateScriptTransport(inbound: try framed(authenticatedTreeResponses() + [
            smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.treeDisconnect, messageId: 4, treeId: 0x3344),
            smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.logoff, messageId: 5, treeId: 0)
        ]))
        SMBTransportTestOverride.factory = { transport }
        defer { SMBTransportTestOverride.factory = nil }

        let session = try await SMBee.connect(
            host: "server",
            credential: SMBCredential(username: "user", password: "pass"),
            share: "share"
        )
        await session.close()

        // Handshake + VALIDATE_NEGOTIATE_INFO + best-effort teardown.
        XCTAssertEqual(try unframed(transport.outbound).count, 7)
    }

    func testSMBeeFacadeEchoUsesTransportOverrideAndTeardown() async throws {
        let transport = SMBValidateNegotiateScriptTransport(inbound: try framed(authenticatedTreeResponses() + [
            smb2EchoResponse(messageId: 4),
            smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.treeDisconnect, messageId: 5, treeId: 0x3344),
            smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.logoff, messageId: 6, treeId: 0)
        ]))
        SMBTransportTestOverride.factory = { transport }
        defer { SMBTransportTestOverride.factory = nil }

        try await SMBee.echo(
            host: "server",
            credential: SMBCredential(username: "user", password: "pass"),
            share: "share"
        )

        let requests = try unframed(transport.outbound)
        XCTAssertEqual(requests.count, 8)
        // Post-auth requests are signed in this plaintext SMB 3.0.2 fixture.
    }

    func testSMBeeFacadeReadlinkUsesTransportOverrideAndTeardown() async throws {
        let fileId = hexBytes("00112233445566778899aabbccddeeff")
        let transport = SMBValidateNegotiateScriptTransport(inbound: try framed(authenticatedTreeResponses() + [
            smb2CreateResponse(fileId: fileId, messageId: 4, treeId: 0x3344),
            smb2IoctlResponse(
                output: reparseSymlinkBuffer(substituteName: "\\??\\C:\\target.txt", printName: "target.txt"),
                status: SMB2Status.success,
                messageId: 5,
                treeId: 0x3344,
                fileId: fileId,
                ctlCode: SMB2Ioctl.fsctlGetReparsePoint
            ),
            smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.close, messageId: 6, treeId: 0x3344),
            smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.treeDisconnect, messageId: 7, treeId: 0x3344),
            smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.logoff, messageId: 8, treeId: 0)
        ]))
        SMBTransportTestOverride.factory = { transport }
        defer { SMBTransportTestOverride.factory = nil }

        let reparsePoint = try await SMBee.readlink(
            host: "server",
            credential: SMBCredential(username: "user", password: "pass"),
            share: "share",
            path: "link"
        )

        XCTAssertEqual(reparsePoint.kind, .symlink)
        XCTAssertEqual(reparsePoint.substituteName, "\\??\\C:\\target.txt")
        XCTAssertEqual(reparsePoint.printName, "target.txt")
        XCTAssertEqual(try unframed(transport.outbound).count, 10)
    }

    func testSMBeeFacadeWithDirectoryStreamUsesTransportOverride() async throws {
        let fileId = hexBytes("00112233445566778899aabbccddeeff")
        let transport = SMBValidateNegotiateScriptTransport(inbound: try framed(authenticatedTreeResponses() + [
            smb2CreateResponse(fileId: fileId, messageId: 4, treeId: 0x3344),
            smb2QueryDirectoryResponse(entries: [
                makeDirectoryEntry(name: "a.txt", isDirectory: false, fileSize: 1, nextOffset: 0)
            ], messageId: 5, treeId: 0x3344),
            smb2StatusResponse(status: SMB2Status.noMoreFiles, command: SMB2Commands.queryDirectory, messageId: 6, treeId: 0x3344),
            smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.close, messageId: 7, treeId: 0x3344),
            smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.treeDisconnect, messageId: 8, treeId: 0x3344),
            smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.logoff, messageId: 9, treeId: 0)
        ]))
        SMBTransportTestOverride.factory = { transport }
        defer { SMBTransportTestOverride.factory = nil }

        let collector = TestDirectoryEntryCollector()
        try await SMBee.withDirectoryStream(
            host: "server",
            credential: SMBCredential(username: "user", password: "pass"),
            share: "share",
            path: ""
        ) { entry in
            collector.append(entry)
        }

        XCTAssertEqual(collector.entries.map(\.name), ["a.txt"])
    }

    func testSMBeeFacadeVolumeInfoUsesTransportOverride() async throws {
        let fileId = hexBytes("00112233445566778899aabbccddeeff")

        var fullSize = SMBByteWriter()
        fullSize.writeUInt64LE(1000)  // TotalAllocationUnits
        fullSize.writeUInt64LE(400)   // CallerAvailableAllocationUnits
        fullSize.writeUInt64LE(400)   // ActualAvailableAllocationUnits
        fullSize.writeUInt32LE(2)     // SectorsPerAllocationUnit
        fullSize.writeUInt32LE(512)   // BytesPerSector

        var attribute = SMBByteWriter()
        attribute.writeUInt32LE(0)    // FileSystemAttributes
        attribute.writeUInt32LE(255)  // MaximumComponentNameLength
        let fsName = NTLM.utf16le("NTFS")
        attribute.writeUInt32LE(UInt32(fsName.count))
        attribute.writeBytes(fsName)

        var volume = SMBByteWriter()
        volume.writeUInt64LE(0)             // VolumeCreationTime
        volume.writeUInt32LE(0x1234_5678)   // VolumeSerialNumber
        let label = NTLM.utf16le("VOL")
        volume.writeUInt32LE(UInt32(label.count))
        volume.writeUInt8(0)                // SupportsObjects
        volume.writeUInt8(0)                // Reserved
        volume.writeBytes(label)

        let transport = SMBValidateNegotiateScriptTransport(inbound: try framed(authenticatedTreeResponses() + [
            smb2CreateResponse(fileId: fileId, messageId: 4, treeId: 0x3344),
            smb2QueryInfoResponse(payload: fullSize.bytes, messageId: 5),
            smb2QueryInfoResponse(payload: attribute.bytes, messageId: 6),
            smb2QueryInfoResponse(payload: volume.bytes, messageId: 7),
            smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.close, messageId: 8, treeId: 0x3344),
            smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.treeDisconnect, messageId: 9, treeId: 0x3344),
            smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.logoff, messageId: 10, treeId: 0)
        ]))
        SMBTransportTestOverride.factory = { transport }
        defer { SMBTransportTestOverride.factory = nil }

        let info = try await SMBee.volumeInfo(
            host: "server",
            credential: SMBCredential(username: "user", password: "pass"),
            share: "share"
        )

        XCTAssertEqual(info.totalBytes, 1000 * 2 * 512)
        XCTAssertEqual(info.availableBytes, 400 * 2 * 512)
        XCTAssertEqual(info.filesystemName, "NTFS")
        XCTAssertEqual(info.volumeLabel, "VOL")
    }

    func testSMBeeFacadeUpdateMetadataUsesTransportOverride() async throws {
        let fileId = hexBytes("00112233445566778899aabbccddeeff")
        let transport = SMBValidateNegotiateScriptTransport(inbound: try framed(authenticatedTreeResponses() + [
            smb2CreateResponse(fileId: fileId, messageId: 4, treeId: 0x3344),
            smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.setInfo, messageId: 5, treeId: 0x3344),
            smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.close, messageId: 6, treeId: 0x3344),
            smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.treeDisconnect, messageId: 7, treeId: 0x3344),
            smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.logoff, messageId: 8, treeId: 0)
        ]))
        SMBTransportTestOverride.factory = { transport }
        defer { SMBTransportTestOverride.factory = nil }

        try await SMBee.updateMetadata(
            host: "server",
            credential: SMBCredential(username: "user", password: "pass"),
            share: "share",
            path: "file.txt",
            update: SMBFileMetadataUpdate(attributes: 0x20)
        )

        // NEGOTIATE + SESSION_SETUP x2 + TREE_CONNECT + VNI + CREATE + SET_INFO + CLOSE + teardown x2.
        // The count also covers the signed VNI request in this SMB 3.0.2 fixture.
        XCTAssertEqual(try unframed(transport.outbound).count, 10)
    }

    func testSMBeeFacadeSecurityInfoUsesTransportOverride() async throws {
        let fileId = hexBytes("00112233445566778899aabbccddeeff")
        let owner = sidBytes(authority: 5, subAuthorities: [32, 544])
        let group = sidBytes(authority: 5, subAuthorities: [32, 545])
        let everyone = sidBytes(authority: 1, subAuthorities: [0])
        let ace = aceBytes(type: 0, flags: 0, accessMask: 0x001f_01ff, sid: everyone)
        var acl = Array(repeating: UInt8(0), count: 8)
        acl[0] = 2  // AclRevision
    writeUInt16LE(UInt16(8 + ace.count), to: &acl, at: 2)  // AclSize
        writeUInt16LE(1, to: &acl, at: 4)  // AceCount
        acl.append(contentsOf: ace)

        let ownerOffset = 20  // self-relative SECURITY_DESCRIPTOR header size
        let groupOffset = ownerOffset + owner.count
        let daclOffset = groupOffset + group.count
        var sd = SMBByteWriter()
        sd.writeUInt8(1)          // Revision
        sd.writeUInt8(0)          // Sbz1
        sd.writeUInt16LE(0x8004)  // Control: SELF_RELATIVE | DACL_PRESENT
        sd.writeUInt32LE(UInt32(ownerOffset))
        sd.writeUInt32LE(UInt32(groupOffset))
        sd.writeUInt32LE(0)       // OffsetSacl
        sd.writeUInt32LE(UInt32(daclOffset))
        sd.writeBytes(owner)
        sd.writeBytes(group)
        sd.writeBytes(acl)

        let transport = SMBValidateNegotiateScriptTransport(inbound: try framed(authenticatedTreeResponses() + [
            smb2CreateResponse(fileId: fileId, messageId: 4, treeId: 0x3344),
            smb2QueryInfoResponse(payload: sd.bytes, messageId: 5),
            smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.close, messageId: 6, treeId: 0x3344),
            smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.treeDisconnect, messageId: 7, treeId: 0x3344),
            smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.logoff, messageId: 8, treeId: 0)
        ]))
        SMBTransportTestOverride.factory = { transport }
        defer { SMBTransportTestOverride.factory = nil }

        let info = try await SMBee.securityInfo(
            host: "server",
            credential: SMBCredential(username: "user", password: "pass"),
            share: "share",
            path: "file.txt"
        )

        XCTAssertEqual(info.ownerSID, "S-1-5-32-544")
        XCTAssertEqual(info.groupSID, "S-1-5-32-545")
        XCTAssertEqual(info.dacl?.count, 1)
    }

    func testSMB2HeaderRoundTrip() throws {
        let header = SMB2Header(
            creditCharge: 7,
            status: 0x1122_3344,
            command: 0,
            credits: 9,
            flags: 0x5566_7788,
            nextCommand: 0,
            messageId: 42,
            treeId: 0xaabb_ccdd,
            sessionId: 0x0102_0304_0506_0708,
            signature: Array(0..<16)
        )

        let encoded = try header.encode()
        XCTAssertEqual(encoded.count, 64)
        XCTAssertEqual(try SMB2Header.decode(encoded), header)
    }

    func testSMB2EchoRequestAndResponseShape() throws {
        let request = try SMB2Echo.encodeRequest(messageId: 21, sessionId: 0x1122_3344)

        let header = try SMB2Header.decode(request)
        XCTAssertEqual(header.command, SMB2Commands.echo)
        XCTAssertEqual(header.messageId, 21)
        XCTAssertEqual(header.sessionId, 0x1122_3344)
        XCTAssertEqual(readUInt16LE(request, at: 64), 4)
        XCTAssertEqual(readUInt16LE(request, at: 66), 0)

        var response = try SMB2Header(command: SMB2Commands.echo, messageId: 21, sessionId: 0x1122_3344).encode()
        response.append(contentsOf: [4, 0, 0, 0])
        XCTAssertNoThrow(try SMB2Echo.decodeResponse(response))
    }

    func testSetSecurityDescriptorOwnerGroupOnlyRequest() throws {
        // Owner/group-only write: AdditionalInformation = OWNER|GROUP (no DACL bit) and
        // the descriptor control flags must not claim DACLPresent.
        let fileId: [UInt8] = Array(repeating: 0xab, count: 16)
        let request = try SMB2SetInfo.encodeSecurityDescriptorRequest(
            messageId: 9,
            sessionId: 1,
            treeId: 2,
            fileId: fileId,
            ownerSID: "S-1-5-21-1-2-3-1000",
            groupSID: "S-1-5-21-1-2-3-513",
            dacl: nil
        )
        // AdditionalInformation offset: header(64) + StructureSize(2)+InfoType(1)+Class(1)+
        // BufferLength(4)+BufferOffset(2)+Reserved(2) = 76.
        XCTAssertEqual(
            readUInt32LE(request, at: 64 + 12),
            SMB2SetInfo.securityOwner | SMB2SetInfo.securityGroup
        )

        let descriptor = try SMB2SetInfo.encodeSecurityDescriptor(
            ownerSID: "S-1-5-21-1-2-3-1000",
            groupSID: nil,
            dacl: nil
        )
        XCTAssertEqual(readUInt16LE(descriptor, at: 2) & 0x0004, 0, "DACLPresent must not be set for owner-only descriptor")
        XCTAssertNotEqual(readUInt32LE(descriptor, at: 4), 0, "owner offset must be set")
        XCTAssertEqual(readUInt32LE(descriptor, at: 8), 0, "group offset must be zero")
        XCTAssertEqual(readUInt32LE(descriptor, at: 16), 0, "DACL offset must be zero")

        XCTAssertThrowsError(
            try SMB2SetInfo.encodeSecurityDescriptorRequest(
                messageId: 9, sessionId: 1, treeId: 2, fileId: fileId,
                ownerSID: nil, groupSID: nil, dacl: nil
            )
        )
    }

    func testSetSecurityCreateRequestAddsWriteOwnerAccess() throws {
        let daclOnly = SMB2CreateRequest.setSecurity(path: "f")
        XCTAssertEqual(daclOnly.desiredAccess, 0x0004_0000)
        let withOwner = SMB2CreateRequest.setSecurity(path: "f", includeOwner: true)
        XCTAssertEqual(withOwner.desiredAccess, 0x0004_0000 | 0x0008_0000)
    }

    func testEncoderRejectsOversizedVariableLengthFieldsInsteadOfTrapping() throws {
        // Regression for issues/011: a >64KiB name/path used to hit the trapping
        // UInt16(Int) initializer and crash the process instead of throwing.
        let hugeName = String(repeating: "a", count: 40_000)
        XCTAssertThrowsError(
            try SMB2Create.encodeRequest(
                messageId: 1,
                sessionId: 1,
                treeId: 1,
                request: .read(path: hugeName, directory: false)
            )
        ) { error in
            guard case SMBCodecError.invalidValue = error else {
                return XCTFail("expected SMBCodecError.invalidValue, got \(error)")
            }
        }

        var writer = SMBByteWriter()
        XCTAssertThrowsError(try writer.writeUInt16LE(count: 65_536, of: "test"))
        XCTAssertThrowsError(try writer.writeUInt16LE(count: -1, of: "test"))
        XCTAssertNoThrow(try writer.writeUInt16LE(count: 65_535, of: "test"))
    }

    func testSMB2LockRequestShape() throws {
        let fileId: [UInt8] = Array(1...16)
        let request = try SMB2Lock.encodeRequest(
            messageId: 30,
            sessionId: 0x1122_3344,
            treeId: 0x5566_7788,
            fileId: fileId,
            elements: [
                .lock(offset: 0x10, length: 0x20, shared: false, failImmediately: true),
                .unlock(offset: 0x30, length: 0x40)
            ]
        )

        let header = try SMB2Header.decode(request)
        XCTAssertEqual(header.command, SMB2Commands.lock)
        XCTAssertEqual(header.messageId, 30)
        XCTAssertEqual(header.treeId, 0x5566_7788)
        XCTAssertEqual(header.sessionId, 0x1122_3344)
        // header(64) + fixed(24) + 2 lock elements(24 each)
        XCTAssertEqual(request.count, 64 + 24 + 48)
        XCTAssertEqual(readUInt16LE(request, at: 64), 48)
        XCTAssertEqual(readUInt16LE(request, at: 66), 2)
        XCTAssertEqual(readUInt32LE(request, at: 68), 0)
        XCTAssertEqual(Array(request[72..<88]), fileId)
        XCTAssertEqual(readUInt64LE(request, at: 88), 0x10)
        XCTAssertEqual(readUInt64LE(request, at: 96), 0x20)
        XCTAssertEqual(
            readUInt32LE(request, at: 104),
            SMB2LockElement.exclusiveLock | SMB2LockElement.failImmediately
        )
        XCTAssertEqual(readUInt32LE(request, at: 108), 0)
        XCTAssertEqual(readUInt64LE(request, at: 112), 0x30)
        XCTAssertEqual(readUInt64LE(request, at: 120), 0x40)
        XCTAssertEqual(readUInt32LE(request, at: 128), SMB2LockElement.unlock)
    }

    func testSMB2LockRequestRejectsEmptyElements() {
        XCTAssertThrowsError(
            try SMB2Lock.encodeRequest(
                messageId: 1, sessionId: 1, treeId: 1, fileId: Array(repeating: 0, count: 16), elements: []
            )
        )
    }

    func testSMB2LockResponseDecodeAndConflictMapping() throws {
        var response = try SMB2Header(command: SMB2Commands.lock, messageId: 30, sessionId: 1).encode()
        response.append(contentsOf: [4, 0, 0, 0])
        XCTAssertNoThrow(try SMB2Lock.decodeResponse(response))

        for status in [SMB2Status.fileLockConflict, SMB2Status.lockNotGranted, SMB2Status.rangeNotLocked] {
            let error = SMBErrorMapper.map(status: status, operation: "LOCK")
            XCTAssertEqual(error, .lockConflict(status: status, operation: "LOCK"))
        }
    }

    func testSMB2CancelRequestShape() throws {
        let request = try SMB2Cancel.encodeRequest(
            target: .sync(messageId: 22),
            sessionId: 0x1122_3344
        )

        let header = try SMB2Header.decode(request)
        XCTAssertEqual(header.command, SMB2Commands.cancel)
        XCTAssertEqual(header.messageId, 22)
        // MS-SMB2 §2.2.1.2: sync CANCEL TreeId SHOULD be 0 (servers correlate by MessageId).
        XCTAssertEqual(header.treeId, 0)
        XCTAssertNil(header.asyncId)
        XCTAssertEqual(header.sessionId, 0x1122_3344)
        // CreditRequest stays at the encoder default and is never patched for CANCEL
        // (credit-exempt, MS-SMB2 §3.2.4.1.2).
        XCTAssertEqual(readUInt16LE(request, at: 14), 1)
        XCTAssertEqual(request.count, 68)
        XCTAssertEqual(readUInt16LE(request, at: 64), 4)
        XCTAssertEqual(readUInt16LE(request, at: 66), 0)
    }

    func testSMB2AsyncCancelRequestShape() throws {
        let request = try SMB2Cancel.encodeRequest(
            target: .async(messageId: 22, asyncId: 0x8899_aabb_ccdd_eeff),
            sessionId: 0x1122_3344
        )

        let header = try SMB2Header.decode(request)
        XCTAssertEqual(header.command, SMB2Commands.cancel)
        // Original MessageId is reused (MS-SMB2 §3.2.4.24 SHOULD; also keeps the SMB 3.1.1
        // AES-GMAC nonce unique per cancelled request, unlike a fixed MessageId of 0).
        XCTAssertEqual(header.messageId, 22)
        XCTAssertTrue(header.isAsync)
        XCTAssertEqual(header.asyncId, 0x8899_aabb_ccdd_eeff)
        XCTAssertEqual(header.treeId, 0)
        // Wire bytes 32-39 are the little-endian AsyncId.
        XCTAssertEqual(Array(request[32..<40]), [0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88])
        XCTAssertEqual(request.count, 68)
        XCTAssertEqual(readUInt16LE(request, at: 64), 4)
        XCTAssertEqual(readUInt16LE(request, at: 66), 0)
    }

    func testSMB2AsyncCancelRejectsZeroAsyncId() {
        XCTAssertThrowsError(try SMB2Cancel.encodeRequest(
            target: .async(messageId: 22, asyncId: 0),
            sessionId: 1
        ))
    }

    func testSMB2HeaderAsyncEncodeDecodeRoundTrip() throws {
        let header = SMB2Header.asyncHeader(
            status: SMB2Status.pending,
            command: SMB2Commands.changeNotify,
            messageId: 41,
            asyncId: 0x8899_aabb_0000_0007,
            sessionId: 9
        )
        let decoded = try SMB2Header.decode(header.encode())
        XCTAssertTrue(decoded.isAsync)
        XCTAssertEqual(decoded.asyncId, 0x8899_aabb_0000_0007)
        XCTAssertEqual(decoded.treeId, 0)
        XCTAssertEqual(decoded.messageId, 41)
    }

    func testSMB2HeaderRejectsInconsistentAsyncEncodings() {
        // Async flag without an AsyncId (the shape the old fixtures produced).
        XCTAssertThrowsError(try SMB2Header(
            command: SMB2Commands.flush,
            flags: SMB2Flags.asyncCommand,
            messageId: 1,
            treeId: 0x5566_7788
        ).encode())
        // Sync header carrying an AsyncId.
        XCTAssertThrowsError(try SMB2Header(
            command: SMB2Commands.flush,
            messageId: 1,
            asyncId: 7
        ).encode())
        // Async header carrying a TreeId.
        var header = SMB2Header.asyncHeader(command: SMB2Commands.flush, messageId: 1, asyncId: 7)
        header.treeId = 3
        XCTAssertThrowsError(try header.encode())
    }

    func testSMB2CreditChargeAndBalanceHelpers() {
        XCTAssertEqual(SMB2Credit.charge(forPayloadLength: 0), 1)
        XCTAssertEqual(SMB2Credit.charge(forPayloadLength: 65_536), 1)
        XCTAssertEqual(SMB2Credit.charge(forPayloadLength: 65_537), 2)
        XCTAssertEqual(SMB2Credit.charge(forPayloadLength: 131_072), 2)
        XCTAssertEqual(SMB2Credit.balanceAfterSending(current: 3, charge: 2), 1)
        XCTAssertEqual(SMB2Credit.balanceAfterSending(current: 1, charge: 2), 0)
        XCTAssertEqual(SMB2Credit.balanceAfterReceiving(current: 1, granted: 4), 5)
    }

    func testSMB2CreditWindowWaitsForGrant() async throws {
        let window = SMB2CreditWindow(initialCredits: 1, diagnosticSessionId: "test")

        let firstReserve = try await window.reserve(charge: 1)
        XCTAssertEqual(firstReserve, 0)
        let task = Task {
            try await window.reserve(charge: 2)
        }
        while await window.pendingWaiterCount == 0 {
            await Task.yield()
        }
        let balanceBeforeGrant = await window.balance
        XCTAssertEqual(balanceBeforeGrant, 0)

        let firstGrant = await window.grant(1)
        XCTAssertEqual(firstGrant, 1)
        await Task.yield()
        let balanceAfterPartialGrant = await window.balance
        XCTAssertEqual(balanceAfterPartialGrant, 1)

        let secondGrant = await window.grant(1)
        XCTAssertEqual(secondGrant, 0)
        let balanceAfterReserve = try await task.value
        XCTAssertEqual(balanceAfterReserve, 0)
        let finalBalance = await window.balance
        XCTAssertEqual(finalBalance, 0)
    }

    func testSMB2CreditWindowAccountsForChargeTwoGrant() async throws {
        let window = SMB2CreditWindow(initialCredits: 1, diagnosticSessionId: "test")

        let parked = Task { try await window.reserve(charge: 2) }
        while await window.pendingWaiterCount == 0 {
            await Task.yield()
        }
        let balanceBeforeGrant = await window.balance
        XCTAssertEqual(balanceBeforeGrant, 1)

        let balanceAfterGrant = await window.grant(2)
        XCTAssertEqual(balanceAfterGrant, 1)
        let parkedBalance = try await parked.value
        XCTAssertEqual(parkedBalance, 1)
        let balanceAfterSecondReserve = try await window.reserve(charge: 1)
        XCTAssertEqual(balanceAfterSecondReserve, 0)
    }

    func testSMB2CreditWindowReserveIsCancellable() async throws {
        let window = SMB2CreditWindow(initialCredits: 0, diagnosticSessionId: "test")
        let task = Task {
            try await window.reserve(charge: 1)
        }
        while await window.pendingWaiterCount == 0 {
            await Task.yield()
        }
        task.cancel()
        do {
            _ = try await awaitWithTimeout("cancelled reserve") { try await task.value }
            XCTFail("cancelled reserve unexpectedly returned")
        } catch is CancellationError {
        }
        let waiters = await window.pendingWaiterCount
        XCTAssertEqual(waiters, 0)
    }

    func testLSARPCLookupSidsRequestShape() throws {
        let handle = Array(repeating: UInt8(0x11), count: 20)
        let stub = try LSARPC.encodeLookupSidsRequest(handle: handle, sids: ["S-1-1-0"])
        XCTAssertEqual(Array(stub[0..<20]), handle)
        XCTAssertEqual(readUInt32LE(stub, at: 20), 1) // Entries
        XCTAssertNotEqual(readUInt32LE(stub, at: 24), 0) // SidInfo pointer
        XCTAssertEqual(readUInt32LE(stub, at: 28), 1) // conformant count
        XCTAssertNotEqual(readUInt32LE(stub, at: 32), 0) // per-SID pointer
        XCTAssertEqual(readUInt32LE(stub, at: 36), 1) // SID conformant count = sub-authority count
        XCTAssertEqual(Array(stub[40..<52]), try SMB2SetInfo.encodeSID("S-1-1-0"))
        // trailer: TranslatedNames {0, NULL}, LookupLevel=1 (+pad), MappedCount=0
        XCTAssertEqual(readUInt32LE(stub, at: 52), 0)
        XCTAssertEqual(readUInt32LE(stub, at: 56), 0)
        XCTAssertEqual(readUInt16LE(stub, at: 60), 1)
        XCTAssertEqual(readUInt32LE(stub, at: 64), 0)
        XCTAssertEqual(stub.count, 68)
    }

    func testLSARPCLookupSidsResponseDecode() throws {
        // Handcrafted MS-LSAT response: one referenced domain ("WORKGROUP"),
        // two translated names: mapped user "alice" (use=1) and unmapped (use=8).
        var writer = NDRWriter()
        writer.writeUInt32(0x0002_0000) // ReferencedDomains pointer
        writer.writeUInt32(1) // Entries
        writer.writeUInt32(0x0002_0004) // Domains array pointer
        writer.writeUInt32(32) // MaxEntries
        writer.writeUInt32(1) // conformant count
        let domain = Array("WORKGROUP".utf16)
        writer.writeUInt16(UInt16(domain.count * 2)) // Name.Length
        writer.writeUInt16(UInt16(domain.count * 2)) // Name.MaximumLength
        writer.writeUInt32(0x0002_0008) // Name.Buffer pointer
        writer.writeUInt32(0x0002_000c) // Sid pointer
        // deferred: domain name buffer
        writer.writeUInt32(UInt32(domain.count))
        writer.writeUInt32(0)
        writer.writeUInt32(UInt32(domain.count))
        for unit in domain { writer.writeUInt16(unit) }
        if domain.count % 2 != 0 { writer.writeUInt16(0) } // align to 4
        // deferred: domain SID S-1-5-21-1-2-3 (3 sub-authorities... use 4 to stay aligned)
        let domainSid = try SMB2SetInfo.encodeSID("S-1-5-21-1-2-3")
        writer.writeUInt32(UInt32(domainSid[1]))
        writer.writeBytes(domainSid)
        // TranslatedNames
        writer.writeUInt32(2) // Entries
        writer.writeUInt32(0x0002_0010) // Names pointer
        writer.writeUInt32(2) // conformant count
        let alice = Array("alice".utf16)
        writer.writeUInt16(1) // Use = SidTypeUser
        writer.writeUInt16(0) // struct padding
        writer.writeUInt16(UInt16(alice.count * 2))
        writer.writeUInt16(UInt16(alice.count * 2))
        writer.writeUInt32(0x0002_0014)
        writer.writeUInt32(0) // DomainIndex
        writer.writeUInt16(8) // Use = SidTypeUnknown
        writer.writeUInt16(0)
        writer.writeUInt16(0)
        writer.writeUInt16(0)
        writer.writeUInt32(0) // Name.Buffer NULL
        writer.writeUInt32(0xffff_ffff) // DomainIndex -1
        // deferred: alice buffer
        writer.writeUInt32(UInt32(alice.count))
        writer.writeUInt32(0)
        writer.writeUInt32(UInt32(alice.count))
        for unit in alice { writer.writeUInt16(unit) }
        if alice.count % 2 != 0 { writer.writeUInt16(0) }
        writer.writeUInt32(1) // MappedCount
        writer.writeUInt32(LSARPC.statusSomeNotMapped)

        let names = try LSARPC.decodeLookupSidsResponse(writer.bytes)
        XCTAssertEqual(names.count, 2)
        XCTAssertEqual(names[0], SMBResolvedSIDName(use: 1, domain: "WORKGROUP", name: "alice"))
        XCTAssertEqual(names[0]?.qualifiedName, "WORKGROUP\\alice")
        XCTAssertNil(names[1])
    }

    func testSparseSessionOperationsDriveFsctlsOverTransport() async throws {
        let fileId = hexBytes("00112233445566778899aabbccddeeff")
        var allocated = SMBByteWriter()
        allocated.writeUInt64LE(0)
        allocated.writeUInt64LE(64 * 1024)
        let transport = SMBValidateNegotiateScriptTransport(inbound: try framed(authenticatedTreeResponses(credential: .anonymous) + [
            // setSparse: create, ioctl(SET_SPARSE), close
            smb2CreateResponse(fileId: fileId, messageId: 4, treeId: 0x3344),
            smb2IoctlResponse(output: [], status: SMB2Status.success, messageId: 5, treeId: 0x3344, fileId: fileId, ctlCode: SMB2Ioctl.fsctlSetSparse),
            smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.close, messageId: 6, treeId: 0x3344),
            // zeroRange: create, ioctl(SET_ZERO_DATA), close
            smb2CreateResponse(fileId: fileId, messageId: 7, treeId: 0x3344),
            smb2IoctlResponse(output: [], status: SMB2Status.success, messageId: 8, treeId: 0x3344, fileId: fileId, ctlCode: SMB2Ioctl.fsctlSetZeroData),
            smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.close, messageId: 9, treeId: 0x3344),
            // allocatedRanges: create, ioctl(QUERY_ALLOCATED_RANGES), close
            smb2CreateResponse(fileId: fileId, messageId: 10, treeId: 0x3344),
            smb2IoctlResponse(output: allocated.bytes, status: SMB2Status.success, messageId: 11, treeId: 0x3344, fileId: fileId, ctlCode: SMB2Ioctl.fsctlQueryAllocatedRanges),
            smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.close, messageId: 12, treeId: 0x3344)
        ]))
        SMBTransportTestOverride.factory = { transport }
        defer { SMBTransportTestOverride.factory = nil }

        let session = try await SMBee.connect(host: "server", credential: .anonymous, share: "share")
        try await session.setSparse(path: "vm.img")
        try await session.zeroRange(path: "vm.img", offset: 64 * 1024, length: 64 * 1024)
        let ranges = try await session.allocatedRanges(path: "vm.img", length: 256 * 1024)
        XCTAssertEqual(ranges, [SMBAllocatedRange(offset: 0, length: 64 * 1024)])

        let requests = try unframed(transport.outbound)
        let ioctlCodes = requests.compactMap { request -> UInt32? in
            guard (try? SMB2Header.decode(request))?.command == SMB2Commands.ioctl else { return nil }
            return readUInt32LE(request, at: 68)
        }
        XCTAssertEqual(ioctlCodes, [
            SMB2Ioctl.fsctlSetSparse,
            SMB2Ioctl.fsctlSetZeroData,
            SMB2Ioctl.fsctlQueryAllocatedRanges
        ])
    }

    func testSparseFileFsctlCodecs() throws {
        XCTAssertEqual(SMB2SparseFile.encodeSetSparseInput(true), [1])
        XCTAssertEqual(SMB2SparseFile.encodeSetSparseInput(false), [0])

        let zero = try SMB2SparseFile.encodeSetZeroDataInput(offset: 0x10, length: 0x20)
        XCTAssertEqual(readUInt64LE(zero, at: 0), 0x10) // FileOffset
        XCTAssertEqual(readUInt64LE(zero, at: 8), 0x30) // BeyondFinalZero = offset + length
        XCTAssertThrowsError(try SMB2SparseFile.encodeSetZeroDataInput(offset: .max, length: 1))

        let query = SMB2SparseFile.encodeQueryAllocatedRangesInput(offset: 0, length: 0x1000)
        XCTAssertEqual(readUInt64LE(query, at: 0), 0)
        XCTAssertEqual(readUInt64LE(query, at: 8), 0x1000)
    }

    func testSparseFileAllocatedRangesDecode() throws {
        XCTAssertEqual(try SMB2SparseFile.decodeAllocatedRanges([]), [])

        var writer = SMBByteWriter()
        writer.writeUInt64LE(0)
        writer.writeUInt64LE(4096)
        writer.writeUInt64LE(8192)
        writer.writeUInt64LE(4096)
        XCTAssertEqual(try SMB2SparseFile.decodeAllocatedRanges(writer.bytes), [
            SMBAllocatedRange(offset: 0, length: 4096),
            SMBAllocatedRange(offset: 8192, length: 4096)
        ])

        XCTAssertThrowsError(try SMB2SparseFile.decodeAllocatedRanges([0, 1, 2]))
    }

    func testLSARPCOpenPolicyAndCloseCodecs() throws {
        let stub = LSARPC.encodeOpenPolicy2Request()
        XCTAssertEqual(stub.count, 32)
        XCTAssertEqual(readUInt32LE(stub, at: 0), 0) // SystemName NULL
        XCTAssertEqual(readUInt32LE(stub, at: 4), 24) // ObjectAttributes.Length
        XCTAssertEqual(readUInt32LE(stub, at: 28), LSARPC.policyLookupNames)

        let handle = Array(repeating: UInt8(0x22), count: 20)
        var response = handle
        response.append(contentsOf: [0, 0, 0, 0]) // status success
        XCTAssertEqual(try LSARPC.decodePolicyHandleResponse(response, operation: "LsarOpenPolicy2"), handle)

        var denied = handle
        denied.append(contentsOf: [0x22, 0x00, 0x00, 0xc0]) // STATUS_ACCESS_DENIED
        XCTAssertThrowsError(try LSARPC.decodePolicyHandleResponse(denied, operation: "LsarOpenPolicy2")) { error in
            guard case SMBError.accessDenied = error else {
                return XCTFail("expected accessDenied, got \(error)")
            }
        }

        XCTAssertEqual(try LSARPC.encodeCloseRequest(handle: handle), handle)
        XCTAssertThrowsError(try LSARPC.encodeCloseRequest(handle: [1, 2, 3]))
        XCTAssertThrowsError(try LSARPC.encodeLookupSidsRequest(handle: handle, sids: []))
    }

    func testLSARPCLookupSidsResponseWithoutDomainsDecodesUnmapped() throws {
        // STATUS_NONE_MAPPED with NULL domains and NULL names array.
        var writer = NDRWriter()
        writer.writeUInt32(0) // ReferencedDomains NULL
        writer.writeUInt32(0) // TranslatedNames.Entries
        writer.writeUInt32(0) // TranslatedNames.Names NULL
        writer.writeUInt32(0) // MappedCount
        writer.writeUInt32(LSARPC.statusNoneMapped)
        let names = try LSARPC.decodeLookupSidsResponse(writer.bytes)
        XCTAssertTrue(names.isEmpty)

        var failed = NDRWriter()
        failed.writeUInt32(0)
        failed.writeUInt32(0)
        failed.writeUInt32(0)
        failed.writeUInt32(0)
        failed.writeUInt32(0xc000_0022) // STATUS_ACCESS_DENIED
        XCTAssertThrowsError(try LSARPC.decodeLookupSidsResponse(failed.bytes))
    }

    func testResolvedSIDNameQualifiedNameFallsBackWithoutDomain() {
        XCTAssertEqual(SMBResolvedSIDName(use: 1, domain: nil, name: "alice").qualifiedName, "alice")
        XCTAssertEqual(SMBResolvedSIDName(use: 1, domain: "", name: "alice").qualifiedName, "alice")
    }

    func testTransferVerificationLocalSHA256MatchesEmptyAndKnownVectors() throws {
        let dir = FileManager.default.temporaryDirectory
        let empty = dir.appendingPathComponent("smbee-empty-\(UUID().uuidString)")
        try Data().write(to: empty)
        defer { try? FileManager.default.removeItem(at: empty) }
        // SHA-256("") NIST vector.
        XCTAssertEqual(
            try SMBTransferVerification.localSHA256Hex(fileURL: empty),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        )

        // Multi-MiB file to exercise the streaming read loop (>1 chunk).
        let big = dir.appendingPathComponent("smbee-big-\(UUID().uuidString)")
        try Data(repeating: 0x5a, count: 3 * 1024 * 1024 + 7).write(to: big)
        defer { try? FileManager.default.removeItem(at: big) }
        XCTAssertEqual(try SMBTransferVerification.localSHA256Hex(fileURL: big).count, 64)
    }

    func testLookupSIDsEmptyInputShortCircuits() async throws {
        // No SIDs must not open a connection; returns [] without touching the transport.
        let empty = try await SMBee.lookupSIDs(
            host: "unused",
            credential: SMBCredential(username: "u", password: "p"),
            sids: []
        )
        XCTAssertTrue(empty.isEmpty)
    }

    func testSMB2CreditWindowFailAllWaitersDrainsParkedReserves() async throws {
        let window = SMB2CreditWindow(initialCredits: 0, diagnosticSessionId: "test")
        let task = Task {
            try await window.reserve(charge: 1)
        }
        while await window.pendingWaiterCount == 0 {
            await Task.yield()
        }
        await window.failAllWaiters(SMBTransportError.connectionClosed)
        do {
            _ = try await awaitWithTimeout("drained reserve") { try await task.value }
            XCTFail("drained reserve unexpectedly returned")
        } catch let error as SMBTransportError {
            XCTAssertEqual(error, .connectionClosed)
        }
        let waiters = await window.pendingWaiterCount
        XCTAssertEqual(waiters, 0)

        do {
            _ = try await window.reserve(charge: 1)
            XCTFail("reserve unexpectedly succeeded after failure")
        } catch let error as SMBTransportError {
            XCTAssertEqual(error, .connectionClosed)
        }
        let balance = await window.balance
        XCTAssertEqual(balance, 0)
        _ = await window.grant(10)
        let balanceAfterGrant = await window.balance
        XCTAssertEqual(balanceAfterGrant, 0)
        _ = await window.refund(charge: 1)
        let balanceAfterRefund = await window.balance
        XCTAssertEqual(balanceAfterRefund, 0)

        await window.failAllWaiters(SMBTransportError.connectionClosed)
    }

    func testSMB2CreditWindowResetReactivatesWindowAndOldFailureCanWinRace() async throws {
        let window = SMB2CreditWindow(initialCredits: 0, diagnosticSessionId: "test")
        let parked = Task { try await window.reserve(charge: 1) }
        while await window.pendingWaiterCount == 0 { await Task.yield() }

        await window.failAllWaiters(SMBTransportError.connectionClosed)
        _ = try? await parked.value
        await window.reset(initialCredits: 2)
        let reserveAfterReset = try await window.reserve(charge: 1)
        XCTAssertEqual(reserveAfterReset, 1)

        // The window does not identify connection generations: a delayed old event
        // transitions the reset window back to failed, as specified.
        await window.failAllWaiters(SMBTransportError.connectionClosed)
        do {
            _ = try await window.reserve(charge: 1)
            XCTFail("reserve unexpectedly succeeded after delayed failure")
        } catch is SMBTransportError {
        }
    }

    func testSMB2CreditWindowDoesNotConsumeZeroChargeRequests() async throws {
        let window = SMB2CreditWindow(initialCredits: 1, diagnosticSessionId: "test")

        let reserve = try await window.reserve(charge: 0)
        XCTAssertEqual(reserve, 1)
        let balance = await window.balance
        XCTAssertEqual(balance, 1)
        let refund = await window.refund(charge: 0)
        XCTAssertEqual(refund, 1)
        let grant = await window.grant(2)
        XCTAssertEqual(grant, 3)
    }

    func testMD4RFC1320Vectors() {
        XCTAssertEqual(hex(MD4.hash([])), "31d6cfe0d16ae931b73c59d7e0c089c0")
        XCTAssertEqual(hex(MD4.hash(Array("a".utf8))), "bde52cb31de33e46245e05fbdbd6fb24")
        XCTAssertEqual(hex(MD4.hash(Array("abc".utf8))), "a448017aaf21d8525fc10ae87aa6729d")
        XCTAssertEqual(hex(MD4.hash(Array("message digest".utf8))), "d9130a8164549fe818874806e1c7014b")
    }

    func testHMACAndSHAUsingSwiftCryptoVectors() {
        let hmacMD5 = HMAC<Insecure.MD5>.authenticationCode(
            for: Array("Hi There".utf8),
            using: SymmetricKey(data: Array(repeating: 0x0b, count: 16))
        )
        XCTAssertEqual(hex(Array(hmacMD5)), "9294727a3638bb1c13f48ef8158bfc9d")

        let hmacSHA256 = SMBCrypto.hmacSHA256(
            key: Array(repeating: 0x0b, count: 20),
            message: Array("Hi There".utf8)
        )
        XCTAssertEqual(
            hex(hmacSHA256),
            "b0344c61d8db38535ca8afceaf0bf12b"
                + "881dc200c9833da726e9376c2e32cff7"
        )

        XCTAssertEqual(
            hex(SMBCrypto.sha512(Array("abc".utf8))),
            "ddaf35a193617abacc417349ae204131"
                + "12e6fa4e89a97ea20a9eeee64b55d39a"
                + "2192992a274fc1a836ba3c23a3feebbd"
                + "454d4423643ce80e2a9ac94fa54ca49f"
        )
    }

    func testRC4KnownVectors() {
        XCTAssertEqual(hex(RC4.crypt(key: Array("Key".utf8), message: Array("Plaintext".utf8))), "bbf316e8d940af0ad3")
        XCTAssertEqual(hex(RC4.crypt(key: Array("Wiki".utf8), message: Array("pedia".utf8))), "1021bf0420")
    }

    func testAESGCMAndGMACNISTVectors() throws {
        let key = Array(repeating: UInt8(0), count: 16)
        let nonce = Array(repeating: UInt8(0), count: 12)
        let gcm = try SMBCrypto.aesGCMSeal(key: key, nonce: nonce, plaintext: [], authenticatedData: [])
        XCTAssertEqual(gcm.ciphertext, [])
        XCTAssertEqual(hex(gcm.tag), "58e2fccefa7e3061367f1d57a4e7455a")

        let gmac = try SMBCrypto.aesGMAC(key: key, nonce: nonce, authenticatedData: [])
        XCTAssertEqual(hex(gmac), "58e2fccefa7e3061367f1d57a4e7455a")
    }

    func testSMB311GMACSigningNonceUsesMessageIdAndSenderFlags() {
        XCTAssertEqual(
            hex(SMBSessionSigning.gmacNonce(messageId: 0x0102_0304_0506_0708, command: SMB2Commands.read, sender: .client)),
            "080706050403020100000000"
        )
        XCTAssertEqual(
            hex(SMBSessionSigning.gmacNonce(messageId: 0x0102_0304_0506_0708, command: SMB2Commands.read, sender: .server)),
            "080706050403020101000000"
        )
        XCTAssertEqual(
            hex(SMBSessionSigning.gmacNonce(messageId: 0x0102_0304_0506_0708, command: SMB2Commands.cancel, sender: .client)),
            "080706050403020102000000"
        )
    }

    func testDCERPCBindEncodesSrvsvcPresentationContext() throws {
        let bind = try DCERPC.encodeBind(callId: 1, abstractSyntax: SRVSVC.interfaceUUID, abstractVersion: SRVSVC.interfaceVersion)

        XCTAssertEqual(bind[0], 5)
        XCTAssertEqual(bind[2], DCERPC.pduTypeBind)
        XCTAssertEqual(readUInt16LE(bind, at: 8), UInt16(bind.count))
        XCTAssertEqual(readUInt32LE(bind, at: 12), 1)
        XCTAssertEqual(readUInt16LE(bind, at: 16), 4_280)
        XCTAssertEqual(readUInt16LE(bind, at: 18), 4_280)
        XCTAssertEqual(bind[24], 1)
        XCTAssertEqual(hex(Array(bind[32..<48])), "c84f324b7016d30112785a47bf6ee188")
        XCTAssertEqual(readUInt32LE(bind, at: 48), 3)
        XCTAssertEqual(hex(Array(bind[52..<68])), "045d888aeb1cc9119fe808002b104860")
        XCTAssertEqual(readUInt32LE(bind, at: 68), 2)
    }

    func testDCERPCBindAckAcceptsAcceptedContext() throws {
        var ack: [UInt8] = [
            0x05, 0x00, DCERPC.pduTypeBindAck, 0x03,
            0x10, 0x00, 0x00, 0x00,
            0x44, 0x00, 0x00, 0x00,
            0x01, 0x00, 0x00, 0x00
        ]
        ack.append(contentsOf: [
            0xb8, 0x10, 0xb8, 0x10, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00,
            0x00, 0x00,
            0x01, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00
        ])
        ack.append(contentsOf: hexBytes("045d888aeb1cc9119fe808002b104860"))
        ack.append(contentsOf: [0x02, 0x00, 0x00, 0x00])
    writeUInt16LE(UInt16(ack.count), to: &ack, at: 8)

        XCTAssertNoThrow(try DCERPC.decodeBindAck(ack))
    }

    func testDCERPCResponseStubUsesFragmentLengthWhenAllocHintIsLarger() throws {
        var response: [UInt8] = [
            0x05, 0x00, DCERPC.pduTypeResponse, 0x03,
            0x10, 0x00, 0x00, 0x00,
            0x1c, 0x00, 0x00, 0x00,
            0x02, 0x00, 0x00, 0x00
        ]
        appendUInt32LE(64, to: &response)
        appendUInt16LE(0, to: &response)
        appendUInt16LE(0, to: &response)
        response.append(contentsOf: [0xaa, 0xbb, 0xcc, 0xdd])

        XCTAssertEqual(try DCERPC.decodeResponseStub(response), [0xaa, 0xbb, 0xcc, 0xdd])
    }

    func testDCERPCResponseStubReassemblesMultipleFragments() throws {
        let stub = makeShareEnumStub([
            ("public", 0, "Public share"),
            ("IPC$", 0x8000_0000, "Remote IPC"),
            ("media", 0, "Media share")
        ])
        let split = stub.count / 2
        let response = try dcerpcResponsePDU(stub: Array(stub[..<split]), flags: DCERPC.pfcFirstFrag)
            + dcerpcResponsePDU(stub: Array(stub[split...]), flags: DCERPC.pfcLastFrag)

        let shares = try SRVSVC.decodeNetrShareEnumResponse(try DCERPC.decodeResponseStub(response))

        XCTAssertEqual(shares.map(\.name), ["public", "IPC$", "media"])
    }

    func testSRVSVCNetrShareEnumRequestUsesLevel1() {
        let request = SRVSVC.encodeNetrShareEnumRequest()

        XCTAssertEqual(request.count, 32)
        XCTAssertEqual(readUInt32LE(request, at: 0), 0) // ServerName ptr NULL
        XCTAssertEqual(readUInt32LE(request, at: 4), 1) // Level
        XCTAssertEqual(readUInt32LE(request, at: 8), 1) // union discriminant
        XCTAssertNotEqual(readUInt32LE(request, at: 12), 0) // container referent (non-NULL, さもないと WERR 87)
        XCTAssertEqual(readUInt32LE(request, at: 16), 0) // EntriesRead
        XCTAssertEqual(readUInt32LE(request, at: 20), 0) // Buffer ptr NULL
        XCTAssertEqual(readUInt32LE(request, at: 24), 0xffff_ffff) // PreferMaximumLength
        XCTAssertEqual(readUInt32LE(request, at: 28), 0) // ResumeHandle ptr NULL
    }

    func testSRVSVCNetrShareEnumResponseDecodesShareInfo1() throws {
        var stub: [UInt8] = []
        appendUInt32LE(1, to: &stub) // level
        appendUInt32LE(1, to: &stub) // discriminant
        appendUInt32LE(0x0002_0000, to: &stub) // SHARE_INFO_1_CONTAINER referent
        appendUInt32LE(2, to: &stub) // entries read
        appendUInt32LE(0x0002_0001, to: &stub) // buffer referent
        appendUInt32LE(2, to: &stub) // conformant array count
        appendUInt32LE(0x0002_0002, to: &stub)
        appendUInt32LE(0, to: &stub)
        appendUInt32LE(0x0002_0003, to: &stub)
        appendUInt32LE(0x0002_0004, to: &stub)
        appendUInt32LE(0x8000_0000, to: &stub)
        appendUInt32LE(0x0002_0005, to: &stub)
        appendNDRString("public", to: &stub)
        appendNDRString("Public share", to: &stub)
        appendNDRString("IPC$", to: &stub)
        appendNDRString("Remote IPC", to: &stub)
        appendUInt32LE(2, to: &stub) // total entries
        appendUInt32LE(0, to: &stub) // resume handle null
        appendUInt32LE(0, to: &stub) // status

        let shares = try SRVSVC.decodeNetrShareEnumResponse(stub)

        XCTAssertEqual(shares, [
            SMBShareInfo(name: "public", type: 0, comment: "Public share"),
            SMBShareInfo(name: "IPC$", type: 0x8000_0000, comment: "Remote IPC")
        ])
    }

    func testSMB2IoctlPipeTransceiveRequestEncodesInputBuffer() throws {
        let fileId = (0x10...0x1f).map(UInt8.init)
        let input: [UInt8] = [0xaa, 0xbb, 0xcc]
        let request = try SMB2Ioctl.encodeRequest(
            messageId: 9,
            sessionId: 0x1122,
            treeId: 0x3344,
            fileId: fileId,
            ctlCode: SMB2Ioctl.fsctlPipeTransceive,
            input: input,
            maxOutputResponse: 65_536
        )

        XCTAssertEqual(readUInt16LE(request, at: 64), 57)
        XCTAssertEqual(readUInt32LE(request, at: 68), SMB2Ioctl.fsctlPipeTransceive)
        XCTAssertEqual(Array(request[72..<88]), fileId)
        XCTAssertEqual(readUInt32LE(request, at: 88), 120)
        XCTAssertEqual(readUInt32LE(request, at: 92), UInt32(input.count))
        XCTAssertEqual(readUInt32LE(request, at: 108), 65_536)
        XCTAssertEqual(readUInt32LE(request, at: 112), 1)
        XCTAssertEqual(Array(request[120..<123]), input)
    }

    func testSMB2IoctlResponseDecodesOutputBuffer() throws {
        let fileId = (0x20...0x2f).map(UInt8.init)
        let output: [UInt8] = [0xde, 0xad, 0xbe, 0xef]
        var response = try SMB2Header(command: SMB2Commands.ioctl, messageId: 9, treeId: 0x3344, sessionId: 0x1122).encode()
        response.append(contentsOf: Array(repeating: 0, count: 56))
        writeUInt16LE(49, to: &response, at: 64)
        writeUInt32LE(SMB2Ioctl.fsctlPipeTransceive, to: &response, at: 68)
        response.replaceSubrange(72..<88, with: fileId)
        writeUInt32LE(120, to: &response, at: 96)
        writeUInt32LE(UInt32(output.count), to: &response, at: 100)
        response.append(contentsOf: output)

        XCTAssertEqual(try SMB2Ioctl.decodeResponse(response), output)
    }

    func testSMB2ReparsePointDecodesSymbolicLinkBuffer() throws {
        let reparsePoint = try SMB2ReparsePoint.decode(
            reparseSymlinkBuffer(substituteName: "\\??\\C:\\target.txt", printName: "target.txt", flags: 1)
        )

        XCTAssertEqual(reparsePoint.tag, SMBReparseTags.symlink)
        XCTAssertEqual(reparsePoint.kind, .symlink)
        XCTAssertEqual(reparsePoint.substituteName, "\\??\\C:\\target.txt")
        XCTAssertEqual(reparsePoint.printName, "target.txt")
        XCTAssertEqual(reparsePoint.flags, 1)
    }

    func testSMB2ReparsePointDecodesMountPointBuffer() throws {
        let reparsePoint = try SMB2ReparsePoint.decode(
            reparseMountPointBuffer(substituteName: "\\??\\C:\\target", printName: "target")
        )

        XCTAssertEqual(reparsePoint.tag, SMBReparseTags.mountPoint)
        XCTAssertEqual(reparsePoint.kind, .mountPoint)
        XCTAssertEqual(reparsePoint.substituteName, "\\??\\C:\\target")
        XCTAssertEqual(reparsePoint.printName, "target")
        XCTAssertNil(reparsePoint.flags)
    }

    func testSMB2ReparsePointDecodesLxSymlinkBuffer() throws {
        // REPARSE_DATA_BUFFER: tag + dataLength + reserved, then Version(=2) + UTF-8 target.
        let target = Array("../relative/target".utf8)
        var writer = SMBByteWriter()
        writer.writeUInt32LE(SMBReparseTags.lxSymlink)
        writer.writeUInt16LE(UInt16(4 + target.count))
        writer.writeUInt16LE(0)
        writer.writeUInt32LE(2)
        writer.writeBytes(target)

        let reparsePoint = try SMB2ReparsePoint.decode(writer.bytes)
        XCTAssertEqual(reparsePoint.kind, .lxSymlink)
        XCTAssertEqual(reparsePoint.substituteName, "../relative/target")
        XCTAssertNil(reparsePoint.printName)
    }

    func testSMB2ReparsePointKeepsDfsAndNfsDataOpaque() throws {
        // MS-FSCC: DFS/NFS reparse data is server-side only; clients treat it as opaque.
        for tag in [SMBReparseTags.dfs, SMBReparseTags.nfs] {
            var writer = SMBByteWriter()
            writer.writeUInt32LE(tag)
            writer.writeUInt16LE(4)
            writer.writeUInt16LE(0)
            writer.writeBytes([0xde, 0xad, 0xbe, 0xef])

            let reparsePoint = try SMB2ReparsePoint.decode(writer.bytes)
            XCTAssertEqual(reparsePoint.tag, tag)
            XCTAssertNil(reparsePoint.substituteName)
            XCTAssertEqual(reparsePoint.rawData, [0xde, 0xad, 0xbe, 0xef])
        }
        XCTAssertEqual(SMBReparseTags.nfs, 0x8000_0014)
        XCTAssertEqual(SMBReparseKind(tag: 0x8000_0014), .nfs)
    }

    func testSMB2DfsReferralRequestInputEncodesMaxLevelAndNullTerminatedPath() throws {
        let input = SMB2DfsReferral.encodeRequestInput(path: "\\\\server\\dfsroot\\link", maxLevel: 4)

        XCTAssertEqual(readUInt16LE(input, at: 0), 4)
        XCTAssertEqual(Array(input[2..<input.count - 2]), NTLM.utf16le("\\\\server\\dfsroot\\link"))
        XCTAssertEqual(Array(input[(input.count - 2)..<input.count]), [0, 0])
    }

    func testDfsTargetParsesUncShareAddress() throws {
        let target = try SMBClient.dfsTarget(from: "\\\\target.example\\public")
        XCTAssertEqual(target.host, "target.example")
        XCTAssertEqual(target.share, "public")
        XCTAssertThrowsError(try SMBClient.dfsTarget(from: "not-a-unc-target"))
    }

    func testDfsReferralCacheHonorsTTL() async throws {
        let cache = SMBDfsReferralCache()
        let credential = SMBCredential(username: "user", password: "pass", domain: "DOMAIN")
        let key = SMBDfsReferralCache.Key(host: "SERVER", port: 445, path: "\\\\server\\dfsroot\\link", credential: credential)
        let referral = SMBDfsReferralResult(pathConsumed: 0, headerFlags: 0, referrals: [])

        await cache.put(referral, for: key, ttl: 1)
        let cached = await cache.get(key)
        XCTAssertEqual(cached?.pathConsumed, 0)

        await cache.put(referral, for: key, ttl: 0)
        let expired = await cache.get(key)
        XCTAssertNil(expired)
    }

    func testDfsReferralCacheKeySeparatesCredentialIdentities() {
        let path = "\\\\server\\dfsroot\\link"
        let passwordCredential = SMBCredential(username: "user", password: "pass", domain: "DOMAIN")
        let otherUser = SMBCredential(username: "other", password: "pass", domain: "DOMAIN")
        let ntHashCredential = try? SMBCredential(username: "user", ntHash: Array(repeating: 0x11, count: 16), domain: "DOMAIN")

        let passwordKey = SMBDfsReferralCache.Key(host: "server", port: 445, path: path, credential: passwordCredential)
        XCTAssertNotEqual(passwordKey, SMBDfsReferralCache.Key(host: "server", port: 445, path: path, credential: otherUser))
        XCTAssertNotEqual(passwordKey, SMBDfsReferralCache.Key(host: "server", port: 445, path: path, credential: ntHashCredential!))
    }

    func testDfsReferralCacheBoundsEntryCount() async throws {
        let cache = SMBDfsReferralCache(maximumEntries: 1)
        let credential = SMBCredential(username: "user", password: "pass")
        let first = SMBDfsReferralCache.Key(host: "server", port: 445, path: "\\\\server\\dfsroot\\one", credential: credential)
        let second = SMBDfsReferralCache.Key(host: "server", port: 445, path: "\\\\server\\dfsroot\\two", credential: credential)
        let referral = SMBDfsReferralResult(pathConsumed: 0, headerFlags: 0, referrals: [])

        await cache.put(referral, for: first, ttl: 1)
        await cache.put(referral, for: second, ttl: 60)
        let count = await cache.count
        let firstEntry = await cache.get(first)
        let secondEntry = await cache.get(second)
        XCTAssertEqual(count, 1)
        XCTAssertNil(firstEntry)
        XCTAssertNotNil(secondEntry)
    }

    func testDfsPathSuffixAccountsForUncPathConsumedConvention() throws {
        let path = "\\\\127.0.0.1\\dfsroot\\chain-link\\known.txt"
        // Samba reports 58 bytes for the 30 UTF-16 code units through chain-link,
        // excluding one leading UNC separator.
        XCTAssertEqual(try SMBClient.dfsPathSuffix(path, consumedUTF16Bytes: 58), "\\known.txt")
    }

    func testSMB2DfsReferralResponseDecodesV3Entries() throws {
        let response = makeDfsReferralResponse(entries: [
            makeDfsReferralV3Entry(
                serverType: 0,
                flags: 0,
                ttl: 300,
                dfsPath: "\\\\server\\dfsroot\\link",
                alternatePath: "\\\\server\\dfsroot\\link",
                networkAddress: "\\\\target-a\\share"
            ),
            makeDfsReferralV3Entry(
                serverType: 1,
                flags: 0,
                ttl: 120,
                dfsPath: "\\\\server\\dfsroot",
                alternatePath: nil,
                networkAddress: "\\\\target-b\\share"
            )
        ])

        let decoded = try SMB2DfsReferral.decodeResponse(response)

        XCTAssertEqual(decoded.pathConsumed, 44)
        XCTAssertEqual(decoded.headerFlags, 0x0000_0002)
        XCTAssertEqual(decoded.referrals.count, 2)
        XCTAssertEqual(decoded.referrals[0].serverType, 0)
        XCTAssertEqual(decoded.referrals[0].timeToLive, 300)
        XCTAssertEqual(decoded.referrals[0].dfsPath, "\\\\server\\dfsroot\\link")
        XCTAssertEqual(decoded.referrals[0].networkAddress, "\\\\target-a\\share")
        XCTAssertEqual(decoded.referrals[1].serverType, 1)
        XCTAssertEqual(decoded.referrals[1].alternatePath, nil)
        XCTAssertEqual(decoded.referrals[1].networkAddress, "\\\\target-b\\share")
        XCTAssertEqual(decoded.targets, [
            try SMBDfsReferralTarget(host: "target-a", share: "share"),
            try SMBDfsReferralTarget(host: "target-b", share: "share")
        ])
    }

    func testSMB2DfsReferralResponseSkipsUnknownVersionBySize() throws {
        var unknown = [UInt8]()
        appendUInt16LE(99, to: &unknown)
        appendUInt16LE(12, to: &unknown)
        unknown.append(contentsOf: Array(repeating: 0xaa, count: 8))
        let response = makeDfsReferralResponse(entries: [
            unknown,
            makeDfsReferralV3Entry(
                serverType: 0,
                flags: 0,
                ttl: 60,
                dfsPath: "\\\\server\\dfsroot\\link",
                alternatePath: nil,
                networkAddress: "\\\\target\\share"
            )
        ])

        let decoded = try SMB2DfsReferral.decodeResponse(response)

        XCTAssertEqual(decoded.referrals.count, 1)
        XCTAssertEqual(decoded.referrals[0].versionNumber, 3)
        XCTAssertEqual(decoded.referrals[0].networkAddress, "\\\\target\\share")
    }

    func testSMB2DfsReferralResponseRejectsOutOfBoundsStringOffset() throws {
        var entry = makeDfsReferralV3Entry(
            serverType: 0,
            flags: 0,
            ttl: 60,
            dfsPath: "\\\\server\\dfsroot\\link",
            alternatePath: nil,
            networkAddress: "\\\\target\\share"
        )
    writeUInt16LE(UInt16(entry.count + 2), to: &entry, at: 16)

        XCTAssertThrowsError(try SMB2DfsReferral.decodeResponse(makeDfsReferralResponse(entries: [entry]))) { error in
            XCTAssertEqual(error as? SMBCodecError, .truncated)
        }
    }

    func testSMB2CopyChunkDecodesResumeKeyFromResponseOutput() throws {
        let resumeKey = Array(0x30...0x47).map(UInt8.init)
        let decoded = try SMB2CopyChunk.decodeResumeKeyResponse(resumeKey + [0xaa, 0xbb])

        XCTAssertEqual(decoded, resumeKey)
    }

    func testSMB2CopyChunkRequestEncodesResumeKeyAndChunks() throws {
        let resumeKey = Array(0x30...0x47).map(UInt8.init)
        let request = try SMB2CopyChunk.encodeCopyChunkRequest(
            resumeKey: resumeKey,
            chunks: [
                SMB2CopyChunkRange(sourceOffset: 1, targetOffset: 2, length: 3),
                SMB2CopyChunkRange(sourceOffset: 4, targetOffset: 5, length: 6)
            ]
        )

        XCTAssertEqual(Array(request[0..<24]), resumeKey)
        XCTAssertEqual(readUInt32LE(request, at: 24), 2)
        XCTAssertEqual(readUInt32LE(request, at: 28), 0)
        XCTAssertEqual(readUInt64LE(request, at: 32), 1)
        XCTAssertEqual(readUInt64LE(request, at: 40), 2)
        XCTAssertEqual(readUInt32LE(request, at: 48), 3)
        XCTAssertEqual(readUInt32LE(request, at: 52), 0)
        XCTAssertEqual(readUInt64LE(request, at: 56), 4)
        XCTAssertEqual(readUInt64LE(request, at: 64), 5)
        XCTAssertEqual(readUInt32LE(request, at: 72), 6)
        XCTAssertEqual(readUInt32LE(request, at: 76), 0)
    }

    func testSMB2CopyChunkResponseDecodesCounters() throws {
        var output: [UInt8] = []
        appendUInt32LE(4, to: &output)
        appendUInt32LE(1024, to: &output)
        appendUInt32LE(4096, to: &output)

        XCTAssertEqual(
            try SMB2CopyChunk.decodeCopyChunkResponse(output),
            SMB2CopyChunkResponse(chunksWritten: 4, chunkBytesWritten: 1024, totalBytesWritten: 4096)
        )
    }

    func testPipeTransceiveContinuesAfterBufferOverflowUntilLastDCEFragment() async throws {
        let fileId = hexBytes("00112233445566778899aabbccddeeff")
        let stub = makeShareEnumStub([
            ("public", 0, "Public share"),
            ("IPC$", 0x8000_0000, "Remote IPC"),
            ("media", 0, "Media share")
        ])
        let split = stub.count / 2
        let firstFragment = try dcerpcResponsePDU(stub: Array(stub[..<split]), flags: DCERPC.pfcFirstFrag)
        let lastFragment = try dcerpcResponsePDU(stub: Array(stub[split...]), flags: DCERPC.pfcLastFrag)
        let inbound = try framed([
            try smb2IoctlResponse(output: firstFragment, status: SMB2Status.bufferOverflow, messageId: 0, treeId: 0x3344, fileId: fileId),
            try smb2ReadResponse(lastFragment, messageId: 1, treeId: 0x3344)
        ])
        let transport = InMemoryTransport(inbound: inbound)
        let session = SMBSession(
            host: "server",
            port: 445,
            credential: SMBCredential(username: "user", password: "pass"),
            transport: transport,
            signingKey: Array(repeating: UInt8(0x11), count: 16)
        )

        let response = try await session.pipeTransceive(treeId: 0x3344, fileId: fileId, input: [0xaa], maxOutputResponse: 16)
        let shares = try SRVSVC.decodeNetrShareEnumResponse(try DCERPC.decodeResponseStub(response))

        XCTAssertEqual(shares.map(\.name), ["public", "IPC$", "media"])
        let requests = try unframed(transport.outbound)
        XCTAssertEqual(requests.count, 2)
        XCTAssertEqual(try SMB2Header.decode(requests[0]).command, SMB2Commands.ioctl)
        XCTAssertEqual(try SMB2Header.decode(requests[1]).command, SMB2Commands.read)
    }

    func testSMB311GMACSignatureZeroesHeaderSignatureField() throws {
        let key = hexBytes("000102030405060708090a0b0c0d0e0f")
        var packet = try SMB2Header(
            command: SMB2Commands.read,
            flags: SMB2Flags.signed,
            messageId: 7,
            treeId: 0x3344,
            sessionId: 0x1122,
            signature: Array(repeating: 0xaa, count: 16)
        ).encode()
        packet.append(contentsOf: [0x11, 0x22, 0x33, 0x44])
        var normalized = packet
        normalized.replaceSubrange(48..<64, with: Array(repeating: 0, count: 16))

        let signature = try SMBSessionSigning.signature(algorithm: .aesGMAC, key: key, packet: packet, sender: .server)
        let expected = try SMBCrypto.aesGMAC(
            key: key,
            nonce: hexBytes("070000000000000001000000"),
            authenticatedData: normalized
        )
        XCTAssertEqual(signature, expected)
    }

    func testAESCMACRFC4493Vectors() throws {
        let key = hexBytes("2b7e151628aed2a6abf7158809cf4f3c")
        let message = hexBytes(
            "6bc1bee22e409f96e93d7e117393172a" +
            "ae2d8a571e03ac9c9eb76fac45af8e51" +
            "30c81c46a35ce411"
        )
        XCTAssertEqual(hex(try AES128.encryptBlock(key: key, block: hexBytes("6bc1bee22e409f96e93d7e117393172a"))), "3ad77bb40d7a3660a89ecaf32466ef97")
        XCTAssertEqual(hex(try AESCMAC.authenticationCode(key: key, message: [])), "bb1d6929e95937287fa37d129b756746")
        XCTAssertEqual(hex(try AESCMAC.authenticationCode(key: key, message: Array(message[0..<16]))), "070a16b46b4d4144f79bdd9dd04a287c")
        XCTAssertEqual(hex(try AESCMAC.authenticationCode(key: key, message: message)), "dfa66747de9ae63030ca32611497c827")
        XCTAssertEqual(
            hex(try AESCMAC.authenticationCode(key: key, message: hexBytes(
                "6bc1bee22e409f96e93d7e117393172a" +
                "ae2d8a571e03ac9c9eb76fac45af8e51" +
                "30c81c46a35ce411e5fbc1191a0a52ef" +
                "f69f2445df4f9b17ad2b417be66c3710"
            ))),
            "51f0bebf7e3b9d92fc49741779363cfe"
        )
    }

    func testAESCMACBoundaryLengthsMatchReferenceImplementation() throws {
        let key = Array(UInt8(0)..<UInt8(16))
        for length in [0, 1, 15, 16, 17, 31, 32, 33, 63, 64, 65, 65_536] {
            let message = (0..<length).map { UInt8(truncatingIfNeeded: $0 &* 31 &+ 7) }
            XCTAssertEqual(
                try AESCMAC.authenticationCode(key: key, message: message),
                try referenceAESCMAC(key: key, message: message),
                "AES-CMAC mismatch at message length \(length)"
            )
            XCTAssertEqual(
                try AESCMAC.pureSwiftAuthenticationCode(key: key, message: message),
                try AESCMAC.authenticationCode(key: key, message: message),
                "pure Swift and CryptoExtras differ at message length \(length)"
            )
        }
    }

    func testAESCMACConcurrentOneShotSigningMatchesReference() async throws {
        let key = Array(UInt8(0)..<UInt8(16))
        let message = (0..<65_536).map { UInt8(truncatingIfNeeded: $0 &* 17 &+ 3) }
        let expected = try referenceAESCMAC(key: key, message: message)
        try await withThrowingTaskGroup(of: [UInt8].self) { group in
            for _ in 0..<64 {
                group.addTask { try AESCMAC.authenticationCode(key: key, message: message) }
            }
            for try await signature in group {
                XCTAssertEqual(signature, expected)
            }
        }
    }

    func testAESCCMRFC3610Vector() throws {
        let key = hexBytes("c0c1c2c3c4c5c6c7c8c9cacbcccdcecf")
        let nonce = hexBytes("00000003020100a0a1a2a3a4a5")
        let aad = hexBytes("0001020304050607")
        let plaintext = hexBytes("08090a0b0c0d0e0f101112131415161718191a1b1c1d1e")
        let sealed = try AESCCM.seal(
            key: key,
            nonce: nonce,
            plaintext: plaintext,
            authenticatedData: aad,
            tagLength: 8
        )
        XCTAssertEqual(hex(sealed.ciphertext + sealed.tag), "588c979a61c663d2f066d0c2c0f989806d5f6b61dac38417e8d12cfdf926e0")
        XCTAssertEqual(
            try AESCCM.open(key: key, nonce: nonce, ciphertext: sealed.ciphertext, authenticatedData: aad, tag: sealed.tag),
            plaintext
        )
    }

    func testSMB3TransformHeaderRoundTripAndCCM() throws {
        let key = hexBytes("000102030405060708090a0b0c0d0e0f")
        let plaintext = Array("plain SMB2 message".utf8)
        let nonce11 = hexBytes("00112233445566778899aa")
        var header = SMB3TransformHeader(
            signature: Array(repeating: 0, count: 16),
            nonce: nonce11 + Array(repeating: 0, count: 5),
            originalMessageSize: UInt32(plaintext.count),
            flags: SMB3TransformHeader.encryptedFlag,
            sessionId: 0x0102_0304_0506_0708
        )
        let sealed = try AESCCM.seal(
            key: key,
            nonce: nonce11,
            plaintext: plaintext,
            authenticatedData: header.authenticatedData(),
            tagLength: 16
        )
        header.signature = sealed.tag
        let encoded = try header.encode()
        let authenticatedData = try header.authenticatedData()
        XCTAssertEqual(encoded.count, SMB3TransformHeader.encodedSize)
        XCTAssertEqual(try SMB3TransformHeader.decode(encoded), header)
        XCTAssertEqual(authenticatedData, Array(encoded[20..<52]))
        XCTAssertEqual(authenticatedData.count, 32)
        XCTAssertEqual(Array(header.nonce.prefix(11)), nonce11)
        XCTAssertEqual(Array(header.nonce.dropFirst(11)), Array(repeating: 0, count: 5))
        XCTAssertEqual(
            try AESCCM.open(
                key: key,
                nonce: nonce11,
                ciphertext: sealed.ciphertext,
                authenticatedData: header.authenticatedData(),
                tag: header.signature
            ),
            plaintext
        )
    }

    func testSMB3TransformHeaderRoundTripAndGCM() throws {
        let key = hexBytes("000102030405060708090a0b0c0d0e0f")
        let plaintext = Array("SMB 3.1.1 encrypted message".utf8)
        let nonce12 = hexBytes("00112233445566778899aabb")
        var header = SMB3TransformHeader(
            signature: Array(repeating: 0, count: 16),
            nonce: nonce12 + Array(repeating: 0, count: 4),
            originalMessageSize: UInt32(plaintext.count),
            flags: SMB3TransformHeader.encryptedFlag,
            sessionId: 0x0102_0304_0506_0708
        )
        let sealed = try SMBCrypto.aesGCMSeal(
            key: key,
            nonce: nonce12,
            plaintext: plaintext,
            authenticatedData: header.authenticatedData()
        )
        header.signature = sealed.tag
        let encoded = try header.encode()

        XCTAssertEqual(encoded.count, SMB3TransformHeader.encodedSize)
        XCTAssertEqual(try SMB3TransformHeader.decode(encoded), header)
        XCTAssertEqual(try header.authenticatedData(), Array(encoded[20..<52]))
        XCTAssertEqual(Array(header.nonce.prefix(12)), nonce12)
        XCTAssertEqual(Array(header.nonce.dropFirst(12)), Array(repeating: 0, count: 4))
        XCTAssertEqual(hex(sealed.ciphertext), "be9e094aa4ce9f28c84a63e967be3521f7d7e06e17fc8b098a59ce")
        XCTAssertEqual(hex(header.signature), "312e6806dd9818cfb5ec7d6faf6e49ac")
        XCTAssertEqual(
            try SMBCrypto.aesGCMOpen(
                key: key,
                nonce: nonce12,
                ciphertext: sealed.ciphertext,
                authenticatedData: header.authenticatedData(),
                tag: header.signature
            ),
            plaintext
        )
    }

    func testSMB3TransformNonceLengthMatchesEncryptionAlgorithmNonceSizes() {
        XCTAssertEqual(
            SMBSession.transformNonce(counter: 0x0102_0304_0506_0708, length: 11),
            hexBytes("0102030405060708000000")
        )
        XCTAssertEqual(
            SMBSession.transformNonce(counter: 0x0102_0304_0506_0708, length: 12),
            hexBytes("010203040506070800000000")
        )
    }

    func testSMB302KeyDerivationLabelAndContextBytes() {
        XCTAssertEqual(hex(SMBCrypto.smb3SigningLabel), "534d4232414553434d414300")
        XCTAssertEqual(hex(SMBCrypto.smb3SigningContext), "536d625369676e00")
        XCTAssertEqual(hex(SMBCrypto.smb302EncryptionLabel), "534d423241455343434d00")
        XCTAssertEqual(hex(SMBCrypto.smb302EncryptionContext), "536572766572496e2000")
        XCTAssertEqual(hex(SMBCrypto.smb302DecryptionContext), "5365727665724f757400")
    }

    func testSMB311PreauthIntegrityHashAndKDFLabels() {
        let messages = [
            Array("NEGOTIATE request fixture".utf8),
            Array("SESSION_SETUP response fixture".utf8)
        ]
        let preauthHash = SMBCrypto.smb311PreauthIntegrityHash(messages)
        let sessionKey = Array(UInt8(0)...UInt8(15))

        // Labels are the ASCII string WITH terminating null (MS-SMB2 §3.1.4.2). The derived
        // keys below are validated against real Samba 3.1.1 signing-required (E2E green), not
        // only self-consistent — a missing label null previously derived keys the server rejected.
        XCTAssertEqual(hex(SMBCrypto.smb311SigningLabel), "534d425369676e696e674b657900")
        XCTAssertEqual(hex(SMBCrypto.smb311EncryptionLabel), "534d424332534369706865724b657900")
        XCTAssertEqual(hex(SMBCrypto.smb311DecryptionLabel), "534d425332434369706865724b657900")
        XCTAssertEqual(hex(SMBCrypto.smb311ApplicationLabel), "534d424170704b657900")
        XCTAssertEqual(
            hex(preauthHash),
            "304e5266d152ea390203ff2ebd32632669f607debb5af2f85ece3932fd6d7091" +
                "42f9e1c44900c1a8e2bf509791c11af65a77fd48f61ddf8a7000ae694ebfb7d2"
        )
        XCTAssertEqual(hex(SMBCrypto.smb311SigningKey(sessionKey: sessionKey, preauthIntegrityHash: preauthHash)), "715673a12970311509579f717524e5d3")
        XCTAssertEqual(hex(SMBCrypto.smb311EncryptionKey(sessionKey: sessionKey, preauthIntegrityHash: preauthHash)), "5dd0bf079b35fa86f2a6dc924d9b3b36")
        XCTAssertEqual(hex(SMBCrypto.smb311DecryptionKey(sessionKey: sessionKey, preauthIntegrityHash: preauthHash)), "76e3458ed426672f6d93d64ba32d15f1")
        XCTAssertEqual(hex(SMBCrypto.smb311ApplicationKey(sessionKey: sessionKey, preauthIntegrityHash: preauthHash)), "9606b4561edc89a465a1d0d4093710b8")
    }

    func testSMB302EncryptionKeyDerivationLabels() {
        let sessionKey = hexBytes("00112233445566778899aabbccddeeff")
        let encryptionKey = SMBCrypto.smb302EncryptionKey(sessionKey: sessionKey)
        let decryptionKey = SMBCrypto.smb302DecryptionKey(sessionKey: sessionKey)
        XCTAssertEqual(encryptionKey.count, 16)
        XCTAssertEqual(decryptionKey.count, 16)
        XCTAssertNotEqual(encryptionKey, decryptionKey)
        XCTAssertEqual(
            encryptionKey,
            SMBCrypto.sp800108CounterModeHMACSHA256(
                key: sessionKey,
                label: SMBCrypto.smb302EncryptionLabel,
                context: SMBCrypto.smb302EncryptionContext,
                length: 16
            )
        )
        XCTAssertEqual(
            decryptionKey,
            SMBCrypto.sp800108CounterModeHMACSHA256(
                key: sessionKey,
                label: SMBCrypto.smb302EncryptionLabel,
                context: SMBCrypto.smb302DecryptionContext,
                length: 16
            )
        )
        XCTAssertNotEqual(
            decryptionKey,
            SMBCrypto.sp800108CounterModeHMACSHA256(
                key: sessionKey,
                label: SMBCrypto.smb302EncryptionLabel,
                context: Array("ServerOut ".utf8) + [0],
                length: 16
            )
        )
    }

    func testNTLMv2KnownVectors() {
        let ntowfv2 = NTLM.ntowfv2(password: "SecREt01", username: "User", domain: "Domain")
        XCTAssertEqual(hex(ntowfv2), "54993fb8ba7bc2d6eacaef6bdc226c49")
        let serverChallenge = hexBytes("0123456789abcdef")
        let blob = hexBytes(
            "01010000000000000090d336b734c301ffffff001122334400000000" +
            "02000c0044004f004d00410049004e00" +
            "01000c00530045005200560045005200" +
            "0400140064006f006d00610069006e002e0063006f006d00" +
            "030022007300650072007600650072002e0064006f006d00610069006e002e0063006f006d00" +
            "0000000000000000"
        )
        XCTAssertEqual(hex(NTLM.ntProofStr(ntowfv2: ntowfv2, serverChallenge: serverChallenge, blob: blob)), "2a8e1bc8a06222ed5301c3fbd2154d0b")
    }

    func testNTLMv2CredentialCanUseNTHashInsteadOfPassword() throws {
        let ntHash = MD4.hash(NTLM.utf16le("Password"))
        let credential = try SMBCredential(username: "User", ntHash: ntHash, domain: "Domain")

        XCTAssertEqual(credential.password, "")
        XCTAssertEqual(credential.ntHash, ntHash)
        XCTAssertEqual(
            try NTLM.ntowfv2(credential: credential),
            NTLM.ntowfv2(password: "Password", username: "User", domain: "Domain")
        )
    }

    func testNTLMv2CredentialRejectsInvalidNTHashLength() {
        XCTAssertThrowsError(try SMBCredential(username: "User", ntHash: [0], domain: "Domain"))
    }

    func testAnonymousCredentialHasEmptyIdentityAndNoSecretMaterial() {
        let credential = SMBCredential.anonymous

        XCTAssertTrue(credential.isAnonymous)
        XCTAssertEqual(credential.username, "")
        XCTAssertEqual(credential.password, "")
        XCTAssertNil(credential.ntHash)
        XCTAssertEqual(credential.domain, "")
    }

    func testMSNLMPSection424NTLMv2SessionKeyExchangeRegressionVector() throws {
        // Regression vector for this implementation's fixed inputs. This is not the
        // literal MS-NLMP 4.2.4 published vector: timestamp and client challenge differ.
        let targetInfo = hexBytes(
            "02000c0044004f004d00410049004e00" +
            "01000c00530045005200560045005200" +
            "0000000000000000"
        )
        let challenge = NTLMChallenge(
            targetName: NTLM.utf16le("Server"),
            flags: NTLM.negotiateFlags,
            serverChallenge: hexBytes("0123456789abcdef"),
            targetInfo: targetInfo
        )
        let authenticate = try NTLM.makeType3(
            credential: SMBCredential(username: "User", password: "Password", domain: "Domain"),
            challenge: challenge,
            timestamp: 0x01c334b736d39000,
            clientChallenge: hexBytes("ffffff0011223344"),
            exportedSessionKey: hexBytes("55555555555555555555555555555555")
        )

        XCTAssertEqual(hex(NTLM.ntowfv2(password: "Password", username: "User", domain: "Domain")), "0c868a403bfd7a93a3001ef22ef02e3f")
        let ntChallengeResponseOffset = Int(readUInt32LE(authenticate.message, at: 24))
        XCTAssertEqual(
            hex(Array(authenticate.message[ntChallengeResponseOffset..<ntChallengeResponseOffset + 16])),
            "11a818b18b5ecd85485ae35d27f6a3df"
        )
        XCTAssertEqual(hex(authenticate.sessionBaseKey), "6e03ecfd4e8b43789dcd872557efa026")
        XCTAssertEqual(readUInt32LE(authenticate.message, at: 60) & NTLM.negotiateKeyExchange, NTLM.negotiateKeyExchange)
        XCTAssertEqual(readUInt16LE(authenticate.message, at: 52), 16)
        XCTAssertEqual(hex(readSecurityBuffer(authenticate.message, at: 52)), "531734fe4e46f82f46a28fadaaaf0e49")
        XCTAssertEqual(authenticate.exportedSessionKey, hexBytes("55555555555555555555555555555555"))
    }

    func testAnonymousNTLMType3UsesAnonymousFlagAndEmptyIdentityResponses() throws {
        let challenge = NTLMChallenge(
            targetName: NTLM.utf16le("Server"),
            flags: NTLM.negotiateFlags,
            serverChallenge: hexBytes("0123456789abcdef"),
            targetInfo: hexBytes("02000c0044004f004d00410049004e0000000000")
        )

        let authenticate = try NTLM.makeType3(credential: .anonymous, challenge: challenge)
        let message = authenticate.message

        XCTAssertEqual(Array(message[0..<8]), Array("NTLMSSP\0".utf8))
        XCTAssertEqual(readUInt32LE(message, at: 8), 3)
        XCTAssertEqual(readSecurityBuffer(message, at: 12), [0x00])
        XCTAssertEqual(readSecurityBuffer(message, at: 20), [])
        XCTAssertEqual(readSecurityBuffer(message, at: 28), [])
        XCTAssertEqual(readSecurityBuffer(message, at: 36), [])
        XCTAssertEqual(readSecurityBuffer(message, at: 44), [])
        XCTAssertEqual(readSecurityBuffer(message, at: 52), [])
        XCTAssertEqual(readUInt32LE(message, at: 60) & NTLM.negotiateAnonymous, NTLM.negotiateAnonymous)
        XCTAssertEqual(readUInt32LE(message, at: 60) & NTLM.negotiateKeyExchange, 0)
        XCTAssertEqual(readUInt32LE(message, at: 60) & NTLM.negotiateSign, 0)
        XCTAssertEqual(readUInt32LE(message, at: 60) & NTLM.negotiateSeal, 0)
        XCTAssertEqual(message.count, 73)
        XCTAssertEqual(authenticate.sessionBaseKey, [])
        XCTAssertEqual(authenticate.exportedSessionKey, [])
    }

    func testNTLMMICUsesExportedSessionKeyAndZeroedMICField() throws {
        let type1 = try NTLM.makeType1()
        let type2 = makeNTLMChallengeMessage(targetInfo: hexBytes("070008000090d336b734c30100000000"))
        let challenge = try NTLM.parseChallenge(type2)
        let exportedSessionKey = hexBytes("00112233445566778899aabbccddeeff")
        let authenticate = try NTLM.makeType3(
            credential: SMBCredential(username: "User", password: "Password", domain: "Domain"),
            challenge: challenge,
            negotiateMessage: type1,
            challengeMessage: type2,
            timestamp: 0x01c334b736d39000,
            clientChallenge: hexBytes("ffffff0011223344"),
            exportedSessionKey: exportedSessionKey
        )

        XCTAssertEqual(authenticate.message.count >= 88, true)
        XCTAssertEqual(readUInt32LE(authenticate.message, at: 60) & NTLM.negotiateKeyExchange, NTLM.negotiateKeyExchange)
        XCTAssertEqual(readUInt32LE(authenticate.message, at: 60) & NTLM.negotiateSeal, 0)
        XCTAssertNotEqual(Array(authenticate.message[72..<88]), Array(repeating: 0, count: 16))
        var zeroed = authenticate.message
        zeroed.replaceSubrange(72..<88, with: Array(repeating: 0, count: 16))
        XCTAssertEqual(
            Array(authenticate.message[72..<88]),
            SMBCrypto.hmacMD5(key: exportedSessionKey, message: type1 + type2 + zeroed)
        )
    }

    func testNTLMType3MICPathAddsRequiredAVPairs() throws {
        let type1 = try NTLM.makeType1()
        var targetInfo: [UInt8] = []
        appendAVPair(id: 1, value: NTLM.utf16le("SERVER"), to: &targetInfo)
        appendAVPair(id: 2, value: NTLM.utf16le("DOMAIN"), to: &targetInfo)
        appendAVPair(id: 3, value: NTLM.utf16le("server.domain.com"), to: &targetInfo)
        appendAVPair(id: 4, value: NTLM.utf16le("domain.com"), to: &targetInfo)
        appendAVPair(id: 7, value: hexBytes("0090d336b734c301"), to: &targetInfo)
        appendAVPair(id: 0, value: [], to: &targetInfo)
        let type2 = makeNTLMChallengeMessage(targetInfo: targetInfo)
        let challenge = try NTLM.parseChallenge(type2)
        let authenticate = try NTLM.makeType3(
            credential: SMBCredential(username: "User", password: "Password", domain: "Domain"),
            challenge: challenge,
            serverName: "169.254.69.111",
            negotiateMessage: type1,
            challengeMessage: type2,
            timestamp: 0x01c334b736d39000,
            clientChallenge: hexBytes("ffffff0011223344"),
            exportedSessionKey: hexBytes("00112233445566778899aabbccddeeff")
        )
        let ntChallengeResponse = readSecurityBuffer(authenticate.message, at: 20)
        let blob = Array(ntChallengeResponse.dropFirst(16))
        let avPairs = try decodeNTLMv2BlobAVPairs(blob)

        XCTAssertEqual(avPairs.map { $0.id }, [1, 2, 3, 4, 7, 6, 9, 10, 0])
        XCTAssertEqual(avPairs.first { $0.id == 6 }?.value, [0x02, 0x00, 0x00, 0x00])
        XCTAssertEqual(avPairs.first { $0.id == 9 }?.value, NTLM.utf16le("cifs/169.254.69.111"))
        XCTAssertEqual(avPairs.first { $0.id == 10 }?.value, Array(repeating: 0, count: 16))
    }

    func testNTLMType3MICPathUpdatesExistingRequiredAVPairsWithoutDuplicates() throws {
        let type1 = try NTLM.makeType1()
        var targetInfo: [UInt8] = []
        appendAVPair(id: 1, value: NTLM.utf16le("SERVER"), to: &targetInfo)
        appendAVPair(id: 6, value: [0x01, 0x00, 0x00, 0x00], to: &targetInfo)
        appendAVPair(id: 7, value: hexBytes("0090d336b734c301"), to: &targetInfo)
        appendAVPair(id: 9, value: NTLM.utf16le("server-sent-target"), to: &targetInfo)
        appendAVPair(id: 10, value: Array(repeating: 0xff, count: 16), to: &targetInfo)
        appendAVPair(id: 0, value: [], to: &targetInfo)
        let type2 = makeNTLMChallengeMessage(targetInfo: targetInfo)
        let challenge = try NTLM.parseChallenge(type2)
        let authenticate = try NTLM.makeType3(
            credential: SMBCredential(username: "User", password: "Password", domain: "Domain"),
            challenge: challenge,
            serverName: "169.254.69.111",
            negotiateMessage: type1,
            challengeMessage: type2,
            timestamp: 0x01c334b736d39000,
            clientChallenge: hexBytes("ffffff0011223344"),
            exportedSessionKey: hexBytes("00112233445566778899aabbccddeeff")
        )
        let ntChallengeResponse = readSecurityBuffer(authenticate.message, at: 20)
        let blob = Array(ntChallengeResponse.dropFirst(16))
        let avPairs = try decodeNTLMv2BlobAVPairs(blob)

        XCTAssertEqual(avPairs.map { $0.id }, [1, 6, 7, 9, 10, 0])
        XCTAssertEqual(avPairs.filter { $0.id == 6 }.count, 1)
        XCTAssertEqual(readUInt32LE(avPairs.first { $0.id == 6 }!.value, at: 0), 0x00000003)
        XCTAssertEqual(avPairs.filter { $0.id == 9 }.count, 1)
        XCTAssertEqual(avPairs.first { $0.id == 9 }?.value, NTLM.utf16le("cifs/169.254.69.111"))
        XCTAssertEqual(avPairs.filter { $0.id == 10 }.count, 1)
        XCTAssertEqual(avPairs.first { $0.id == 10 }?.value, Array(repeating: 0, count: 16))
    }

    func testNTLMClientSigningKeyAndMechListMICUseFixedVectors() throws {
        let exportedSessionKey = hexBytes("00112233445566778899aabbccddeeff")
        let signingKey = NTLM.clientSigningKey(exportedSessionKey: exportedSessionKey)
        let sealingKey = NTLM.clientSealingKey(exportedSessionKey: exportedSessionKey)
        let mic = NTLM.makeMechListMIC(exportedSessionKey: exportedSessionKey)

        XCTAssertEqual(hex(signingKey), "59d6baefd8fb9cfe7c66605162a2b238")
        XCTAssertEqual(hex(sealingKey), "248e660b070223ef5f92354062032e48")
        XCTAssertEqual(SPNEGO.ntlmMechTypeListDER, hexBytes("300c060a2b06010401823702020a"))
        XCTAssertEqual(hex(mic), "01000000549d70fe51ab6ebd00000000")
    }

    func testNTLMType1FixedBytesAndSecurityBuffers() throws {
        let type1 = try NTLM.makeType1()

        XCTAssertEqual(type1.count, 40)
        XCTAssertEqual(Array(type1[0..<8]), Array("NTLMSSP\0".utf8))
        XCTAssertEqual(readUInt32LE(type1, at: 8), 1)
        XCTAssertEqual(readUInt32LE(type1, at: 12), NTLM.negotiateFlags)
        XCTAssertEqual(hex(Array(type1[12..<16])), "358288e2")
        XCTAssertEqual(readUInt16LE(type1, at: 16), 0)
        XCTAssertEqual(readUInt16LE(type1, at: 18), 0)
        XCTAssertEqual(readUInt32LE(type1, at: 20), 40)
        XCTAssertEqual(readUInt16LE(type1, at: 24), 0)
        XCTAssertEqual(readUInt16LE(type1, at: 26), 0)
        XCTAssertEqual(readUInt32LE(type1, at: 28), 40)
        XCTAssertEqual(hex(Array(type1[32..<40])), "0601b11d0000000f")
    }

    func testNTLMType1DomainAndWorkstationSecurityBuffers() throws {
        let type1 = try NTLM.makeType1(domain: "dom", workstation: "wkst")

        XCTAssertEqual(readUInt16LE(type1, at: 16), 3)
        XCTAssertEqual(readUInt16LE(type1, at: 18), 3)
        XCTAssertEqual(readUInt32LE(type1, at: 20), 40)
        XCTAssertEqual(readUInt16LE(type1, at: 24), 4)
        XCTAssertEqual(readUInt16LE(type1, at: 26), 4)
        XCTAssertEqual(readUInt32LE(type1, at: 28), 43)
        XCTAssertEqual(String(bytes: type1[40..<43], encoding: .utf8), "DOM")
        XCTAssertEqual(String(bytes: type1[43..<47], encoding: .utf8), "WKST")
    }

    func testSPNEGONegTokenInitDERStructure() throws {
        let type1 = try NTLM.makeType1()
        let token = SPNEGO.wrapNegTokenInit(type1)

        var cursor = 0
        let applicationEnd = try expectDERTag(0x60, in: token, cursor: &cursor)

        let spnegoOIDEnd = try expectDERTag(0x06, in: token, cursor: &cursor)
        XCTAssertEqual(Array(token[cursor..<spnegoOIDEnd]), [0x2b, 0x06, 0x01, 0x05, 0x05, 0x02])
        cursor = spnegoOIDEnd

        let negTokenInitEnd = try expectDERTag(0xa0, in: token, cursor: &cursor)
        let sequenceEnd = try expectDERTag(0x30, in: token, cursor: &cursor)
        let mechTypesEnd = try expectDERTag(0xa0, in: token, cursor: &cursor)
        let listEnd = try expectDERTag(0x30, in: token, cursor: &cursor)
        let ntlmOIDEnd = try expectDERTag(0x06, in: token, cursor: &cursor)
        XCTAssertEqual(Array(token[cursor..<ntlmOIDEnd]), [0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a])
        cursor = ntlmOIDEnd
        XCTAssertEqual(cursor, listEnd)
        XCTAssertEqual(cursor, mechTypesEnd)

        let mechTokenEnd = try expectDERTag(0xa2, in: token, cursor: &cursor)
        let octetEnd = try expectDERTag(0x04, in: token, cursor: &cursor)
        XCTAssertEqual(Array(token[cursor..<octetEnd]), type1)
        cursor = octetEnd
        XCTAssertEqual(cursor, mechTokenEnd)
        XCTAssertEqual(cursor, sequenceEnd)
        XCTAssertEqual(cursor, negTokenInitEnd)
        XCTAssertEqual(cursor, applicationEnd)
        XCTAssertEqual(cursor, token.count)
    }

    func testSPNEGONegTokenRespDERLengthMatchesSessionSetupSecurityBuffer() throws {
        let challenge = NTLMChallenge(
            targetName: [],
            flags: NTLM.negotiateFlags,
            serverChallenge: hexBytes("0123456789abcdef"),
            targetInfo: hexBytes(
                "02000c0044004f004d00410049004e00" +
                "01000c00530045005200560045005200" +
                "00000000"
            )
        )
        let type3 = try NTLM.makeType3(
            credential: SMBCredential(username: "User", password: "Password", domain: "Domain"),
            challenge: challenge,
            timestamp: 0,
            clientChallenge: hexBytes("ffffff0011223344")
        ).message
        let blob = SPNEGO.wrapNegTokenResp(type3)

        var cursor = 0
        let negTokenRespEnd = try expectDERTag(0xa1, in: blob, cursor: &cursor)
        let sequenceEnd = try expectDERTag(0x30, in: blob, cursor: &cursor)
        let responseTokenEnd = try expectDERTag(0xa2, in: blob, cursor: &cursor)
        let octetEnd = try expectDERTag(0x04, in: blob, cursor: &cursor)
        XCTAssertEqual(octetEnd - cursor, type3.count)
        XCTAssertEqual(Array(blob[cursor..<octetEnd]), type3)
        cursor = octetEnd
        XCTAssertEqual(cursor, responseTokenEnd)
        XCTAssertEqual(cursor, sequenceEnd)
        XCTAssertEqual(cursor, negTokenRespEnd)
        XCTAssertEqual(cursor, blob.count)

        let request = try SMB2SessionSetup.encodeRequest(
            messageId: 8,
            sessionId: 0x1122,
            securityBlob: blob,
            signed: false
        )
        XCTAssertEqual(readUInt16LE(request, at: 78), UInt16(blob.count))
        XCTAssertEqual(Array(request[88..<request.count]), blob)
    }

    func testSPNEGONegTokenRespIncludesMechListMIC() throws {
        let type3 = Array("type3".utf8)
        let mechListMIC = hexBytes("01000000549d70fe51ab6ebd00000000")
        let blob = SPNEGO.wrapNegTokenResp(type3, mechListMIC: mechListMIC)

        var cursor = 0
        let negTokenRespEnd = try expectDERTag(0xa1, in: blob, cursor: &cursor)
        let sequenceEnd = try expectDERTag(0x30, in: blob, cursor: &cursor)
        let responseTokenEnd = try expectDERTag(0xa2, in: blob, cursor: &cursor)
        let tokenEnd = try expectDERTag(0x04, in: blob, cursor: &cursor)
        XCTAssertEqual(Array(blob[cursor..<tokenEnd]), type3)
        cursor = tokenEnd
        XCTAssertEqual(cursor, responseTokenEnd)

        let micContextStart = cursor
        let mechListMICEnd = try expectDERTag(0xa3, in: blob, cursor: &cursor)
        let octetStart = cursor
        let octetEnd = try expectDERTag(0x04, in: blob, cursor: &cursor)
        XCTAssertEqual(octetEnd - cursor, 16)
        XCTAssertEqual(Array(blob[cursor..<octetEnd]), mechListMIC)
        XCTAssertEqual(Array(blob[micContextStart..<octetStart]), [0xa3, 0x12])
        cursor = octetEnd
        XCTAssertEqual(cursor, mechListMICEnd)
        XCTAssertEqual(cursor, sequenceEnd)
        XCTAssertEqual(cursor, negTokenRespEnd)
        XCTAssertEqual(cursor, blob.count)
    }

    func testSessionSetupRequestFixedFieldsAndSecurityBuffer() throws {
        let blob = SPNEGO.wrapNegTokenInit(try NTLM.makeType1())
        let request = try SMB2SessionSetup.encodeRequest(
            messageId: 7,
            sessionId: 0,
            securityBlob: blob,
            signed: false
        )

        let header = try SMB2Header.decode(request)
        XCTAssertEqual(header.command, SMB2Commands.sessionSetup)
        XCTAssertEqual(header.messageId, 7)
        XCTAssertEqual(header.sessionId, 0)
        XCTAssertEqual(readUInt16LE(request, at: 64), 25)
        XCTAssertEqual(request[66], 0)
        XCTAssertEqual(request[67], 1)
        XCTAssertEqual(readUInt32LE(request, at: 68), 0)
        XCTAssertEqual(readUInt32LE(request, at: 72), 0)
        XCTAssertEqual(readUInt16LE(request, at: 76), 88)
        XCTAssertEqual(readUInt16LE(request, at: 78), UInt16(blob.count))
        XCTAssertEqual(readUInt64LE(request, at: 80), 0)
        XCTAssertEqual(Array(request[88..<request.count]), blob)
    }

    func testCreateRootDirectoryRequestFixedFieldsAndEmptyNameBuffer() throws {
        let request = try SMB2Create.encodeRequest(
            messageId: 9,
            sessionId: 0x1122_3344_5566_7788,
            treeId: 0xaabb_ccdd,
            path: "",
            directory: true
        )

        let header = try SMB2Header.decode(request)
        XCTAssertEqual(header.command, SMB2Commands.create)
        XCTAssertEqual(header.messageId, 9)
        XCTAssertEqual(header.treeId, 0xaabb_ccdd)
        XCTAssertEqual(header.sessionId, 0x1122_3344_5566_7788)
        XCTAssertEqual(request.count, 121)
        XCTAssertEqual(readUInt16LE(request, at: 64), 57)
        XCTAssertEqual(request[66], 0)
        XCTAssertEqual(request[67], 0)
        XCTAssertEqual(readUInt32LE(request, at: 68), 2)
        XCTAssertEqual(readUInt64LE(request, at: 72), 0)
        XCTAssertEqual(readUInt64LE(request, at: 80), 0)
        XCTAssertEqual(readUInt32LE(request, at: 88), 0x0000_0089)
        XCTAssertEqual(readUInt32LE(request, at: 92), 0)
        XCTAssertEqual(readUInt32LE(request, at: 96), 0x0000_0007)
        XCTAssertEqual(readUInt32LE(request, at: 100), 0x0000_0001)
        XCTAssertEqual(readUInt32LE(request, at: 104), 0x0000_0001)
        XCTAssertEqual(readUInt16LE(request, at: 108), 120)
        XCTAssertEqual(readUInt16LE(request, at: 110), 0)
        XCTAssertEqual(readUInt32LE(request, at: 112), 0)
        XCTAssertEqual(readUInt32LE(request, at: 116), 0)
        XCTAssertEqual(request[120], 0)
    }

    func testCreateSubpathRequestUsesRelativeUtf16NameAfterFixedPart() throws {
        let request = try SMB2Create.encodeRequest(
            messageId: 10,
            sessionId: 0x1122,
            treeId: 0x3344,
            path: "\\dir\\child",
            directory: true
        )
        let expectedName = NTLM.utf16le("dir\\child")

        XCTAssertEqual(readUInt16LE(request, at: 108), 120)
        XCTAssertEqual(readUInt16LE(request, at: 110), UInt16(expectedName.count))
        XCTAssertEqual(request.count, 120 + expectedName.count)
        XCTAssertEqual(Array(request[120..<request.count]), expectedName)
    }

    func testCreateRequestRejectsUnsafeRelativePathComponents() {
        XCTAssertThrowsError(try SMB2Create.encodeRequest(
            messageId: 10,
            sessionId: 0x1122,
            treeId: 0x3344,
            request: .read(path: "dir\\..\\child", directory: false)
        ))
        XCTAssertThrowsError(try SMB2Create.encodeRequest(
            messageId: 10,
            sessionId: 0x1122,
            treeId: 0x3344,
            request: .read(path: "dir//child", directory: false)
        ))
    }

    func testCreateFileRequestUsesReadDataAndReadAttributesAccess() throws {
        let request = try SMB2Create.encodeRequest(
            messageId: 10,
            sessionId: 0x1122,
            treeId: 0x3344,
            path: "known.txt",
            directory: false
        )

        XCTAssertEqual(readUInt32LE(request, at: 88), 0x0000_0081)
        XCTAssertEqual(readUInt32LE(request, at: 104), 0x0000_0040)
    }

    func testCreateDirectoryRequestUsesFileCreateAndDirectoryOption() throws {
        let request = try SMB2Create.encodeRequest(
            messageId: 10,
            sessionId: 0x1122,
            treeId: 0x3344,
            request: .makeDirectory(path: "newdir")
        )

        XCTAssertEqual(readUInt32LE(request, at: 88), 0x0000_0085)
        XCTAssertEqual(readUInt32LE(request, at: 100), 0x0000_0002)
        XCTAssertEqual(readUInt32LE(request, at: 104), 0x0000_0001)
    }

    func testCreateUploadRequestUsesOverwriteDispositionWhenRequested() throws {
        let request = try SMB2Create.encodeRequest(
            messageId: 10,
            sessionId: 0x1122,
            treeId: 0x3344,
            request: .upload(path: "out.txt", overwrite: true)
        )

        XCTAssertEqual(readUInt32LE(request, at: 88), 0x0000_0082)
        XCTAssertEqual(readUInt32LE(request, at: 100), 0x0000_0005)
        XCTAssertEqual(readUInt32LE(request, at: 104), 0x0000_0040)
    }

    func testCreateDeleteRequestUsesDeleteAccessAndDeleteOnClose() throws {
        let request = try SMB2Create.encodeRequest(
            messageId: 10,
            sessionId: 0x1122,
            treeId: 0x3344,
            request: .delete(path: "out.txt", directory: false)
        )

        XCTAssertEqual(readUInt32LE(request, at: 88), 0x0001_0000)
        XCTAssertEqual(readUInt32LE(request, at: 100), 0x0000_0001)
        XCTAssertEqual(readUInt32LE(request, at: 104), 0x0000_1040)
    }

    func testCreateDeleteReparsePointRequestDoesNotFollowDirectoryTarget() throws {
        let request = try SMB2Create.encodeRequest(
            messageId: 10,
            sessionId: 0x1122,
            treeId: 0x3344,
            request: .deleteReparsePoint(path: "link", directory: true)
        )

        XCTAssertEqual(readUInt32LE(request, at: 88), 0x0001_0000)
        XCTAssertEqual(readUInt32LE(request, at: 100), 0x0000_0001)
        XCTAssertEqual(readUInt32LE(request, at: 104), 0x0020_1001)
    }

    func testCreateSetSecurityRequestUsesWriteDACAccess() throws {
        let request = try SMB2Create.encodeRequest(
            messageId: 10,
            sessionId: 0x1122,
            treeId: 0x3344,
            request: .setSecurity(path: "out.txt")
        )

        XCTAssertEqual(readUInt32LE(request, at: 88), 0x0004_0000)
        XCTAssertEqual(readUInt32LE(request, at: 100), 0x0000_0001)
        XCTAssertEqual(readUInt32LE(request, at: 104), 0)
    }

    func testDeleteNonRecursiveRetriesAsDirectoryWhenCreateReportsFileIsADirectory() async throws {
        let fileId = hexBytes("00112233445566778899aabbccddeeff")
        let inbound = try framed([
            try smb2StatusResponse(status: SMB2Status.fileIsADirectory, command: SMB2Commands.create, messageId: 0, treeId: 0x3344),
            try smb2CreateResponse(fileId: fileId, messageId: 1, treeId: 0x3344),
            try smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.close, messageId: 2, treeId: 0x3344)
        ])
        let transport = InMemoryTransport(inbound: inbound)
        let session = SMBSession(
            host: "server",
            port: 445,
            credential: SMBCredential(username: "user", password: "pass"),
            transport: transport,
            signingKey: Array(repeating: UInt8(0x11), count: 16)
        )

        try await session.deleteNonRecursive(treeId: 0x3344, path: "dir", directory: false)

        let requests = try unframed(transport.outbound)
        XCTAssertEqual(requests.count, 3)
        XCTAssertEqual(try SMB2Header.decode(requests[0]).command, SMB2Commands.create)
        XCTAssertEqual(readUInt32LE(requests[0], at: 104), 0x0000_1040)
        XCTAssertEqual(try SMB2Header.decode(requests[1]).command, SMB2Commands.create)
        XCTAssertEqual(readUInt32LE(requests[1], at: 104), 0x0000_1001)
        XCTAssertEqual(try SMB2Header.decode(requests[2]).command, SMB2Commands.close)
        XCTAssertEqual(Array(requests[2][72..<88]), fileId)
    }

    func testCreateForMetadataRetriesAsDirectoryWhenFileIsADirectory() async throws {
        // stat 用の handle open。file 想定 (directory:false) の CREATE が
        // STATUS_FILE_IS_A_DIRECTORY を返したら directory:true で 1 回 retry して
        // handle を返す (S0c。deleteNonRecursive の自動判定と同型)。
        let fileId = hexBytes("00112233445566778899aabbccddeeff")
        let inbound = try framed([
            try smb2StatusResponse(status: SMB2Status.fileIsADirectory, command: SMB2Commands.create, messageId: 0, treeId: 0x3344),
            smb2CreateResponse(fileId: fileId, messageId: 1, treeId: 0x3344)
        ])
        let transport = InMemoryTransport(inbound: inbound)
        let session = SMBSession(
            host: "server",
            port: 445,
            credential: SMBCredential(username: "user", password: "pass"),
            transport: transport,
            signingKey: Array(repeating: UInt8(0x11), count: 16)
        )

        let returned = try await session.createForMetadata(treeId: 0x3344, path: "folder")

        XCTAssertEqual(returned, fileId)
        let requests = try unframed(transport.outbound)
        XCTAssertEqual(requests.count, 2)
        XCTAssertEqual(try SMB2Header.decode(requests[0]).command, SMB2Commands.create)
        XCTAssertEqual(try SMB2Header.decode(requests[1]).command, SMB2Commands.create)
        // 1 回目は non-directory bit (FILE_NON_DIRECTORY_FILE 0x40)、2 回目は
        // directory bit (FILE_DIRECTORY_FILE 0x1) を CreateOptions (offset 104) に持つ。
        XCTAssertEqual(readUInt32LE(requests[0], at: 104) & 0x40, 0x40)
        XCTAssertEqual(readUInt32LE(requests[1], at: 104) & 0x1, 0x1)
        XCTAssertEqual(readUInt32LE(requests[0], at: 104) & 0x0020_0000, 0x0020_0000)
        XCTAssertEqual(readUInt32LE(requests[1], at: 104) & 0x0020_0000, 0x0020_0000)
    }

    func testCreateResponseDecodesFileIdAtResponseStructureOffset64() throws {
        var response = try SMB2Header(
            command: SMB2Commands.create,
            messageId: 10,
            treeId: 0x3344,
            sessionId: 0x1122
        ).encode()
        response.append(contentsOf: Array(repeating: UInt8(0), count: 88))
        let expectedFileId = hexBytes("0123456789abcdeffedcba9876543210")

        writeUInt16LE(89, to: &response, at: 64)
        response.replaceSubrange(128..<144, with: expectedFileId)

        XCTAssertEqual(response.count, 152)
        XCTAssertEqual(try SMB2Create.decodeFileId(response), expectedFileId)
    }

    func testQueryDirectoryRequestUsesWildcardSearchPattern() throws {
        let fileId = (0..<16).map(UInt8.init)
        let request = try SMB2QueryDirectory.encodeRequest(
            messageId: 11,
            sessionId: 0x1122_3344,
            treeId: 0x5566_7788,
            fileId: fileId
        )

        let header = try SMB2Header.decode(request)
        XCTAssertEqual(header.command, SMB2Commands.queryDirectory)
        XCTAssertEqual(readUInt32LE(request, at: 92), SMB2QueryDirectory.outputBufferSize)
        XCTAssertEqual(header.messageId, 11)
        XCTAssertEqual(header.treeId, 0x5566_7788)
        XCTAssertEqual(header.sessionId, 0x1122_3344)
        XCTAssertEqual(request.count, 98)
        XCTAssertEqual(readUInt16LE(request, at: 64), 33)
        XCTAssertEqual(request[66], 37)
        XCTAssertEqual(request[67], 0x01)
        XCTAssertEqual(readUInt32LE(request, at: 68), 0)
        XCTAssertEqual(Array(request[72..<88]), fileId)
        XCTAssertEqual(readUInt16LE(request, at: 88), 96)
        XCTAssertEqual(readUInt16LE(request, at: 90), 2)
        XCTAssertEqual(readUInt32LE(request, at: 92), SMB2QueryDirectory.outputBufferSize)
        XCTAssertEqual(Array(request[96..<98]), [0x2a, 0x00])
    }

    // MARK: - directoryEntry(matching:) — canonical name 解決 (obaket issue 505)

    func testDirectoryEntryMatchingUsesLeafPatternAndReturnsCanonicalName() async throws {
        let directoryFileId = Array(UInt8(32)..<UInt8(48))
        let treeId: UInt32 = 0x3344
        let transport = SMBValidateNegotiateScriptTransport(inbound: try framed(
            authenticatedTreeResponses(treeId: treeId) + [
                try smb2CreateResponse(fileId: directoryFileId, messageId: 4, treeId: treeId),
                try smb2QueryDirectoryResponse(
                    entries: [makeDirectoryEntry(name: "Report.txt", isDirectory: false, fileSize: 3, nextOffset: 0)],
                    messageId: 5,
                    treeId: treeId
                ),
                try smb2StatusResponse(status: SMB2Status.noMoreFiles, command: SMB2Commands.queryDirectory, messageId: 6, treeId: treeId),
                try smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.close, messageId: 7, treeId: treeId)
            ]
        ))
        let session = try await SMBClient.connect(
            host: "server",
            share: "share",
            credential: SMBCredential(username: "user", password: "pass"),
            makeTransport: { transport }
        )

        // case 違いの要求 leaf に対し、server 応答の canonical (case-preserved) name が返る
        let entry = try await session.directoryEntry(matching: "docs/report.txt")
        XCTAssertEqual(entry?.name, "Report.txt")
        XCTAssertEqual(entry?.fileSize, 3)

        // outbound の QUERY_DIRECTORY request が leaf を search pattern として運んでいる
        // ("*" の全列挙ではない)
        // 注: 本ファイルの wire fixture は SMB 3.x 暗号化を有効にするため outbound が
        // 平文にならない。「pattern が実際に wire へ出る」ことの検証は平文 transport
        // fixture を持つ SMBeePerformanceRegressionTests 側に置いている
        // (testQueryDirectoryRequestCarriesLeafPatternOnTheWire)。
    }

    func testListReturnsEmptyWhenServerReportsNoSuchFile() async throws {
        // noSuchFile の写像は queryDirectoryPage (共有 low-level) に入れたので、
        // 既定の "*" を使う list(path:) にも効く。空 directory に NO_SUCH_FILE を
        // 返す server 実装で throw せず空配列になることを固定する。
        let directoryFileId = Array(UInt8(32)..<UInt8(48))
        let treeId: UInt32 = 0x3344
        let transport = SMBValidateNegotiateScriptTransport(inbound: try framed(
            authenticatedTreeResponses(treeId: treeId) + [
                try smb2CreateResponse(fileId: directoryFileId, messageId: 4, treeId: treeId),
                try smb2StatusResponse(status: SMB2Status.noSuchFile, command: SMB2Commands.queryDirectory, messageId: 5, treeId: treeId),
                try smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.close, messageId: 6, treeId: treeId)
            ]
        ))
        let session = try await SMBClient.connect(
            host: "server",
            share: "share",
            credential: SMBCredential(username: "user", password: "pass"),
            makeTransport: { transport }
        )

        let entries = try await session.list(path: "empty")
        XCTAssertEqual(entries, [])
    }

    func testDirectoryEntryMatchingRecoversCanonicalNameFromEnumeration() async throws {
        // 親を全列挙し、client 側で case-insensitive に照合して canonical name を返す
        // (obaket issue 505)。server の pattern マッチには頼らない — macOS 共有は
        // pattern に要求表記をそのまま返し、canonical を隠してしまう (2026-08-19 実測)。
        let directoryFileId = Array(UInt8(32)..<UInt8(48))
        let treeId: UInt32 = 0x3344
        let transport = SMBValidateNegotiateScriptTransport(inbound: try framed(
            authenticatedTreeResponses(treeId: treeId) + [
                try smb2CreateResponse(fileId: directoryFileId, messageId: 4, treeId: treeId),
                try smb2QueryDirectoryResponse(
                    entries: [
                        makeDirectoryEntry(name: "other.bin", isDirectory: false, fileSize: 1, nextOffset: 122),
                        makeDirectoryEntry(name: "Report.TXT", isDirectory: false, fileSize: 3, nextOffset: 0)
                    ],
                    messageId: 5,
                    treeId: treeId
                ),
                try smb2StatusResponse(status: SMB2Status.noMoreFiles, command: SMB2Commands.queryDirectory, messageId: 6, treeId: treeId),
                try smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.close, messageId: 7, treeId: treeId)
            ]
        ))
        let session = try await SMBClient.connect(
            host: "server",
            share: "share",
            credential: SMBCredential(username: "user", password: "pass"),
            makeTransport: { transport }
        )

        let entry = try await session.directoryEntry(matching: "docs/report.txt")
        XCTAssertEqual(entry?.name, "Report.TXT", "enumeration should recover the canonical name")
        XCTAssertEqual(entry?.fileSize, 3)
    }

    func testDirectoryEntryMatchingReturnsNilWhenAbsentFromEnumeration() async throws {
        // 列挙に無い leaf は nil (照合が false positive を作らないこと)。
        let directoryFileId = Array(UInt8(32)..<UInt8(48))
        let treeId: UInt32 = 0x3344
        let transport = SMBValidateNegotiateScriptTransport(inbound: try framed(
            authenticatedTreeResponses(treeId: treeId) + [
                try smb2CreateResponse(fileId: directoryFileId, messageId: 4, treeId: treeId),
                try smb2QueryDirectoryResponse(
                    entries: [makeDirectoryEntry(name: "unrelated.bin", isDirectory: false, fileSize: 1, nextOffset: 0)],
                    messageId: 5,
                    treeId: treeId
                ),
                try smb2StatusResponse(status: SMB2Status.noMoreFiles, command: SMB2Commands.queryDirectory, messageId: 6, treeId: treeId),
                try smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.close, messageId: 7, treeId: treeId)
            ]
        ))
        let session = try await SMBClient.connect(
            host: "server",
            share: "share",
            credential: SMBCredential(username: "user", password: "pass"),
            makeTransport: { transport }
        )

        let entry = try await session.directoryEntry(matching: "docs/missing.txt")
        XCTAssertNil(entry)
    }

    func testListPropagatesQueryDirectoryFailureStatus() async throws {
        // noSuchFile / noMoreFiles を「空の列挙」に写像したことで、他の失敗ステータス
        // まで空リストに倒れていないことを固定する (accessDenied が silent に空になると
        // 「権限が無いディレクトリが空に見える」最悪の退行になる)。
        let directoryFileId = Array(UInt8(32)..<UInt8(48))
        let treeId: UInt32 = 0x3344
        let transport = SMBValidateNegotiateScriptTransport(inbound: try framed(
            authenticatedTreeResponses(treeId: treeId) + [
                try smb2CreateResponse(fileId: directoryFileId, messageId: 4, treeId: treeId),
                try smb2StatusResponse(status: SMB2Status.accessDenied, command: SMB2Commands.queryDirectory, messageId: 5, treeId: treeId),
                try smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.close, messageId: 6, treeId: treeId)
            ]
        ))
        let session = try await SMBClient.connect(
            host: "server",
            share: "share",
            credential: SMBCredential(username: "user", password: "pass"),
            makeTransport: { transport }
        )

        do {
            _ = try await session.list(path: "restricted")
            XCTFail("expected QUERY_DIRECTORY accessDenied to propagate")
        } catch let error as SMBError {
            guard case .accessDenied = error else {
                XCTFail("expected accessDenied, got \(error)")
                return
            }
        }
    }

    func testDirectoryEntryMatchingRejectsDotSegments() async throws {
        // public API 単体でも安全であること: ".." を含む path の親を CREATE に
        // 渡さない (wire に出る前に reject する)。
        let treeId: UInt32 = 0x3344
        let transport = SMBValidateNegotiateScriptTransport(inbound: try framed(authenticatedTreeResponses(treeId: treeId)))
        let session = try await SMBClient.connect(
            host: "server",
            share: "share",
            credential: SMBCredential(username: "user", password: "pass"),
            makeTransport: { transport }
        )
        let outboundBeforeReject = transport.outbound.count

        // leaf 自体が "." / ".." のケースを必ず含める: これらは親 path から dot が
        // 消えるため、directoryEntry 側の guard が無いと CREATE(parent) が成功して
        // pattern="." で wire に出てしまう (親に dot がある形は CREATE 時の SMBPath
        // 検証でも弾かれるので、guard の有無を区別できない)。
        for path in ["a/..", ".", "a/../b.txt", "./b.txt", "a/./b.txt"] {
            do {
                _ = try await session.directoryEntry(matching: path)
                XCTFail("expected dot-segment rejection for \(path)")
            } catch let error as SMBCodecError {
                XCTAssertTrue(
                    "\(error)".contains("must not contain . or .."),
                    "unexpected codec error for \(path): \(error)"
                )
            }
        }

        // reject は wire に出る前なので追加のリクエストは 1 byte も送られていない
        XCTAssertEqual(transport.outbound.count, outboundBeforeReject)
    }

    func testQueryDirectoryRequestEncodesCustomSearchPattern() throws {
        let fileId = (0..<16).map(UInt8.init)
        let request = try SMB2QueryDirectory.encodeRequest(
            messageId: 11,
            sessionId: 0x1122_3344,
            treeId: 0x5566_7788,
            fileId: fileId,
            searchPattern: "Report.txt"
        )

        // UTF-16LE で pattern を encode し、FileNameLength がバイト数と一致すること
        let expected = "Report.txt".utf16.flatMap { [UInt8($0 & 0xff), UInt8($0 >> 8)] }
        XCTAssertEqual(readUInt16LE(request, at: 90), UInt16(expected.count))
        XCTAssertEqual(Array(request[96..<(96 + expected.count)]), expected)
        XCTAssertEqual(request.count, 96 + expected.count)
    }

    func testQueryDirectoryRequestRejectsEmptySearchPattern() {
        let fileId = (0..<16).map(UInt8.init)
        XCTAssertThrowsError(
            try SMB2QueryDirectory.encodeRequest(
                messageId: 11,
                sessionId: 0x1122_3344,
                treeId: 0x5566_7788,
                fileId: fileId,
                searchPattern: ""
            )
        )
    }

    func testDirectoryEntrySelectionPrefersExactThenCaseInsensitive() {
        func entry(_ name: String) -> SMBDirectoryEntry {
            SMBDirectoryEntry(name: name, fileSize: 0, isDirectory: false, attributes: 0)
        }

        // exact 一致が case-insensitive 一致より優先される
        XCTAssertEqual(
            SMBDirectoryEntrySelection.entry(
                matching: "report.txt",
                from: [entry("Report.txt"), entry("report.txt")]
            )?.name,
            "report.txt"
        )
        // exact が無ければ case-insensitive 一致 (= server の canonical 表記) を返す
        XCTAssertEqual(
            SMBDirectoryEntrySelection.entry(matching: "report.txt", from: [entry("Report.txt")])?.name,
            "Report.txt"
        )
        // wildcard の over-match (別名ファイル) は弾く
        XCTAssertNil(
            SMBDirectoryEntrySelection.entry(matching: "repor?.txt", from: [entry("report.txt")])
        )
        XCTAssertNil(SMBDirectoryEntrySelection.entry(matching: "report.txt", from: []))
    }

    func testQueryDirectoryContinuationRequestClearsRestartScanFlag() throws {
        let fileId = (0..<16).map(UInt8.init)
        let request = try SMB2QueryDirectory.encodeRequest(
            messageId: 11,
            sessionId: 0x1122_3344,
            treeId: 0x5566_7788,
            fileId: fileId,
            restartScan: false
        )

        XCTAssertEqual(request[67], 0x00)
    }

    func testChangeNotifyRequestShape() throws {
        let fileId = (0..<16).map(UInt8.init)
        let request = try SMB2ChangeNotify.encodeRequest(
            messageId: 12,
            sessionId: 0x1122_3344,
            treeId: 0x5566_7788,
            fileId: fileId,
            completionFilter: [.fileName, .dirName, .lastWrite],
            watchTree: true,
            outputBufferLength: 4096
        )

        let header = try SMB2Header.decode(request)
        XCTAssertEqual(header.command, SMB2Commands.changeNotify)
        XCTAssertEqual(header.messageId, 12)
        XCTAssertEqual(header.treeId, 0x5566_7788)
        XCTAssertEqual(header.sessionId, 0x1122_3344)
        XCTAssertEqual(request.count, 96)
        XCTAssertEqual(readUInt16LE(request, at: 64), 32)
        XCTAssertEqual(readUInt16LE(request, at: 66), 0x0001)
        XCTAssertEqual(readUInt32LE(request, at: 68), 4096)
        XCTAssertEqual(Array(request[72..<88]), fileId)
        XCTAssertEqual(readUInt32LE(request, at: 88), 0x0000_0013)
        XCTAssertEqual(readUInt32LE(request, at: 92), 0)
    }

    func testChangeNotifyResponseDecodesFileNotifyInformationEntries() throws {
        let response = try smb2ChangeNotifyResponse(
            entries: [
                makeFileNotifyEntry(action: 1, name: "new.txt", nextOffset: 32),
                makeFileNotifyEntry(action: 2, name: "old.txt", nextOffset: 0)
            ],
            messageId: 12,
            treeId: 0x3344
        )

        let changes = try SMB2ChangeNotify.decodeResponse(response)

        XCTAssertEqual(changes, [
            SMBFileChange(action: .added, name: "new.txt"),
            SMBFileChange(action: .removed, name: "old.txt")
        ])
    }

    func testChangeNotifyResponseRejectsTruncatedFileNotifyInformation() throws {
        var response = try smb2ChangeNotifyResponse(
            entries: [makeFileNotifyEntry(action: 3, name: "bad.txt", nextOffset: 0)],
            messageId: 12,
            treeId: 0x3344
        )
        writeUInt32LE(10_000, to: &response, at: 80)

        XCTAssertThrowsError(try SMB2ChangeNotify.decodeResponse(response)) { error in
            XCTAssertEqual(error as? SMBCodecError, .truncated)
        }
    }

    func testChangeNotifyOverflowStatusMapsToOverflowEvent() async throws {
        let fileId = hexBytes("00112233445566778899aabbccddeeff")
        let inbound = try framed([
            try smb2StatusResponse(status: SMB2Status.notifyEnumDir, command: SMB2Commands.changeNotify, messageId: 0, treeId: 0x3344)
        ])
        let transport = InMemoryTransport(inbound: inbound)
        let session = SMBSession(
            host: "server",
            port: 445,
            credential: SMBCredential(username: "user", password: "pass"),
            transport: transport,
            signingKey: Array(repeating: UInt8(0x11), count: 16)
        )

        let collector = ChangeNotifyCollector()
        let task = Task {
            try await session.changeNotify(treeId: 0x3344, fileId: fileId, filter: .default, watchTree: false) { event in
                collector.append(event)
                throw CancellationError()
            }
        }
        do {
            try await awaitWithTimeout("CHANGE_NOTIFY overflow") {
                try await task.value
            }
        } catch is CancellationError {
        }

        XCTAssertEqual(collector.events, [.overflow])
    }

    func testChangeNotifyCancellationSendsSMB2Cancel() async throws {
        let fileId = hexBytes("00112233445566778899aabbccddeeff")
        let transport = ControlledReceiveTransport()
        let session = SMBSession(
            host: "server",
            port: 445,
            credential: SMBCredential(username: "user", password: "pass"),
            transport: transport,
            signingKey: Array(repeating: UInt8(0x11), count: 16)
        )

        let task = Task {
            try await session.changeNotify(treeId: 0x3344, fileId: fileId, filter: .default, watchTree: false) { _ in
                XCTFail("cancelled CHANGE_NOTIFY should not deliver an event")
            }
        }

        try await waitForOutboundFrameCount(1, transport: transport)
        task.cancel()
        try await waitForOutboundFrameCount(2, transport: transport)

        let requests = try unframed(transport.outbound)
        let changeHeader = try SMB2Header.decode(requests[0])
        let cancelHeader = try SMB2Header.decode(requests[1])
        XCTAssertEqual(changeHeader.command, SMB2Commands.changeNotify)
        XCTAssertEqual(cancelHeader.command, SMB2Commands.cancel)
        XCTAssertEqual(cancelHeader.messageId, changeHeader.messageId)
        // Pre-interim cancellation uses the sync CANCEL form with TreeId 0 (MS-SMB2 §2.2.1.2).
        XCTAssertEqual(cancelHeader.treeId, 0)
        XCTAssertNil(cancelHeader.asyncId)

        transport.enqueueInbound(try framed([
            try smb2StatusResponse(
                status: SMB2Status.cancelled,
                command: SMB2Commands.changeNotify,
                messageId: changeHeader.messageId,
                treeId: changeHeader.treeId
            )
        ]))

        do {
            try await awaitWithTimeout("cancel CHANGE_NOTIFY") {
                try await task.value
            }
            XCTFail("cancelled CHANGE_NOTIFY unexpectedly completed")
        } catch is CancellationError {
        }
    }

    /// STATUS_PENDING interim: async-form header + SMB2 ERROR response body
    /// (StructureSize=9, MS-SMB2 §2.2.2 — servers attach it to interim responses too).
    private func smb2AsyncPendingResponse(
        command: UInt16,
        messageId: UInt64,
        asyncId: UInt64,
        sessionId: UInt64 = 0,
        credits: UInt16 = 1
    ) throws -> [UInt8] {
        var response = try SMB2Header.asyncHeader(
            status: SMB2Status.pending,
            command: command,
            credits: credits,
            messageId: messageId,
            asyncId: asyncId,
            sessionId: sessionId
        ).encode()
        response.append(contentsOf: [9, 0, 0, 0, 0, 0, 0, 0])
        return response
    }

    private func smb2AsyncReadResponse(
        _ payload: [UInt8],
        messageId: UInt64,
        asyncId: UInt64,
        credits: UInt16 = 1
    ) throws -> [UInt8] {
        var response = try SMB2Header.asyncHeader(
            command: SMB2Commands.read,
            credits: credits,
            messageId: messageId,
            asyncId: asyncId
        ).encode()
        response.append(contentsOf: Array(repeating: UInt8(0), count: 16))
        writeUInt16LE(17, to: &response, at: 64)
        response[66] = 80
        writeUInt32LE(UInt32(payload.count), to: &response, at: 68)
        response.append(contentsOf: payload)
        return response
    }

    private func makeAsyncCorrelationSession(_ transport: ControlledReceiveTransport) -> SMBSession {
        SMBSession(
            host: "server",
            port: 445,
            credential: SMBCredential(username: "user", password: "pass"),
            transport: transport,
            signingKey: Array(repeating: UInt8(0x11), count: 16)
        )
    }

    private func waitForDispatchCount(_ expected: Int, session: SMBSession) async throws {
        try await awaitWithTimeout("dispatch count \(expected)") {
            while await session.receivedPacketDispatchCountForTesting() < expected {
                try Task.checkCancellation()
                await Task.yield()
            }
        }
    }

    // AsyncId 上位 32bit が非 zero でも treeId 照合に落ちない (issues/078 の相関バグの直接回帰)。
    func testAsyncInterimThenMatchingAsyncFinalCompletes() async throws {
        let fileId = hexBytes("00112233445566778899aabbccddeeff")
        let transport = ControlledReceiveTransport()
        let session = makeAsyncCorrelationSession(transport)
        let asyncId: UInt64 = 0x5566_7788_0000_0001

        let task = Task {
            try await session.readChunk(treeId: 0x3344, fileId: fileId, offset: 0, length: 3)
        }
        try await waitForOutboundFrameCount(1, transport: transport)
        let readHeader = try SMB2Header.decode(try unframed(transport.outbound)[0])

        transport.enqueueInbound(try framed([
            try smb2AsyncPendingResponse(command: SMB2Commands.read, messageId: readHeader.messageId, asyncId: asyncId)
        ]))
        try await waitForDispatchCount(1, session: session)
        transport.enqueueInbound(try framed([
            try smb2AsyncReadResponse(Array("abc".utf8), messageId: readHeader.messageId, asyncId: asyncId)
        ]))

        let data = try await awaitWithTimeout("async final read") { try await task.value }
        XCTAssertEqual(data, Array("abc".utf8))
        let pendingCount = await session.pendingCountForTesting()
        XCTAssertEqual(pendingCount, 0)
    }

    func testAsyncFinalWithMismatchedAsyncIdFailsRequest() async throws {
        let fileId = hexBytes("00112233445566778899aabbccddeeff")
        let transport = ControlledReceiveTransport()
        let session = makeAsyncCorrelationSession(transport)

        let task = Task {
            try await session.readChunk(treeId: 0x3344, fileId: fileId, offset: 0, length: 3)
        }
        defer { task.cancel() }
        try await waitForOutboundFrameCount(1, transport: transport)
        let readHeader = try SMB2Header.decode(try unframed(transport.outbound)[0])

        transport.enqueueInbound(try framed([
            try smb2AsyncPendingResponse(command: SMB2Commands.read, messageId: readHeader.messageId, asyncId: 7)
        ]))
        try await waitForDispatchCount(1, session: session)
        transport.enqueueInbound(try framed([
            try smb2AsyncReadResponse([0x61], messageId: readHeader.messageId, asyncId: 8)
        ]))

        do {
            _ = try await awaitWithTimeout("mismatched async final") { try await task.value }
            XCTFail("mismatched AsyncId final unexpectedly completed")
        } catch is CancellationError {
            XCTFail("expected a correlation failure, got cancellation")
        } catch is SMBTestTimeoutError {
            XCTFail("expected a correlation failure, got a timeout (possible hang)")
        } catch {
        }
    }

    func testAsyncFinalWithoutInterimIsRejected() async throws {
        let fileId = hexBytes("00112233445566778899aabbccddeeff")
        let transport = ControlledReceiveTransport()
        let session = makeAsyncCorrelationSession(transport)

        let task = Task {
            try await session.readChunk(treeId: 0x3344, fileId: fileId, offset: 0, length: 3)
        }
        defer { task.cancel() }
        try await waitForOutboundFrameCount(1, transport: transport)
        let readHeader = try SMB2Header.decode(try unframed(transport.outbound)[0])

        transport.enqueueInbound(try framed([
            try smb2AsyncReadResponse([0x61], messageId: readHeader.messageId, asyncId: 9)
        ]))

        do {
            _ = try await awaitWithTimeout("async final without interim") { try await task.value }
            XCTFail("async final without interim unexpectedly completed")
        } catch is CancellationError {
            XCTFail("expected a correlation failure, got cancellation")
        } catch is SMBTestTimeoutError {
            XCTFail("expected a correlation failure, got a timeout (possible hang)")
        } catch {
        }
    }

    func testSecondInterimWithDifferentAsyncIdIsRejected() async throws {
        let fileId = hexBytes("00112233445566778899aabbccddeeff")
        let transport = ControlledReceiveTransport()
        let session = makeAsyncCorrelationSession(transport)

        let task = Task {
            try await session.readChunk(treeId: 0x3344, fileId: fileId, offset: 0, length: 3)
        }
        defer { task.cancel() }
        try await waitForOutboundFrameCount(1, transport: transport)
        let readHeader = try SMB2Header.decode(try unframed(transport.outbound)[0])

        transport.enqueueInbound(try framed([
            try smb2AsyncPendingResponse(command: SMB2Commands.read, messageId: readHeader.messageId, asyncId: 7)
        ]))
        try await waitForDispatchCount(1, session: session)
        transport.enqueueInbound(try framed([
            try smb2AsyncPendingResponse(command: SMB2Commands.read, messageId: readHeader.messageId, asyncId: 8)
        ]))

        do {
            _ = try await awaitWithTimeout("second interim mismatch") { try await task.value }
            XCTFail("AsyncId change across interims unexpectedly completed")
        } catch is CancellationError {
            XCTFail("expected a correlation failure, got cancellation")
        } catch is SMBTestTimeoutError {
            XCTFail("expected a correlation failure, got a timeout (possible hang)")
        } catch {
        }
    }

    func testSyncFinalAfterAsyncInterimIsRejected() async throws {
        let fileId = hexBytes("00112233445566778899aabbccddeeff")
        let transport = ControlledReceiveTransport()
        let session = makeAsyncCorrelationSession(transport)

        let task = Task {
            try await session.readChunk(treeId: 0x3344, fileId: fileId, offset: 0, length: 3)
        }
        defer { task.cancel() }
        try await waitForOutboundFrameCount(1, transport: transport)
        let readHeader = try SMB2Header.decode(try unframed(transport.outbound)[0])

        transport.enqueueInbound(try framed([
            try smb2AsyncPendingResponse(command: SMB2Commands.read, messageId: readHeader.messageId, asyncId: 7)
        ]))
        try await waitForDispatchCount(1, session: session)
        transport.enqueueInbound(try framed([
            try smb2ReadResponse([0x61], messageId: readHeader.messageId, treeId: 0x3344)
        ]))

        do {
            _ = try await awaitWithTimeout("sync final after interim") { try await task.value }
            XCTFail("sync final after async interim unexpectedly completed")
        } catch is CancellationError {
            XCTFail("expected a correlation failure, got cancellation")
        } catch is SMBTestTimeoutError {
            XCTFail("expected a correlation failure, got a timeout (possible hang)")
        } catch {
        }
    }

    // interim を処理済みの request の cancel は async CANCEL (保存済み AsyncId + 元 MessageId)。
    func testCancellationAfterInterimSendsAsyncCancel() async throws {
        let fileId = hexBytes("00112233445566778899aabbccddeeff")
        let transport = ControlledReceiveTransport()
        let session = makeAsyncCorrelationSession(transport)
        let asyncId: UInt64 = 0xdead_beef_0000_0042

        let task = Task {
            try await session.readChunk(treeId: 0x3344, fileId: fileId, offset: 0, length: 3)
        }
        try await waitForOutboundFrameCount(1, transport: transport)
        let readHeader = try SMB2Header.decode(try unframed(transport.outbound)[0])

        transport.enqueueInbound(try framed([
            try smb2AsyncPendingResponse(command: SMB2Commands.read, messageId: readHeader.messageId, asyncId: asyncId)
        ]))
        try await waitForDispatchCount(1, session: session)

        task.cancel()
        try await waitForOutboundFrameCount(2, transport: transport)
        let cancelHeader = try SMB2Header.decode(try unframed(transport.outbound)[1])
        XCTAssertEqual(cancelHeader.command, SMB2Commands.cancel)
        XCTAssertTrue(cancelHeader.isAsync)
        XCTAssertEqual(cancelHeader.asyncId, asyncId)
        XCTAssertEqual(cancelHeader.messageId, readHeader.messageId)

        do {
            _ = try await awaitWithTimeout("cancelled async read") { try await task.value }
            XCTFail("cancelled READ unexpectedly completed")
        } catch is CancellationError {
        }
    }

    // cancel 先着なら sync CANCEL を送り、後着 interim では 2 本目の CANCEL を送らない。
    // tombstone は interim の AsyncId を保存し、async final を相関検査のうえ drain する。
    func testCancelBeforeInterimDrainsTombstoneWithAsyncFinal() async throws {
        let fileId = hexBytes("00112233445566778899aabbccddeeff")
        let transport = ControlledReceiveTransport()
        let session = makeAsyncCorrelationSession(transport)
        let asyncId: UInt64 = 0x0bad_cafe_0000_0001

        let task = Task {
            try await session.readChunk(treeId: 0x3344, fileId: fileId, offset: 0, length: 3)
        }
        try await waitForOutboundFrameCount(1, transport: transport)
        let readHeader = try SMB2Header.decode(try unframed(transport.outbound)[0])

        task.cancel()
        try await waitForOutboundFrameCount(2, transport: transport)
        let cancelHeader = try SMB2Header.decode(try unframed(transport.outbound)[1])
        XCTAssertEqual(cancelHeader.treeId, 0)
        XCTAssertNil(cancelHeader.asyncId)
        do {
            _ = try await awaitWithTimeout("cancelled read") { try await task.value }
            XCTFail("cancelled READ unexpectedly completed")
        } catch is CancellationError {
        }

        let dispatchBase = await session.receivedPacketDispatchCountForTesting()
        transport.enqueueInbound(try framed([
            try smb2AsyncPendingResponse(command: SMB2Commands.read, messageId: readHeader.messageId, asyncId: asyncId)
        ]))
        try await waitForDispatchCount(dispatchBase + 1, session: session)
        transport.enqueueInbound(try framed([
            try smb2AsyncReadResponse([0x61], messageId: readHeader.messageId, asyncId: asyncId)
        ]))
        try await waitForDispatchCount(dispatchBase + 2, session: session)

        // No second CANCEL was sent for the late interim, and the tombstone drained.
        let requests = try unframed(transport.outbound)
        XCTAssertEqual(requests.count, 2)
        let pendingCount = await session.pendingCountForTesting()
        let wirePendingCount = await session.wirePendingRecordCountForTesting()
        XCTAssertEqual(pendingCount, 0)
        XCTAssertEqual(wirePendingCount, 0, "the cancellation tombstone is retired by its async final")
    }

    func testReadCancellationSendsSMB2Cancel() async throws {
        let fileId = hexBytes("00112233445566778899aabbccddeeff")
        let transport = ControlledReceiveTransport()
        let session = SMBSession(
            host: "server",
            port: 445,
            credential: SMBCredential(username: "user", password: "pass"),
            transport: transport,
            signingKey: Array(repeating: UInt8(0x11), count: 16)
        )

        let task = Task {
            try await session.readChunk(treeId: 0x3344, fileId: fileId, offset: 0, length: 1024)
        }

        try await waitForOutboundFrameCount(1, transport: transport)
        task.cancel()
        try await waitForOutboundFrameCount(2, transport: transport)

        let requests = try unframed(transport.outbound)
        let readHeader = try SMB2Header.decode(requests[0])
        let cancelHeader = try SMB2Header.decode(requests[1])
        XCTAssertEqual(readHeader.command, SMB2Commands.read)
        XCTAssertEqual(cancelHeader.command, SMB2Commands.cancel)
        XCTAssertEqual(cancelHeader.messageId, readHeader.messageId)
        // Pre-interim cancellation uses the sync CANCEL form with TreeId 0 (MS-SMB2 §2.2.1.2).
        XCTAssertEqual(cancelHeader.treeId, 0)
        XCTAssertNil(cancelHeader.asyncId)

        transport.enqueueInbound(try framed([
            try smb2StatusResponse(
                status: SMB2Status.cancelled,
                command: SMB2Commands.read,
                messageId: readHeader.messageId,
                treeId: readHeader.treeId
            )
        ]))

        do {
            _ = try await awaitWithTimeout("cancel READ") {
                try await task.value
            }
            XCTFail("cancelled READ unexpectedly completed")
        } catch is CancellationError {
        }
    }

    func testCancelledEchoResponseReturnsCreditForNextRequest() async throws {
        let transport = ControlledReceiveTransport()
        let session = SMBSession(
            host: "server",
            port: 445,
            credential: SMBCredential(username: "user", password: "pass"),
            transport: transport,
            initialCredits: 1
        )

        let first = Task { try await session.echo() }
        try await waitForOutboundFrameCount(1, transport: transport)
        let firstHeader = try SMB2Header.decode(try unframed(transport.outbound)[0])
        XCTAssertEqual(firstHeader.messageId, 0)
        first.cancel()
        try await waitForOutboundFrameCount(2, transport: transport)
        let cancelHeader = try SMB2Header.decode(try unframed(transport.outbound)[1])
        XCTAssertEqual(cancelHeader.command, SMB2Commands.cancel)
        XCTAssertEqual(cancelHeader.messageId, firstHeader.messageId, "CANCEL reuses the target MID")
        transport.enqueueInbound(try framed([smb2EchoResponse(messageId: firstHeader.messageId)]))

        do {
            try await awaitWithTimeout("cancelled ECHO") { try await first.value }
            XCTFail("cancelled ECHO unexpectedly completed")
        } catch is CancellationError {
        }

        let second = Task { try await session.echo() }
        try await waitForOutboundFrameCount(3, transport: transport)
        let secondHeader = try SMB2Header.decode(try unframed(transport.outbound)[2])
        XCTAssertEqual(secondHeader.messageId, firstHeader.messageId + 1)
        transport.enqueueInbound(try framed([smb2EchoResponse(messageId: secondHeader.messageId)]))
        try await awaitWithTimeout("ECHO after cancelled ECHO") { try await second.value }
    }

    func testEncryptedEchoRejectsPlaintextStatusPendingBeforeCorrelationOrGrant() async throws {
        let transport = ControlledReceiveTransport()
        let encryptionKey = [UInt8](repeating: 0x6D, count: 16)
        let sessionId: UInt64 = 0x8877_6655_4433_2211
        let session = SMBSession(
            host: "server",
            port: 445,
            credential: .anonymous,
            transport: transport,
            initialCredits: 2
        )
        await session.installEncryptionStateForTesting(
            encryptionKey: encryptionKey,
            decryptionKey: encryptionKey,
            sessionId: sessionId
        )

        let echo = Task { try await session.echo() }
        try await awaitWithTimeout("encrypted ECHO is sent") {
            await session.waitForRequestSentCountForTesting(atLeast: 1)
        }
        let request = try XCTUnwrap(try unframed(transport.outbound).first)
        XCTAssertTrue(request.starts(with: SMB3TransformHeader.protocolId), "ECHO must be sent inside SMB3 transform")
        let messageId: UInt64 = 0
        let creditsBefore = await session.creditBalanceForTesting()
        let grantsBefore = await session.creditGrantReceiptCountForTesting()
        for innerSessionId in [sessionId, UInt64(0)] {
            let plainInterim = try smb2AsyncPendingResponse(
                command: SMB2Commands.echo,
                messageId: messageId,
                asyncId: 0x1234_5678,
                sessionId: innerSessionId,
                credits: UInt16.max
            )
            do {
                _ = try await session.processRawFrameForTesting(plainInterim, generation: 1)
                XCTFail("a plaintext STATUS_PENDING cannot answer an encrypted request")
            } catch SMBCodecError.invalidValue(let message) {
                XCTAssertTrue(message.contains("plaintext SMB response to an encrypted request"), message)
            }

            let asyncIdAfter = await session.pendingAsyncIdForTesting(messageId: messageId)
            let interimCountAfter = await session.pendingInterimCountForTesting(messageId: messageId)
            let pendingCountAfter = await session.pendingCountForTesting()
            let creditsAfter = await session.creditBalanceForTesting()
            let grantsAfter = await session.creditGrantReceiptCountForTesting()
            XCTAssertNil(asyncIdAfter)
            XCTAssertEqual(interimCountAfter, 0)
            XCTAssertEqual(pendingCountAfter, 1)
            XCTAssertEqual(creditsAfter, creditsBefore)
            XCTAssertEqual(grantsAfter, grantsBefore)
        }
        XCTAssertEqual(grantsBefore, 0)

        await session.closeTransportAndWait(cause: "test_encrypted_request_rejects_plaintext_interim")
        do {
            try await awaitWithTimeout("encrypted ECHO teardown") { try await echo.value }
            XCTFail("the rejected plaintext interim must not complete ECHO")
        } catch {
        }
    }

    func testEncryptedEarlyFinalDiscardsPlaintextFinalUntilSendCompletes() async throws {
        try await assertEncryptedEarlyFinalDiscardsPlaintextPostFinalFrame(isInterim: false)
    }

    func testEncryptedEarlyFinalDiscardsPlaintextStatusPendingUntilSendCompletes() async throws {
        try await assertEncryptedEarlyFinalDiscardsPlaintextPostFinalFrame(isInterim: true)
    }

    private func assertEncryptedEarlyFinalDiscardsPlaintextPostFinalFrame(isInterim: Bool) async throws {
        let transport = ControlledReceiveTransport()
        let encryptionKey = [UInt8](repeating: 0x6D, count: 16)
        let sessionId: UInt64 = 0x8877_6655_4433_2211
        let session = SMBSession(
            host: "server",
            port: 445,
            credential: .anonymous,
            transport: transport,
            initialCredits: 4
        )
        await session.installEncryptionStateForTesting(
            encryptionKey: encryptionKey,
            decryptionKey: encryptionKey,
            sessionId: sessionId
        )
        var sessionJoined = false
        defer {
            if !sessionJoined {
                transport.releaseBlockedSend()
                Task { await session.closeTransportAndWait(cause: "encrypted_early_final_test_cleanup") }
            }
        }

        // R keeps the single reader alive while X is still inside transport.send.
        let unrelatedRequest = Task { try await session.echo() }
        try await awaitWithTimeout("unrelated encrypted ECHO sent") {
            await session.waitForRequestSentCountForTesting(atLeast: 1)
        }
        let unrelatedRequestBytes = try XCTUnwrap(try unframed(transport.outbound).first)
        XCTAssertTrue(unrelatedRequestBytes.starts(with: SMB3TransformHeader.protocolId))
        let readerClock = ManualSMBSleeper()
        try await awaitWithTimeout("reader waits for R response") {
            try await transport.waitForReceiveCount(
                atLeast: 1,
                timeout: .seconds(1),
                sleeper: { try await readerClock.sleep(for: $0) }
            )
        }
        let readerRunningForR = await session.receiveLoopRunningForTesting()
        XCTAssertTrue(readerRunningForR)

        transport.blockNextSend()
        let earlyFinalRequest = Task { try await session.echo() }
        let sendClock = ManualSMBSleeper()
        try await awaitWithTimeout("encrypted X send is held") {
            try await transport.waitForSendAttemptCount(
                atLeast: 2,
                timeout: .seconds(1),
                sleeper: { try await sendClock.sleep(for: $0) }
            )
        }
        let blockedSendBytes = try XCTUnwrap(transport.firstBlockedSendBytes)
        let blockedSendLength = try DirectTCPFraming.length(from: Array(blockedSendBytes.prefix(4)))
        XCTAssertEqual(
            Array(blockedSendBytes[4..<(4 + blockedSendLength)].prefix(4)),
            SMB3TransformHeader.protocolId,
            "X must be an encrypted request while its send completion is held"
        )
        let pendingRequests = await session.pendingCountForTesting()
        XCTAssertEqual(pendingRequests, 2)

        // The fresh session assigns R MID 0 and X MID 1. X's transform is authenticated,
        // with matching command, MID, and inner/outer SessionId.
        let xMessageId: UInt64 = 1
        let earlyFinal = try SMB2Header(
            command: SMB2Commands.echo,
            credits: 1,
            messageId: xMessageId,
            sessionId: sessionId
        ).encode() + [4, 0, 0, 0]
        let encryptedEarlyFinal = try smb3CCMTransform(
            earlyFinal,
            key: encryptionKey,
            nonce: Array(repeating: 0x41, count: 11),
            sessionId: sessionId
        )
        transport.enqueueInbound(try framed([encryptedEarlyFinal]))
        try await awaitWithTimeout("encrypted early final accepted for X") {
            await session.waitForReceivedPacketDispatchCountForTesting(atLeast: 1)
        }
        let finalSeenBeforeSend = await session.pendingFinalSeenForTesting(messageId: xMessageId)
        let callerResumedBeforeSend = await session.pendingContinuationResumedForTesting(messageId: xMessageId)
        XCTAssertTrue(finalSeenBeforeSend)
        XCTAssertFalse(callerResumedBeforeSend)
        let sessionOpenAfterEarlyFinal = !(await session.isTransportClosedForTesting())
        XCTAssertTrue(sessionOpenAfterEarlyFinal)

        let plaintextPostFinal: [UInt8]
        if isInterim {
            plaintextPostFinal = try smb2AsyncPendingResponse(
                command: SMB2Commands.echo,
                messageId: xMessageId,
                asyncId: 0x1234_5678,
                sessionId: sessionId,
                credits: UInt16.max
            )
        } else {
            plaintextPostFinal = try SMB2Header(
                command: SMB2Commands.echo,
                credits: UInt16.max,
                messageId: xMessageId,
                sessionId: sessionId
            ).encode() + [4, 0, 0, 0]
        }
        let dispatchCountAfterEarlyFinal = await session.receivedPacketDispatchCountForTesting()
        transport.enqueueInbound(try framed([plaintextPostFinal]))
        try await awaitWithTimeout("plaintext post-final frame discarded while X send is held") {
            await session.waitForReceivedPacketDispatchCountForTesting(atLeast: dispatchCountAfterEarlyFinal + 1)
        }
        let sessionOpenWhileXSendHeld = !(await session.isTransportClosedForTesting())
        XCTAssertTrue(sessionOpenWhileXSendHeld)
        let readerRunningWhileXSendHeld = await session.receiveLoopRunningForTesting()
        XCTAssertTrue(readerRunningWhileXSendHeld)
        let finalStillSeenBeforeSend = await session.pendingFinalSeenForTesting(messageId: xMessageId)
        let callerStillBlocked = await session.pendingContinuationResumedForTesting(messageId: xMessageId)
        XCTAssertTrue(finalStillSeenBeforeSend)
        XCTAssertFalse(callerStillBlocked)

        let grantsBeforeSendRelease = await session.creditGrantReceiptCountForTesting()
        XCTAssertEqual(grantsBeforeSendRelease, 1, "the discarded plaintext frame grants no credits")
        transport.releaseBlockedSend()
        try await awaitWithTimeout("X succeeds after its full send") { try await earlyFinalRequest.value }
        let pendingAfterXCompletes = await session.pendingCountForTesting()
        XCTAssertEqual(pendingAfterXCompletes, 1, "R remains outstanding after X completes")

        // Once X is retired, the same late plaintext frame is unknown and must also leave
        // the shared session and R's reader untouched.
        let dispatchCountAfterXCompletes = await session.receivedPacketDispatchCountForTesting()
        transport.enqueueInbound(try framed([plaintextPostFinal]))
        try await awaitWithTimeout("same plaintext frame discarded after X send completes") {
            await session.waitForReceivedPacketDispatchCountForTesting(atLeast: dispatchCountAfterXCompletes + 1)
        }
        let sessionOpenAfterPostSendDuplicate = !(await session.isTransportClosedForTesting())
        XCTAssertTrue(sessionOpenAfterPostSendDuplicate)

        let unrelatedFinal = try SMB2Header(
            command: SMB2Commands.echo,
            credits: 1,
            messageId: 0,
            sessionId: sessionId
        ).encode() + [4, 0, 0, 0]
        let encryptedUnrelatedFinal = try smb3CCMTransform(
            unrelatedFinal,
            key: encryptionKey,
            nonce: Array(repeating: 0x42, count: 11),
            sessionId: sessionId
        )
        transport.enqueueInbound(try framed([encryptedUnrelatedFinal]))
        try await awaitWithTimeout("R succeeds after X") { try await unrelatedRequest.value }
        let sessionOpenAfterBothRequests = !(await session.isTransportClosedForTesting())
        XCTAssertTrue(sessionOpenAfterBothRequests)
        XCTAssertEqual(transport.closeCount, 0)

        await session.closeTransportAndWait(cause: "encrypted_early_final_plaintext_post_final")
        sessionJoined = true
    }

    func testChangeNotifyEventConvenienceProperties() {
        let changes = [
            SMBFileChange(action: .added, name: "new.txt")
        ]
        let changeEvent = SMBChangeNotifyEvent.changes(changes)
        let overflowEvent = SMBChangeNotifyEvent.overflow

        XCTAssertEqual(changeEvent.changes, changes)
        XCTAssertFalse(changeEvent.requiresRescan)
        XCTAssertNil(overflowEvent.changes)
        XCTAssertTrue(overflowEvent.requiresRescan)
    }

    func testSessionQueryDirectoryStreamsPagesUntilNoMoreFiles() async throws {
        let fileId = hexBytes("00112233445566778899aabbccddeeff")
        let inbound = try framed([
            try smb2QueryDirectoryResponse(
                entries: [
                    makeDirectoryEntry(name: "a.txt", isDirectory: false, fileSize: 1, nextOffset: 0)
                ],
                messageId: 0,
                treeId: 0x3344
            ),
            try smb2QueryDirectoryResponse(
                entries: [
                    makeDirectoryEntry(name: "b", isDirectory: true, nextOffset: 0)
                ],
                messageId: 1,
                treeId: 0x3344
            ),
            try smb2StatusResponse(status: SMB2Status.noMoreFiles, command: SMB2Commands.queryDirectory, messageId: 2, treeId: 0x3344)
        ])
        let transport = InMemoryTransport(inbound: inbound)
        let session = SMBSession(
            host: "server",
            port: 445,
            credential: SMBCredential(username: "user", password: "pass"),
            transport: transport,
            signingKey: Array(repeating: UInt8(0x11), count: 16)
        )

        let streamed = TestDirectoryEntryCollector()
        try await session.queryDirectory(treeId: 0x3344, fileId: fileId) { entry in
            streamed.append(entry)
        }

        XCTAssertEqual(streamed.entries, [
            SMBDirectoryEntry(name: "a.txt", fileSize: 1, isDirectory: false, attributes: 0x80),
            SMBDirectoryEntry(name: "b", fileSize: 0, isDirectory: true, attributes: 0x10)
        ])
        let requests = try unframed(transport.outbound)
        XCTAssertEqual(requests.map { try? SMB2Header.decode($0).command }, [
            SMB2Commands.queryDirectory,
            SMB2Commands.queryDirectory,
            SMB2Commands.queryDirectory
        ])
        XCTAssertEqual(requests[0][67], 0x01)
        XCTAssertEqual(requests[1][67], 0x00)
        XCTAssertEqual(requests[2][67], 0x00)
    }

    func testSessionQueryDirectoryStopsOnEmptySuccessPage() async throws {
        let fileId = hexBytes("00112233445566778899aabbccddeeff")
        let inbound = try framed([
            try smb2QueryDirectoryResponse(entries: [], messageId: 0, treeId: 0x3344)
        ])
        let transport = InMemoryTransport(inbound: inbound)
        let session = SMBSession(host: "server", port: 445,
                                 credential: SMBCredential(username: "user", password: "pass"),
                                 transport: transport)
        let collector = TestDirectoryEntryCollector()
        try await session.queryDirectory(treeId: 0x3344, fileId: fileId) { collector.append($0) }
        XCTAssertEqual(collector.entries.count, 0)
        XCTAssertEqual(try unframed(transport.outbound).count, 1)
    }

    func testDCERPCResponseFragmentValidationRejectsWrongCallID() throws {
        var response = try DCERPC.encodeRequest(callId: 99, opnum: 1, stub: [])
        response[2] = 2
        response[3] = 3
        XCTAssertThrowsError(try DCERPC.validateResponseFragments(response, expectedCallId: 1))
    }

    func testClientSessionReusesConnectedTreeForMultipleOperations() async throws {
        let directoryFileId = hexBytes("00112233445566778899aabbccddeeff")
        let statFileId = hexBytes("ffeeddccbbaa99887766554433221100")
        let inbound = try framed([
            try smb2CreateResponse(fileId: directoryFileId, messageId: 0, treeId: 0x3344),
            try smb2QueryDirectoryResponse(
                entries: [
                    makeDirectoryEntry(name: "a.txt", isDirectory: false, fileSize: 7, nextOffset: 0)
                ],
                messageId: 1,
                treeId: 0x3344
            ),
            try smb2StatusResponse(status: SMB2Status.noMoreFiles, command: SMB2Commands.queryDirectory, messageId: 2, treeId: 0x3344),
            try smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.close, messageId: 3, treeId: 0x3344),
            try smb2CreateResponse(fileId: statFileId, messageId: 4, treeId: 0x3344),
            try smb2QueryInfoResponse(size: 7, messageId: 5, treeId: 0x3344),
            try smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.close, messageId: 6, treeId: 0x3344)
        ])
        let transport = InMemoryTransport(inbound: inbound)
        let session = SMBSession(
            host: "server",
            port: 445,
            credential: SMBCredential(username: "user", password: "pass"),
            transport: transport,
            signingKey: Array(repeating: UInt8(0x11), count: 16)
        )
        let clientSession = SMBClientSession(session: session, treeId: 0x3344)

        let entries = try await clientSession.list(path: "")
        let stat = try await clientSession.stat(path: "a.txt")

        XCTAssertEqual(entries, [SMBDirectoryEntry(name: "a.txt", fileSize: 7, isDirectory: false, attributes: 0x80)])
        XCTAssertEqual(stat.size, 7)
        let requests = try unframed(transport.outbound)
        XCTAssertEqual(requests.map { try? SMB2Header.decode($0).command }, [
            SMB2Commands.create,
            SMB2Commands.queryDirectory,
            SMB2Commands.queryDirectory,
            SMB2Commands.close,
            SMB2Commands.create,
            SMB2Commands.queryInfo,
            SMB2Commands.close
        ])
        XCTAssertTrue(requests.allSatisfy { (try? SMB2Header.decode($0).treeId) == 0x3344 })
    }

    func testClientSessionWithTreeUsesAdditionalTreeAndDisconnectsIt() async throws {
        let fileId = hexBytes("00112233445566778899aabbccddeeff")
        let inbound = try framed([
            try smb2TreeConnectResponse(
                treeId: 0x7788,
                shareType: 1,
                shareFlags: 0,
                capabilities: 0,
                maximalAccess: 0x001f_01ff,
                messageId: 0
            ),
            try smb2CreateResponse(fileId: fileId, messageId: 1, treeId: 0x7788),
            try smb2QueryDirectoryResponse(
                entries: [
                    makeDirectoryEntry(name: "b.txt", isDirectory: false, fileSize: 9, nextOffset: 0)
                ],
                messageId: 2,
                treeId: 0x7788
            ),
            try smb2StatusResponse(status: SMB2Status.noMoreFiles, command: SMB2Commands.queryDirectory, messageId: 3, treeId: 0x7788),
            try smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.close, messageId: 4, treeId: 0x7788),
            try smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.treeDisconnect, messageId: 5, treeId: 0x7788)
        ])
        let transport = InMemoryTransport(inbound: inbound)
        let session = SMBSession(
            host: "server",
            port: 445,
            credential: SMBCredential(username: "user", password: "pass"),
            transport: transport,
            signingKey: Array(repeating: UInt8(0x11), count: 16)
        )
        let clientSession = SMBClientSession(session: session, treeId: 0x3344)

        let entries = try await clientSession.withTree(share: "other") { tree in
            try await tree.list(path: "")
        }

        XCTAssertEqual(entries, [SMBDirectoryEntry(name: "b.txt", fileSize: 9, isDirectory: false, attributes: 0x80)])
        let requests = try unframed(transport.outbound)
        XCTAssertEqual(requests.map { try? SMB2Header.decode($0).command }, [
            SMB2Commands.treeConnect,
            SMB2Commands.create,
            SMB2Commands.queryDirectory,
            SMB2Commands.queryDirectory,
            SMB2Commands.close,
            SMB2Commands.treeDisconnect
        ])
        XCTAssertEqual(try SMB2Header.decode(requests[0]).treeId, 0)
        XCTAssertTrue(requests.dropFirst().allSatisfy { (try? SMB2Header.decode($0).treeId) == 0x7788 })
    }

    func testClientSessionReadProgressIsMonotonicAndFinishesAtTotal() async throws {
        let fileId = hexBytes("00112233445566778899aabbccddeeff")
        let inbound = try framed([
            try smb2CreateResponse(fileId: fileId, messageId: 0, treeId: 0x3344),
            try smb2QueryInfoResponse(size: 5, messageId: 1, treeId: 0x3344),
            try smb2ReadResponse(Array("hel".utf8), messageId: 2, treeId: 0x3344),
            try smb2ReadResponse(Array("lo".utf8), messageId: 3, treeId: 0x3344),
            try smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.close, messageId: 4, treeId: 0x3344)
        ])
        let transport = InMemoryTransport(inbound: inbound)
        let session = SMBSession(
            host: "server",
            port: 445,
            credential: SMBCredential(username: "user", password: "pass"),
            transport: transport,
            signingKey: Array(repeating: UInt8(0x11), count: 16)
        )
        let clientSession = SMBClientSession(session: session, treeId: 0x3344)
        let progress = TransferProgressCollector()

        let data = try await clientSession.read(path: "file.txt", onProgress: progress.append)

        XCTAssertEqual(data, Array("hello".utf8))
        let snapshots = progress.snapshots
        XCTAssertFalse(snapshots.isEmpty)
        XCTAssertEqual(snapshots.last?.bytesTransferred, 5)
        XCTAssertEqual(snapshots.last?.totalBytes, 5)
        XCTAssertTrue(zip(snapshots, snapshots.dropFirst()).allSatisfy {
            $0.bytesTransferred < $1.bytesTransferred
        })
        XCTAssertTrue(snapshots.allSatisfy { $0.bytesPerSecond >= 0 })
    }

    func testClientSessionReadPrefixUsesCreateReadCloseWithoutQueryInfo() async throws {
        let fileId = hexBytes("00112233445566778899aabbccddeeff")
        let inbound = try framed([
            try smb2CreateResponse(fileId: fileId, messageId: 0, treeId: 0x3344),
            try smb2ReadResponse(Array("hello".utf8), messageId: 1, treeId: 0x3344),
            try smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.close, messageId: 2, treeId: 0x3344)
        ])
        let transport = InMemoryTransport(inbound: inbound)
        let session = SMBSession(
            host: "server", port: 445,
            credential: SMBCredential(username: "user", password: "pass"),
            transport: transport, signingKey: Array(repeating: UInt8(0x11), count: 16)
        )
        let clientSession = SMBClientSession(session: session, treeId: 0x3344)

        let data = try await clientSession.readPrefix(path: "file.txt", maxLength: 5)

        XCTAssertEqual(data, Array("hello".utf8))
        XCTAssertEqual(try unframed(transport.outbound).map { try SMB2Header.decode($0).command }, [
            SMB2Commands.create, SMB2Commands.read, SMB2Commands.close
        ])
    }

    func testClientSessionReadPrefixStopsAfterShortSuccessWhenMaxLengthExceedsFile() async throws {
        let fileId = hexBytes("00112233445566778899aabbccddeeff")
        let inbound = try framed([
            try smb2CreateResponse(fileId: fileId, messageId: 0, treeId: 0x3344),
            try smb2ReadResponse(Array("hello".utf8), messageId: 1, treeId: 0x3344),
            try smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.close, messageId: 2, treeId: 0x3344)
        ])
        let transport = InMemoryTransport(inbound: inbound)
        let session = SMBSession(
            host: "server", port: 445,
            credential: SMBCredential(username: "user", password: "pass"),
            transport: transport, signingKey: Array(repeating: UInt8(0x11), count: 16)
        )
        let clientSession = SMBClientSession(session: session, treeId: 0x3344)

        let data = try await clientSession.readPrefix(path: "short.bin", maxLength: 131_072)

        XCTAssertEqual(data, Array("hello".utf8))
        XCTAssertEqual(try unframed(transport.outbound).map { try SMB2Header.decode($0).command }, [
            SMB2Commands.create, SMB2Commands.read, SMB2Commands.close
        ])
    }

    func testClientSessionReadPrefixZeroDoesNotOpenAHandle() async throws {
        let transport = InMemoryTransport()
        let session = SMBSession(
            host: "server", port: 445,
            credential: SMBCredential(username: "user", password: "pass"),
            transport: transport, signingKey: Array(repeating: UInt8(0x11), count: 16)
        )
        let clientSession = SMBClientSession(session: session, treeId: 0x3344)

        let data = try await clientSession.readPrefix(path: "file.txt", maxLength: 0)
        XCTAssertEqual(data, [])
        XCTAssertTrue(transport.outbound.isEmpty)
    }

    func testClientSessionReadPrefixCancelledZeroLengthDoesNotOpenAHandle() async throws {
        let transport = InMemoryTransport()
        let session = SMBSession(
            host: "server", port: 445,
            credential: SMBCredential(username: "user", password: "pass"),
            transport: transport, signingKey: Array(repeating: UInt8(0x11), count: 16)
        )
        let clientSession = SMBClientSession(session: session, treeId: 0x3344)
        let task = Task {
            // Deterministic ordering: the API must only run once cancellation is already
            // delivered. Cancelling a freshly created Task races with its body on other
            // schedulers (observed on Linux CI: the body completed before cancel()).
            while !Task.isCancelled { await Task.yield() }
            return try await clientSession.readPrefix(path: "file.txt", maxLength: 0)
        }
        task.cancel()

        do {
            _ = try await task.value
            XCTFail("cancelled zero-length readPrefix unexpectedly completed")
        } catch is CancellationError {
        }
        XCTAssertTrue(transport.outbound.isEmpty)
    }

    func testClientSessionPrefixStreamCancelledZeroLengthDoesNotOpenAHandle() async throws {
        let transport = InMemoryTransport()
        let session = SMBSession(
            host: "server", port: 445,
            credential: SMBCredential(username: "user", password: "pass"),
            transport: transport, signingKey: Array(repeating: UInt8(0x11), count: 16)
        )
        let clientSession = SMBClientSession(session: session, treeId: 0x3344)
        let task = Task {
            // Same deterministic ordering as the readPrefix variant above.
            while !Task.isCancelled { await Task.yield() }
            try await clientSession.withPrefixReadStream(path: "file.txt", maxLength: 0) { _ in }
        }
        task.cancel()

        do {
            try await task.value
            XCTFail("cancelled zero-length prefix stream unexpectedly completed")
        } catch is CancellationError {
        }
        XCTAssertTrue(transport.outbound.isEmpty)
    }

    /// A zero-length file is indistinguishable from a truncated one without QUERY_INFO, so the
    /// first READ has to carry the whole answer: EOF on the initial request yields an empty
    /// prefix instead of an error.
    func testClientSessionReadPrefixOnEmptyFileReturnsNoBytes() async throws {
        let fileId = hexBytes("00112233445566778899aabbccddeeff")
        let inbound = try framed([
            try smb2CreateResponse(fileId: fileId, messageId: 0, treeId: 0x3344),
            try smb2StatusResponse(status: SMB2Status.endOfFile, command: SMB2Commands.read, messageId: 1, treeId: 0x3344),
            try smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.close, messageId: 2, treeId: 0x3344)
        ])
        let transport = InMemoryTransport(inbound: inbound)
        let session = SMBSession(
            host: "server", port: 445,
            credential: SMBCredential(username: "user", password: "pass"),
            transport: transport, signingKey: Array(repeating: UInt8(0x11), count: 16)
        )
        let clientSession = SMBClientSession(session: session, treeId: 0x3344)

        let data = try await clientSession.readPrefix(path: "empty.bin", maxLength: 65_536)

        XCTAssertEqual(data, [])
        // One READ only: the EOF status must not be probed a second time.
        XCTAssertEqual(try unframed(transport.outbound).map { try SMB2Header.decode($0).command }, [
            SMB2Commands.create, SMB2Commands.read, SMB2Commands.close
        ])
    }

    func testClientSessionReadPrefixRejectsInMemoryLimitBeforeCreate() async throws {
        let transport = InMemoryTransport()
        let session = SMBSession(
            host: "server", port: 445,
            credential: SMBCredential(username: "user", password: "pass"),
            transport: transport, signingKey: Array(repeating: UInt8(0x11), count: 16)
        )
        let clientSession = SMBClientSession(session: session, treeId: 0x3344)

        do {
            _ = try await clientSession.readPrefix(
                path: "large.bin",
                maxLength: SMBClientSession.maxPrefixReadLength + 1
            )
            XCTFail("expected prefix accumulation limit to fail")
        } catch {
            // Expected.
        }
        XCTAssertTrue(transport.outbound.isEmpty)
    }

    func testClientSessionReadPrefixStopsAfterShortSuccessAndReturnsOnEOF() async throws {
        let fileId = hexBytes("00112233445566778899aabbccddeeff")
        let inbound = try framed([
            try smb2CreateResponse(fileId: fileId, messageId: 0, treeId: 0x3344),
            try smb2ReadResponse(Array("hel".utf8), messageId: 1, treeId: 0x3344),
            try smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.close, messageId: 2, treeId: 0x3344),
            try smb2CreateResponse(fileId: fileId, messageId: 3, treeId: 0x3344),
            try smb2ReadResponse(Array(repeating: UInt8(0x5a), count: 65_536), messageId: 4, treeId: 0x3344),
            try smb2StatusResponse(status: SMB2Status.endOfFile, command: SMB2Commands.read, messageId: 5, treeId: 0x3344),
            try smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.close, messageId: 6, treeId: 0x3344)
        ])
        let transport = InMemoryTransport(inbound: inbound)
        let session = SMBSession(
            host: "server", port: 445,
            credential: SMBCredential(username: "user", password: "pass"),
            transport: transport, signingKey: Array(repeating: UInt8(0x11), count: 16)
        )
        let clientSession = SMBClientSession(session: session, treeId: 0x3344)

        let shortData = try await clientSession.readPrefix(path: "short.bin", maxLength: 5)
        XCTAssertEqual(shortData, Array("hel".utf8))
        let eofData = try await clientSession.readPrefix(path: "eof.bin", maxLength: 131_072)
        XCTAssertEqual(eofData, Array(repeating: UInt8(0x5a), count: 65_536))
        let requests = try unframed(transport.outbound)
        let readRequests = requests.filter { (try? SMB2Header.decode($0).command) == SMB2Commands.read }
        // SMB2 header (64) + StructureSize (2) + Padding (1) + Flags (1) = Length at 68;
        // the following UInt64LE field is Offset at 72.
        XCTAssertEqual(readRequests.map { readUInt32LE($0, at: 68) }, [5, 65_536, 65_536])
        XCTAssertEqual(readRequests.map { readUInt64LE($0, at: 72) }, [0, 0, 65_536])
        XCTAssertEqual(try requests.map { try SMB2Header.decode($0).command }, [
            SMB2Commands.create, SMB2Commands.read, SMB2Commands.close,
            SMB2Commands.create, SMB2Commands.read, SMB2Commands.read, SMB2Commands.close
        ])
    }

    func testClientSessionReadPrefixRejectsOversizeResponseAndCloses() async throws {
        let fileId = hexBytes("00112233445566778899aabbccddeeff")
        let inbound = try framed([
            try smb2CreateResponse(fileId: fileId, messageId: 0, treeId: 0x3344),
            try smb2ReadResponse(Array(repeating: UInt8(0x5a), count: 65_537), messageId: 1, treeId: 0x3344),
            try smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.close, messageId: 2, treeId: 0x3344)
        ])
        let transport = InMemoryTransport(inbound: inbound)
        let session = SMBSession(
            host: "server", port: 445,
            credential: SMBCredential(username: "user", password: "pass"),
            transport: transport, signingKey: Array(repeating: UInt8(0x11), count: 16)
        )
        let clientSession = SMBClientSession(session: session, treeId: 0x3344)

        do {
            // maxLength must exceed the 65,536-byte chunk request: with remaining == requestLength
            // an oversized response also trips advancedReadPosition (received > remaining), which
            // would mask a deleted oversize guard. remaining = 131,072 isolates the guard itself.
            _ = try await clientSession.readPrefix(path: "bad.bin", maxLength: 131_072)
            XCTFail("expected oversized READ response to fail")
        } catch SMBCodecError.invalidValue(let message) {
            // Pin the failure to the oversize guard, not some other invalidValue path.
            XCTAssertTrue(message.contains("more data than requested"), "unexpected failure: \(message)")
        }
        XCTAssertEqual(try unframed(transport.outbound).map { try SMB2Header.decode($0).command }, [
            SMB2Commands.create, SMB2Commands.read, SMB2Commands.close
        ])
    }

    func testClientSessionReadPrefixRejectsDirectoryAtCreateWithoutRead() async throws {
        let transport = InMemoryTransport(inbound: try framed([
            try smb2StatusResponse(
                status: SMB2Status.fileIsADirectory,
                command: SMB2Commands.create,
                messageId: 0,
                treeId: 0x3344
            )
        ]))
        let session = SMBSession(
            host: "server", port: 445,
            credential: SMBCredential(username: "user", password: "pass"),
            transport: transport, signingKey: Array(repeating: UInt8(0x11), count: 16)
        )
        let clientSession = SMBClientSession(session: session, treeId: 0x3344)

        do {
            _ = try await clientSession.readPrefix(path: "directory", maxLength: 1)
            XCTFail("readPrefix unexpectedly opened a directory")
        } catch SMBError.fileIsADirectory {
        }

        XCTAssertEqual(try unframed(transport.outbound).map { try SMB2Header.decode($0).command }, [
            SMB2Commands.create
        ])
    }

    func testClientSessionPrefixStreamStopsAfterShortSuccess() async throws {
        let fileId = hexBytes("00112233445566778899aabbccddeeff")
        let transport = InMemoryTransport(inbound: try framed([
            try smb2CreateResponse(fileId: fileId, messageId: 0, treeId: 0x3344),
            try smb2ReadResponse(Array("hello".utf8), messageId: 1, treeId: 0x3344),
            try smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.close, messageId: 2, treeId: 0x3344)
        ]))
        let session = SMBSession(
            host: "server", port: 445,
            credential: SMBCredential(username: "user", password: "pass"),
            transport: transport, signingKey: Array(repeating: UInt8(0x11), count: 16)
        )
        let clientSession = SMBClientSession(session: session, treeId: 0x3344)
        let chunks = PrefixChunkCollector()

        try await clientSession.withPrefixReadStream(path: "stream.bin", maxLength: 131_072) { chunk in
            chunks.append(chunk)
        }

        XCTAssertEqual(chunks.chunks, [Array("hello".utf8)])
        XCTAssertEqual(try unframed(transport.outbound).map { try SMB2Header.decode($0).command }, [
            SMB2Commands.create, SMB2Commands.read, SMB2Commands.close
        ])
    }

    func testClientSessionPrefixStreamReturnsNormallyOnEOF() async throws {
        let fileId = hexBytes("00112233445566778899aabbccddeeff")
        let transport = InMemoryTransport(inbound: try framed([
            try smb2CreateResponse(fileId: fileId, messageId: 0, treeId: 0x3344),
            try smb2StatusResponse(status: SMB2Status.endOfFile, command: SMB2Commands.read, messageId: 1, treeId: 0x3344),
            try smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.close, messageId: 2, treeId: 0x3344)
        ]))
        let session = SMBSession(
            host: "server", port: 445,
            credential: SMBCredential(username: "user", password: "pass"),
            transport: transport, signingKey: Array(repeating: UInt8(0x11), count: 16)
        )
        let clientSession = SMBClientSession(session: session, treeId: 0x3344)
        let chunks = PrefixChunkCollector()

        try await clientSession.withPrefixReadStream(path: "empty.bin", maxLength: 65_536) { chunk in
            chunks.append(chunk)
        }

        XCTAssertTrue(chunks.chunks.isEmpty)
        XCTAssertEqual(try unframed(transport.outbound).map { try SMB2Header.decode($0).command }, [
            SMB2Commands.create, SMB2Commands.read, SMB2Commands.close
        ])
    }

    func testClientSessionPrefixStreamPropagatesChunkFailureAndCloses() async throws {
        let fileId = hexBytes("00112233445566778899aabbccddeeff")
        let transport = InMemoryTransport(inbound: try framed([
            try smb2CreateResponse(fileId: fileId, messageId: 0, treeId: 0x3344),
            try smb2ReadResponse(Array("data".utf8), messageId: 1, treeId: 0x3344),
            try smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.close, messageId: 2, treeId: 0x3344)
        ]))
        let session = SMBSession(
            host: "server", port: 445,
            credential: SMBCredential(username: "user", password: "pass"),
            transport: transport, signingKey: Array(repeating: UInt8(0x11), count: 16)
        )
        let clientSession = SMBClientSession(session: session, treeId: 0x3344)

        do {
            try await clientSession.withPrefixReadStream(path: "stream.bin", maxLength: 4) { _ in
                throw SMBCodecError.invalidValue("sink failed")
            }
            XCTFail("expected chunk sink failure")
        } catch SMBCodecError.invalidValue {
            // Expected.
        }
        XCTAssertEqual(try unframed(transport.outbound).map { try SMB2Header.decode($0).command }, [
            SMB2Commands.create, SMB2Commands.read, SMB2Commands.close
        ])
    }

    /// issues/070: the stream variant shares readPrefix's limit because the length bounds how
    /// long the handle stays open, and it is rejected before any request is sent.
    func testClientSessionPrefixStreamRejectsPrefixLimitBeforeCreate() async throws {
        let transport = InMemoryTransport()
        let session = SMBSession(
            host: "server", port: 445,
            credential: SMBCredential(username: "user", password: "pass"),
            transport: transport, signingKey: Array(repeating: UInt8(0x11), count: 16)
        )
        let clientSession = SMBClientSession(session: session, treeId: 0x3344)
        let chunks = LockedCounter()

        do {
            try await clientSession.withPrefixReadStream(
                path: "large.bin",
                maxLength: SMBClientSession.maxPrefixReadLength + 1
            ) { _ in chunks.increment() }
            XCTFail("expected the prefix read limit to reject the stream")
        } catch SMBCodecError.invalidValue {
            // Expected.
        }
        XCTAssertTrue(transport.outbound.isEmpty)
        XCTAssertEqual(chunks.value, 0)
    }

    /// The limit is inclusive: exactly `maxPrefixReadLength` still opens the file.
    func testClientSessionPrefixStreamAcceptsExactlyThePrefixLimit() async throws {
        let fileId = hexBytes("00112233445566778899aabbccddeeff")
        let transport = InMemoryTransport(inbound: try framed([
            try smb2CreateResponse(fileId: fileId, messageId: 0, treeId: 0x3344),
            try smb2ReadResponse(Array("data".utf8), messageId: 1, treeId: 0x3344),
            try smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.close, messageId: 2, treeId: 0x3344)
        ]))
        let session = SMBSession(
            host: "server", port: 445,
            credential: SMBCredential(username: "user", password: "pass"),
            transport: transport, signingKey: Array(repeating: UInt8(0x11), count: 16)
        )
        let clientSession = SMBClientSession(session: session, treeId: 0x3344)
        let received = PrefixChunkCollector()

        try await clientSession.withPrefixReadStream(
            path: "stream.bin",
            maxLength: SMBClientSession.maxPrefixReadLength
        ) { chunk in received.append(chunk) }

        XCTAssertEqual(received.chunks, [Array("data".utf8)])
        XCTAssertEqual(try unframed(transport.outbound).map { try SMB2Header.decode($0).command }, [
            SMB2Commands.create, SMB2Commands.read, SMB2Commands.close
        ])
    }

    /// issues/070: there is no built-in operation timeout; the documented way to bound a stalled
    /// (cooperative) onChunk is to wrap the call in SMBOperationDeadline. That must end the call
    /// with `timedOut` and still close the handle.
    func testClientSessionPrefixStreamDeadlineCancelsStalledChunkAndClosesHandle() async throws {
        let fileId = hexBytes("00112233445566778899aabbccddeeff")
        let transport = InMemoryTransport(inbound: try framed([
            try smb2CreateResponse(fileId: fileId, messageId: 0, treeId: 0x3344),
            try smb2ReadResponse(Array("data".utf8), messageId: 1, treeId: 0x3344),
            try smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.close, messageId: 2, treeId: 0x3344)
        ]))
        let session = SMBSession(
            host: "server", port: 445,
            credential: SMBCredential(username: "user", password: "pass"),
            transport: transport, signingKey: Array(repeating: UInt8(0x11), count: 16)
        )
        let clientSession = SMBClientSession(session: session, treeId: 0x3344)
        let chunkEntered = LockedCounter()

        do {
            try await awaitWithTimeout("prefix stream bounded by SMBOperationDeadline") {
                try await SMBOperationDeadline.run(timeout: .milliseconds(100)) {
                    try await clientSession.withPrefixReadStream(path: "stream.bin", maxLength: 4) { _ in
                        chunkEntered.increment()
                        try await Task.sleep(for: .seconds(60))
                    }
                }
            }
            XCTFail("expected the deadline to end the stalled prefix stream")
        } catch SMBTransportError.timedOut {
            // Expected.
        }
        XCTAssertEqual(chunkEntered.value, 1, "the stall must happen inside onChunk, not before the first chunk")
        XCTAssertEqual(try unframed(transport.outbound).map { try SMB2Header.decode($0).command }, [
            SMB2Commands.create, SMB2Commands.read, SMB2Commands.close
        ])
    }

    /// issues/070: the doc promises that cancellation is observed after each chunk. With one
    /// credit every READ is capped at 64 KiB, so a 128 KiB prefix needs two READs; cancelling
    /// inside the first onChunk must stop before the second READ and still close the handle.
    /// The uncancelled control proves the fixture really would issue that second READ.
    func testClientSessionPrefixStreamCancellationAfterChunkStopsBeforeNextRead() async throws {
        let chunk = [UInt8](repeating: 0x42, count: 64 * 1024)
        let fileId = hexBytes("00112233445566778899aabbccddeeff")

        func run(cancelInFirstChunk: Bool) async throws -> (outcome: Result<Void, Error>, commands: [UInt16], chunks: Int) {
            let transport = InMemoryTransport(inbound: try framed([
                try smb2CreateResponse(fileId: fileId, messageId: 0, treeId: 0x3344),
                try smb2ReadResponse(chunk, messageId: 1, treeId: 0x3344),
                cancelInFirstChunk
                    ? try smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.close, messageId: 2, treeId: 0x3344)
                    : try smb2ReadResponse(chunk, messageId: 2, treeId: 0x3344),
                try smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.close, messageId: 3, treeId: 0x3344)
            ]))
            let session = SMBSession(
                host: "server", port: 445,
                credential: SMBCredential(username: "user", password: "pass"),
                transport: transport, signingKey: Array(repeating: UInt8(0x11), count: 16)
            )
            let clientSession = SMBClientSession(session: session, treeId: 0x3344)
            let chunks = LockedCounter()
            let task = Task {
                try await clientSession.withPrefixReadStream(path: "stream.bin", maxLength: 128 * 1024) { _ in
                    chunks.increment()
                    if cancelInFirstChunk {
                        withUnsafeCurrentTask { $0?.cancel() }
                    }
                }
            }
            let outcome = await awaitResult { try await task.value }
            let commands = try unframed(transport.outbound).map { try SMB2Header.decode($0).command }
            return (outcome, commands, chunks.value)
        }

        let control = try await run(cancelInFirstChunk: false)
        XCTAssertNoThrow(try control.outcome.get())
        XCTAssertEqual(control.chunks, 2)
        XCTAssertEqual(control.commands, [SMB2Commands.create, SMB2Commands.read, SMB2Commands.read, SMB2Commands.close])

        let cancelled = try await run(cancelInFirstChunk: true)
        XCTAssertThrowsError(try cancelled.outcome.get()) { error in
            XCTAssertTrue(error is CancellationError, "expected CancellationError, got \(error)")
        }
        XCTAssertEqual(cancelled.chunks, 1)
        XCTAssertEqual(cancelled.commands, [SMB2Commands.create, SMB2Commands.read, SMB2Commands.close])
    }

    func testClientSessionPrefixStreamNormalizesConnectionLossAfterYield() async throws {
        let fileId = hexBytes("00112233445566778899aabbccddeeff")
        let transport = ControlledReceiveTransport()
        let session = SMBSession(
            host: "server", port: 445,
            credential: SMBCredential(username: "user", password: "pass"),
            transport: transport, signingKey: Array(repeating: UInt8(0x11), count: 16)
        )
        let clientSession = SMBClientSession(session: session, treeId: 0x3344)
        let chunkDelivered = SMBContinuationCountBarrier()
        let chunkDeliveredClock = ManualSMBSleeper()
        let callbackRelease = SMBContinuationCountBarrier()
        let callbackReleaseClock = ManualSMBSleeper()
        let operation = Task {
            try await clientSession.withPrefixReadStream(path: "lost.bin", maxLength: 131_072) { _ in
                chunkDelivered.signal()
                try await callbackRelease.waitForCount(
                    1,
                    timeout: .seconds(1),
                    sleeper: { try await callbackReleaseClock.sleep(for: $0) }
                )
            }
        }

        try await awaitWithTimeout("prefix CREATE send completed") {
            await session.waitForRequestSentCountForTesting(atLeast: 1)
        }
        let createHeader = try SMB2Header.decode(try XCTUnwrap(try unframed(transport.outbound).first))
        transport.enqueueInbound(try DirectTCPFraming.frame(
            smb2CreateResponse(fileId: fileId, messageId: createHeader.messageId, treeId: 0x3344)
        ))
        try await awaitWithTimeout("prefix READ send completed") {
            await session.waitForRequestSentCountForTesting(atLeast: 2)
        }
        let readRequest = try XCTUnwrap(try unframed(transport.outbound).last)
        let readHeader = try SMB2Header.decode(readRequest)
        let requestedLength = Int(readUInt32LE(readRequest, at: 68))
        XCTAssertGreaterThan(requestedLength, 0)
        transport.enqueueInbound(try DirectTCPFraming.frame(
            smb2ReadResponse(
                Array(repeating: UInt8(0x5a), count: requestedLength),
                messageId: readHeader.messageId,
                treeId: 0x3344
            )
        ))
        try await smbIssue102AwaitWithTimeout("prefix chunk yielded") {
            try await chunkDelivered.waitForCount(
                1,
                timeout: .seconds(1),
                sleeper: { try await chunkDeliveredClock.sleep(for: $0) }
            )
        }
        await session.closeTransport(cause: "test_connection_loss_after_prefix_chunk")
        callbackRelease.signal()

        do {
            try await awaitWithTimeout("prefix read reports connection loss after yield") { try await operation.value }
            XCTFail("expected connection loss")
        } catch SMBError.connectionLost(operation: "READ") {
            // Expected: yielded bytes must not become a successful partial result.
        }
    }

    func testClientSessionUploadEmitsTransferProgressPerChunk() async throws {
        let fileId = hexBytes("00112233445566778899aabbccddeeff")
        let inbound = try framed([
            try smb2CreateResponse(fileId: fileId, messageId: 0, treeId: 0x3344),
            try smb2WriteResponse(count: 65_537, messageId: 1, treeId: 0x3344),
            try smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.flush, messageId: 3, treeId: 0x3344),
            try smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.close, messageId: 4, treeId: 0x3344)
        ])
        let transport = InMemoryTransport(inbound: inbound)
        let session = SMBSession(
            host: "server",
            port: 445,
            credential: SMBCredential(username: "user", password: "pass"),
            transport: transport,
            signingKey: Array(repeating: UInt8(0x11), count: 16),
            // 65 537 bytes must go out as ONE charge-2 WRITE (flush fixture is at messageId 3);
            // the credit-window chunk cap would split it if the server had only granted 1 credit.
            initialCredits: negotiatedServerCredits
        )
        let clientSession = SMBClientSession(session: session, treeId: 0x3344)
        let progress = TransferProgressCollector()
        let data = Array(repeating: UInt8(0x41), count: 65_537)

        try await clientSession.upload(path: "file.txt", data: data, onProgress: progress.append)

        XCTAssertEqual(progress.snapshots.map(\.bytesTransferred), [65_537])
        XCTAssertEqual(progress.snapshots.map(\.totalBytes), [65_537])
        XCTAssertTrue(progress.snapshots.allSatisfy { $0.bytesPerSecond >= 0 })
    }

    func testClientSessionAsyncSupplierUploadUsesCreditAwareSizesAndWritesSupplierBytes() async throws {
        let fileId = hexBytes("00112233445566778899aabbccddeeff")
        let firstChunk = [UInt8(1), 2, 3]
        let secondChunk = [UInt8(4), 5]
        let inbound = try framed([
            try smb2CreateResponse(fileId: fileId, messageId: 0, treeId: 0x3344),
            try smb2WriteResponse(count: firstChunk.count, messageId: 1, treeId: 0x3344, credits: 3),
            try smb2WriteResponse(count: secondChunk.count, messageId: 2, treeId: 0x3344),
            try smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.flush, messageId: 3, treeId: 0x3344),
            try smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.close, messageId: 4, treeId: 0x3344)
        ])
        let transport = InMemoryTransport(inbound: inbound)
        let session = SMBSession(
            host: "server",
            port: 445,
            credential: SMBCredential(username: "user", password: "pass"),
            transport: transport,
            initialCredits: 1
        )
        let clientSession = SMBClientSession(session: session, treeId: 0x3344)
        let supplier = AsyncChunkSupplierRecorder(chunks: [firstChunk, secondChunk])
        let progress = TransferProgressCollector()

        try await clientSession.upload(
            path: "file.bin",
            totalBytes: UInt64(firstChunk.count + secondChunk.count),
            nextChunk: { maxLength in
                supplier.nextChunk(maxLength: maxLength)
            },
            onProgress: progress.append
        )

        XCTAssertEqual(supplier.requestedSizes, [65_536, 196_608, 196_608])
        let writes = try unframed(transport.outbound).filter {
            try SMB2Header.decode($0).command == SMB2Commands.write
        }
        XCTAssertEqual(try writes.flatMap { try writePayload(from: $0) }, firstChunk + secondChunk)
        XCTAssertEqual(progress.snapshots.last?.bytesTransferred, UInt64(firstChunk.count + secondChunk.count))
        XCTAssertEqual(progress.snapshots.last?.totalBytes, UInt64(firstChunk.count + secondChunk.count))
    }

    func testClientSessionAsyncSupplierUploadStopsOnEmptyChunkAndFlushesAndCloses() async throws {
        let fileId = hexBytes("00112233445566778899aabbccddeeff")
        let transport = InMemoryTransport(inbound: try framed([
            try smb2CreateResponse(fileId: fileId, messageId: 0, treeId: 0x3344),
            try smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.flush, messageId: 1, treeId: 0x3344),
            try smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.close, messageId: 2, treeId: 0x3344)
        ]))
        let session = SMBSession(
            host: "server",
            port: 445,
            credential: SMBCredential(username: "user", password: "pass"),
            transport: transport
        )
        let clientSession = SMBClientSession(session: session, treeId: 0x3344)
        let supplier = AsyncChunkSupplierRecorder(chunks: [])

        try await clientSession.upload(
            path: "empty.bin",
            totalBytes: 0,
            nextChunk: { maxLength in
                supplier.nextChunk(maxLength: maxLength)
            }
        )

        XCTAssertEqual(supplier.requestedSizes, [65_536])
        XCTAssertEqual(try unframed(transport.outbound).map { try SMB2Header.decode($0).command }, [
            SMB2Commands.create,
            SMB2Commands.flush,
            SMB2Commands.close
        ])
    }

    func testClientSessionAsyncSupplierUploadPropagatesSupplierFailureAndCloses() async throws {
        let fileId = hexBytes("00112233445566778899aabbccddeeff")
        let transport = InMemoryTransport(inbound: try framed([
            try smb2CreateResponse(fileId: fileId, messageId: 0, treeId: 0x3344),
            try smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.close, messageId: 1, treeId: 0x3344)
        ]))
        let session = SMBSession(
            host: "server",
            port: 445,
            credential: SMBCredential(username: "user", password: "pass"),
            transport: transport
        )
        let clientSession = SMBClientSession(session: session, treeId: 0x3344)

        do {
            try await clientSession.upload(
                path: "failed.bin",
                totalBytes: 1,
                nextChunk: { _ in
                    throw SMBCodecError.invalidValue("supplier failed")
                }
            )
            XCTFail("expected supplier failure")
        } catch let error as SMBCodecError {
            XCTAssertEqual(error, .invalidValue("supplier failed"))
        }

        XCTAssertEqual(try unframed(transport.outbound).map { try SMB2Header.decode($0).command }, [
            SMB2Commands.create,
            SMB2Commands.close
        ])
    }

    func testClientSessionAsyncSupplierUploadCancellationClosesAfterPartialWrite() async throws {
        let fileId = hexBytes("00112233445566778899aabbccddeeff")
        let transport = InMemoryTransport(inbound: try framed([
            try smb2CreateResponse(fileId: fileId, messageId: 0, treeId: 0x3344),
            try smb2WriteResponse(count: 1, messageId: 1, treeId: 0x3344),
            try smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.close, messageId: 2, treeId: 0x3344)
        ]))
        let session = SMBSession(
            host: "server",
            port: 445,
            credential: SMBCredential(username: "user", password: "pass"),
            transport: transport
        )
        let clientSession = SMBClientSession(session: session, treeId: 0x3344)
        let supplier = AsyncChunkSupplierRecorder(chunks: [])
        let uploadTask = Task {
            try await clientSession.upload(
                path: "cancelled.bin",
                totalBytes: 2,
                nextChunk: { maxLength in
                    let callNumber = supplier.recordRequest(maxLength: maxLength)
                    if callNumber == 1 { return [0x41] }
                    try await Task.sleep(for: .seconds(3_600))
                    return []
                }
            )
        }

        try await awaitWithTimeout("async supplier second request") {
            while supplier.requestedSizes.count < 2 {
                try await Task.sleep(for: .milliseconds(1))
            }
        }
        uploadTask.cancel()

        do {
            try await uploadTask.value
            XCTFail("expected upload cancellation")
        } catch is CancellationError {
            // Expected.
        }

        XCTAssertEqual(try unframed(transport.outbound).map { try SMB2Header.decode($0).command }, [
            SMB2Commands.create,
            SMB2Commands.write,
            SMB2Commands.close
        ])
    }

    func testClientSessionStreamingUploadWritesTempFileInChunks() async throws {
        let fileId = hexBytes("00112233445566778899aabbccddeeff")
        let firstChunkSize = 65_536 + 11
        let inbound = try framed([
            try smb2CreateResponse(fileId: fileId, messageId: 0, treeId: 0x3344),
            try smb2WriteResponse(count: firstChunkSize, messageId: 1, treeId: 0x3344),
            try smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.flush, messageId: 3, treeId: 0x3344),
            try smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.close, messageId: 4, treeId: 0x3344)
        ])
        let transport = InMemoryTransport(inbound: inbound)
        let session = SMBSession(
            host: "server",
            port: 445,
            credential: SMBCredential(username: "user", password: "pass"),
            transport: transport,
            signingKey: Array(repeating: UInt8(0x11), count: 16),
            // Same as the progress test above: keep the >64KiB payload a single charge-2 WRITE.
            initialCredits: negotiatedServerCredits
        )
        let clientSession = SMBClientSession(session: session, treeId: 0x3344)
        let payload = (0..<firstChunkSize).map { UInt8($0 % 251) }
        let fileURL = try writeTemporaryFile(bytes: payload)
        defer { try? FileManager.default.removeItem(at: fileURL) }

        try await clientSession.upload(path: "file.bin", fileURL: fileURL)

        let requests = try unframed(transport.outbound)
        XCTAssertEqual(requests.map { try? SMB2Header.decode($0).command }, [
            SMB2Commands.create,
            SMB2Commands.write,
            SMB2Commands.flush,
            SMB2Commands.close
        ])
        XCTAssertEqual(readUInt64LE(requests[1], at: 72), 0)
        XCTAssertEqual(try writePayload(from: requests[1]).count, firstChunkSize)
        XCTAssertEqual(try writePayload(from: requests[1]), payload)
    }

    func testClientSessionStreamingUploadResumeWritesFromRemoteSize() async throws {
        let uploadFileId = hexBytes("ffeeddccbbaa99887766554433221100")
        let inbound = try framed([
            try smb2CreateResponse(fileId: uploadFileId, messageId: 0, treeId: 0x3344),
            try smb2QueryInfoResponse(size: 6, messageId: 1, treeId: 0x3344),
            try smb2ReadResponse(Array("hello ".utf8), messageId: 2, treeId: 0x3344),
            try smb2QueryInfoResponse(size: 6, messageId: 3, treeId: 0x3344),
            try smb2WriteResponse(count: 5, messageId: 4, treeId: 0x3344),
            try smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.flush, messageId: 5, treeId: 0x3344),
            try smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.close, messageId: 6, treeId: 0x3344)
        ])
        let transport = InMemoryTransport(inbound: inbound)
        let session = SMBSession(
            host: "server",
            port: 445,
            credential: SMBCredential(username: "user", password: "pass"),
            transport: transport,
            signingKey: Array(repeating: UInt8(0x11), count: 16)
        )
        let clientSession = SMBClientSession(session: session, treeId: 0x3344)
        let fileURL = try writeTemporaryFile(bytes: Array("hello world".utf8))
        defer { try? FileManager.default.removeItem(at: fileURL) }

        try await clientSession.upload(path: "file.bin", fileURL: fileURL, overwrite: false, resume: true)

        let requests = try unframed(transport.outbound)
        XCTAssertEqual(requests.map { try? SMB2Header.decode($0).command }, [
            SMB2Commands.create,
            SMB2Commands.queryInfo,
            SMB2Commands.read,
            SMB2Commands.queryInfo,
            SMB2Commands.write,
            SMB2Commands.flush,
            SMB2Commands.close
        ])
        XCTAssertEqual(readUInt32LE(requests[0], at: 100), 0x0000_0001)
        XCTAssertEqual(readUInt32LE(requests[0], at: 88), 0x0000_0083)
        XCTAssertEqual(readUInt64LE(requests[4], at: 72), 6)
        XCTAssertEqual(try writePayload(from: requests[4]), Array("world".utf8))
    }

    func testClientSessionStreamingUploadRejectsMismatchedRemoteResumePrefix() async throws {
        let fileId = hexBytes("ffeeddccbbaa99887766554433221100")
        let inbound = try framed([
            try smb2CreateResponse(fileId: fileId, messageId: 0, treeId: 0x3344),
            try smb2QueryInfoResponse(size: 6, messageId: 1, treeId: 0x3344),
            try smb2ReadResponse(Array("wrong!".utf8), messageId: 2, treeId: 0x3344),
            try smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.close, messageId: 3, treeId: 0x3344)
        ])
        let transport = InMemoryTransport(inbound: inbound)
        let session = SMBSession(
            host: "server", port: 445,
            credential: SMBCredential(username: "user", password: "pass"),
            transport: transport,
            signingKey: Array(repeating: UInt8(0x11), count: 16)
        )
        let clientSession = SMBClientSession(session: session, treeId: 0x3344)
        let fileURL = try writeTemporaryFile(bytes: Array("hello world".utf8))
        defer { try? FileManager.default.removeItem(at: fileURL) }

        do {
            try await clientSession.upload(path: "file.bin", fileURL: fileURL, resume: true)
            XCTFail("expected resume prefix validation failure")
        } catch let error as SMBCodecError {
            XCTAssertEqual(error, .invalidValue("remote upload resume prefix does not match local source"))
        }
        let requests = try unframed(transport.outbound)
        XCTAssertEqual(requests.compactMap { try? SMB2Header.decode($0).command }, [
            SMB2Commands.create, SMB2Commands.queryInfo, SMB2Commands.read, SMB2Commands.close
        ])
    }

    func testClientSessionStreamingUploadRejectsLocalSourceMutation() async throws {
        let fileId = hexBytes("00112233445566778899aabbccddeeff")
        let payload = Array(repeating: UInt8(0x41), count: 65_537)
        let inbound = try framed([
            try smb2CreateResponse(fileId: fileId, messageId: 0, treeId: 0x3344),
            try smb2WriteResponse(count: payload.count, messageId: 1, treeId: 0x3344),
            try smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.close, messageId: 3, treeId: 0x3344)
        ])
        let transport = InMemoryTransport(inbound: inbound)
        let session = SMBSession(
            host: "server", port: 445,
            credential: SMBCredential(username: "user", password: "pass"),
            transport: transport,
            signingKey: Array(repeating: UInt8(0x11), count: 16),
            initialCredits: negotiatedServerCredits
        )
        let clientSession = SMBClientSession(session: session, treeId: 0x3344)
        let fileURL = try writeTemporaryFile(bytes: payload)
        defer { try? FileManager.default.removeItem(at: fileURL) }

        do {
            try await clientSession.upload(path: "file.bin", fileURL: fileURL) { _ in
                _ = truncate(fileURL.path, 1)
            }
            XCTFail("expected local mutation failure")
        } catch let error as SMBCodecError {
            XCTAssertEqual(error, .invalidValue("local source file changed during upload"))
        }
        let requests = try unframed(transport.outbound)
        XCTAssertEqual(requests.compactMap { try? SMB2Header.decode($0).command }, [
            SMB2Commands.create, SMB2Commands.write, SMB2Commands.close
        ])
    }

    func testClientSessionStreamingUploadEmptyTempFileSendsNoWrite() async throws {
        let fileId = hexBytes("00112233445566778899aabbccddeeff")
        let inbound = try framed([
            try smb2CreateResponse(fileId: fileId, messageId: 0, treeId: 0x3344),
            try smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.flush, messageId: 1, treeId: 0x3344),
            try smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.close, messageId: 2, treeId: 0x3344)
        ])
        let transport = InMemoryTransport(inbound: inbound)
        let session = SMBSession(
            host: "server",
            port: 445,
            credential: SMBCredential(username: "user", password: "pass"),
            transport: transport,
            signingKey: Array(repeating: UInt8(0x11), count: 16)
        )
        let clientSession = SMBClientSession(session: session, treeId: 0x3344)
        let fileURL = try writeTemporaryFile(bytes: [])
        defer { try? FileManager.default.removeItem(at: fileURL) }

        try await clientSession.upload(path: "empty.bin", fileURL: fileURL)

        let requests = try unframed(transport.outbound)
        XCTAssertEqual(requests.map { try? SMB2Header.decode($0).command }, [
            SMB2Commands.create,
            SMB2Commands.flush,
            SMB2Commands.close
        ])
    }

    func testClientSessionCloseSendsTreeDisconnectAndLogoff() async throws {
        let inbound = try framed([
            try smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.treeDisconnect, messageId: 0, treeId: 0x3344),
            try smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.logoff, messageId: 1, treeId: 0)
        ])
        let transport = InMemoryTransport(inbound: inbound)
        let session = SMBSession(
            host: "server",
            port: 445,
            credential: SMBCredential(username: "user", password: "pass"),
            transport: transport,
            signingKey: Array(repeating: UInt8(0x11), count: 16)
        )
        let clientSession = SMBClientSession(session: session, treeId: 0x3344)

        await clientSession.close()
        await clientSession.close()

        let requests = try unframed(transport.outbound)
        XCTAssertEqual(requests.count, 2)
        let treeDisconnect = try SMB2Header.decode(requests[0])
        XCTAssertEqual(treeDisconnect.command, SMB2Commands.treeDisconnect)
        XCTAssertEqual(treeDisconnect.treeId, 0x3344)
        XCTAssertEqual(readUInt16LE(requests[0], at: 64), 4)
        let logoff = try SMB2Header.decode(requests[1])
        XCTAssertEqual(logoff.command, SMB2Commands.logoff)
        XCTAssertEqual(logoff.treeId, 0)
        XCTAssertEqual(readUInt16LE(requests[1], at: 64), 4)
    }

    func testGracefulDisconnectKeepsTheReaderUntilLogoffResponse() async throws {
        let transport = ControlledReceiveTransport()
        let session = SMBSession(
            host: "server",
            port: 445,
            credential: .anonymous,
            transport: transport,
            initialCredits: 2
        )
        let treeId: UInt32 = 0x3344
        let disconnect = Task { await session.disconnect(treeId: treeId) }
        let clock = ManualSMBSleeper()
        try await waitForOutboundFrameCount(1, transport: transport)
        let firstReaderHandle = await session.readerHandleForTesting()
        let readerRunningDuringTreeDisconnect = await session.receiveLoopRunningForTesting()
        XCTAssertNotNil(firstReaderHandle)
        XCTAssertTrue(readerRunningDuringTreeDisconnect)
        XCTAssertEqual(transport.closeCount, 0, "graceful disconnect awaits its response")

        let treeDisconnect = try SMB2Header.decode(try XCTUnwrap(try unframed(transport.outbound).first))
        transport.enqueueInbound(try framed([
            smb2StatusResponse(
                status: SMB2Status.success,
                command: SMB2Commands.treeDisconnect,
                messageId: treeDisconnect.messageId,
                treeId: treeId
            )
        ]))
        try await waitForOutboundFrameCount(2, transport: transport)
        try await awaitWithTimeout("LOGOFF send completes after TREE_DISCONNECT") {
            await session.waitForRequestSentCountForTesting(atLeast: 2)
        }
        try await awaitWithTimeout("reader is active for LOGOFF") {
            try await transport.waitForReceiveCount(
                atLeast: 3,
                timeout: .seconds(1),
                sleeper: { try await clock.sleep(for: $0) }
            )
        }
        let logoff = try SMB2Header.decode(try XCTUnwrap(try unframed(transport.outbound).last))
        XCTAssertEqual(logoff.command, SMB2Commands.logoff)
        let readerHandleDuringLogoff = await session.readerHandleForTesting()
        let readerRunningDuringLogoff = await session.receiveLoopRunningForTesting()
        XCTAssertNotNil(readerHandleDuringLogoff)
        XCTAssertTrue(readerRunningDuringLogoff)
        XCTAssertEqual(transport.closeCount, 0, "reader stays active while LOGOFF is pending")

        transport.enqueueInbound(try framed([
            smb2StatusResponse(
                status: SMB2Status.success,
                command: SMB2Commands.logoff,
                messageId: logoff.messageId,
                treeId: 0
            )
        ]))
        try await awaitWithTimeout("graceful disconnect closes after LOGOFF response") {
            await disconnect.value
        }
        XCTAssertEqual(transport.closeCount, 1)
        let readerRunningAfterLogoff = await session.receiveLoopRunningForTesting()
        XCTAssertFalse(readerRunningAfterLogoff)
    }

    func testClientSessionKeepAliveSendsPeriodicEchoUntilClose() async throws {
        let transport = ControlledReceiveTransport()
        let session = SMBSession(
            host: "server",
            port: 445,
            credential: SMBCredential(username: "user", password: "pass"),
            transport: transport,
            signingKey: Array(repeating: UInt8(0x11), count: 16)
        )
        let clientSession = SMBClientSession(session: session, treeId: 0x3344)

        try await clientSession.startKeepAlive(interval: .milliseconds(50))
        try await waitForOutboundFrameCount(1, transport: transport)
        var observed = try unframed(transport.outbound)
        let firstEcho = try SMB2Header.decode(observed[0])
        transport.enqueueInbound(try framed([try smb2EchoResponse(messageId: firstEcho.messageId)]))

        let closeTask = Task { await clientSession.close() }
        var responded = Set<UInt64>([firstEcho.messageId])
        for _ in 0..<500 {
            let requests = try unframed(transport.outbound)
            if requests.count > observed.count {
                for request in requests.dropFirst(observed.count) {
                    let header = try SMB2Header.decode(request)
                    guard responded.insert(header.messageId).inserted else { continue }
                    switch header.command {
                    case SMB2Commands.echo:
                        transport.enqueueInbound(try framed([try smb2EchoResponse(messageId: header.messageId)]))
                    case SMB2Commands.treeDisconnect:
                        transport.enqueueInbound(try framed([try smb2StatusResponse(status: SMB2Status.success, command: header.command, messageId: header.messageId, treeId: header.treeId)]))
                    case SMB2Commands.logoff:
                        transport.enqueueInbound(try framed([try smb2StatusResponse(status: SMB2Status.success, command: header.command, messageId: header.messageId, treeId: header.treeId)]))
                    default: break
                    }
                }
                observed = requests
            }
            let commands = try observed.map { try SMB2Header.decode($0).command }.filter { $0 != SMB2Commands.cancel }
            if commands.count >= 3,
               commands.dropFirst().suffix(2).elementsEqual([SMB2Commands.treeDisconnect, SMB2Commands.logoff]) {
                break
            }
            try await Task.sleep(nanoseconds: 10_000_000)
        }
        _ = await closeTask.value
        let commands = try observed.map { try SMB2Header.decode($0).command }.filter { $0 != SMB2Commands.cancel }
        XCTAssertGreaterThanOrEqual(commands.count, 3)
        XCTAssertEqual(Array(commands.suffix(2)), [SMB2Commands.treeDisconnect, SMB2Commands.logoff])
        XCTAssertTrue(commands.dropLast(2).allSatisfy { $0 == SMB2Commands.echo })
    }

    func testClientSessionCloseWaitsForInFlightKeepAliveEcho() async throws {
        let transport = ControlledReceiveTransport()
        let session = SMBSession(
            host: "server", port: 445,
            credential: SMBCredential(username: "user", password: "pass"),
            transport: transport, signingKey: Array(repeating: UInt8(0x11), count: 16)
        )
        let clientSession = SMBClientSession(session: session, treeId: 0x3344)

        try await clientSession.startKeepAlive(interval: .milliseconds(50))
        try await waitForOutboundFrameCount(1, transport: transport)
        try await awaitWithTimeout("keepalive ECHO full-send") {
            await session.waitForRequestSentCountForTesting(atLeast: 1)
        }
        let echoRequest = try XCTUnwrap(try unframed(transport.outbound).first)
        let echoHeader = try SMB2Header.decode(echoRequest)
        let closeTask = Task { await clientSession.close() }

        try await awaitWithTimeout("close registers the in-flight ECHO drain") {
            await session.waitForPendingCommandResponseDrainWaiterCountForTesting(
                command: SMB2Commands.echo,
                atLeast: 1
            )
        }
        try await waitForOutboundFrameCount(2, transport: transport)
        let outboundBeforeEchoFinal = try unframed(transport.outbound)
        let commandsBeforeEchoFinal = try outboundBeforeEchoFinal.map { try SMB2Header.decode($0).command }
        XCTAssertEqual(commandsBeforeEchoFinal, [SMB2Commands.echo, SMB2Commands.cancel])

        transport.enqueueInbound(try framed([smb2EchoResponse(messageId: echoHeader.messageId)]))
        try await awaitWithTimeout("keepalive ECHO final retires its wire record") {
            await session.waitForReceivedPacketDispatchCountForTesting(atLeast: 1)
        }
        try await waitForOutboundFrameCount(3, transport: transport)
        let treeDisconnect = try SMB2Header.decode(try XCTUnwrap(try unframed(transport.outbound).last))
        XCTAssertEqual(treeDisconnect.command, SMB2Commands.treeDisconnect)
        transport.enqueueInbound(try framed([smb2StatusResponse(
            status: SMB2Status.success,
            command: treeDisconnect.command,
            messageId: treeDisconnect.messageId,
            treeId: 0x3344
        )]))

        try await waitForOutboundFrameCount(4, transport: transport)
        let logoff = try SMB2Header.decode(try XCTUnwrap(try unframed(transport.outbound).last))
        XCTAssertEqual(logoff.command, SMB2Commands.logoff)
        transport.enqueueInbound(try framed([smb2StatusResponse(
            status: SMB2Status.success,
            command: logoff.command,
            messageId: logoff.messageId,
            treeId: 0
        )]))
        try await awaitWithTimeout("close after in-flight keepalive final") { await closeTask.value }

        let commands = try unframed(transport.outbound).map { try SMB2Header.decode($0).command }
        XCTAssertEqual(commands.filter { $0 != SMB2Commands.cancel }, [
            SMB2Commands.echo, SMB2Commands.treeDisconnect, SMB2Commands.logoff
        ])
    }

    func testClientSessionCloseSkipsGracefulTeardownWhenKeepAliveEchoNeverDrains() async throws {
        let transport = ControlledReceiveTransport()
        let clock = ManualSMBSleeper()
        let session = SMBSession(
            host: "server", port: 445,
            credential: SMBCredential(username: "user", password: "pass"),
            transport: transport, signingKey: Array(repeating: UInt8(0x11), count: 16),
            cleanupTimeout: .seconds(5),
            cleanupTimeoutSleeper: { try await clock.sleep(for: $0) }
        )
        let clientSession = SMBClientSession(session: session, treeId: 0x3344)

        try await clientSession.startKeepAlive(interval: .milliseconds(50))
        try await waitForOutboundFrameCount(1, transport: transport)
        try await awaitWithTimeout("keepalive ECHO full-send") {
            await session.waitForRequestSentCountForTesting(atLeast: 1)
        }
        let closeTask = Task { await clientSession.close() }
        try await awaitWithTimeout("close registers the in-flight ECHO drain") {
            await session.waitForPendingCommandResponseDrainWaiterCountForTesting(
                command: SMB2Commands.echo,
                atLeast: 1
            )
        }
        try await awaitWithTimeout("ECHO drain deadline armed") {
            try await clock.waitUntilCallCount(
                atLeast: 1,
                timeout: .seconds(1),
                sleeper: { try await ManualSMBSleeper().sleep(for: $0) }
            )
        }
        // The ECHO final never arrives: the deadline closes the wire instead of sending
        // TREE_DISCONNECT / LOGOFF across the unresolved request.
        clock.fireNext()
        try await awaitWithTimeout("close after ECHO drain timeout") { await closeTask.value }

        let transportClosed = await session.isTransportClosedForTesting()
        XCTAssertTrue(transportClosed)
        let commands = try unframed(transport.outbound).map { try SMB2Header.decode($0).command }
        XCTAssertFalse(commands.contains(SMB2Commands.treeDisconnect), "\(commands)")
        XCTAssertFalse(commands.contains(SMB2Commands.logoff), "\(commands)")
    }

    func testCancelledParkedEchoDoesNotSendStaleFrameAfterCreditGrant() async throws {
        let transport = ControlledReceiveTransport()
        let session = SMBSession(
            host: "server", port: 445,
            credential: SMBCredential(username: "user", password: "pass"),
            transport: transport, signingKey: Array(repeating: UInt8(0x11), count: 16),
            initialCredits: 1
        )

        let first = Task { try await session.echo() }
        try await waitForOutboundFrameCount(1, transport: transport)
        let firstHeader = try SMB2Header.decode(try unframed(transport.outbound)[0])
        let second = Task { try await session.echo() }
        try await awaitWithTimeout("second ECHO parks on the credit waiter") {
            await session.waitForCreditWaiterCountForTesting(atLeast: 1)
        }
        XCTAssertEqual(try unframed(transport.outbound).count, 1, "second ECHO should be parked on credits")
        second.cancel()
        do {
            _ = try await awaitWithTimeout("cancel parked ECHO") { try await second.value }
            XCTFail("cancelled parked ECHO unexpectedly completed")
        } catch is CancellationError {
        }

        transport.enqueueInbound(try framed([
            smb2EchoResponse(messageId: firstHeader.messageId, credits: 1)
        ]))
        try await awaitWithTimeout("first ECHO") { try await first.value }
        try await awaitWithTimeout("grant frame is fully dispatched after cancellation") {
            await session.waitForReceivedPacketDispatchCountForTesting(atLeast: 1)
        }
        // Cancellation legitimately emits an SMB2 CANCEL frame; the regression under test
        // is a stale ECHO being replayed once the grant arrives, so count ECHO frames only.
        let echoFrames = try unframed(transport.outbound).filter {
            (try? SMB2Header.decode($0).command) == SMB2Commands.echo
        }
        XCTAssertEqual(echoFrames.count, 1)
    }

    func testQueryDirectoryResponseDropsDotEntriesForRecursiveDeleteWalks() throws {
        var response = try SMB2Header(command: SMB2Commands.queryDirectory, messageId: 11).encode()
        let payload = makeDirectoryEntry(name: ".", isDirectory: true, nextOffset: 112)
            + makeDirectoryEntry(name: "..", isDirectory: true, nextOffset: 112)
            + makeDirectoryEntry(name: "child.txt", isDirectory: false, fileSize: 7, nextOffset: 0)
        response.append(contentsOf: Array(repeating: UInt8(0), count: 8))
        writeUInt16LE(9, to: &response, at: 64)
        writeUInt16LE(72, to: &response, at: 66)
        writeUInt32LE(UInt32(payload.count), to: &response, at: 68)
        response.append(contentsOf: payload)

        XCTAssertEqual(
            try SMB2QueryDirectory.decodeResponse(response),
            [SMBDirectoryEntry(name: "child.txt", fileSize: 7, isDirectory: false, attributes: 0x80)]
        )
    }

    func testQueryDirectoryResponsePreservesFileAttributes() throws {
        var response = try SMB2Header(command: SMB2Commands.queryDirectory, messageId: 11).encode()
        let payload = makeDirectoryEntry(name: "hidden.txt", isDirectory: false, fileSize: 7, nextOffset: 0, attributes: 0x82)
        response.append(contentsOf: Array(repeating: UInt8(0), count: 8))
        writeUInt16LE(9, to: &response, at: 64)
        writeUInt16LE(72, to: &response, at: 66)
        writeUInt32LE(UInt32(payload.count), to: &response, at: 68)
        response.append(contentsOf: payload)

        let entries = try SMB2QueryDirectory.decodeResponse(response)
        XCTAssertEqual(entries.first?.attributes, 0x82)
        XCTAssertEqual(entries.first?.isDirectory, false)
    }

    func testQueryDirectoryResponsePreservesFileIdAndReparsePoint() throws {
        var response = try SMB2Header(command: SMB2Commands.queryDirectory, messageId: 11).encode()
        let payload = makeDirectoryEntry(
            name: "link",
            isDirectory: true,
            fileSize: 0,
            nextOffset: 0,
            attributes: SMBFileAttributes.directory | SMBFileAttributes.reparsePoint,
            fileId: 0x0102_0304_0506_0708
        )
        response.append(contentsOf: Array(repeating: UInt8(0), count: 8))
        writeUInt16LE(9, to: &response, at: 64)
        writeUInt16LE(72, to: &response, at: 66)
        writeUInt32LE(UInt32(payload.count), to: &response, at: 68)
        response.append(contentsOf: payload)

        let entry = try XCTUnwrap(SMB2QueryDirectory.decodeResponse(response).first)

        XCTAssertEqual(entry.fileId, 0x0102_0304_0506_0708)
        XCTAssertTrue(entry.isReparsePoint)
    }

    func testQueryDirectoryResponseDecodesTimestamps() throws {
        var response = try SMB2Header(command: SMB2Commands.queryDirectory, messageId: 11).encode()
        let payload = makeDirectoryEntry(
            name: "dated.txt",
            isDirectory: false,
            fileSize: 7,
            nextOffset: 0,
            creationTime: 116_444_736_010_000_000,
            lastWriteTime: 116_444_736_020_000_000
        )
        response.append(contentsOf: Array(repeating: UInt8(0), count: 8))
        writeUInt16LE(9, to: &response, at: 64)
        writeUInt16LE(72, to: &response, at: 66)
        writeUInt32LE(UInt32(payload.count), to: &response, at: 68)
        response.append(contentsOf: payload)

        let entry = try XCTUnwrap(SMB2QueryDirectory.decodeResponse(response).first)

        XCTAssertEqual(entry.creationTime, Date(timeIntervalSince1970: 1))
        XCTAssertEqual(entry.modifiedTime, Date(timeIntervalSince1970: 2))
    }

    func testQueryDirectoryResponseTreatsZeroTimestampsAsNil() throws {
        var response = try SMB2Header(command: SMB2Commands.queryDirectory, messageId: 11).encode()
        let payload = makeDirectoryEntry(name: "undated.txt", isDirectory: false, fileSize: 7, nextOffset: 0)
        response.append(contentsOf: Array(repeating: UInt8(0), count: 8))
        writeUInt16LE(9, to: &response, at: 64)
        writeUInt16LE(72, to: &response, at: 66)
        writeUInt32LE(UInt32(payload.count), to: &response, at: 68)
        response.append(contentsOf: payload)

        let entry = try XCTUnwrap(SMB2QueryDirectory.decodeResponse(response).first)

        XCTAssertNil(entry.creationTime)
        XCTAssertNil(entry.modifiedTime)
    }

    func testQueryDirectoryResponseRejectsInvalidNextEntryOffset() throws {
        var response = try SMB2Header(command: SMB2Commands.queryDirectory, messageId: 11).encode()
        let payload = makeDirectoryEntry(name: "child", isDirectory: true, nextOffset: 1)
        response.append(contentsOf: Array(repeating: UInt8(0), count: 8))
        writeUInt16LE(9, to: &response, at: 64)
        writeUInt16LE(72, to: &response, at: 66)
        writeUInt32LE(UInt32(payload.count), to: &response, at: 68)
        response.append(contentsOf: payload)

        XCTAssertThrowsError(try SMB2QueryDirectory.decodeResponse(response)) { error in
            XCTAssertEqual(error as? SMBCodecError, .truncated)
        }
    }

    func testQueryInfoRequestUsesFileNetworkOpenInformationAndOneByteBuffer() throws {
        let fileId = (0..<16).map(UInt8.init)
        let request = try SMB2QueryInfo.encodeRequest(
            messageId: 12,
            sessionId: 0x1122_3344,
            treeId: 0x5566_7788,
            fileId: fileId
        )

        let header = try SMB2Header.decode(request)
        XCTAssertEqual(header.command, SMB2Commands.queryInfo)
        XCTAssertEqual(header.messageId, 12)
        XCTAssertEqual(header.treeId, 0x5566_7788)
        XCTAssertEqual(header.sessionId, 0x1122_3344)
        XCTAssertEqual(request.count, 105)
        XCTAssertEqual(readUInt16LE(request, at: 64), 41)
        XCTAssertEqual(request[66], 0x01)
        XCTAssertEqual(request[67], 34)
        XCTAssertEqual(readUInt32LE(request, at: 68), 65_536)
        XCTAssertEqual(readUInt16LE(request, at: 72), 104)
        XCTAssertEqual(readUInt16LE(request, at: 74), 0)
        XCTAssertEqual(readUInt32LE(request, at: 76), 0)
        XCTAssertEqual(readUInt32LE(request, at: 80), 0)
        XCTAssertEqual(readUInt32LE(request, at: 84), 0)
        XCTAssertEqual(Array(request[88..<104]), fileId)
        XCTAssertEqual(request[104], 0)
    }

    func testQueryInfoRequestCanUseFilesystemInfoClass() throws {
        let fileId = (0..<16).map(UInt8.init)
        let request = try SMB2QueryInfo.encodeRequest(
            messageId: 12,
            sessionId: 0x1122_3344,
            treeId: 0x5566_7788,
            fileId: fileId,
            infoType: SMB2QueryInfo.infoTypeFilesystem,
            fileInfoClass: SMB2QueryInfo.fileFsFullSizeInformation
        )

        XCTAssertEqual(request[66], 0x02)
        XCTAssertEqual(request[67], 7)
        XCTAssertEqual(readUInt32LE(request, at: 68), 65_536)
        XCTAssertEqual(readUInt16LE(request, at: 72), 104)
        XCTAssertEqual(readUInt16LE(request, at: 74), 0)
        XCTAssertEqual(Array(request[88..<104]), fileId)
        XCTAssertEqual(request[104], 0)
    }

    func testQueryInfoRequestCanSetAdditionalInformation() throws {
        let fileId = (0..<16).map(UInt8.init)
        let request = try SMB2QueryInfo.encodeRequest(
            messageId: 12,
            sessionId: 0x1122_3344,
            treeId: 0x5566_7788,
            fileId: fileId,
            infoType: SMB2QueryInfo.infoTypeSecurity,
            fileInfoClass: 0,
            additionalInformation: SMB2QueryInfo.securityOwner | SMB2QueryInfo.securityGroup | SMB2QueryInfo.securityDACL
        )

        XCTAssertEqual(request[66], 0x03)
        XCTAssertEqual(request[67], 0)
        XCTAssertEqual(readUInt32LE(request, at: 80), 0x0000_0007)
        XCTAssertEqual(readUInt32LE(request, at: 84), 0)
        XCTAssertEqual(Array(request[88..<104]), fileId)
    }

    func testQueryInfoRequestCanUseFileAttributeTagInformation() throws {
        let fileId = (0..<16).map(UInt8.init)
        let request = try SMB2QueryInfo.encodeRequest(
            messageId: 12,
            sessionId: 0x1122_3344,
            treeId: 0x5566_7788,
            fileId: fileId,
            fileInfoClass: SMB2QueryInfo.fileAttributeTagInformation,
            outputBufferLength: 8
        )

        XCTAssertEqual(request[66], SMB2QueryInfo.infoTypeFile)
        XCTAssertEqual(request[67], 35)
        XCTAssertEqual(readUInt32LE(request, at: 68), 8)
        XCTAssertEqual(Array(request[88..<104]), fileId)
    }

    func testQueryInfoResponsePreservesFileAttributes() throws {
        let response = try smb2QueryInfoResponse(size: 7, messageId: 12, treeId: 0x3344, attributes: 0x82)

        let stat = try SMB2QueryInfo.decodeNetworkOpenInformation(response)

        XCTAssertEqual(stat.size, 7)
        XCTAssertEqual(stat.attributes, 0x82)
        XCTAssertFalse(stat.isDirectory)
    }

    func testQueryInfoResponseDecodesAllBasicTimes() throws {
        let response = try smb2QueryInfoResponse(
            size: 7,
            messageId: 12,
            treeId: 0x3344,
            creationTime: 116_444_736_010_000_000,
            lastAccessTime: 116_444_736_020_000_000,
            lastWriteTime: 116_444_736_030_000_000,
            changeTime: 116_444_736_040_000_000,
            attributes: SMBFileAttributes.reparsePoint
        )

        let stat = try SMB2QueryInfo.decodeNetworkOpenInformation(response)

        XCTAssertEqual(stat.creationTime?.timeIntervalSince1970, 1)
        XCTAssertEqual(stat.lastAccessTime?.timeIntervalSince1970, 2)
        XCTAssertEqual(stat.modifiedTime?.timeIntervalSince1970, 3)
        XCTAssertEqual(stat.changeTime?.timeIntervalSince1970, 4)
        XCTAssertTrue(stat.isReparsePoint)
    }

    func testFileAttributeTagInformationDecodesReparseTagFixture() throws {
        var payload = Array(repeating: UInt8(0), count: 8)
        writeUInt32LE(SMBFileAttributes.reparsePoint, to: &payload, at: 0)
        writeUInt32LE(SMBReparseTags.symlink, to: &payload, at: 4)

        let info = try SMB2QueryInfo.decodeAttributeTagInformation(smb2QueryInfoResponse(payload: payload))

        XCTAssertEqual(info.attributes, SMBFileAttributes.reparsePoint)
        XCTAssertEqual(info.reparseTag, 0xa000_000c)
        XCTAssertEqual(SMBReparseKind(tag: info.reparseTag), .symlink)
    }

    func testFileAttributeTagInformationRejectsTruncatedPayload() throws {
        let payload = Array(repeating: UInt8(0), count: 7)

        XCTAssertThrowsError(try SMB2QueryInfo.decodeAttributeTagInformation(smb2QueryInfoResponse(payload: payload))) { error in
            XCTAssertEqual(error as? SMBCodecError, .truncated)
        }
    }

    func testReparseKindMapsKnownAndUnknownTags() {
        XCTAssertEqual(SMBReparseKind(tag: SMBReparseTags.symlink), .symlink)
        XCTAssertEqual(SMBReparseKind(tag: SMBReparseTags.mountPoint), .mountPoint)
        XCTAssertEqual(SMBReparseKind(tag: SMBReparseTags.dfs), .dfs)
        XCTAssertEqual(SMBReparseKind(tag: SMBReparseTags.nfs), .nfs)
        XCTAssertEqual(SMBReparseKind(tag: 0x1234_5678), .other(0x1234_5678))
        XCTAssertNil(SMBFileStat(size: 0, modifiedTime: nil, isDirectory: false).reparseKind)
    }

    func testWellKnownSIDResolverMapsCommonSIDs() {
        XCTAssertEqual(SMBWellKnownSID.name(for: "S-1-1-0"), "Everyone")
        XCTAssertEqual(SMBWellKnownSID.name(for: "S-1-5-32-544"), "BUILTIN\\Administrators")
        XCTAssertNil(SMBWellKnownSID.name(for: "S-1-5-21-1000-1001-1002"))
    }

    func testFileFsFullSizeInformationDecodesByteCountsFromFixture() throws {
        var payload = Array(repeating: UInt8(0), count: 32)
        writeUInt64LE(100, to: &payload, at: 0)
        writeUInt64LE(25, to: &payload, at: 8)
        writeUInt64LE(20, to: &payload, at: 16)
        writeUInt32LE(8, to: &payload, at: 24)
        writeUInt32LE(512, to: &payload, at: 28)

        let info = try SMB2QueryInfo.decodeFullSizeInformation(smb2QueryInfoResponse(payload: payload))

        XCTAssertEqual(info.totalBytes, 409_600)
        XCTAssertEqual(info.availableBytes, 102_400)
    }

    func testFileFsAttributeInformationDecodesUTF16NameFromFixture() throws {
        var payload = Array(repeating: UInt8(0), count: 12)
        let name = NTLM.utf16le("NTFS")
        writeUInt32LE(0x0000_0003, to: &payload, at: 0)
        writeUInt32LE(255, to: &payload, at: 4)
        writeUInt32LE(UInt32(name.count), to: &payload, at: 8)
        payload.append(contentsOf: name)

        let info = try SMB2QueryInfo.decodeAttributeInformation(smb2QueryInfoResponse(payload: payload))

        XCTAssertEqual(info.filesystemAttributes, 0x0000_0003)
        XCTAssertEqual(info.maxComponentLength, 255)
        XCTAssertEqual(info.filesystemName, "NTFS")
    }

    func testFileFsVolumeInformationDecodesUTF16LabelFromFixture() throws {
        var payload = Array(repeating: UInt8(0), count: 18)
        let label = NTLM.utf16le("DATA")
        writeUInt64LE(116_444_736_010_000_000, to: &payload, at: 0)
        writeUInt32LE(0x1234_abcd, to: &payload, at: 8)
        writeUInt32LE(UInt32(label.count), to: &payload, at: 12)
        payload[16] = 1
        payload[17] = 0
        payload.append(contentsOf: label)

        let info = try SMB2QueryInfo.decodeVolumeInformation(smb2QueryInfoResponse(payload: payload))

        XCTAssertEqual(info.volumeSerialNumber, 0x1234_abcd)
        XCTAssertEqual(info.volumeLabel, "DATA")
    }

    func testSecurityDescriptorDecodesOwnerGroupAndDACLFromFixture() throws {
        var payload = Array(repeating: UInt8(0), count: 20)
        let ownerSIDOffset = payload.count
        payload.append(contentsOf: sidBytes(authority: 5, subAuthorities: [32, 544]))
        let groupSIDOffset = payload.count
        payload.append(contentsOf: sidBytes(authority: 5, subAuthorities: [32, 545]))
        let daclOffset = payload.count
        let everyoneSID = sidBytes(authority: 1, subAuthorities: [0])
        let userSID = sidBytes(authority: 5, subAuthorities: [21, 1000, 1001, 1002])
        var acl = Array(repeating: UInt8(0), count: 8)
        acl[0] = 2
    writeUInt16LE(UInt16(8 + 8 + everyoneSID.count + 8 + userSID.count), to: &acl, at: 2)
        writeUInt16LE(2, to: &acl, at: 4)
        acl.append(contentsOf: aceBytes(type: 0, flags: 0, accessMask: 0x001f_01ff, sid: everyoneSID))
        acl.append(contentsOf: aceBytes(type: 1, flags: 0x10, accessMask: 0x0001_0000, sid: userSID))
        payload.append(contentsOf: acl)

        payload[0] = 1
        writeUInt16LE(0x8004, to: &payload, at: 2)
        writeUInt32LE(UInt32(ownerSIDOffset), to: &payload, at: 4)
        writeUInt32LE(UInt32(groupSIDOffset), to: &payload, at: 8)
        writeUInt32LE(UInt32(daclOffset), to: &payload, at: 16)

        let info = try SMB2QueryInfo.decodeSecurityInfo(smb2QueryInfoResponse(payload: payload))

        XCTAssertEqual(info.ownerSID, "S-1-5-32-544")
        XCTAssertEqual(info.groupSID, "S-1-5-32-545")
        XCTAssertEqual(info.controlFlags, 0x8004)
        XCTAssertEqual(info.dacl?.count, 2)
        XCTAssertEqual(info.dacl?[0], SMBAccessControlEntry(type: 0, flags: 0, accessMask: 0x001f_01ff, trusteeSID: "S-1-1-0"))
        XCTAssertEqual(info.dacl?[1], SMBAccessControlEntry(type: 1, flags: 0x10, accessMask: 0x0001_0000, trusteeSID: "S-1-5-21-1000-1001-1002"))
    }

    func testSecurityDescriptorRejectsTruncatedSIDOffset() throws {
        var payload = Array(repeating: UInt8(0), count: 20)
        payload[0] = 1
        writeUInt32LE(128, to: &payload, at: 4)

        XCTAssertThrowsError(try SMB2QueryInfo.decodeSecurityInfo(smb2QueryInfoResponse(payload: payload))) { error in
            XCTAssertEqual(error as? SMBCodecError, .truncated)
        }
    }

    func testSecurityDescriptorSkipsUnknownAceBySize() throws {
        var payload = Array(repeating: UInt8(0), count: 20)
        let daclOffset = payload.count
        var acl = Array(repeating: UInt8(0), count: 8)
        acl[0] = 2
        writeUInt16LE(16, to: &acl, at: 2)
        writeUInt16LE(1, to: &acl, at: 4)
        acl.append(0x05)
        acl.append(0x11)
        acl.append(8)
        acl.append(0)
        acl.append(contentsOf: Array(repeating: UInt8(0), count: 4))
        writeUInt32LE(0x0002_0000, to: &acl, at: 12)
        payload.append(contentsOf: acl)
        payload[0] = 1
        writeUInt32LE(UInt32(daclOffset), to: &payload, at: 16)

        let info = try SMB2QueryInfo.decodeSecurityInfo(smb2QueryInfoResponse(payload: payload))

        XCTAssertEqual(info.dacl, [SMBAccessControlEntry(type: 0x05, flags: 0x11, accessMask: 0x0002_0000, trusteeSID: nil)])
    }

    func testSecuritySIDEncoderMatchesMSDTYPBytes() throws {
        XCTAssertEqual(
            try SMB2SetInfo.encodeSID("S-1-5-32-544"),
            [0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x20, 0x00, 0x00, 0x00, 0x20, 0x02, 0x00, 0x00]
        )
    }

    func testSecurityDescriptorEncodeRoundTripsThroughDecoder() throws {
        let dacl = [
            SMBAccessControlEntry(type: 0, flags: 0, accessMask: 0x001f_01ff, trusteeSID: "S-1-1-0"),
            SMBAccessControlEntry(type: 1, flags: 0x10, accessMask: 0x0001_0000, trusteeSID: "S-1-5-21-1000-1001-1002")
        ]

        let descriptor = try SMB2SetInfo.encodeSecurityDescriptor(
            ownerSID: "S-1-5-32-544",
            groupSID: "S-1-5-32-545",
            dacl: dacl
        )
        let info = try SMB2QueryInfo.decodeSecurityDescriptor(descriptor)

        XCTAssertEqual(info.ownerSID, "S-1-5-32-544")
        XCTAssertEqual(info.groupSID, "S-1-5-32-545")
        XCTAssertEqual(info.controlFlags, 0x8004)
        XCTAssertEqual(info.dacl, dacl)
    }

    func testSetInfoSecurityRequestUsesSecurityInfoTypeAndDACLAdditionalInformation() throws {
        let fileId = hexBytes("00112233445566778899aabbccddeeff")
        let request = try SMB2SetInfo.encodeSecurityDescriptorRequest(
            messageId: 7,
            sessionId: 0x1122,
            treeId: 0x3344,
            fileId: fileId,
            ownerSID: nil,
            groupSID: nil,
            dacl: [SMBAccessControlEntry(type: 0, flags: 0, accessMask: 0x001f_01ff, trusteeSID: "S-1-1-0")]
        )

        let header = try SMB2Header.decode(request)
        XCTAssertEqual(header.command, SMB2Commands.setInfo)
        XCTAssertEqual(request[66], 0x03)
        XCTAssertEqual(request[67], 0)
        XCTAssertEqual(readUInt16LE(request, at: 72), 96)
        XCTAssertEqual(readUInt32LE(request, at: 76), 0x0000_0004)
        XCTAssertEqual(Array(request[80..<96]), fileId)
        XCTAssertEqual(request[96], 1)
        XCTAssertEqual(readUInt16LE(request, at: 98), 0x8004)
    }

    func testSetSecurityLockoutGuardRejectsEmptyOrDenyOnlyDACLUnlessForced() throws {
        XCTAssertThrowsError(try SMB2SetInfo.validateWritableDACL([], force: false)) { error in
            XCTAssertEqual(error as? SMBCodecError, .invalidValue("refusing to write empty DACL without force"))
        }
        let denyOnly = [SMBAccessControlEntry(type: 1, flags: 0, accessMask: 0x001f_01ff, trusteeSID: "S-1-1-0")]
        XCTAssertThrowsError(try SMB2SetInfo.validateWritableDACL(denyOnly, force: false)) { error in
            XCTAssertEqual(error as? SMBCodecError, .invalidValue("refusing to write DACL without ACCESS_ALLOWED ACE without force"))
        }
        XCTAssertNoThrow(try SMB2SetInfo.validateWritableDACL([], force: true))
        XCTAssertNoThrow(try SMB2SetInfo.validateWritableDACL(denyOnly, force: true))
    }

    func testSetSecurityRejectsACEWithoutTrusteeSID() throws {
        XCTAssertThrowsError(
            try SMB2SetInfo.encodeSecurityDescriptor(
                ownerSID: nil,
                groupSID: nil,
                dacl: [SMBAccessControlEntry(type: 0, flags: 0, accessMask: 1, trusteeSID: nil)],
                force: true
            )
        ) { error in
            XCTAssertEqual(error as? SMBCodecError, .invalidValue("DACL ACE trustee SID is required for SET_SECURITY"))
        }
    }

    func testTreeConnectResponseDecodesSharePolicy() throws {
        let response = try smb2TreeConnectResponse(
            treeId: 0x3344,
            shareType: 1,
            shareFlags: SMBTreeConnectConstants.shareFlagEncryptData,
            capabilities: SMBTreeConnectConstants.shareCapDFS,
            maximalAccess: 0x001f_01ff
        )

        let parsed = try SMB2TreeConnect.decodeResponse(response)

        XCTAssertEqual(parsed.treeId, 0x3344)
        XCTAssertEqual(parsed.shareType, 1)
        XCTAssertEqual(parsed.shareFlags, SMBTreeConnectConstants.shareFlagEncryptData)
        XCTAssertEqual(parsed.capabilities, SMBTreeConnectConstants.shareCapDFS)
        XCTAssertTrue(parsed.encryptionRequired)
        XCTAssertEqual(parsed.maximalAccess, 0x001f_01ff)
    }

    func testTreeConnectDFSShareCapabilityDoesNotRequireEncryption() throws {
        let response = try smb2TreeConnectResponse(
            treeId: 0x3344,
            shareType: 1,
            shareFlags: 0,
            capabilities: SMBTreeConnectConstants.shareCapDFS,
            maximalAccess: 0x001f_01ff
        )

        let parsed = try SMB2TreeConnect.decodeResponse(response)

        XCTAssertEqual(parsed.capabilities, SMBTreeConnectConstants.shareCapDFS)
        XCTAssertFalse(parsed.encryptionRequired)
    }

    func testSetInfoBasicRequestUsesFileBasicInformation() throws {
        let fileId = hexBytes("00112233445566778899aabbccddeeff")
        let request = try SMB2SetInfo.encodeBasicInfoRequest(
            messageId: 7,
            sessionId: 0x1122,
            treeId: 0x3344,
            fileId: fileId,
            update: SMBFileMetadataUpdate(
                creationTime: Date(timeIntervalSince1970: 1),
                lastAccessTime: Date(timeIntervalSince1970: 2),
                modifiedTime: Date(timeIntervalSince1970: 3),
                changeTime: Date(timeIntervalSince1970: 4),
                attributes: SMBFileAttributes.hidden | SMBFileAttributes.archive
            )
        )

        let header = try SMB2Header.decode(request)
        XCTAssertEqual(header.command, SMB2Commands.setInfo)
        XCTAssertEqual(request[66], 0x01)
        XCTAssertEqual(request[67], 4)
        XCTAssertEqual(readUInt32LE(request, at: 68), 40)
        XCTAssertEqual(readUInt16LE(request, at: 72), 96)
        XCTAssertEqual(Array(request[80..<96]), fileId)
        XCTAssertEqual(readUInt64LE(request, at: 96), 116_444_736_010_000_000)
        XCTAssertEqual(readUInt64LE(request, at: 104), 116_444_736_020_000_000)
        XCTAssertEqual(readUInt64LE(request, at: 112), 116_444_736_030_000_000)
        XCTAssertEqual(readUInt64LE(request, at: 120), 116_444_736_040_000_000)
        XCTAssertEqual(readUInt32LE(request, at: 128), SMBFileAttributes.hidden | SMBFileAttributes.archive)
    }

    func testSetInfoBasicRequestRejectsDatesOutsideFILETIME() throws {
        XCTAssertThrowsError(try SMB2SetInfo.encodeBasicInfoRequest(
            messageId: 1, sessionId: 2, treeId: 3, fileId: Array(repeating: 0, count: 16),
            update: SMBFileMetadataUpdate(creationTime: Date(timeIntervalSince1970: -20_000_000_000), lastAccessTime: nil, modifiedTime: nil, changeTime: nil)
        ))
    }

    func testDownloadTemporaryFilesAreUniqueAndCleanable() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let first = try makeSMBDownloadTemporaryFile(in: directory)
        let second = try makeSMBDownloadTemporaryFile(in: directory)
        XCTAssertNotEqual(first.url, second.url)
        try first.handle.close()
        try second.handle.close()
        try FileManager.default.removeItem(at: first.url)
        try FileManager.default.removeItem(at: second.url)
        XCTAssertFalse(FileManager.default.fileExists(atPath: first.url.path))
        XCTAssertFalse(FileManager.default.fileExists(atPath: second.url.path))
    }

    func testDownloadTemporaryFileHonorsUmaskLikeFileManagerCreateFile() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let previousMask = umask(0o022)
        defer { umask(previousMask) }

        let temporary = try makeSMBDownloadTemporaryFile(in: directory)
        try temporary.handle.close()
        let reference = directory.appendingPathComponent("reference")
        XCTAssertTrue(FileManager.default.createFile(atPath: reference.path, contents: nil))

        let mode = { (url: URL) throws -> Int in
            let permissions = try FileManager.default.attributesOfItem(atPath: url.path)[.posixPermissions]
            return try XCTUnwrap(permissions as? Int)
        }
        XCTAssertEqual(try mode(temporary.url), 0o644)
        XCTAssertEqual(try mode(temporary.url), try mode(reference))
    }

    func testSetInfoRejectsOutOfRangeFiletimeWithoutTrapping() {
        let fileId = Array(repeating: UInt8(0), count: 16)
        XCTAssertThrowsError(try SMB2SetInfo.encodeBasicInfoRequest(
            messageId: 1, sessionId: 2, treeId: 3, fileId: fileId,
            update: SMBFileMetadataUpdate(creationTime: Date(timeIntervalSince1970: -11_644_473_601))
        ))
        XCTAssertThrowsError(try SMB2SetInfo.encodeBasicInfoRequest(
            messageId: 1, sessionId: 2, treeId: 3, fileId: fileId,
            update: SMBFileMetadataUpdate(creationTime: Date(timeIntervalSince1970: 1e20))
        ))
    }

    func testReadRequestUsesOffsetLengthFileIdAndOneByteBuffer() throws {
        let fileId = (0..<16).map(UInt8.init)
        let request = try SMB2Read.encodeRequest(
            messageId: 13,
            sessionId: 0x1122_3344,
            treeId: 0x5566_7788,
            fileId: fileId,
            offset: 0x0102_0304_0506_0708,
            length: 4096
        )

        let header = try SMB2Header.decode(request)
        XCTAssertEqual(header.command, SMB2Commands.read)
        XCTAssertEqual(header.messageId, 13)
        XCTAssertEqual(header.treeId, 0x5566_7788)
        XCTAssertEqual(header.sessionId, 0x1122_3344)
        XCTAssertEqual(header.creditCharge, 1)
        XCTAssertEqual(header.credits, 1)
        XCTAssertEqual(request.count, 113)
        XCTAssertEqual(readUInt16LE(request, at: 64), 49)
        XCTAssertEqual(request[66], 0x50)
        XCTAssertEqual(request[67], 0)
        XCTAssertEqual(readUInt32LE(request, at: 68), 4096)
        XCTAssertEqual(readUInt64LE(request, at: 72), 0x0102_0304_0506_0708)
        XCTAssertEqual(Array(request[80..<96]), fileId)
        XCTAssertEqual(readUInt32LE(request, at: 96), 0)
        XCTAssertEqual(readUInt32LE(request, at: 100), 0)
        XCTAssertEqual(readUInt32LE(request, at: 104), 0)
        XCTAssertEqual(readUInt16LE(request, at: 108), 0)
        XCTAssertEqual(readUInt16LE(request, at: 110), 0)
        XCTAssertEqual(request[112], 0)
    }

    func testReadRequestUsesMultiCreditChargeForLargeLength() throws {
        let request = try SMB2Read.encodeRequest(
            messageId: 13,
            sessionId: 0x1122_3344,
            treeId: 0x5566_7788,
            fileId: (0..<16).map(UInt8.init),
            offset: 0,
            length: 65_537
        )

        let header = try SMB2Header.decode(request)
        XCTAssertEqual(header.creditCharge, 2)
        XCTAssertEqual(header.credits, 2)
    }

    func testQueryDirectoryRequestChargesCreditsForOutputBuffer() throws {
        let request = try SMB2QueryDirectory.encodeRequest(
            messageId: 21,
            sessionId: 0x1122_3344,
            treeId: 0x5566_7788,
            fileId: (0..<16).map(UInt8.init)
        )

        let header = try SMB2Header.decode(request)
        let expected = SMB2Credit.charge(forPayloadLength: UInt64(SMB2QueryDirectory.outputBufferSize))
        XCTAssertGreaterThan(expected, 1)
        XCTAssertEqual(header.creditCharge, expected)
        XCTAssertEqual(header.credits, expected)

        let capped = try SMB2QueryDirectory.encodeRequest(
            messageId: 21,
            sessionId: 0x1122_3344,
            treeId: 0x5566_7788,
            fileId: (0..<16).map(UInt8.init),
            outputBufferLength: 65_536
        )
        let cappedHeader = try SMB2Header.decode(capped)
        XCTAssertEqual(cappedHeader.creditCharge, 1)
        XCTAssertEqual(readUInt32LE(capped, at: 92), 65_536)
    }

    func testReadResponseDecodesDataOffsetAndLength() throws {
        var response = try SMB2Header(command: SMB2Commands.read, messageId: 14).encode()
        response.append(contentsOf: Array(repeating: UInt8(0), count: 16))
        let payload = Array("hello".utf8)
        writeUInt16LE(17, to: &response, at: 64)
        response[66] = 80
        writeUInt32LE(UInt32(payload.count), to: &response, at: 68)
        response.append(contentsOf: payload)

        XCTAssertEqual(try SMB2Read.decodeResponse(response), payload)
    }

    func testSessionReadChunkReadsOneResponseAtRequestedOffset() async throws {
        let fileId = hexBytes("00112233445566778899aabbccddeeff")
        let inbound = try framed([
            try smb2ReadResponse(Array("hel".utf8), messageId: 0, treeId: 0x3344),
            try smb2ReadResponse(Array("lo".utf8), messageId: 1, treeId: 0x3344)
        ])
        let transport = InMemoryTransport(inbound: inbound)
        let session = SMBSession(
            host: "server",
            port: 445,
            credential: SMBCredential(username: "user", password: "pass"),
            transport: transport,
            signingKey: Array(repeating: UInt8(0x11), count: 16)
        )

        let first = try await session.readChunk(treeId: 0x3344, fileId: fileId, offset: 10, length: 5)
        let second = try await session.readChunk(treeId: 0x3344, fileId: fileId, offset: 13, length: 2)

        XCTAssertEqual(first, Array("hel".utf8))
        XCTAssertEqual(second, Array("lo".utf8))
        let requests = try unframed(transport.outbound)
        XCTAssertEqual(requests.count, 2)
        XCTAssertEqual(try SMB2Header.decode(requests[0]).command, SMB2Commands.read)
        XCTAssertEqual(readUInt64LE(requests[0], at: 72), 10)
        XCTAssertEqual(readUInt32LE(requests[0], at: 68), 5)
        XCTAssertEqual(try SMB2Header.decode(requests[1]).command, SMB2Commands.read)
        XCTAssertEqual(readUInt64LE(requests[1], at: 72), 13)
        XCTAssertEqual(readUInt32LE(requests[1], at: 68), 2)
    }

    func testSessionReadChunkUsesGMACSigningWithoutEncryption() async throws {
        let key = hexBytes("000102030405060708090a0b0c0d0e0f")
        let fileId = hexBytes("00112233445566778899aabbccddeeff")
        let response = try signedTestPacket(
            try smb2ReadResponse(Array("ok".utf8), messageId: 0, treeId: 0x3344),
            algorithm: .aesGMAC,
            key: key,
            sender: .server
        )
        let transport = InMemoryTransport(inbound: try framed([response]))
        let session = SMBSession(
            host: "server",
            port: 445,
            credential: SMBCredential(username: "user", password: "pass"),
            transport: transport,
            signingKey: key,
            signingAlgorithm: .aesGMAC
        )

        let data = try await session.readChunk(treeId: 0x3344, fileId: fileId, offset: 0, length: 2)

        XCTAssertEqual(data, Array("ok".utf8))
        let requests = try unframed(transport.outbound)
        XCTAssertEqual(requests.count, 1)
        let requestHeader = try SMB2Header.decode(requests[0])
        XCTAssertEqual(requestHeader.command, SMB2Commands.read)
        XCTAssertEqual(requestHeader.flags & SMB2Flags.signed, SMB2Flags.signed)
        XCTAssertEqual(
            requestHeader.signature,
            try SMBSessionSigning.signature(algorithm: .aesGMAC, key: key, packet: requests[0], sender: .client)
        )
    }

    func testSessionRejectsUnsignedResponseWhenSigningIsRequired() async throws {
        let key = Array(repeating: UInt8(0x11), count: 16)
        let fileId = hexBytes("00112233445566778899aabbccddeeff")
        let transport = InMemoryTransport(inbound: try framed([
            try smb2ReadResponse(Array("ok".utf8), messageId: 0, treeId: 0x3344)
        ]))
        let session = SMBSession(
            host: "server", port: 445,
            credential: SMBCredential(username: "user", password: "pass"),
            transport: transport, signingKey: key, signingRequired: true
        )
        do {
            _ = try await session.readChunk(treeId: 0x3344, fileId: fileId, offset: 0, length: 2)
            XCTFail("unsigned response unexpectedly accepted")
        } catch {
            XCTAssertTrue(String(describing: error).contains("signature"))
        }
    }

    func testSessionReadChunkDoesNotReplayPreviousChunkAfterConnectionLoss() async throws {
        let fileId = hexBytes("00112233445566778899aabbccddeeff")
        let transport = ControlledReceiveTransport()
        let session = SMBSession(
            host: "server",
            port: 445,
            credential: SMBCredential(username: "user", password: "pass"),
            transport: transport,
            signingKey: Array(repeating: UInt8(0x11), count: 16)
        )
        let firstRead = Task {
            try await session.readChunk(treeId: 0x3344, fileId: fileId, offset: 0, length: 5)
        }
        try await awaitWithTimeout("first read request sent") {
            await session.waitForRequestSentCountForTesting(atLeast: 1)
        }
        let firstRequest = try XCTUnwrap(try unframed(transport.outbound).first)
        let firstRequestHeader = try SMB2Header.decode(firstRequest)
        transport.enqueueInbound(try DirectTCPFraming.frame(
            smb2ReadResponse(Array("hel".utf8), messageId: firstRequestHeader.messageId, treeId: 0x3344)
        ))
        let first = try await awaitWithTimeout("first read response") { try await firstRead.value }
        XCTAssertEqual(first, Array("hel".utf8))

        let secondRead = Task {
            try await session.readChunk(treeId: 0x3344, fileId: fileId, offset: 3, length: 2)
        }
        try await awaitWithTimeout("second read request sent") {
            await session.waitForRequestSentCountForTesting(atLeast: 2)
        }
        await session.closeTransport(cause: "test_connection_loss_after_partial_read")

        do {
            _ = try await awaitWithTimeout("second read fails after connection loss") { try await secondRead.value }
            XCTFail("expected connectionClosed")
        } catch SMBTransportError.connectionClosed {
            let requests = try unframed(transport.outbound)
            XCTAssertEqual(requests.count, 2)
            XCTAssertEqual(readUInt64LE(requests[1], at: 72), 3)
        } catch {
            XCTFail("expected connectionClosed, got \(error)")
        }
    }

    func testRequestAfterReceiveLoopFailureFailsWithoutCreditWait() async throws {
        let fileId = hexBytes("00112233445566778899aabbccddeeff")
        let transport = ControlledReceiveTransport()
        let session = SMBSession(
            host: "server",
            port: 445,
            credential: SMBCredential(username: "user", password: "pass"),
            transport: transport,
            signingKey: Array(repeating: UInt8(0x11), count: 16)
        )

        let firstRead = Task {
            try await session.readChunk(treeId: 0x3344, fileId: fileId, offset: 0, length: 3)
        }
        try await awaitWithTimeout("first read before peer EOF") {
            await session.waitForRequestSentCountForTesting(atLeast: 1)
        }
        let firstRequest = try XCTUnwrap(try unframed(transport.outbound).first)
        let firstRequestHeader = try SMB2Header.decode(firstRequest)
        transport.enqueueInbound(try DirectTCPFraming.frame(
            smb2ReadResponse(Array("hel".utf8), messageId: firstRequestHeader.messageId, treeId: 0x3344)
        ))
        _ = try await awaitWithTimeout("first read response before peer EOF") { try await firstRead.value }
        transport.finishInput()
        do {
            _ = try await awaitWithTimeout("request after receive failure") {
                try await session.readChunk(treeId: 0x3344, fileId: fileId, offset: 3, length: 2)
            }
            XCTFail("expected connectionClosed")
        } catch SMBTransportError.connectionClosed {
            // Expected: the second request must not park on the exhausted credit window.
        } catch {
            XCTFail("expected connectionClosed, got \(error)")
        }
    }

    func testOperationsAfterClosedTransportFailWithExistingWireFailureWithoutPendingResponse() async throws {
        let fileId = hexBytes("00112233445566778899aabbccddeeff")
        let session = SMBSession(
            host: "server",
            port: 445,
            credential: SMBCredential(username: "user", password: "pass"),
            transport: InMemoryTransport(),
            signingKey: Array(repeating: UInt8(0x11), count: 16)
        )

        await session.failWireForTesting(error: SMBTransportError.timedOut)
        await session.closeTransport(cause: "unit_test")

        do {
            try await awaitWithTimeout("ECHO after closed transport") {
                try await session.echo()
            }
            XCTFail("ECHO unexpectedly completed after transport close")
        } catch SMBTransportError.timedOut {
            // The first wire failure remains the terminal session error.
        } catch {
            XCTFail("expected timedOut, got \(error)")
        }
        let pendingAfterEcho = await session.pendingCountForTesting()
        XCTAssertEqual(pendingAfterEcho, 0)

        do {
            _ = try await awaitWithTimeout("READ after closed transport") {
                try await session.readChunk(treeId: 0x3344, fileId: fileId, offset: 0, length: 1)
            }
            XCTFail("READ unexpectedly completed after transport close")
        } catch SMBTransportError.timedOut {
            // The operation must fail before installing a pending continuation.
        } catch {
            XCTFail("expected timedOut, got \(error)")
        }
        let pendingAfterRead = await session.pendingCountForTesting()
        XCTAssertEqual(pendingAfterRead, 0)
    }

    func testConcurrentReadChunksDemuxOutOfOrderResponses() async throws {
        let fileId = hexBytes("00112233445566778899aabbccddeeff")
        let transport = ControlledReceiveTransport()
        let session = SMBSession(
            host: "server",
            port: 445,
            credential: SMBCredential(username: "user", password: "pass"),
            transport: transport,
            signingKey: Array(repeating: UInt8(0x11), count: 16),
            initialCredits: 2
        )

        let first = Task {
            try await session.readChunk(treeId: 0x3344, fileId: fileId, offset: 0, length: 3)
        }
        let second = Task {
            try await session.readChunk(treeId: 0x3344, fileId: fileId, offset: 3, length: 2)
        }

        try await waitForOutboundFrameCount(2, transport: transport)
        let requests = try unframed(transport.outbound)
        XCTAssertEqual(requests.count, 2)
        // messageId assignment follows actor arrival order, which is scheduler dependent:
        // do NOT assume `first` got messageId 0 (issues/010 — the old assumption made the
        // Linux global executor hang the suite when `second` arrived first). Map each
        // request's messageId by its read offset instead, and answer out of order.
        let headersByOffset = Dictionary(uniqueKeysWithValues: try requests.map { request in
            (readUInt64LE(request, at: 72), try SMB2Header.decode(request))
        })
        guard let firstHeader = headersByOffset[0], let secondHeader = headersByOffset[3] else {
            XCTFail("expected READ requests for offsets 0 and 3, got \(headersByOffset.keys.sorted())")
            return
        }

        transport.enqueueInbound(try framed([smb2ReadResponse(Array("lo".utf8), messageId: secondHeader.messageId, treeId: 0x3344)]))
        let secondData = try await awaitWithTimeout("second.readChunk") { try await second.value }
        XCTAssertEqual(secondData, Array("lo".utf8))

        transport.enqueueInbound(try framed([smb2ReadResponse(Array("hel".utf8), messageId: firstHeader.messageId, treeId: 0x3344)]))
        let firstData = try await awaitWithTimeout("first.readChunk") { try await first.value }
        XCTAssertEqual(firstData, Array("hel".utf8))
    }

    func testDefaultRequestTimeoutSleeperTimesOutSilentTransportAfterSend() async throws {
        let transport = ControlledReceiveTransport()
        let session = SMBSession(
            host: "server",
            port: 445,
            credential: SMBCredential(username: "user", password: "pass"),
            transport: transport,
            requestTimeout: .milliseconds(150)
        )
        let echo = Task { try await session.echo() }
        defer { echo.cancel() }

        try await waitForOutboundFrameCount(1, transport: transport)
        do {
            try await awaitWithTimeout(seconds: 3, "default request-timeout sleeper") {
                try await echo.value
            }
            XCTFail("silent ECHO unexpectedly completed")
        } catch SMBTransportError.timedOut {
        } catch {
            XCTFail("expected timedOut, got \(error)")
        }
        XCTAssertEqual(transport.closeCount, 1)
    }

    func testSMBClientConnectPropagatesRequestTimeoutToConnectedSession() async throws {
        let transport = SMBValidateNegotiateScriptTransport(
            inbound: try framed(authenticatedTreeResponses()),
            blockWhenDrained: true
        )
        let requestTimeout = Duration.seconds(2)
        let client = try await SMBClient.connect(
            host: "server",
            share: "share",
            credential: SMBCredential(username: "user", password: "pass"),
            requestTimeout: requestTimeout,
            makeTransport: { transport }
        )
        let wireSession = await client.wireSessionForTesting()
        let installedTimeout = await wireSession.requestTimeoutDurationForTesting()
        XCTAssertEqual(installedTimeout, requestTimeout)
        await wireSession.closeTransportAndWait(cause: "credential_connect_timeout_propagation_test")
        XCTAssertEqual(transport.closeCount, 1)
    }

    func testSMBClientCredentialProviderConnectPropagatesRequestTimeout() async throws {
        let transport = SMBValidateNegotiateScriptTransport(
            inbound: try framed(authenticatedTreeResponses()),
            blockWhenDrained: true
        )
        let requestTimeout = Duration.milliseconds(150)
        let client = try await SMBClient.connect(
            host: "server",
            share: "share",
            credentialProvider: { SMBCredential(username: "user", password: "pass") },
            requestTimeout: requestTimeout,
            makeTransport: { transport }
        )
        let wireSession = await client.wireSessionForTesting()
        let installedTimeout = await wireSession.requestTimeoutDurationForTesting()
        XCTAssertEqual(installedTimeout, requestTimeout)
        await wireSession.closeTransportAndWait(cause: "credential_provider_timeout_propagation_test")
        XCTAssertEqual(transport.closeCount, 1)
    }

    func testRequestTimeoutDoesNotStartUntilBlockedTransportSendCompletes() async throws {
        let transport = BlockingSendTransport(inbound: [])
        let sleeper = RequestTimeoutSleeperGate()
        let session = SMBSession(
            host: "server",
            port: 445,
            credential: SMBCredential(username: "user", password: "pass"),
            transport: transport,
            requestTimeout: .milliseconds(100),
            requestTimeoutSleeper: { try await sleeper.sleep(for: $0) }
        )
        let echo = Task { try await session.echo() }
        defer {
            echo.cancel()
            transport.releaseBlockedSend()
        }

        try await awaitWithTimeout("blocked transport send start") {
            while !transport.isSendStarted {
                try Task.checkCancellation()
                await Task.yield()
            }
        }
        XCTAssertTrue(transport.outbound.isEmpty)
        let timersDuringSend = await session.requestTimeoutTaskCountForTesting()
        XCTAssertEqual(timersDuringSend, 0)
        XCTAssertEqual(sleeper.callCount, 0)

        transport.releaseBlockedSend()
        try await awaitWithTimeout("request timeout starts after send completion") {
            while await session.requestSentCountForTesting() < 1 || sleeper.callCount < 1 {
                try Task.checkCancellation()
                await Task.yield()
            }
        }
        let request = try XCTUnwrap(try unframed(transport.outbound).first)
        let header = try SMB2Header.decode(request)
        let timersAfterSend = await session.requestTimeoutTaskCountForTesting()
        XCTAssertEqual(timersAfterSend, 1)
        transport.appendInbound(try framed([smb2EchoResponse(messageId: header.messageId)]))

        try await awaitWithTimeout("blocked-send ECHO response") {
            try await echo.value
        }
        XCTAssertEqual(sleeper.callCount, 1)
    }

    /// 既定値の契約を pin する (issue 010 §修正方針 3 / obaket issue 453)。
    /// 「公開エントリの省略時に response 待ちが unbounded に戻る」退行 (= 呼び忘れた
    /// consumer が無言ハングする footgun の再導入) を、値の変更が意図的な diff として
    /// 現れる形で検出する。
    func testDefaultRequestTimeoutIsSixtySecondsAndOptOutIsExplicitNil() {
        XCTAssertEqual(SMBClient.defaultRequestTimeout, .seconds(60))
    }

    func testNilRequestTimeoutNeverInvokesSleeperForSentOrdinaryRequest() async throws {
        let transport = ControlledReceiveTransport()
        let sleeper = RequestTimeoutSleeperGate()
        let session = SMBSession(
            host: "server",
            port: 445,
            credential: SMBCredential(username: "user", password: "pass"),
            transport: transport,
            requestTimeout: nil,
            requestTimeoutSleeper: { try await sleeper.sleep(for: $0) }
        )
        let echo = Task { try await session.echo() }
        defer { echo.cancel() }

        try await waitForOutboundFrameCount(1, transport: transport)
        try await awaitWithTimeout("nil request-timeout sent barrier") {
            while await session.requestSentCountForTesting() < 1 {
                try Task.checkCancellation()
                await Task.yield()
            }
        }
        let timersAfterSend = await session.requestTimeoutTaskCountForTesting()
        XCTAssertEqual(timersAfterSend, 0)
        XCTAssertEqual(sleeper.callCount, 0)

        let request = try XCTUnwrap(try unframed(transport.outbound).first)
        let header = try SMB2Header.decode(request)
        transport.enqueueInbound(try framed([smb2EchoResponse(messageId: header.messageId)]))
        try await awaitWithTimeout("nil request-timeout ECHO response") {
            try await echo.value
        }
        XCTAssertEqual(sleeper.callCount, 0)
    }

    func testFailImmediatelyLockStartsAndFiresRequestTimeout() async throws {
        let fileId = hexBytes("00112233445566778899aabbccddeeff")
        let transport = ControlledReceiveTransport()
        let sleeper = RequestTimeoutSleeperGate()
        let session = SMBSession(
            host: "server",
            port: 445,
            credential: SMBCredential(username: "user", password: "pass"),
            transport: transport,
            signingKey: Array(repeating: UInt8(0x11), count: 16),
            requestTimeout: .milliseconds(100),
            requestTimeoutSleeper: { try await sleeper.sleep(for: $0) }
        )
        let lock = Task {
            try await session.lock(
                treeId: 0x3344,
                fileId: fileId,
                elements: [.lock(offset: 0, length: 1, shared: false, failImmediately: true)]
            )
        }
        defer { lock.cancel() }

        try await waitForOutboundFrameCount(1, transport: transport)
        try await awaitWithTimeout("fail-immediately LOCK timeout installation") {
            while await session.requestSentCountForTesting() < 1 || sleeper.callCount < 1 {
                try Task.checkCancellation()
                await Task.yield()
            }
        }
        let request = try XCTUnwrap(try unframed(transport.outbound).first)
        XCTAssertEqual(try SMB2Header.decode(request).command, SMB2Commands.lock)
        let timersAfterSend = await session.requestTimeoutTaskCountForTesting()
        XCTAssertEqual(timersAfterSend, 1)

        sleeper.fireNext()
        do {
            try await awaitWithTimeout("fail-immediately LOCK request timeout") {
                try await lock.value
            }
            XCTFail("silent fail-immediately LOCK unexpectedly completed")
        } catch SMBTransportError.timedOut {
        } catch {
            XCTFail("expected timedOut, got \(error)")
        }
        XCTAssertEqual(transport.closeCount, 1)
    }

    func testNamedPipeFragmentFollowUpReadDoesNotStartRequestTimeout() async throws {
        let fileId = hexBytes("00112233445566778899aabbccddeeff")
        let stub = makeShareEnumStub([("public", 0, "Public share")])
        let split = stub.count / 2
        let firstFragment = try dcerpcResponsePDU(
            stub: Array(stub[..<split]),
            flags: DCERPC.pfcFirstFrag
        )
        let lastFragment = try dcerpcResponsePDU(
            stub: Array(stub[split...]),
            flags: DCERPC.pfcLastFrag
        )
        let transport = ControlledReceiveTransport()
        let sleeper = RequestTimeoutSleeperGate()
        let session = SMBSession(
            host: "server",
            port: 445,
            credential: SMBCredential(username: "user", password: "pass"),
            transport: transport,
            signingKey: Array(repeating: UInt8(0x11), count: 16),
            requestTimeout: .milliseconds(100),
            requestTimeoutSleeper: { try await sleeper.sleep(for: $0) }
        )
        let transceive = Task {
            try await session.pipeTransceive(
                treeId: 0x3344,
                fileId: fileId,
                input: [0xaa],
                maxOutputResponse: 16
            )
        }
        defer { transceive.cancel() }

        try await waitForOutboundFrameCount(1, transport: transport)
        let ioctlRequest = try XCTUnwrap(try unframed(transport.outbound).first)
        let ioctlHeader = try SMB2Header.decode(ioctlRequest)
        XCTAssertEqual(ioctlHeader.command, SMB2Commands.ioctl)
        transport.enqueueInbound(try framed([
            smb2IoctlResponse(
                output: firstFragment,
                status: SMB2Status.bufferOverflow,
                messageId: ioctlHeader.messageId,
                treeId: 0x3344,
                fileId: fileId
            )
        ]))

        try await waitForOutboundFrameCount(2, transport: transport)
        try await awaitWithTimeout("named-pipe follow-up READ sent barrier") {
            while await session.requestSentCountForTesting() < 2 {
                try Task.checkCancellation()
                await Task.yield()
            }
        }
        let requests = try unframed(transport.outbound)
        let readHeader = try SMB2Header.decode(requests[1])
        XCTAssertEqual(readHeader.command, SMB2Commands.read)
        let timersAfterReadSend = await session.requestTimeoutTaskCountForTesting()
        XCTAssertEqual(timersAfterReadSend, 0)
        XCTAssertEqual(sleeper.callCount, 0)

        transport.enqueueInbound(try framed([
            smb2ReadResponse(lastFragment, messageId: readHeader.messageId, treeId: 0x3344)
        ]))
        let response = try await awaitWithTimeout("named-pipe fragmented response") {
            try await transceive.value
        }
        XCTAssertEqual(response, firstFragment + lastFragment)
        XCTAssertEqual(sleeper.callCount, 0)
    }

    func testSentRequestTimeoutIsSessionFatalAndDrainsPendingAndCreditWaiters() async throws {
        let fileId = hexBytes("00112233445566778899aabbccddeeff")
        let transport = ControlledReceiveTransport()
        let sleeper = RequestTimeoutSleeperGate()
        let session = SMBSession(
            host: "server",
            port: 445,
            credential: SMBCredential(username: "user", password: "pass"),
            transport: transport,
            signingKey: Array(repeating: UInt8(0x11), count: 16),
            initialCredits: 2,
            requestTimeout: .milliseconds(300),
            requestTimeoutSleeper: { try await sleeper.sleep(for: $0) }
        )
        defer { sleeper.reset() }

        let first = Task {
            try await session.readChunk(treeId: 0x3344, fileId: fileId, offset: 0, length: 1)
        }
        let second = Task {
            try await session.readChunk(treeId: 0x3344, fileId: fileId, offset: 1, length: 1)
        }
        let creditParked = Task {
            try await session.readChunk(treeId: 0x3344, fileId: fileId, offset: 2, length: 1)
        }
        let requests = [first, second, creditParked]
        defer { requests.forEach { $0.cancel() } }

        try await waitForOutboundFrameCount(2, transport: transport)
        try await awaitWithTimeout("third READ parked on credits") {
            while await session.creditWaiterCountForTesting() != 1 {
                try Task.checkCancellation()
                await Task.yield()
            }
        }
        try await awaitWithTimeout("sent READ timeout installation") {
            await session.waitForRequestSentCountForTesting(atLeast: 2)
            try await sleeper.waitUntilCallCount(
                atLeast: 2,
                timeout: .seconds(1),
                sleeper: { try await ManualSMBSleeper().sleep(for: $0) }
            )
        }
        let pendingBeforeTimeout = await session.pendingCountForTesting()
        let timersBeforeTimeout = await session.requestTimeoutTaskCountForTesting()
        XCTAssertEqual(pendingBeforeTimeout, 2, "a credit waiter has no response record until its charge is reserved")
        XCTAssertEqual(timersBeforeTimeout, 2)
        sleeper.fireNext()
        try await awaitWithTimeout("request timeout processing") {
            while await session.requestTimeoutCompletionCountForTesting() < 1 {
                try Task.checkCancellation()
                await Task.yield()
            }
        }

        var timedOutCount = 0
        var connectionClosedCount = 0
        for (index, request) in requests.enumerated() {
            do {
                _ = try await awaitWithTimeout("request timeout victim \(index)") {
                    try await request.value
                }
                XCTFail("request \(index) unexpectedly completed")
            } catch SMBTransportError.timedOut {
                timedOutCount += 1
            } catch SMBTransportError.connectionClosed {
                connectionClosedCount += 1
            }
        }

        XCTAssertEqual(timedOutCount, 1)
        XCTAssertEqual(connectionClosedCount, 2)
        XCTAssertEqual(transport.closeCount, 1)
        try await awaitWithTimeout("request-timeout drain") {
            while true {
                let pendingCount = await session.pendingCountForTesting()
                let waiterCount = await session.creditWaiterCountForTesting()
                if pendingCount == 0, waiterCount == 0 { break }
                try Task.checkCancellation()
                await Task.yield()
            }
        }
        let timersAfterTimeout = await session.requestTimeoutTaskCountForTesting()
        XCTAssertEqual(timersAfterTimeout, 0)
        await session.closeTransportAndWait(cause: "test_request_timeout_reader_join")
        let readerRunningAfterTimeout = await session.receiveLoopRunningForTesting()
        XCTAssertFalse(readerRunningAfterTimeout)
        XCTAssertEqual(sleeper.pendingCount, 0)
    }

    func testRequestResponseCancelsTimeoutWithoutClosingTransport() async throws {
        let fileId = hexBytes("00112233445566778899aabbccddeeff")
        let transport = ControlledReceiveTransport()
        let sleeper = RequestTimeoutSleeperGate()
        let session = SMBSession(
            host: "server",
            port: 445,
            credential: SMBCredential(username: "user", password: "pass"),
            transport: transport,
            signingKey: Array(repeating: UInt8(0x11), count: 16),
            requestTimeout: .milliseconds(100),
            requestTimeoutSleeper: { try await sleeper.sleep(for: $0) }
        )
        let read = Task {
            try await session.readChunk(treeId: 0x3344, fileId: fileId, offset: 0, length: 2)
        }
        defer { read.cancel() }

        try await waitForOutboundFrameCount(1, transport: transport)
        try await awaitWithTimeout("READ timeout installation") {
            while await session.requestSentCountForTesting() < 1 || sleeper.callCount < 1 {
                try Task.checkCancellation()
                await Task.yield()
            }
        }
        let timersWhilePending = await session.requestTimeoutTaskCountForTesting()
        XCTAssertEqual(timersWhilePending, 1)
        let request = try XCTUnwrap(try unframed(transport.outbound).first)
        let header = try SMB2Header.decode(request)
        transport.enqueueInbound(try framed([
            smb2ReadResponse(Array("ok".utf8), messageId: header.messageId, treeId: 0x3344)
        ]))

        let result = try await awaitWithTimeout("READ response beats request timeout") {
            try await read.value
        }
        XCTAssertEqual(result, Array("ok".utf8))
        let pendingAfterResponse = await session.pendingCountForTesting()
        let timersAfterResponse = await session.requestTimeoutTaskCountForTesting()
        XCTAssertEqual(pendingAfterResponse, 0)
        XCTAssertEqual(timersAfterResponse, 0)
        try await awaitWithTimeout("cancelled READ timeout sleeper") {
            while sleeper.pendingCount != 0 {
                try Task.checkCancellation()
                await Task.yield()
            }
        }
        XCTAssertEqual(transport.closeCount, 0)
    }

    func testCreditParkedRequestDoesNotStartRequestTimeout() async throws {
        let fileId = hexBytes("00112233445566778899aabbccddeeff")
        let transport = ControlledReceiveTransport()
        let sleeper = RequestTimeoutSleeperGate()
        let session = SMBSession(
            host: "server",
            port: 445,
            credential: SMBCredential(username: "user", password: "pass"),
            transport: transport,
            signingKey: Array(repeating: UInt8(0x11), count: 16),
            initialCredits: 0,
            requestTimeout: .milliseconds(100),
            requestTimeoutSleeper: { try await sleeper.sleep(for: $0) }
        )
        let read = Task {
            try await session.readChunk(treeId: 0x3344, fileId: fileId, offset: 0, length: 1)
        }
        defer { read.cancel() }

        try await awaitWithTimeout("READ parked before wire send") {
            await session.waitForCreditWaiterCountForTesting(atLeast: 1)
        }
        let pendingWhileCreditParked = await session.pendingCountForTesting()
        XCTAssertEqual(pendingWhileCreditParked, 0, "MessageId and pending response are assigned after variable charge reservation")
        XCTAssertTrue(transport.outbound.isEmpty)
        let timersBeforeElapsedTimeout = await session.requestTimeoutTaskCountForTesting()
        XCTAssertEqual(timersBeforeElapsedTimeout, 0)
        let pendingAfterElapsedTimeout = await session.pendingCountForTesting()
        let waitersAfterElapsedTimeout = await session.creditWaiterCountForTesting()
        let timersAfterElapsedTimeout = await session.requestTimeoutTaskCountForTesting()
        XCTAssertEqual(pendingAfterElapsedTimeout, 0)
        XCTAssertEqual(waitersAfterElapsedTimeout, 1)
        XCTAssertEqual(timersAfterElapsedTimeout, 0)
        XCTAssertEqual(sleeper.callCount, 0)
        XCTAssertEqual(transport.closeCount, 0)

        read.cancel()
        do {
            _ = try await awaitWithTimeout("cancel credit-parked READ") { try await read.value }
            XCTFail("cancelled READ unexpectedly completed")
        } catch is CancellationError {
        }
        try await awaitWithTimeout("cancelled credit waiter drain") {
            while true {
                let pendingCount = await session.pendingCountForTesting()
                let waiterCount = await session.creditWaiterCountForTesting()
                if pendingCount == 0, waiterCount == 0 { break }
                try Task.checkCancellation()
                await Task.yield()
            }
        }
    }

    func testLongPollDoesNotStartRequestTimeout() async throws {
        let fileId = hexBytes("00112233445566778899aabbccddeeff")
        let transport = ControlledReceiveTransport()
        let sleeper = RequestTimeoutSleeperGate()
        let session = SMBSession(
            host: "server",
            port: 445,
            credential: SMBCredential(username: "user", password: "pass"),
            transport: transport,
            signingKey: Array(repeating: UInt8(0x11), count: 16),
            requestTimeout: .milliseconds(100),
            requestTimeoutSleeper: { try await sleeper.sleep(for: $0) }
        )
        let notify = Task {
            try await session.changeNotify(
                treeId: 0x3344,
                fileId: fileId,
                filter: .default,
                watchTree: false
            ) { _ in
                XCTFail("cancelled CHANGE_NOTIFY should not deliver an event")
            }
        }
        defer { notify.cancel() }

        try await waitForOutboundFrameCount(1, transport: transport)
        try await awaitWithTimeout("CHANGE_NOTIFY sent barrier") {
            while await session.requestSentCountForTesting() < 1 {
                try Task.checkCancellation()
                await Task.yield()
            }
        }
        let timersBeforeLongPollWait = await session.requestTimeoutTaskCountForTesting()
        XCTAssertEqual(timersBeforeLongPollWait, 0)
        let pendingAfterLongPollWait = await session.pendingCountForTesting()
        let timersAfterLongPollWait = await session.requestTimeoutTaskCountForTesting()
        XCTAssertEqual(pendingAfterLongPollWait, 1)
        XCTAssertEqual(timersAfterLongPollWait, 0)
        XCTAssertEqual(sleeper.callCount, 0)
        XCTAssertEqual(transport.closeCount, 0)

        let request = try XCTUnwrap(try unframed(transport.outbound).first)
        let header = try SMB2Header.decode(request)
        notify.cancel()
        try await waitForOutboundFrameCount(2, transport: transport)
        transport.enqueueInbound(try framed([
            smb2StatusResponse(
                status: SMB2Status.cancelled,
                command: SMB2Commands.changeNotify,
                messageId: header.messageId,
                treeId: header.treeId
            )
        ]))
        do {
            try await awaitWithTimeout("cancel request-timeout-exempt CHANGE_NOTIFY") {
                try await notify.value
            }
            XCTFail("cancelled CHANGE_NOTIFY unexpectedly completed")
        } catch is CancellationError {
        }
    }

    func testBlockingLockAndNamedPipeTransactionsDoNotStartRequestTimeout() async throws {
        let fileId = hexBytes("00112233445566778899aabbccddeeff")
        let transport = ControlledReceiveTransport()
        let sleeper = RequestTimeoutSleeperGate()
        let session = SMBSession(
            host: "server",
            port: 445,
            credential: SMBCredential(username: "user", password: "pass"),
            transport: transport,
            signingKey: Array(repeating: UInt8(0x11), count: 16),
            initialCredits: 2,
            requestTimeout: .milliseconds(100),
            requestTimeoutSleeper: { try await sleeper.sleep(for: $0) }
        )
        let blockingLock = Task {
            try await session.lock(
                treeId: 0x3344,
                fileId: fileId,
                elements: [.lock(offset: 0, length: 1, shared: false, failImmediately: false)]
            )
        }
        let pipeIO = Task {
            try await session.pipeTransceive(
                treeId: 0x3344,
                fileId: fileId,
                input: [UInt8](repeating: 0, count: 16)
            )
        }
        defer {
            blockingLock.cancel()
            pipeIO.cancel()
        }

        try await waitForOutboundFrameCount(2, transport: transport)
        try await awaitWithTimeout("timeout-exempt requests sent barrier") {
            while await session.requestSentCountForTesting() < 2 {
                try Task.checkCancellation()
                await Task.yield()
            }
        }
        let requests = try unframed(transport.outbound)
        let requestHeaders = try requests.map(SMB2Header.decode)
        XCTAssertEqual(Set(requestHeaders.map(\.command)), [SMB2Commands.lock, SMB2Commands.ioctl])
        let timersBeforeWait = await session.requestTimeoutTaskCountForTesting()
        XCTAssertEqual(timersBeforeWait, 0)
        let pendingAfterWait = await session.pendingCountForTesting()
        let timersAfterWait = await session.requestTimeoutTaskCountForTesting()
        XCTAssertEqual(pendingAfterWait, 2)
        XCTAssertEqual(timersAfterWait, 0)
        XCTAssertEqual(sleeper.callCount, 0)
        XCTAssertEqual(transport.closeCount, 0)

        blockingLock.cancel()
        pipeIO.cancel()
        try await waitForOutboundFrameCount(4, transport: transport)
        do {
            try await awaitWithTimeout("cancel timeout-exempt blocking LOCK") {
                try await blockingLock.value
            }
            XCTFail("cancelled LOCK unexpectedly completed")
        } catch is CancellationError {
        }
        do {
            _ = try await awaitWithTimeout("cancel timeout-exempt named-pipe I/O") {
                try await pipeIO.value
            }
            XCTFail("cancelled named-pipe I/O unexpectedly completed")
        } catch is CancellationError {
        }
        transport.enqueueInbound(try framed(requestHeaders.map { header in
            try smb2StatusResponse(
                status: SMB2Status.cancelled,
                command: header.command,
                messageId: header.messageId,
                treeId: header.treeId
            )
        }))
        try await awaitWithTimeout("timeout-exempt cancellation responses") {
            while await session.pendingCountForTesting() != 0 {
                try Task.checkCancellation()
                await Task.yield()
            }
        }
    }

    func testLateResponseAfterRequestTimeoutDoesNotResumeTwice() async throws {
        let fileId = hexBytes("00112233445566778899aabbccddeeff")
        let transport = ControlledReceiveTransport()
        let sleeper = RequestTimeoutSleeperGate()
        let session = SMBSession(
            host: "server",
            port: 445,
            credential: SMBCredential(username: "user", password: "pass"),
            transport: transport,
            signingKey: Array(repeating: UInt8(0x11), count: 16),
            requestTimeout: .milliseconds(100),
            requestTimeoutSleeper: { try await sleeper.sleep(for: $0) }
        )
        let read = Task {
            try await session.readChunk(treeId: 0x3344, fileId: fileId, offset: 0, length: 1)
        }
        defer { read.cancel() }

        try await waitForOutboundFrameCount(1, transport: transport)
        try await awaitWithTimeout("late-response READ timeout installation") {
            while await session.requestSentCountForTesting() < 1 || sleeper.callCount < 1 {
                try Task.checkCancellation()
                await Task.yield()
            }
        }
        let request = try XCTUnwrap(try unframed(transport.outbound).first)
        let header = try SMB2Header.decode(request)
        sleeper.fireNext()
        do {
            _ = try await awaitWithTimeout("READ request timeout") { try await read.value }
            XCTFail("READ unexpectedly completed")
        } catch SMBTransportError.timedOut {
        }
        try await awaitWithTimeout("late-response timeout processing") {
            while await session.requestTimeoutCompletionCountForTesting() < 1 {
                try Task.checkCancellation()
                await Task.yield()
            }
        }
        XCTAssertEqual(transport.closeCount, 1)
        await session.closeTransportAndWait(cause: "test_late_response_reader_join")
        let readerRunningAfterLateTimeout = await session.receiveLoopRunningForTesting()
        XCTAssertFalse(readerRunningAfterLateTimeout)

        let dispatchesBeforeLateResponse = await session.receivedPacketDispatchCountForTesting()
        try await session.dispatchReceivedPacketForTesting(
            smb2ReadResponse([0x2a], messageId: header.messageId, treeId: 0x3344)
        )
        let dispatchesAfterLateResponse = await session.receivedPacketDispatchCountForTesting()
        let pendingAfterLateResponse = await session.pendingCountForTesting()
        let timersAfterLateResponse = await session.requestTimeoutTaskCountForTesting()
        XCTAssertEqual(pendingAfterLateResponse, 0)
        XCTAssertEqual(timersAfterLateResponse, 0)
        XCTAssertEqual(dispatchesAfterLateResponse, dispatchesBeforeLateResponse, "a terminal generation discards late responses")
        XCTAssertEqual(transport.closeCount, 1)
    }

    func testUnsolicitedOplockBreakNotificationIsIgnoredByDemux() async throws {
        let fileId = hexBytes("00112233445566778899aabbccddeeff")
        let transport = ControlledReceiveTransport()
        let session = SMBSession(
            host: "server",
            port: 445,
            credential: SMBCredential(username: "user", password: "pass"),
            transport: transport,
            signingKey: Array(repeating: UInt8(0x11), count: 16)
        )

        let read = Task {
            try await session.readChunk(treeId: 0x3344, fileId: fileId, offset: 0, length: 5)
        }
        try await waitForOutboundFrameCount(1, transport: transport)

        // Server-initiated break notification: MessageId = 0xFFFF... / command = OPLOCK_BREAK.
        // It must be dropped, not queued as an orphan or delivered to the pending read.
        let breakNotification = try smb2StatusResponse(
            status: SMB2Status.success,
            command: SMB2Commands.oplockBreak,
            messageId: UInt64.max,
            treeId: 0x3344
        )
        transport.enqueueInbound(try framed([breakNotification]))
        transport.enqueueInbound(try framed([smb2ReadResponse(Array("hello".utf8), messageId: 0, treeId: 0x3344)]))

        let data = try await awaitWithTimeout("read.readChunk") { try await read.value }
        XCTAssertEqual(data, Array("hello".utf8))
    }

    func testSessionCopyFileFallsBackToReadWriteWhenServerSideCopyIsUnsupported() async throws {
        let sourceFileId = hexBytes("00112233445566778899aabbccddeeff")
        let destinationFileId = hexBytes("ffeeddccbbaa99887766554433221100")
        let inbound = try framed([
            try smb2CreateResponse(fileId: sourceFileId, messageId: 0, treeId: 0x3344),
            try smb2QueryInfoResponse(size: 5, messageId: 1, treeId: 0x3344),
            try smb2CreateResponse(fileId: destinationFileId, messageId: 2, treeId: 0x3344),
            try smb2IoctlResponse(output: [], status: SMB2Status.notSupported, messageId: 3, treeId: 0x3344, fileId: sourceFileId, ctlCode: SMB2Ioctl.fsctlSrvRequestResumeKey),
            try smb2ReadResponse(Array("hel".utf8), messageId: 4, treeId: 0x3344),
            try smb2WriteResponse(count: 3, messageId: 5, treeId: 0x3344),
            try smb2ReadResponse(Array("lo".utf8), messageId: 6, treeId: 0x3344),
            try smb2WriteResponse(count: 2, messageId: 7, treeId: 0x3344),
            try smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.flush, messageId: 8, treeId: 0x3344),
            try smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.close, messageId: 9, treeId: 0x3344),
            try smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.close, messageId: 10, treeId: 0x3344)
        ])
        let transport = InMemoryTransport(inbound: inbound)
        let session = SMBSession(
            host: "server",
            port: 445,
            credential: SMBCredential(username: "user", password: "pass"),
            transport: transport,
            signingKey: Array(repeating: UInt8(0x11), count: 16)
        )

        try await session.copyFile(treeId: 0x3344, fromPath: "source.txt", toPath: "copy.txt", overwrite: false)

        let requests = try unframed(transport.outbound)
        XCTAssertEqual(requests.map { try? SMB2Header.decode($0).command }, [
            SMB2Commands.create,
            SMB2Commands.queryInfo,
            SMB2Commands.create,
            SMB2Commands.ioctl,
            SMB2Commands.read,
            SMB2Commands.write,
            SMB2Commands.read,
            SMB2Commands.write,
            SMB2Commands.flush,
            SMB2Commands.close,
            SMB2Commands.close
        ])
        XCTAssertEqual(readUInt32LE(requests[2], at: 100), 0x0000_0002)
        XCTAssertEqual(readUInt32LE(requests[3], at: 68), SMB2Ioctl.fsctlSrvRequestResumeKey)
        XCTAssertEqual(Array(requests[3][72..<88]), sourceFileId)
        XCTAssertEqual(readUInt64LE(requests[4], at: 72), 0)
        XCTAssertEqual(readUInt32LE(requests[4], at: 68), 5)
        XCTAssertEqual(readUInt64LE(requests[5], at: 72), 0)
        XCTAssertEqual(Array(requests[5][112..<requests[5].count]), Array("hel".utf8))
        XCTAssertEqual(readUInt64LE(requests[6], at: 72), 3)
        XCTAssertEqual(readUInt32LE(requests[6], at: 68), 2)
        XCTAssertEqual(readUInt64LE(requests[7], at: 72), 3)
        XCTAssertEqual(Array(requests[7][112..<requests[7].count]), Array("lo".utf8))
        XCTAssertEqual(Array(requests[9][72..<88]), destinationFileId)
        XCTAssertEqual(Array(requests[10][72..<88]), sourceFileId)
    }

    func testSessionCopyFileFallsBackWhenCopyChunkReturnsErrorFormatResponse() async throws {
        // Real Samba (on filesystems without copy offload) replies to FSCTL_SRV_COPYCHUNK_WRITE
        // with a StructureSize-9 SMB2 ERROR response carrying STATUS_INVALID_DEVICE_REQUEST,
        // not an IOCTL response. The client must treat it as "unsupported" and fall back.
        let sourceFileId = hexBytes("00112233445566778899aabbccddeeff")
        let destinationFileId = hexBytes("ffeeddccbbaa99887766554433221100")
        let resumeKey = Array(0x30...0x47).map(UInt8.init)
        let inbound = try framed([
            try smb2CreateResponse(fileId: sourceFileId, messageId: 0, treeId: 0x3344),
            try smb2QueryInfoResponse(size: 5, messageId: 1, treeId: 0x3344),
            try smb2CreateResponse(fileId: destinationFileId, messageId: 2, treeId: 0x3344),
            try smb2IoctlResponse(output: resumeKey, status: SMB2Status.success, messageId: 3, treeId: 0x3344, fileId: sourceFileId, ctlCode: SMB2Ioctl.fsctlSrvRequestResumeKey),
            try smb2ErrorResponse(status: SMB2Status.invalidDeviceRequest, command: SMB2Commands.ioctl, messageId: 4, treeId: 0x3344),
            try smb2ReadResponse(Array("hel".utf8), messageId: 5, treeId: 0x3344),
            try smb2WriteResponse(count: 3, messageId: 6, treeId: 0x3344),
            try smb2ReadResponse(Array("lo".utf8), messageId: 7, treeId: 0x3344),
            try smb2WriteResponse(count: 2, messageId: 8, treeId: 0x3344),
            try smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.flush, messageId: 9, treeId: 0x3344),
            try smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.close, messageId: 10, treeId: 0x3344),
            try smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.close, messageId: 11, treeId: 0x3344)
        ])
        let transport = InMemoryTransport(inbound: inbound)
        let session = SMBSession(
            host: "server",
            port: 445,
            credential: SMBCredential(username: "user", password: "pass"),
            transport: transport,
            signingKey: Array(repeating: UInt8(0x11), count: 16)
        )

        try await session.copyFile(treeId: 0x3344, fromPath: "source.txt", toPath: "copy.txt", overwrite: false)

        let requests = try unframed(transport.outbound)
        XCTAssertEqual(requests.map { try? SMB2Header.decode($0).command }, [
            SMB2Commands.create,
            SMB2Commands.queryInfo,
            SMB2Commands.create,
            SMB2Commands.ioctl,
            SMB2Commands.ioctl,
            SMB2Commands.read,
            SMB2Commands.write,
            SMB2Commands.read,
            SMB2Commands.write,
            SMB2Commands.flush,
            SMB2Commands.close,
            SMB2Commands.close
        ])
        XCTAssertEqual(readUInt32LE(requests[3], at: 68), SMB2Ioctl.fsctlSrvRequestResumeKey)
        XCTAssertEqual(readUInt32LE(requests[4], at: 68), SMB2Ioctl.fsctlSrvCopychunkWrite)
        XCTAssertEqual(Array(requests[6][112..<requests[6].count]), Array("hel".utf8))
        XCTAssertEqual(Array(requests[8][112..<requests[8].count]), Array("lo".utf8))
    }

    func testSessionCopyFileUsesServerSideCopyChunkAndVerifiesSize() async throws {
        let sourceFileId = hexBytes("00112233445566778899aabbccddeeff")
        let destinationFileId = hexBytes("ffeeddccbbaa99887766554433221100")
        let resumeKey = Array(0x30...0x47).map(UInt8.init)
        var copyResponse: [UInt8] = []
        appendUInt32LE(1, to: &copyResponse)
        appendUInt32LE(5, to: &copyResponse)
        appendUInt32LE(5, to: &copyResponse)
        let inbound = try framed([
            try smb2CreateResponse(fileId: sourceFileId, messageId: 0, treeId: 0x3344),
            try smb2QueryInfoResponse(size: 5, messageId: 1, treeId: 0x3344),
            try smb2CreateResponse(fileId: destinationFileId, messageId: 2, treeId: 0x3344),
            try smb2IoctlResponse(output: resumeKey, status: SMB2Status.success, messageId: 3, treeId: 0x3344, fileId: sourceFileId, ctlCode: SMB2Ioctl.fsctlSrvRequestResumeKey),
            try smb2IoctlResponse(output: copyResponse, status: SMB2Status.success, messageId: 4, treeId: 0x3344, fileId: destinationFileId, ctlCode: SMB2Ioctl.fsctlSrvCopychunkWrite),
            try smb2QueryInfoResponse(size: 5, messageId: 5, treeId: 0x3344),
            try smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.flush, messageId: 6, treeId: 0x3344),
            try smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.close, messageId: 7, treeId: 0x3344),
            try smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.close, messageId: 8, treeId: 0x3344)
        ])
        let transport = InMemoryTransport(inbound: inbound)
        let session = SMBSession(
            host: "server",
            port: 445,
            credential: SMBCredential(username: "user", password: "pass"),
            transport: transport,
            signingKey: Array(repeating: UInt8(0x11), count: 16)
        )

        try await session.copyFile(treeId: 0x3344, fromPath: "source.txt", toPath: "copy.txt", overwrite: false)

        let requests = try unframed(transport.outbound)
        XCTAssertEqual(requests.map { try? SMB2Header.decode($0).command }, [
            SMB2Commands.create,
            SMB2Commands.queryInfo,
            SMB2Commands.create,
            SMB2Commands.ioctl,
            SMB2Commands.ioctl,
            SMB2Commands.queryInfo,
            SMB2Commands.flush,
            SMB2Commands.close,
            SMB2Commands.close
        ])
        XCTAssertEqual(readUInt32LE(requests[3], at: 68), SMB2Ioctl.fsctlSrvRequestResumeKey)
        XCTAssertEqual(readUInt32LE(requests[4], at: 68), SMB2Ioctl.fsctlSrvCopychunkWrite)
        XCTAssertEqual(Array(requests[4][120..<144]), resumeKey)
        XCTAssertEqual(readUInt32LE(requests[4], at: 144), 1)
        XCTAssertEqual(readUInt64LE(requests[4], at: 152), 0)
        XCTAssertEqual(readUInt64LE(requests[4], at: 160), 0)
        XCTAssertEqual(readUInt32LE(requests[4], at: 168), 5)
    }

    func testSessionCopyFileRetriesCopyChunkWithServerLimits() async throws {
        let sourceFileId = hexBytes("00112233445566778899aabbccddeeff")
        let destinationFileId = hexBytes("ffeeddccbbaa99887766554433221100")
        let resumeKey = Array(0x30...0x47).map(UInt8.init)
        var limits: [UInt8] = []
        appendUInt32LE(2, to: &limits)
        appendUInt32LE(3, to: &limits)
        appendUInt32LE(5, to: &limits)
        var firstCopy: [UInt8] = []
        appendUInt32LE(2, to: &firstCopy)
        appendUInt32LE(3, to: &firstCopy)
        appendUInt32LE(5, to: &firstCopy)
        var secondCopy: [UInt8] = []
        appendUInt32LE(1, to: &secondCopy)
        appendUInt32LE(2, to: &secondCopy)
        appendUInt32LE(2, to: &secondCopy)
        let inbound = try framed([
            try smb2CreateResponse(fileId: sourceFileId, messageId: 0, treeId: 0x3344),
            try smb2QueryInfoResponse(size: 7, messageId: 1, treeId: 0x3344),
            try smb2CreateResponse(fileId: destinationFileId, messageId: 2, treeId: 0x3344),
            try smb2IoctlResponse(output: resumeKey, status: SMB2Status.success, messageId: 3, treeId: 0x3344, fileId: sourceFileId, ctlCode: SMB2Ioctl.fsctlSrvRequestResumeKey),
            try smb2IoctlResponse(output: limits, status: SMB2Status.invalidParameter, messageId: 4, treeId: 0x3344, fileId: destinationFileId, ctlCode: SMB2Ioctl.fsctlSrvCopychunkWrite),
            try smb2IoctlResponse(output: firstCopy, status: SMB2Status.success, messageId: 5, treeId: 0x3344, fileId: destinationFileId, ctlCode: SMB2Ioctl.fsctlSrvCopychunkWrite),
            try smb2IoctlResponse(output: secondCopy, status: SMB2Status.success, messageId: 6, treeId: 0x3344, fileId: destinationFileId, ctlCode: SMB2Ioctl.fsctlSrvCopychunkWrite),
            try smb2QueryInfoResponse(size: 7, messageId: 7, treeId: 0x3344),
            try smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.flush, messageId: 8, treeId: 0x3344),
            try smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.close, messageId: 9, treeId: 0x3344),
            try smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.close, messageId: 10, treeId: 0x3344)
        ])
        let transport = InMemoryTransport(inbound: inbound)
        let session = SMBSession(
            host: "server",
            port: 445,
            credential: SMBCredential(username: "user", password: "pass"),
            transport: transport,
            signingKey: Array(repeating: UInt8(0x11), count: 16)
        )

        try await session.copyFile(treeId: 0x3344, fromPath: "source.txt", toPath: "copy.txt", overwrite: false)

        let requests = try unframed(transport.outbound)
        XCTAssertEqual(readUInt32LE(requests[4], at: 144), 1)
        XCTAssertEqual(readUInt32LE(requests[4], at: 168), 7)
        XCTAssertEqual(readUInt32LE(requests[5], at: 144), 2)
        XCTAssertEqual(readUInt32LE(requests[5], at: 168), 3)
        XCTAssertEqual(readUInt32LE(requests[5], at: 192), 2)
        XCTAssertEqual(readUInt32LE(requests[6], at: 144), 1)
        XCTAssertEqual(readUInt64LE(requests[6], at: 152), 5)
        XCTAssertEqual(readUInt64LE(requests[6], at: 160), 5)
        XCTAssertEqual(readUInt32LE(requests[6], at: 168), 2)
    }

    func testSessionCopyFileUsesOverwriteDispositionWhenRequested() async throws {
        let sourceFileId = hexBytes("00112233445566778899aabbccddeeff")
        let destinationFileId = hexBytes("ffeeddccbbaa99887766554433221100")
        let inbound = try framed([
            try smb2CreateResponse(fileId: sourceFileId, messageId: 0, treeId: 0x3344),
            try smb2QueryInfoResponse(size: 0, messageId: 1, treeId: 0x3344),
            try smb2CreateResponse(fileId: destinationFileId, messageId: 2, treeId: 0x3344),
            try smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.flush, messageId: 3, treeId: 0x3344),
            try smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.close, messageId: 4, treeId: 0x3344),
            try smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.close, messageId: 5, treeId: 0x3344)
        ])
        let transport = InMemoryTransport(inbound: inbound)
        let session = SMBSession(
            host: "server",
            port: 445,
            credential: SMBCredential(username: "user", password: "pass"),
            transport: transport,
            signingKey: Array(repeating: UInt8(0x11), count: 16)
        )

        try await session.copyFile(treeId: 0x3344, fromPath: "source.txt", toPath: "copy.txt", overwrite: true)

        let requests = try unframed(transport.outbound)
        XCTAssertEqual(readUInt32LE(requests[2], at: 100), 0x0000_0005)
    }

    func testSessionCopyFileClosesSourceWhenDestinationCreateFails() async throws {
        let sourceFileId = hexBytes("00112233445566778899aabbccddeeff")
        let inbound = try framed([
            try smb2CreateResponse(fileId: sourceFileId, messageId: 0, treeId: 0x3344),
            try smb2QueryInfoResponse(size: 5, messageId: 1, treeId: 0x3344),
            try smb2StatusResponse(status: SMB2Status.objectNameCollision, command: SMB2Commands.create, messageId: 2, treeId: 0x3344),
            try smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.close, messageId: 3, treeId: 0x3344)
        ])
        let transport = InMemoryTransport(inbound: inbound)
        let session = SMBSession(
            host: "server",
            port: 445,
            credential: SMBCredential(username: "user", password: "pass"),
            transport: transport,
            signingKey: Array(repeating: UInt8(0x11), count: 16)
        )

        do {
            try await session.copyFile(treeId: 0x3344, fromPath: "source.txt", toPath: "copy.txt", overwrite: false)
            XCTFail("expected nameCollision")
        } catch SMBError.nameCollision {
            let requests = try unframed(transport.outbound)
            XCTAssertEqual(requests.count, 4)
            XCTAssertEqual(try SMB2Header.decode(requests[3]).command, SMB2Commands.close)
            XCTAssertEqual(Array(requests[3][72..<88]), sourceFileId)
        } catch {
            XCTFail("expected nameCollision, got \(error)")
        }
    }

    func testSessionCopyDirectoryRecursivelyCopiesEntries() async throws {
        let sourceRootId = hexBytes("00000000000000000000000000000001")
        let destinationRootId = hexBytes("00000000000000000000000000000002")
        let sourceFileId = hexBytes("00000000000000000000000000000003")
        let destinationFileId = hexBytes("00000000000000000000000000000004")
        let sourceChildDirectoryId = hexBytes("00000000000000000000000000000005")
        let destinationChildDirectoryId = hexBytes("00000000000000000000000000000006")
        let inbound = try framed([
            try smb2CreateResponse(fileId: sourceRootId, messageId: 0, treeId: 0x3344),
            try smb2CreateResponse(fileId: destinationRootId, messageId: 1, treeId: 0x3344),
            try smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.close, messageId: 2, treeId: 0x3344),
            try smb2QueryDirectoryResponse(
                entries: [
                    makeDirectoryEntry(name: "a.txt", isDirectory: false, fileSize: 4, nextOffset: 0)
                ],
                messageId: 3,
                treeId: 0x3344
            ),
            try smb2CreateResponse(fileId: sourceFileId, messageId: 4, treeId: 0x3344),
            try smb2QueryInfoResponse(size: 4, messageId: 5, treeId: 0x3344),
            try smb2CreateResponse(fileId: destinationFileId, messageId: 6, treeId: 0x3344),
            try smb2IoctlResponse(output: [], status: SMB2Status.notSupported, messageId: 7, treeId: 0x3344, fileId: sourceFileId, ctlCode: SMB2Ioctl.fsctlSrvRequestResumeKey),
            try smb2ReadResponse(Array("data".utf8), messageId: 8, treeId: 0x3344),
            try smb2WriteResponse(count: 4, messageId: 9, treeId: 0x3344),
            try smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.flush, messageId: 10, treeId: 0x3344),
            try smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.close, messageId: 11, treeId: 0x3344),
            try smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.close, messageId: 12, treeId: 0x3344),
            try smb2QueryDirectoryResponse(
                entries: [
                    makeDirectoryEntry(name: "child", isDirectory: true, nextOffset: 0)
                ],
                messageId: 13,
                treeId: 0x3344
            ),
            try smb2CreateResponse(fileId: sourceChildDirectoryId, messageId: 14, treeId: 0x3344),
            try smb2CreateResponse(fileId: destinationChildDirectoryId, messageId: 15, treeId: 0x3344),
            try smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.close, messageId: 16, treeId: 0x3344),
            try smb2StatusResponse(status: SMB2Status.noMoreFiles, command: SMB2Commands.queryDirectory, messageId: 17, treeId: 0x3344),
            try smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.close, messageId: 18, treeId: 0x3344),
            try smb2StatusResponse(status: SMB2Status.noMoreFiles, command: SMB2Commands.queryDirectory, messageId: 19, treeId: 0x3344),
            try smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.close, messageId: 20, treeId: 0x3344)
        ])
        let transport = InMemoryTransport(inbound: inbound)
        let session = SMBSession(
            host: "server",
            port: 445,
            credential: SMBCredential(username: "user", password: "pass"),
            transport: transport,
            signingKey: Array(repeating: UInt8(0x11), count: 16)
        )

        try await session.copyDirectory(treeId: 0x3344, fromPath: "src", toPath: "dst", overwrite: false)

        let requests = try unframed(transport.outbound)
        XCTAssertEqual(requests.map { try? SMB2Header.decode($0).command }, [
            SMB2Commands.create,
            SMB2Commands.create,
            SMB2Commands.close,
            SMB2Commands.queryDirectory,
            SMB2Commands.create,
            SMB2Commands.queryInfo,
            SMB2Commands.create,
            SMB2Commands.ioctl,
            SMB2Commands.read,
            SMB2Commands.write,
            SMB2Commands.flush,
            SMB2Commands.close,
            SMB2Commands.close,
            SMB2Commands.queryDirectory,
            SMB2Commands.create,
            SMB2Commands.create,
            SMB2Commands.close,
            SMB2Commands.queryDirectory,
            SMB2Commands.close,
            SMB2Commands.queryDirectory,
            SMB2Commands.close
        ])
        XCTAssertEqual(readUInt32LE(requests[1], at: 100), 0x0000_0002)
        XCTAssertEqual(readUInt32LE(requests[6], at: 100), 0x0000_0002)
        XCTAssertEqual(readUInt32LE(requests[7], at: 68), SMB2Ioctl.fsctlSrvRequestResumeKey)
        XCTAssertEqual(Array(requests[9][112..<requests[9].count]), Array("data".utf8))
        XCTAssertEqual(readUInt32LE(requests[15], at: 100), 0x0000_0002)
    }

    func testSessionCopyDirectoryContinueOnErrorAggregatesAndContinues() async throws {
        let sourceRootId = hexBytes("00000000000000000000000000000011")
        let destinationRootId = hexBytes("00000000000000000000000000000012")
        let failedSourceId = hexBytes("00000000000000000000000000000013")
        let okSourceId = hexBytes("00000000000000000000000000000014")
        let okDestinationId = hexBytes("00000000000000000000000000000015")
        let inbound = try framed([
            try smb2CreateResponse(fileId: sourceRootId, messageId: 0, treeId: 0x3344),
            try smb2CreateResponse(fileId: destinationRootId, messageId: 1, treeId: 0x3344),
            try smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.close, messageId: 2, treeId: 0x3344),
            try smb2QueryDirectoryResponse(
                entries: [makeDirectoryEntry(name: "bad.txt", isDirectory: false, fileSize: 0, nextOffset: 0)],
                messageId: 3,
                treeId: 0x3344
            ),
            try smb2CreateResponse(fileId: failedSourceId, messageId: 4, treeId: 0x3344),
            try smb2QueryInfoResponse(size: 0, messageId: 5, treeId: 0x3344),
            try smb2StatusResponse(status: SMB2Status.accessDenied, command: SMB2Commands.create, messageId: 6, treeId: 0x3344),
            try smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.close, messageId: 7, treeId: 0x3344),
            try smb2QueryDirectoryResponse(
                entries: [makeDirectoryEntry(name: "ok.txt", isDirectory: false, fileSize: 0, nextOffset: 0)],
                messageId: 8,
                treeId: 0x3344
            ),
            try smb2CreateResponse(fileId: okSourceId, messageId: 9, treeId: 0x3344),
            try smb2QueryInfoResponse(size: 0, messageId: 10, treeId: 0x3344),
            try smb2CreateResponse(fileId: okDestinationId, messageId: 11, treeId: 0x3344),
            try smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.flush, messageId: 12, treeId: 0x3344),
            try smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.close, messageId: 13, treeId: 0x3344),
            try smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.close, messageId: 14, treeId: 0x3344),
            try smb2StatusResponse(status: SMB2Status.noMoreFiles, command: SMB2Commands.queryDirectory, messageId: 15, treeId: 0x3344),
            try smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.close, messageId: 16, treeId: 0x3344)
        ])
        let transport = InMemoryTransport(inbound: inbound)
        let session = SMBSession(
            host: "server",
            port: 445,
            credential: SMBCredential(username: "user", password: "pass"),
            transport: transport,
            signingKey: Array(repeating: UInt8(0x11), count: 16)
        )

        do {
            try await session.copyDirectory(
                treeId: 0x3344,
                fromPath: "src",
                toPath: "dst",
                overwrite: false,
                continueOnError: true
            )
            XCTFail("expected recursiveOperationIncomplete")
        } catch let SMBError.recursiveOperationIncomplete(failures) {
            XCTAssertEqual(failures.count, 1)
            XCTAssertEqual(failures[0].path, "src\\bad.txt")
            let requests = try unframed(transport.outbound)
            XCTAssertEqual(requests.count, 17)
            XCTAssertEqual(try SMB2Header.decode(requests[9]).command, SMB2Commands.create)
        } catch {
            XCTFail("expected recursiveOperationIncomplete, got \(error)")
        }
    }

    func testSessionCopyDirectoryDefaultAbortsOnFirstEntryFailure() async throws {
        let sourceRootId = hexBytes("00000000000000000000000000000021")
        let destinationRootId = hexBytes("00000000000000000000000000000022")
        let failedSourceId = hexBytes("00000000000000000000000000000023")
        let inbound = try framed([
            try smb2CreateResponse(fileId: sourceRootId, messageId: 0, treeId: 0x3344),
            try smb2CreateResponse(fileId: destinationRootId, messageId: 1, treeId: 0x3344),
            try smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.close, messageId: 2, treeId: 0x3344),
            try smb2QueryDirectoryResponse(
                entries: [makeDirectoryEntry(name: "bad.txt", isDirectory: false, fileSize: 0, nextOffset: 0)],
                messageId: 3,
                treeId: 0x3344
            ),
            try smb2CreateResponse(fileId: failedSourceId, messageId: 4, treeId: 0x3344),
            try smb2QueryInfoResponse(size: 0, messageId: 5, treeId: 0x3344),
            try smb2StatusResponse(status: SMB2Status.accessDenied, command: SMB2Commands.create, messageId: 6, treeId: 0x3344),
            try smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.close, messageId: 7, treeId: 0x3344),
            try smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.close, messageId: 8, treeId: 0x3344)
        ])
        let transport = InMemoryTransport(inbound: inbound)
        let session = SMBSession(
            host: "server",
            port: 445,
            credential: SMBCredential(username: "user", password: "pass"),
            transport: transport,
            signingKey: Array(repeating: UInt8(0x11), count: 16)
        )

        do {
            try await session.copyDirectory(treeId: 0x3344, fromPath: "src", toPath: "dst", overwrite: false)
            XCTFail("expected accessDenied")
        } catch SMBError.accessDenied {
            let requests = try unframed(transport.outbound)
            XCTAssertEqual(requests.count, 9)
        } catch {
            XCTFail("expected accessDenied, got \(error)")
        }
    }

    func testSessionCopyDirectorySkipExistingSkipsCollidingFile() async throws {
        let sourceRootId = hexBytes("00000000000000000000000000000031")
        let destinationRootId = hexBytes("00000000000000000000000000000032")
        let sourceFileId = hexBytes("00000000000000000000000000000033")
        let inbound = try framed([
            try smb2CreateResponse(fileId: sourceRootId, messageId: 0, treeId: 0x3344),
            try smb2CreateResponse(fileId: destinationRootId, messageId: 1, treeId: 0x3344),
            try smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.close, messageId: 2, treeId: 0x3344),
            try smb2QueryDirectoryResponse(
                entries: [makeDirectoryEntry(name: "exists.txt", isDirectory: false, fileSize: 0, nextOffset: 0)],
                messageId: 3,
                treeId: 0x3344
            ),
            try smb2CreateResponse(fileId: sourceFileId, messageId: 4, treeId: 0x3344),
            try smb2QueryInfoResponse(size: 0, messageId: 5, treeId: 0x3344),
            try smb2StatusResponse(status: SMB2Status.objectNameCollision, command: SMB2Commands.create, messageId: 6, treeId: 0x3344),
            try smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.close, messageId: 7, treeId: 0x3344),
            try smb2StatusResponse(status: SMB2Status.noMoreFiles, command: SMB2Commands.queryDirectory, messageId: 8, treeId: 0x3344),
            try smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.close, messageId: 9, treeId: 0x3344)
        ])
        let transport = InMemoryTransport(inbound: inbound)
        let session = SMBSession(
            host: "server",
            port: 445,
            credential: SMBCredential(username: "user", password: "pass"),
            transport: transport,
            signingKey: Array(repeating: UInt8(0x11), count: 16)
        )

        try await session.copyDirectory(
            treeId: 0x3344,
            fromPath: "src",
            toPath: "dst",
            overwrite: false,
            skipExisting: true
        )
    }

    func testSessionCopyDirectoryDryRunDoesNotSendDestinationMutations() async throws {
        let sourceRootId = hexBytes("00000000000000000000000000000041")
        let inbound = try framed([
            try smb2CreateResponse(fileId: sourceRootId, messageId: 0, treeId: 0x3344),
            try smb2QueryDirectoryResponse(
                entries: [makeDirectoryEntry(name: "a.txt", isDirectory: false, fileSize: 0, nextOffset: 0)],
                messageId: 1,
                treeId: 0x3344
            ),
            try smb2StatusResponse(status: SMB2Status.noMoreFiles, command: SMB2Commands.queryDirectory, messageId: 2, treeId: 0x3344),
            try smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.close, messageId: 3, treeId: 0x3344)
        ])
        let transport = InMemoryTransport(inbound: inbound)
        let session = SMBSession(
            host: "server",
            port: 445,
            credential: SMBCredential(username: "user", password: "pass"),
            transport: transport,
            signingKey: Array(repeating: UInt8(0x11), count: 16)
        )
        let recorder = RecursiveActionRecorder()

        try await session.copyDirectory(
            treeId: 0x3344,
            fromPath: "src",
            toPath: "dst",
            overwrite: false,
            dryRun: true
        ) { action in
            recorder.append(action)
        }

        XCTAssertEqual(recorder.actions, [
            SMBRecursiveAction(kind: .mkdir, path: "dst"),
            SMBRecursiveAction(kind: .copy, path: "dst\\a.txt")
        ])
        let requests = try unframed(transport.outbound)
        XCTAssertEqual(requests.map { try? SMB2Header.decode($0).command }, [
            SMB2Commands.create,
            SMB2Commands.queryDirectory,
            SMB2Commands.queryDirectory,
            SMB2Commands.close
        ])
    }

    func testSessionCopyDirectorySkipsReparsePointWithoutFollowingTarget() async throws {
        let sourceRootId = hexBytes("00000000000000000000000000000042")
        let inbound = try framed([
            try smb2CreateResponse(fileId: sourceRootId, messageId: 0, treeId: 0x3344),
            try smb2QueryDirectoryResponse(
                entries: [
                    makeDirectoryEntry(
                        name: "linked-directory",
                        isDirectory: true,
                        nextOffset: 0,
                        attributes: SMBFileAttributes.directory | SMBFileAttributes.reparsePoint
                    )
                ],
                messageId: 1,
                treeId: 0x3344
            ),
            try smb2StatusResponse(
                status: SMB2Status.noMoreFiles,
                command: SMB2Commands.queryDirectory,
                messageId: 2,
                treeId: 0x3344
            ),
            try smb2StatusResponse(
                status: SMB2Status.success,
                command: SMB2Commands.close,
                messageId: 3,
                treeId: 0x3344
            )
        ])
        let transport = InMemoryTransport(inbound: inbound)
        let session = SMBSession(
            host: "server",
            port: 445,
            credential: SMBCredential(username: "user", password: "pass"),
            transport: transport,
            signingKey: Array(repeating: UInt8(0x11), count: 16)
        )
        let recorder = RecursiveActionRecorder()

        try await session.copyDirectory(
            treeId: 0x3344,
            fromPath: "src",
            toPath: "dst",
            overwrite: false,
            dryRun: true
        ) { action in
            recorder.append(action)
        }

        XCTAssertEqual(recorder.actions, [
            SMBRecursiveAction(kind: .mkdir, path: "dst"),
            SMBRecursiveAction(kind: .skip, path: "dst\\linked-directory")
        ])
        XCTAssertEqual(try unframed(transport.outbound).map { try SMB2Header.decode($0).command }, [
            SMB2Commands.create,
            SMB2Commands.queryDirectory,
            SMB2Commands.queryDirectory,
            SMB2Commands.close
        ])
    }

    func testSessionCopyDirectoryRejectsUnsafeServerEntryBeforeChildOperation() async throws {
        let sourceRootId = hexBytes("00000000000000000000000000000047")
        let inbound = try framed([
            try smb2CreateResponse(fileId: sourceRootId, messageId: 0, treeId: 0x3344),
            try smb2QueryDirectoryResponse(
                entries: [makeDirectoryEntry(name: "bad\\name", isDirectory: true, nextOffset: 0)],
                messageId: 1,
                treeId: 0x3344
            ),
            try smb2StatusResponse(
                status: SMB2Status.success,
                command: SMB2Commands.close,
                messageId: 2,
                treeId: 0x3344
            )
        ])
        let transport = InMemoryTransport(inbound: inbound)
        let session = SMBSession(
            host: "server",
            port: 445,
            credential: SMBCredential(username: "user", password: "pass"),
            transport: transport,
            signingKey: Array(repeating: UInt8(0x11), count: 16)
        )

        do {
            try await session.copyDirectory(
                treeId: 0x3344,
                fromPath: "src",
                toPath: "dst",
                overwrite: false,
                dryRun: true
            )
            XCTFail("expected unsafe directory entry rejection")
        } catch SMBCodecError.invalidValue("invalid directory entry name") {
        }

        XCTAssertEqual(try unframed(transport.outbound).map { try SMB2Header.decode($0).command }, [
            SMB2Commands.create,
            SMB2Commands.queryDirectory,
            SMB2Commands.close
        ])
    }

    func testSessionRecursiveDeleteRemovesReparsePointWithoutFollowingTarget() async throws {
        let rootFileId = hexBytes("00000000000000000000000000000043")
        let linkFileId = hexBytes("00000000000000000000000000000044")
        let deleteRootFileId = hexBytes("00000000000000000000000000000045")
        let inbound = try framed([
            try smb2CreateResponse(fileId: rootFileId, messageId: 0, treeId: 0x3344),
            try smb2QueryDirectoryResponse(
                entries: [
                    makeDirectoryEntry(
                        name: "linked-directory",
                        isDirectory: true,
                        nextOffset: 0,
                        attributes: SMBFileAttributes.directory | SMBFileAttributes.reparsePoint
                    )
                ],
                messageId: 1,
                treeId: 0x3344
            ),
            try smb2CreateResponse(fileId: linkFileId, messageId: 2, treeId: 0x3344),
            try smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.close, messageId: 3, treeId: 0x3344),
            try smb2StatusResponse(status: SMB2Status.noMoreFiles, command: SMB2Commands.queryDirectory, messageId: 4, treeId: 0x3344),
            try smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.close, messageId: 5, treeId: 0x3344),
            try smb2CreateResponse(fileId: deleteRootFileId, messageId: 6, treeId: 0x3344),
            try smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.close, messageId: 7, treeId: 0x3344)
        ])
        let transport = InMemoryTransport(inbound: inbound)
        let session = SMBSession(
            host: "server",
            port: 445,
            credential: SMBCredential(username: "user", password: "pass"),
            transport: transport,
            signingKey: Array(repeating: UInt8(0x11), count: 16)
        )
        let recorder = RecursiveActionRecorder()

        try await session.deleteRecursively(
            treeId: 0x3344,
            path: "root",
            directory: true
        ) { action in
            recorder.append(action)
        }

        XCTAssertEqual(recorder.actions, [
            SMBRecursiveAction(kind: .delete, path: "root\\linked-directory"),
            SMBRecursiveAction(kind: .delete, path: "root")
        ])
        let requests = try unframed(transport.outbound)
        XCTAssertEqual(try SMB2Header.decode(requests[2]).command, SMB2Commands.create)
        XCTAssertEqual(readUInt32LE(requests[2], at: 104), 0x0020_1001)
        XCTAssertEqual(Array(requests[3][72..<88]), linkFileId)
    }

    func testSessionCopyDirectoryDryRunFiltersRecursiveFiles() async throws {
        let sourceRootId = hexBytes("00000000000000000000000000000051")
        let sourceChildId = hexBytes("00000000000000000000000000000052")
        let inbound = try framed([
            try smb2CreateResponse(fileId: sourceRootId, messageId: 0, treeId: 0x3344),
            try smb2QueryDirectoryResponse(entries: [
                makeDirectoryEntry(name: "keep.log", isDirectory: false, fileSize: 0, nextOffset: 128),
                makeDirectoryEntry(name: "skip.tmp", isDirectory: false, fileSize: 0, nextOffset: 256),
                makeDirectoryEntry(name: "nested", isDirectory: true, nextOffset: 0)
            ], messageId: 1, treeId: 0x3344),
            try smb2CreateResponse(fileId: sourceChildId, messageId: 2, treeId: 0x3344),
            try smb2QueryDirectoryResponse(entries: [
                makeDirectoryEntry(name: "child.log", isDirectory: false, fileSize: 0, nextOffset: 128),
                makeDirectoryEntry(name: "skip.log", isDirectory: false, fileSize: 0, nextOffset: 0)
            ], messageId: 3, treeId: 0x3344),
            try smb2StatusResponse(status: SMB2Status.noMoreFiles, command: SMB2Commands.queryDirectory, messageId: 4, treeId: 0x3344),
            try smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.close, messageId: 5, treeId: 0x3344),
            try smb2StatusResponse(status: SMB2Status.noMoreFiles, command: SMB2Commands.queryDirectory, messageId: 6, treeId: 0x3344),
            try smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.close, messageId: 7, treeId: 0x3344)
        ])
        let transport = InMemoryTransport(inbound: inbound)
        let session = SMBSession(
            host: "server",
            port: 445,
            credential: SMBCredential(username: "user", password: "pass"),
            transport: transport,
            signingKey: Array(repeating: UInt8(0x11), count: 16)
        )
        let recorder = RecursiveActionRecorder()

        try await session.copyDirectory(
            treeId: 0x3344,
            fromPath: "src",
            toPath: "dst",
            overwrite: false,
            dryRun: true,
            include: ["*.log"],
            exclude: ["nested/skip*"]
        ) { action in
            recorder.append(action)
        }

        XCTAssertEqual(recorder.actions, [
            SMBRecursiveAction(kind: .mkdir, path: "dst"),
            SMBRecursiveAction(kind: .copy, path: "dst\\keep.log"),
            SMBRecursiveAction(kind: .mkdir, path: "dst\\nested"),
            SMBRecursiveAction(kind: .copy, path: "dst\\nested\\child.log")
        ])
    }

    func testWriteRequestUsesOffsetLengthFileIdAndDataBuffer() throws {
        let fileId = (0..<16).map(UInt8.init)
        let payload = Array("hello".utf8)
        let request = try SMB2Write.encodeRequest(
            messageId: 15,
            sessionId: 0x1122_3344,
            treeId: 0x5566_7788,
            fileId: fileId,
            offset: 0x0102_0304_0506_0708,
            data: payload
        )

        let header = try SMB2Header.decode(request)
        XCTAssertEqual(header.command, SMB2Commands.write)
        XCTAssertEqual(header.messageId, 15)
        XCTAssertEqual(header.treeId, 0x5566_7788)
        XCTAssertEqual(header.sessionId, 0x1122_3344)
        XCTAssertEqual(header.creditCharge, 1)
        XCTAssertEqual(header.credits, 1)
        XCTAssertEqual(readUInt16LE(request, at: 64), 49)
        XCTAssertEqual(readUInt16LE(request, at: 66), 112)
        XCTAssertEqual(readUInt32LE(request, at: 68), UInt32(payload.count))
        XCTAssertEqual(readUInt64LE(request, at: 72), 0x0102_0304_0506_0708)
        XCTAssertEqual(Array(request[80..<96]), fileId)
        XCTAssertEqual(readUInt32LE(request, at: 96), 0)
        XCTAssertEqual(readUInt32LE(request, at: 100), 0)
        XCTAssertEqual(readUInt16LE(request, at: 104), 0)
        XCTAssertEqual(readUInt16LE(request, at: 106), 0)
        XCTAssertEqual(readUInt32LE(request, at: 108), 0)
        XCTAssertEqual(Array(request[112..<request.count]), payload)
    }

    func testWriteRequestUsesMultiCreditChargeForLargePayload() throws {
        let request = try SMB2Write.encodeRequest(
            messageId: 15,
            sessionId: 0x1122_3344,
            treeId: 0x5566_7788,
            fileId: (0..<16).map(UInt8.init),
            offset: 0,
            data: Array(repeating: 0xab, count: 65_537)
        )

        let header = try SMB2Header.decode(request)
        XCTAssertEqual(header.creditCharge, 2)
        XCTAssertEqual(header.credits, 2)
    }

    func testWriteResponseDecodesCount() throws {
        var response = try SMB2Header(command: SMB2Commands.write, messageId: 16).encode()
        response.append(contentsOf: Array(repeating: UInt8(0), count: 16))
        writeUInt16LE(17, to: &response, at: 64)
        writeUInt32LE(5, to: &response, at: 68)

        XCTAssertEqual(try SMB2Write.decodeResponseCount(response), 5)
    }

    func testHexSummaryCapsLargeDebugPayloads() {
        let bytes = (0..<80).map(UInt8.init)

        XCTAssertEqual(
            SMBDebug.hexSummary(bytes),
            "000102030405060708090a0b0c0d0e0f" +
                "101112131415161718191a1b1c1d1e1f" +
                "202122232425262728292a2b2c2d2e2f" +
                "303132333435363738393a3b3c3d3e3f" +
                "... totalBytes=80"
        )
    }

    func testPacketSummaryRedactsUnlessWireTraceIsEnabled() {
        let bytes = (0..<4).map(UInt8.init)

        XCTAssertEqual(
            SMBDebug.packetSummary(
                bytes,
                traceWire: false,
                traceWireFull: true,
                provenance: .plaintext,
                encryptedSession: true
            ),
            "<redacted; set SMBEE_TRACE_WIRE=1 to dump raw packet hex>"
        )
        XCTAssertEqual(
            SMBDebug.packetSummary(
                bytes,
                traceWire: true,
                traceWireFull: true,
                provenance: .plaintext,
                encryptedSession: true
            ),
            "<redacted; encrypted session plaintext>"
        )
        XCTAssertEqual(
            SMBDebug.packetSummary(
                bytes,
                traceWire: true,
                traceWireFull: true,
                provenance: .ciphertext,
                encryptedSession: true
            ),
            "00010203"
        )
        XCTAssertEqual(
            SMBDebug.packetSummary(
                bytes,
                traceWire: true,
                traceWireFull: true,
                provenance: .plaintext,
                encryptedSession: false
            ),
            "00010203"
        )
    }

    func testEncryptedSessionWireTraceRedactsWriteAndDecryptedReadPayloads() async throws {
        let sentinel = Array("SMBEE_TRACE_SECRET_SENTINEL_19".utf8)
        let sentinelHex = SMBDebug.hex(sentinel)
        let encryptionKey = Array(repeating: UInt8(0x5a), count: 16)
        let encryptedSessionId: UInt64 = 0x8877_6655_4433_2211
        let encryptedWriteResponse = try smb3CCMTransform(
            smb2WriteResponse(count: sentinel.count, messageId: 0, treeId: 0x3344, sessionId: encryptedSessionId),
            key: encryptionKey,
            nonce: (1...11).map(UInt8.init),
            sessionId: encryptedSessionId
        )
        let encryptedReadResponse = try smb3CCMTransform(
            smb2ReadResponse(sentinel, messageId: 1, treeId: 0x3344, sessionId: encryptedSessionId),
            key: encryptionKey,
            nonce: (12...22).map(UInt8.init),
            sessionId: encryptedSessionId
        )
        let encryptedTransport = InMemoryTransport(
            inbound: try framed([
                encryptedWriteResponse,
                encryptedReadResponse
            ]),
            mode: .sendGatedWaitUntilClosed,
            responseIdentityOverrides: [
                SMBWireRequestIdentity(messageId: 0, command: SMB2Commands.write),
                SMBWireRequestIdentity(messageId: 1, command: SMB2Commands.read)
            ],
            allowedUnansweredRequests: [],
            requestDecoder: smbEncryptedRequestDecoder(key: encryptionKey)
        )
        let encryptedCapture = SMBTraceLogCapture()
        let logger = SMBSessionDebugLogger(
            configuration: SMBSessionDebugConfiguration(enabled: true, traceWire: true, traceWireFull: true),
            sink: { encryptedCapture.append($0) }
        )
        let encryptedSession = SMBSession(
            host: "test",
            port: 445,
            credential: .anonymous,
            transport: encryptedTransport,
            debugLogger: logger
        )
        await encryptedSession.installEncryptionStateForTesting(
            encryptionKey: encryptionKey,
            decryptionKey: encryptionKey,
            sessionId: encryptedSessionId
        )
        let sessionFlags = await encryptedSession.sessionFlagsForTesting()
        XCTAssertEqual(sessionFlags, 0)

        try await encryptedSession.write(
            treeId: 0x3344,
            fileId: Array(repeating: 0x11, count: 16),
            data: sentinel
        )
        let decryptedRead = try await encryptedSession.readChunk(
            treeId: 0x3344,
            fileId: Array(repeating: 0x22, count: 16),
            offset: 0,
            length: UInt64(sentinel.count)
        )
        XCTAssertEqual(decryptedRead, sentinel)

        let encryptedMessages = encryptedCapture.messages
        XCTAssertTrue(encryptedMessages.contains {
            $0.hasPrefix("WRITE request") && $0.contains("<redacted; encrypted session plaintext>")
        })
        XCTAssertTrue(encryptedMessages.contains {
            $0.hasPrefix("decrypted ") && $0.contains("<redacted; encrypted session plaintext>")
        })
        XCTAssertTrue(encryptedMessages.contains {
            $0.hasPrefix("SMB response") && $0.contains(SMBDebug.hex(encryptedReadResponse))
        })
        XCTAssertFalse(encryptedMessages.joined(separator: "\n").contains(sentinelHex))

        let plaintextTransport = InMemoryTransport(inbound: try framed([
            smb2WriteResponse(count: sentinel.count, messageId: 0, treeId: 0x3344),
            smb2ReadResponse(sentinel, messageId: 1, treeId: 0x3344)
        ]))
        let plaintextCapture = SMBTraceLogCapture()
        let plaintextLogger = SMBSessionDebugLogger(
            configuration: SMBSessionDebugConfiguration(enabled: true, traceWire: true, traceWireFull: true),
            sink: { plaintextCapture.append($0) }
        )
        let plaintextSession = SMBSession(
            host: "test",
            port: 445,
            credential: .anonymous,
            transport: plaintextTransport,
            debugLogger: plaintextLogger
        )
        try await plaintextSession.write(
            treeId: 0x3344,
            fileId: Array(repeating: 0x11, count: 16),
            data: sentinel
        )
        let plaintextRead = try await plaintextSession.readChunk(
            treeId: 0x3344,
            fileId: Array(repeating: 0x22, count: 16),
            offset: 0,
            length: UInt64(sentinel.count)
        )
        XCTAssertEqual(plaintextRead, sentinel)
        XCTAssertTrue(plaintextCapture.messages.joined(separator: "\n").contains(sentinelHex))

        let untransformedReadResponse = try smb2ReadResponse(sentinel, messageId: 0, treeId: 0x3344)
        let untransformedTransport = InMemoryTransport(
            inbound: try framed([untransformedReadResponse]),
            mode: .sendGatedWaitUntilClosed,
            responseIdentityOverrides: nil,
            allowedUnansweredRequests: [],
            requestDecoder: smbEncryptedRequestDecoder(key: encryptionKey)
        )
        let untransformedCapture = SMBTraceLogCapture()
        let untransformedLogger = SMBSessionDebugLogger(
            configuration: SMBSessionDebugConfiguration(enabled: true, traceWire: true, traceWireFull: true),
            sink: { untransformedCapture.append($0) }
        )
        let untransformedSession = SMBSession(
            host: "test",
            port: 445,
            credential: .anonymous,
            transport: untransformedTransport,
            debugLogger: untransformedLogger
        )
        await untransformedSession.installEncryptionStateForTesting(
            encryptionKey: encryptionKey,
            decryptionKey: encryptionKey,
            sessionId: encryptedSessionId
        )
        let untransformedSessionFlags = await untransformedSession.sessionFlagsForTesting()
        XCTAssertEqual(untransformedSessionFlags, 0)
        do {
            _ = try await untransformedSession.readChunk(
                treeId: 0x3344,
                fileId: Array(repeating: 0x33, count: 16),
                offset: 0,
                length: UInt64(sentinel.count)
            )
            XCTFail("a plaintext response to an encrypted READ must be rejected")
        } catch {
            XCTAssertTrue(String(describing: error).contains("plaintext SMB response to an encrypted request"))
        }

        let untransformedMessages = untransformedCapture.messages
        XCTAssertTrue(untransformedMessages.contains {
            $0.hasPrefix("SMB response") && $0.contains("<redacted; encrypted session plaintext>")
        })
        XCTAssertFalse(untransformedMessages.joined(separator: "\n").contains(SMBDebug.hex(untransformedReadResponse)))
        XCTAssertFalse(untransformedMessages.joined(separator: "\n").contains(sentinelHex))

        await encryptedSession.closeTransport(cause: "wire_trace_redaction_test")
        await plaintextSession.closeTransport(cause: "wire_trace_positive_control_test")
        await untransformedSession.closeTransport(cause: "wire_trace_untransformed_response_test")
    }

    func testEncryptedInvalidResponseDoesNotLeakDecryptedBytesThroughDiagnostics() async throws {
        let sentinel = Array("DECRYPTED_ERROR_SENTINEL_10219".utf8)
        let sentinelHex = SMBDebug.hex(sentinel)
        let encryptionKey = Array(repeating: UInt8(0x6b), count: 16)
        let encryptedSessionId: UInt64 = 0x8877_6655_4433_2211
        let invalidPlaintext = sentinel + Array(repeating: UInt8(0x00), count: 80 - sentinel.count)
        let encryptedResponse = try smb3CCMTransform(
            invalidPlaintext,
            key: encryptionKey,
            nonce: (31...41).map(UInt8.init),
            sessionId: encryptedSessionId
        )
        let transport = InMemoryTransport(
            inbound: try framed([encryptedResponse]),
            mode: .sendGatedWaitUntilClosed,
            responseIdentityOverrides: [SMBWireRequestIdentity(messageId: 0, command: SMB2Commands.read)],
            allowedUnansweredRequests: [],
            requestDecoder: smbEncryptedRequestDecoder(key: encryptionKey)
        )
        let debugCapture = SMBTraceLogCapture()
        let debugLogger = SMBSessionDebugLogger(
            configuration: SMBSessionDebugConfiguration(enabled: true, traceWire: true, traceWireFull: true),
            sink: { debugCapture.append($0) }
        )
        let perfCapture = SMBTraceLogCapture()
        SMBPerfLog.enabledOverride = true
        SMBPerfLog.testSink = { perfCapture.append($0) }
        defer {
            SMBPerfLog.testSink = nil
            SMBPerfLog.enabledOverride = nil
        }

        let session = SMBSession(
            host: "test",
            port: 445,
            credential: .anonymous,
            transport: transport,
            debugLogger: debugLogger
        )
        await session.installEncryptionStateForTesting(
            encryptionKey: encryptionKey,
            decryptionKey: encryptionKey,
            sessionId: encryptedSessionId
        )

        var returnedErrorDescription: String?
        do {
            _ = try await awaitWithTimeout("invalid encrypted response fails read") {
                try await session.readChunk(
                    treeId: 0x3344,
                    fileId: Array(repeating: 0x44, count: 16),
                    offset: 0,
                    length: 1
                )
            }
            XCTFail("expected invalid decrypted SMB2 header to fail dispatch")
        } catch let error as SMBCodecError {
            guard case .invalidValue(let message) = error else {
                return XCTFail("expected SMBCodecError.invalidValue, got \(error)")
            }
            XCTAssertEqual(message, "invalid SMB2 protocol id: length=80")
            returnedErrorDescription = String(describing: error)
        }
        await session.waitForReceivedPacketDispatchCountForTesting(atLeast: 1)

        let debugOutput = debugCapture.messages.joined(separator: "\n")
        let perfOutput = perfCapture.messages.joined(separator: "\n")
        XCTAssertTrue(debugCapture.messages.contains {
            $0.hasPrefix("decrypted ") && $0.contains("<redacted; encrypted session plaintext>")
        })
        XCTAssertTrue(perfCapture.messages.contains { $0.contains("[wire] first_fault") })
        XCTAssertFalse(debugOutput.contains(sentinelHex))
        XCTAssertFalse(perfOutput.contains(sentinelHex))
        XCTAssertFalse(returnedErrorDescription?.contains(sentinelHex) ?? true)
        await session.closeTransport(cause: "invalid_encrypted_response_redaction_test")
    }

    func testDefaultEnvironmentTraceUsesRealStderrAndKeepsFullTracePositiveControls() async throws {
        let childFlag = "SMBEE_TRACE_STDERR_PROBE_CHILD"
        if ProcessInfo.processInfo.environment[childFlag] == "1" {
            try await runDefaultEnvironmentTraceProbe()
            return
        }
        #if os(macOS)
        // On macOS a sanitizer-instrumented bundle aborts (exit 6) when re-launched by a plain
        // `xcrun xctest` host that does not load the sanitizer runtime, so the macOS TSan job skips
        // this probe. Linux re-launches the same test executable, which links the runtime itself.
        // The handle is Darwin's RTLD_DEFAULT; glibc's RTLD_DEFAULT is NULL, and passing this value
        // there crashes ld.so (SIGSEGV in the Linux and ASan jobs).
        let defaultHandle = UnsafeMutableRawPointer(bitPattern: -2)
        if dlsym(defaultHandle, "__tsan_init") != nil || dlsym(defaultHandle, "__asan_init") != nil {
            throw XCTSkip("subprocess trace probe cannot re-launch a sanitizer-instrumented test bundle")
        }
        #endif

        let process = try defaultEnvironmentTraceProbeProcess(childFlag: childFlag)
        // stdout is discarded instead of piped: reading two pipes sequentially deadlocks once the
        // unread one fills its buffer while the child is still writing.
        let stderr = Pipe()
        process.standardOutput = FileHandle.nullDevice
        process.standardError = stderr
        try process.run()
        let childStderr = try XCTUnwrap(
            String(bytes: stderr.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8)
        )
        process.waitUntilExit()
        XCTAssertEqual(process.terminationStatus, 0, "trace probe child exited with status \(process.terminationStatus)")

        let fixtures = try defaultEnvironmentTraceProbeFixtures()
        let outputLines = childStderr.split(separator: "\n").map(String.init)
        let encryptedHex = SMBDebug.hex(fixtures.encryptedResponse)
        let plaintextHex = SMBDebug.hex(fixtures.plaintextResponse)
        let encryptedSentinelHex = SMBDebug.hex(fixtures.encryptedSentinel)
        XCTAssertTrue(outputLines.contains { $0.contains("SMB response (") && $0.contains(encryptedHex) })
        XCTAssertTrue(outputLines.contains { $0.contains("SMB response (") && $0.contains(plaintextHex) })
        XCTAssertTrue(outputLines.contains {
            $0.contains("direct-TCP header") && $0.hasSuffix(" (4 bytes): \(fixtures.encryptedFrameHeaderHex)")
        })
        XCTAssertTrue(outputLines.contains {
            $0.contains("direct-TCP header") && $0.hasSuffix(" (4 bytes): \(fixtures.plaintextFrameHeaderHex)")
        })
        XCTAssertTrue(childStderr.contains("<redacted; encrypted session plaintext>"))
        XCTAssertFalse(childStderr.contains(encryptedSentinelHex))
    }

    private func defaultEnvironmentTraceProbeProcess(childFlag: String) throws -> Process {
        let process = Process()
        var environment = ProcessInfo.processInfo.environment
        environment[childFlag] = "1"
        environment["SMBEE_DEBUG"] = "1"
        environment["SMBEE_TRACE_WIRE"] = "1"
        environment["SMBEE_TRACE_WIRE_FULL"] = "1"
        environment["SMBEE_PERF"] = "0"
        process.environment = environment

        #if os(macOS)
        process.executableURL = URL(fileURLWithPath: "/usr/bin/xcrun")
        process.arguments = [
            "xctest",
            "-XCTest",
            "SMBeeTests/testDefaultEnvironmentTraceUsesRealStderrAndKeepsFullTracePositiveControls",
            Bundle(for: SMBeeTests.self).bundleURL.path
        ]
        #else
        process.executableURL = URL(fileURLWithPath: CommandLine.arguments[0])
        // swift-corelibs-xctest takes the selected test as a positional `Module.Class/method` argument.
        process.arguments = [
            "SMBeeTests.SMBeeTests/testDefaultEnvironmentTraceUsesRealStderrAndKeepsFullTracePositiveControls"
        ]
        #endif
        return process
    }

    private func runDefaultEnvironmentTraceProbe() async throws {
        let fixtures = try defaultEnvironmentTraceProbeFixtures()
        let encryptedTransport = InMemoryTransport(
            inbound: try framed([fixtures.encryptedResponse]),
            mode: .sendGatedWaitUntilClosed,
            responseIdentityOverrides: [SMBWireRequestIdentity(messageId: 0, command: SMB2Commands.read)],
            allowedUnansweredRequests: [],
            requestDecoder: smbEncryptedRequestDecoder(key: fixtures.encryptionKey)
        )
        let encryptedSession = SMBSession(
            host: "test",
            port: 445,
            credential: .anonymous,
            transport: encryptedTransport
        )
        await encryptedSession.installEncryptionStateForTesting(
            encryptionKey: fixtures.encryptionKey,
            decryptionKey: fixtures.encryptionKey,
            sessionId: fixtures.sessionId
        )
        let sessionFlags = await encryptedSession.sessionFlagsForTesting()
        XCTAssertEqual(sessionFlags, 0)
        let encryptedRead = try await encryptedSession.readChunk(
            treeId: 0x3344,
            fileId: Array(repeating: 0x55, count: 16),
            offset: 0,
            length: UInt64(fixtures.encryptedSentinel.count)
        )
        XCTAssertEqual(encryptedRead, fixtures.encryptedSentinel)
        await encryptedSession.closeTransport(cause: "stderr_trace_probe_encrypted_done")

        let plaintextTransport = InMemoryTransport(inbound: try framed([fixtures.plaintextResponse]))
        let plaintextSession = SMBSession(
            host: "test",
            port: 445,
            credential: .anonymous,
            transport: plaintextTransport
        )
        let plaintextRead = try await plaintextSession.readChunk(
            treeId: 0x3344,
            fileId: Array(repeating: 0x66, count: 16),
            offset: 0,
            length: UInt64(fixtures.plaintextSentinel.count)
        )
        XCTAssertEqual(plaintextRead, fixtures.plaintextSentinel)
        await plaintextSession.closeTransport(cause: "stderr_trace_probe_plaintext_done")
    }

    private func defaultEnvironmentTraceProbeFixtures() throws -> (
        encryptionKey: [UInt8],
        sessionId: UInt64,
        encryptedSentinel: [UInt8],
        encryptedResponse: [UInt8],
        encryptedFrameHeaderHex: String,
        plaintextSentinel: [UInt8],
        plaintextResponse: [UInt8],
        plaintextFrameHeaderHex: String
    ) {
        let encryptionKey = Array(repeating: UInt8(0x73), count: 16)
        let sessionId: UInt64 = 0x8877_6655_4433_2211
        let encryptedSentinel = Array("ENCRYPTED_STDERR_SENTINEL_10219".utf8)
        let encryptedReadResponse = try smb2ReadResponse(
            encryptedSentinel,
            messageId: 0,
            treeId: 0x3344,
            sessionId: sessionId
        )
        let encryptedResponse = try smb3CCMTransform(
            encryptedReadResponse,
            key: encryptionKey,
            nonce: (51...61).map(UInt8.init),
            sessionId: sessionId
        )
        let plaintextSentinel = Array("PLAIN_STDERR_FULL_TRACE_10219".utf8)
        let plaintextResponse = try smb2ReadResponse(plaintextSentinel, messageId: 0, treeId: 0x3344)
        return (
            encryptionKey,
            sessionId,
            encryptedSentinel,
            encryptedResponse,
            SMBDebug.hex(Array(try DirectTCPFraming.frame(encryptedResponse).prefix(4))),
            plaintextSentinel,
            plaintextResponse,
            SMBDebug.hex(Array(try DirectTCPFraming.frame(plaintextResponse).prefix(4)))
        )
    }

    func testWriteChunkRangesCoverBoundarySizes() throws {
        let chunkSize = 4
        let cases: [(Int, [Range<Int>])] = [
            (0, []),
            (chunkSize - 1, [0..<3]),
            (chunkSize, [0..<4]),
            (chunkSize + 1, [0..<4, 4..<5]),
            (chunkSize * 2 + 1, [0..<4, 4..<8, 8..<9])
        ]

        for (dataCount, expectedRanges) in cases {
            var cursor = 0
            var ranges: [Range<Int>] = []
            while let range = try SMBChunkedTransfer.nextWriteRange(
                cursor: cursor,
                dataCount: dataCount,
                chunkSize: chunkSize
            ) {
                ranges.append(range)
                cursor = range.upperBound
            }

            XCTAssertEqual(ranges.map { "\($0.lowerBound)..<\($0.upperBound)" }, expectedRanges.map { "\($0.lowerBound)..<\($0.upperBound)" })
            XCTAssertEqual(cursor, dataCount)
        }
    }

    func testSessionWriteWithOneCreditSplitsMultiCreditPayload() async throws {
        let fileId = hexBytes("00112233445566778899aabbccddeeff")
        let inbound = try framed([
            try smb2WriteResponse(count: 65_536, messageId: 0, treeId: 0x3344),
            try smb2WriteResponse(count: 65_536, messageId: 1, treeId: 0x3344)
        ])
        let transport = InMemoryTransport(inbound: inbound)
        let session = SMBSession(
            host: "server", port: 445,
            credential: SMBCredential(username: "user", password: "pass"),
            transport: transport,
            initialCredits: 1
        )

        try await session.write(
            treeId: 0x3344,
            fileId: fileId,
            data: Array(repeating: 0x41, count: 128 * 1024)
        )

        let writes = try unframed(transport.outbound).filter {
            try SMB2Header.decode($0).command == SMB2Commands.write
        }
        XCTAssertEqual(try writes.map { try writePayload(from: $0).count }, [65_536, 65_536])
    }

    func testDownloadRejectsExistingDestinationWhenOverwriteIsFalse() async throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("smbee-unit-\(UUID().uuidString)")
        let destination = directory.appendingPathComponent("download.txt")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        try Data("existing".utf8).write(to: destination)
        defer { try? FileManager.default.removeItem(at: directory) }

        do {
            try await SMBClient.download(
                host: "server",
                share: "share",
                path: "remote.txt",
                localFile: destination,
                overwrite: false,
                credential: SMBCredential(username: "user", password: "pass")
            )
            XCTFail("expected local destination error")
        } catch SMBCodecError.invalidValue("local destination already exists") {
            XCTAssertEqual(try Data(contentsOf: destination), Data("existing".utf8))
        } catch {
            XCTFail("expected local destination error, got \(error)")
        }
    }

    func testDownloadResumeAppendsFromExistingLocalSize() async throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("smbee-unit-\(UUID().uuidString)")
        let destination = directory.appendingPathComponent("download.txt")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        try Data("hello ".utf8).write(to: destination)
        defer { try? FileManager.default.removeItem(at: directory) }

        let fileId = hexBytes("00112233445566778899aabbccddeeff")
        let prefixTransport = SMBValidateNegotiateScriptTransport(inbound: try framed(authenticatedTreeResponses() + [
            smb2CreateResponse(fileId: fileId, messageId: 4, treeId: 0x3344),
            smb2QueryInfoResponse(size: 11, messageId: 5, treeId: 0x3344),
            smb2ReadResponse(Array("hello ".utf8), messageId: 6, treeId: 0x3344),
            smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.close, messageId: 7, treeId: 0x3344),
            smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.treeDisconnect, messageId: 8, treeId: 0x3344),
            smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.logoff, messageId: 9, treeId: 0)
        ]))
        let resumeTransport = SMBValidateNegotiateScriptTransport(inbound: try framed(authenticatedTreeResponses() + [
            smb2CreateResponse(fileId: fileId, messageId: 4, treeId: 0x3344),
            smb2QueryInfoResponse(size: 11, messageId: 5, treeId: 0x3344),
            smb2ReadResponse(Array("world".utf8), messageId: 6, treeId: 0x3344),
            smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.close, messageId: 7, treeId: 0x3344),
            smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.treeDisconnect, messageId: 8, treeId: 0x3344),
            smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.logoff, messageId: 9, treeId: 0)
        ]))
        let factory = TransportFactorySequence([prefixTransport, resumeTransport])
        SMBTransportTestOverride.factory = { factory.make() }
        defer { SMBTransportTestOverride.factory = nil }

        try await SMBee.download(
            host: "server",
            credential: SMBCredential(username: "user", password: "pass"),
            share: "share",
            path: "remote.txt",
            localFile: destination,
            overwrite: false,
            resume: true
        )

        XCTAssertEqual(try Data(contentsOf: destination), Data("hello world".utf8))
    }

    func testDownloadDirectoryAtomicSuccessReplacesFromStagingAndCleansUp() async throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("smbee-unit-\(UUID().uuidString)")
        let destination = root.appendingPathComponent("downloaded")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let firstId = hexBytes("00112233445566778899aabbccddeeff")
        let secondId = hexBytes("102132435465768798a9babbdcddedef")
        let directoryId = hexBytes("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        let listTransport = SMBValidateNegotiateScriptTransport(inbound: try framed(authenticatedTreeResponses() + [
            smb2CreateResponse(fileId: directoryId, messageId: 4, treeId: 0x3344),
            smb2QueryDirectoryResponse(entries: [
                makeDirectoryEntry(name: "a.txt", isDirectory: false, fileSize: 5, nextOffset: 0)
            ], messageId: 5, treeId: 0x3344),
            smb2QueryDirectoryResponse(entries: [
                makeDirectoryEntry(name: "b.txt", isDirectory: false, fileSize: 4, nextOffset: 0)
            ], messageId: 6, treeId: 0x3344),
            smb2StatusResponse(status: SMB2Status.noMoreFiles, command: SMB2Commands.queryDirectory, messageId: 7, treeId: 0x3344),
            smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.close, messageId: 8, treeId: 0x3344),
            smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.treeDisconnect, messageId: 9, treeId: 0x3344),
            smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.logoff, messageId: 10, treeId: 0)
        ]))
        let firstTransport = SMBValidateNegotiateScriptTransport(inbound: try framed(authenticatedTreeResponses() + [
            smb2CreateResponse(fileId: firstId, messageId: 4, treeId: 0x3344),
            smb2QueryInfoResponse(size: 5, messageId: 5, treeId: 0x3344),
            smb2ReadResponse(Array("alpha".utf8), messageId: 6, treeId: 0x3344),
            smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.close, messageId: 7, treeId: 0x3344),
            smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.treeDisconnect, messageId: 8, treeId: 0x3344),
            smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.logoff, messageId: 9, treeId: 0)
        ]))
        let secondTransport = SMBValidateNegotiateScriptTransport(inbound: try framed(authenticatedTreeResponses() + [
            smb2CreateResponse(fileId: secondId, messageId: 4, treeId: 0x3344),
            smb2QueryInfoResponse(size: 4, messageId: 5, treeId: 0x3344),
            smb2ReadResponse(Array("beta".utf8), messageId: 6, treeId: 0x3344),
            smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.close, messageId: 7, treeId: 0x3344),
            smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.treeDisconnect, messageId: 8, treeId: 0x3344),
            smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.logoff, messageId: 9, treeId: 0)
        ]))
        let factory = TransportFactorySequence([listTransport, firstTransport, secondTransport])

        try await SMBClient.downloadDirectory(
            host: "server",
            share: "share",
            path: "remote",
            localDirectory: destination,
            atomic: true,
            credential: SMBCredential(username: "user", password: "pass"),
            makeTransport: factory.make
        )

        XCTAssertEqual(try String(contentsOf: destination.appendingPathComponent("a.txt"), encoding: .utf8), "alpha")
        XCTAssertEqual(try String(contentsOf: destination.appendingPathComponent("b.txt"), encoding: .utf8), "beta")
        XCTAssertEqual(try atomicStagingDirectories(in: root, destinationName: "downloaded"), [])
    }

    func testDownloadDirectorySkipsReparsePointWithoutFollowingTarget() async throws {
        let destination = FileManager.default.temporaryDirectory
            .appendingPathComponent("smbee-reparse-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: destination) }
        let directoryId = hexBytes("00000000000000000000000000000046")
        let transport = SMBValidateNegotiateScriptTransport(inbound: try framed(authenticatedTreeResponses(credential: .anonymous) + [
            smb2CreateResponse(fileId: directoryId, messageId: 4, treeId: 0x3344),
            smb2QueryDirectoryResponse(
                entries: [
                    makeDirectoryEntry(
                        name: "linked-directory",
                        isDirectory: true,
                        nextOffset: 0,
                        attributes: SMBFileAttributes.directory | SMBFileAttributes.reparsePoint
                    )
                ],
                messageId: 5,
                treeId: 0x3344
            ),
            smb2StatusResponse(status: SMB2Status.noMoreFiles, command: SMB2Commands.queryDirectory, messageId: 6, treeId: 0x3344),
            smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.close, messageId: 7, treeId: 0x3344),
            smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.treeDisconnect, messageId: 8, treeId: 0x3344),
            smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.logoff, messageId: 9, treeId: 0)
        ]))
        let recorder = RecursiveActionRecorder()

        try await SMBClient.downloadDirectory(
            host: "server",
            share: "share",
            path: "remote",
            localDirectory: destination,
            dryRun: true,
            credential: .anonymous,
            makeTransport: { transport },
            onAction: { action in recorder.append(action) }
        )

        XCTAssertEqual(recorder.actions, [
            SMBRecursiveAction(kind: .mkdir, path: destination.path),
            SMBRecursiveAction(kind: .skip, path: destination.appendingPathComponent("linked-directory").path)
        ])
        XCTAssertFalse(FileManager.default.fileExists(atPath: destination.path))
    }

    func testDownloadDirectoryAtomicFailurePreservesExistingDestinationAndRemovesStaging() async throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("smbee-unit-\(UUID().uuidString)")
        let destination = root.appendingPathComponent("downloaded")
        try FileManager.default.createDirectory(at: destination, withIntermediateDirectories: true)
        try Data("old".utf8).write(to: destination.appendingPathComponent("keep.txt"))
        defer { try? FileManager.default.removeItem(at: root) }
        let firstId = hexBytes("00112233445566778899aabbccddeeff")
        let secondId = hexBytes("102132435465768798a9babbdcddedef")
        let directoryId = hexBytes("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        let listTransport = SMBValidateNegotiateScriptTransport(inbound: try framed(authenticatedTreeResponses() + [
            smb2CreateResponse(fileId: directoryId, messageId: 4, treeId: 0x3344),
            smb2QueryDirectoryResponse(entries: [
                makeDirectoryEntry(name: "ok.txt", isDirectory: false, fileSize: 2, nextOffset: 0)
            ], messageId: 5, treeId: 0x3344),
            smb2QueryDirectoryResponse(entries: [
                makeDirectoryEntry(name: "bad.txt", isDirectory: false, fileSize: 3, nextOffset: 0)
            ], messageId: 6, treeId: 0x3344),
            smb2StatusResponse(status: SMB2Status.noMoreFiles, command: SMB2Commands.queryDirectory, messageId: 7, treeId: 0x3344),
            smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.close, messageId: 8, treeId: 0x3344),
            smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.treeDisconnect, messageId: 9, treeId: 0x3344),
            smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.logoff, messageId: 10, treeId: 0)
        ]))
        let firstTransport = SMBValidateNegotiateScriptTransport(inbound: try framed(authenticatedTreeResponses() + [
            smb2CreateResponse(fileId: firstId, messageId: 4, treeId: 0x3344),
            smb2QueryInfoResponse(size: 2, messageId: 5, treeId: 0x3344),
            smb2ReadResponse(Array("ok".utf8), messageId: 6, treeId: 0x3344),
            smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.close, messageId: 7, treeId: 0x3344),
            smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.treeDisconnect, messageId: 8, treeId: 0x3344),
            smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.logoff, messageId: 9, treeId: 0)
        ]))
        let secondTransport = SMBValidateNegotiateScriptTransport(inbound: try framed(authenticatedTreeResponses() + [
            smb2CreateResponse(fileId: secondId, messageId: 4, treeId: 0x3344),
            smb2QueryInfoResponse(size: 3, messageId: 5, treeId: 0x3344),
            smb2StatusResponse(status: SMB2Status.accessDenied, command: SMB2Commands.read, messageId: 6, treeId: 0x3344),
            smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.close, messageId: 7, treeId: 0x3344),
            smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.treeDisconnect, messageId: 8, treeId: 0x3344),
            smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.logoff, messageId: 9, treeId: 0)
        ]))
        let factory = TransportFactorySequence([listTransport, firstTransport, secondTransport])

        do {
            try await SMBClient.downloadDirectory(
                host: "server",
                share: "share",
                path: "remote",
                localDirectory: destination,
                continueOnError: true,
                atomic: true,
                credential: SMBCredential(username: "user", password: "pass"),
                makeTransport: factory.make
            )
            XCTFail("expected recursiveOperationIncomplete")
        } catch let SMBError.recursiveOperationIncomplete(failures) {
            XCTAssertEqual(failures.count, 1)
            XCTAssertEqual(failures[0].path, "remote\\bad.txt")
        } catch {
            XCTFail("expected recursiveOperationIncomplete, got \(error)")
        }

        XCTAssertEqual(try String(contentsOf: destination.appendingPathComponent("keep.txt"), encoding: .utf8), "old")
        XCTAssertFalse(FileManager.default.fileExists(atPath: destination.appendingPathComponent("ok.txt").path))
        XCTAssertEqual(try atomicStagingDirectories(in: root, destinationName: "downloaded"), [])
    }

    func testDownloadDirectoryAtomicDryRunDoesNotCreateDestinationOrStaging() async throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("smbee-unit-\(UUID().uuidString)")
        let destination = root.appendingPathComponent("downloaded")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let directoryId = hexBytes("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        let transport = SMBValidateNegotiateScriptTransport(inbound: try framed(authenticatedTreeResponses() + [
            smb2CreateResponse(fileId: directoryId, messageId: 4, treeId: 0x3344),
            smb2QueryDirectoryResponse(entries: [
                makeDirectoryEntry(name: "planned.txt", isDirectory: false, fileSize: 7, nextOffset: 0)
            ], messageId: 5, treeId: 0x3344),
            smb2StatusResponse(status: SMB2Status.noMoreFiles, command: SMB2Commands.queryDirectory, messageId: 6, treeId: 0x3344),
            smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.close, messageId: 7, treeId: 0x3344),
            smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.treeDisconnect, messageId: 8, treeId: 0x3344),
            smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.logoff, messageId: 9, treeId: 0)
        ]))
        let recorder = RecursiveActionRecorder()

        try await SMBClient.downloadDirectory(
            host: "server",
            share: "share",
            path: "remote",
            localDirectory: destination,
            dryRun: true,
            atomic: true,
            credential: SMBCredential(username: "user", password: "pass"),
            makeTransport: { transport },
            onAction: { action in
                recorder.append(action)
            }
        )

        XCTAssertFalse(FileManager.default.fileExists(atPath: destination.path))
        XCTAssertEqual(try atomicStagingDirectories(in: root, destinationName: "downloaded"), [])
        XCTAssertEqual(recorder.actions, [
            SMBRecursiveAction(kind: .mkdir, path: destination.path),
            SMBRecursiveAction(kind: .download, path: destination.appendingPathComponent("planned.txt").path)
        ])
    }

    func testDownloadDirectoryDryRunFiltersRecursiveFiles() async throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("smbee-unit-\(UUID().uuidString)")
        let destination = root.appendingPathComponent("downloaded")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let rootId = hexBytes("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        let nestedId = hexBytes("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
        let listRootTransport = SMBValidateNegotiateScriptTransport(inbound: try framed(authenticatedTreeResponses() + [
            smb2CreateResponse(fileId: rootId, messageId: 4, treeId: 0x3344),
            smb2QueryDirectoryResponse(entries: [
                makeDirectoryEntry(name: "keep.log", isDirectory: false, fileSize: 1, nextOffset: 128),
                makeDirectoryEntry(name: "skip.tmp", isDirectory: false, fileSize: 1, nextOffset: 256),
                makeDirectoryEntry(name: "nested", isDirectory: true, nextOffset: 0)
            ], messageId: 5, treeId: 0x3344),
            smb2StatusResponse(status: SMB2Status.noMoreFiles, command: SMB2Commands.queryDirectory, messageId: 6, treeId: 0x3344),
            smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.close, messageId: 7, treeId: 0x3344),
            smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.treeDisconnect, messageId: 8, treeId: 0x3344),
            smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.logoff, messageId: 9, treeId: 0)
        ]))
        let listNestedTransport = SMBValidateNegotiateScriptTransport(inbound: try framed(authenticatedTreeResponses() + [
            smb2CreateResponse(fileId: nestedId, messageId: 4, treeId: 0x3344),
            smb2QueryDirectoryResponse(entries: [
                makeDirectoryEntry(name: "child.log", isDirectory: false, fileSize: 1, nextOffset: 128),
                makeDirectoryEntry(name: "skip.log", isDirectory: false, fileSize: 1, nextOffset: 0)
            ], messageId: 5, treeId: 0x3344),
            smb2StatusResponse(status: SMB2Status.noMoreFiles, command: SMB2Commands.queryDirectory, messageId: 6, treeId: 0x3344),
            smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.close, messageId: 7, treeId: 0x3344),
            smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.treeDisconnect, messageId: 8, treeId: 0x3344),
            smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.logoff, messageId: 9, treeId: 0)
        ]))
        let factory = TransportFactorySequence([listRootTransport, listNestedTransport])
        let recorder = RecursiveActionRecorder()

        try await SMBClient.downloadDirectory(
            host: "server",
            share: "share",
            path: "remote",
            localDirectory: destination,
            dryRun: true,
            include: ["*.log"],
            exclude: ["nested/skip*"],
            credential: SMBCredential(username: "user", password: "pass"),
            makeTransport: factory.make
        ) { recorder.append($0) }

        XCTAssertEqual(recorder.actions, [
            SMBRecursiveAction(kind: .mkdir, path: destination.path),
            SMBRecursiveAction(kind: .download, path: destination.appendingPathComponent("keep.log").path),
            SMBRecursiveAction(kind: .mkdir, path: destination.appendingPathComponent("nested").path),
            SMBRecursiveAction(kind: .download, path: destination.appendingPathComponent("nested/child.log").path)
        ])
    }

    func testDownloadDirectoryResumeSkipsMatchingSizeAndDownloadsMismatchedFile() async throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("smbee-unit-\(UUID().uuidString)")
        let destination = root.appendingPathComponent("downloaded")
        try FileManager.default.createDirectory(at: destination, withIntermediateDirectories: true)
        try Data("done".utf8).write(to: destination.appendingPathComponent("done.txt"))
        try Data("old".utf8).write(to: destination.appendingPathComponent("partial.txt"))
        defer { try? FileManager.default.removeItem(at: root) }

        let directoryId = hexBytes("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        let partialId = hexBytes("00112233445566778899aabbccddeeff")
        let listTransport = SMBValidateNegotiateScriptTransport(inbound: try framed(authenticatedTreeResponses() + [
            smb2CreateResponse(fileId: directoryId, messageId: 4, treeId: 0x3344),
            smb2QueryDirectoryResponse(entries: [
                makeDirectoryEntry(name: "done.txt", isDirectory: false, fileSize: 4, nextOffset: 128),
                makeDirectoryEntry(name: "partial.txt", isDirectory: false, fileSize: 7, nextOffset: 0)
            ], messageId: 5, treeId: 0x3344),
            smb2StatusResponse(status: SMB2Status.noMoreFiles, command: SMB2Commands.queryDirectory, messageId: 6, treeId: 0x3344),
            smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.close, messageId: 7, treeId: 0x3344),
            smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.treeDisconnect, messageId: 8, treeId: 0x3344),
            smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.logoff, messageId: 9, treeId: 0)
        ]))
        let partialTransport = SMBValidateNegotiateScriptTransport(inbound: try framed(authenticatedTreeResponses() + [
            smb2CreateResponse(fileId: partialId, messageId: 4, treeId: 0x3344),
            smb2QueryInfoResponse(size: 7, messageId: 5, treeId: 0x3344),
            smb2ReadResponse(Array("updated".utf8), messageId: 6, treeId: 0x3344),
            smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.close, messageId: 7, treeId: 0x3344),
            smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.treeDisconnect, messageId: 8, treeId: 0x3344),
            smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.logoff, messageId: 9, treeId: 0)
        ]))
        let factory = TransportFactorySequence([listTransport, partialTransport])
        let recorder = RecursiveActionRecorder()
        let progress = TransferProgressCollector()

        try await SMBClient.downloadDirectory(
            host: "server",
            share: "share",
            path: "remote",
            localDirectory: destination,
            resume: true,
            credential: SMBCredential(username: "user", password: "pass"),
            makeTransport: factory.make,
            onAction: { recorder.append($0) },
            onProgress: progress.append
        )

        XCTAssertEqual(factory.makeCount, 2)
        XCTAssertEqual(try String(contentsOf: destination.appendingPathComponent("done.txt"), encoding: .utf8), "done")
        XCTAssertEqual(try String(contentsOf: destination.appendingPathComponent("partial.txt"), encoding: .utf8), "updated")
        XCTAssertEqual(progress.snapshots.map(\.bytesTransferred), [7])
        XCTAssertEqual(progress.snapshots.map(\.totalBytes), [7])
        XCTAssertEqual(recorder.actions, [
            SMBRecursiveAction(kind: .mkdir, path: destination.path),
            SMBRecursiveAction(kind: .skip, path: destination.appendingPathComponent("done.txt").path),
            SMBRecursiveAction(kind: .download, path: destination.appendingPathComponent("partial.txt").path)
        ])
        XCTAssertFalse(try outboundFrames(listTransport, containCommand: SMB2Commands.read))
    }

    func testDownloadDirectoryDryRunResumeReportsSkipAndTransferPlanWithoutReads() async throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("smbee-unit-\(UUID().uuidString)")
        let destination = root.appendingPathComponent("downloaded")
        try FileManager.default.createDirectory(at: destination, withIntermediateDirectories: true)
        try Data("done".utf8).write(to: destination.appendingPathComponent("done.txt"))
        try Data("old".utf8).write(to: destination.appendingPathComponent("partial.txt"))
        defer { try? FileManager.default.removeItem(at: root) }

        let directoryId = hexBytes("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        let transport = SMBValidateNegotiateScriptTransport(inbound: try framed(authenticatedTreeResponses() + [
            smb2CreateResponse(fileId: directoryId, messageId: 4, treeId: 0x3344),
            smb2QueryDirectoryResponse(entries: [
                makeDirectoryEntry(name: "done.txt", isDirectory: false, fileSize: 4, nextOffset: 128),
                makeDirectoryEntry(name: "partial.txt", isDirectory: false, fileSize: 7, nextOffset: 0)
            ], messageId: 5, treeId: 0x3344),
            smb2StatusResponse(status: SMB2Status.noMoreFiles, command: SMB2Commands.queryDirectory, messageId: 6, treeId: 0x3344),
            smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.close, messageId: 7, treeId: 0x3344),
            smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.treeDisconnect, messageId: 8, treeId: 0x3344),
            smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.logoff, messageId: 9, treeId: 0)
        ]))
        let recorder = RecursiveActionRecorder()

        try await SMBClient.downloadDirectory(
            host: "server",
            share: "share",
            path: "remote",
            localDirectory: destination,
            resume: true,
            dryRun: true,
            credential: SMBCredential(username: "user", password: "pass"),
            makeTransport: { transport },
            onAction: { recorder.append($0) }
        )

        XCTAssertEqual(try String(contentsOf: destination.appendingPathComponent("partial.txt"), encoding: .utf8), "old")
        XCTAssertEqual(recorder.actions, [
            SMBRecursiveAction(kind: .mkdir, path: destination.path),
            SMBRecursiveAction(kind: .skip, path: destination.appendingPathComponent("done.txt").path),
            SMBRecursiveAction(kind: .download, path: destination.appendingPathComponent("partial.txt").path)
        ])
        XCTAssertFalse(try outboundFrames(transport, containCommand: SMB2Commands.read))
    }

    func testUploadDirectoryResumeSkipsMatchingSizeAndUploadsMismatchedOrMissingFiles() async throws {
        let localDirectory = FileManager.default.temporaryDirectory.appendingPathComponent("smbee-unit-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: localDirectory, withIntermediateDirectories: true)
        try Data("done".utf8).write(to: localDirectory.appendingPathComponent("done.txt"))
        try Data("update".utf8).write(to: localDirectory.appendingPathComponent("mismatch.txt"))
        try Data("new".utf8).write(to: localDirectory.appendingPathComponent("missing.txt"))
        defer { try? FileManager.default.removeItem(at: localDirectory) }

        let doneId = hexBytes("00112233445566778899aabbccddeeff")
        let mismatchStatId = hexBytes("102132435465768798a9babbdcddedef")
        let mismatchUploadId = hexBytes("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        let missingUploadId = hexBytes("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
        let doneStatTransport = SMBValidateNegotiateScriptTransport(inbound: try framed(authenticatedTreeResponses() + [
            smb2CreateResponse(fileId: doneId, messageId: 4, treeId: 0x3344),
            smb2QueryInfoResponse(size: 4, messageId: 5, treeId: 0x3344),
            smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.close, messageId: 6, treeId: 0x3344),
            smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.treeDisconnect, messageId: 7, treeId: 0x3344),
            smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.logoff, messageId: 8, treeId: 0)
        ]))
        let mismatchStatTransport = SMBValidateNegotiateScriptTransport(inbound: try framed(authenticatedTreeResponses() + [
            smb2CreateResponse(fileId: mismatchStatId, messageId: 4, treeId: 0x3344),
            smb2QueryInfoResponse(size: 1, messageId: 5, treeId: 0x3344),
            smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.close, messageId: 6, treeId: 0x3344),
            smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.treeDisconnect, messageId: 7, treeId: 0x3344),
            smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.logoff, messageId: 8, treeId: 0)
        ]))
        let mismatchUploadTransport = SMBValidateNegotiateScriptTransport(inbound: try framed(authenticatedTreeResponses() + [
            smb2CreateResponse(fileId: mismatchUploadId, messageId: 4, treeId: 0x3344),
            smb2WriteResponse(count: 6, messageId: 5, treeId: 0x3344),
            smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.flush, messageId: 6, treeId: 0x3344),
            smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.close, messageId: 7, treeId: 0x3344),
            smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.treeDisconnect, messageId: 8, treeId: 0x3344),
            smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.logoff, messageId: 9, treeId: 0)
        ]))
        let missingStatTransport = SMBValidateNegotiateScriptTransport(inbound: try framed(authenticatedTreeResponses() + [
            smb2StatusResponse(status: SMB2Status.objectNameNotFound, command: SMB2Commands.create, messageId: 4, treeId: 0x3344),
            smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.treeDisconnect, messageId: 5, treeId: 0x3344),
            smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.logoff, messageId: 6, treeId: 0)
        ]))
        let missingUploadTransport = SMBValidateNegotiateScriptTransport(inbound: try framed(authenticatedTreeResponses() + [
            smb2CreateResponse(fileId: missingUploadId, messageId: 4, treeId: 0x3344),
            smb2WriteResponse(count: 3, messageId: 5, treeId: 0x3344),
            smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.flush, messageId: 6, treeId: 0x3344),
            smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.close, messageId: 7, treeId: 0x3344),
            smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.treeDisconnect, messageId: 8, treeId: 0x3344),
            smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.logoff, messageId: 9, treeId: 0)
        ]))
        let factory = TransportFactorySequence([
            doneStatTransport,
            mismatchStatTransport,
            mismatchUploadTransport,
            missingStatTransport,
            missingUploadTransport
        ])
        let recorder = RecursiveActionRecorder()
        let progress = TransferProgressCollector()

        try await SMBClient.uploadDirectory(
            host: "server",
            share: "share",
            path: "",
            localDirectory: localDirectory,
            resume: true,
            credential: SMBCredential(username: "user", password: "pass"),
            makeTransport: factory.make,
            onAction: { recorder.append($0) },
            onProgress: progress.append
        )

        XCTAssertEqual(factory.makeCount, 5)
        XCTAssertFalse(try outboundFrames(doneStatTransport, containCommand: SMB2Commands.write))
        XCTAssertEqual(progress.snapshots.map(\.bytesTransferred), [6, 3])
        XCTAssertEqual(progress.snapshots.map(\.totalBytes), [6, 3])
        XCTAssertEqual(recorder.actions, [
            SMBRecursiveAction(kind: .skip, path: "done.txt"),
            SMBRecursiveAction(kind: .upload, path: "mismatch.txt"),
            SMBRecursiveAction(kind: .upload, path: "missing.txt")
        ])
    }

    func testUploadDirectoryDryRunResumeReportsSkipAndTransferPlanWithoutWrites() async throws {
        let localDirectory = FileManager.default.temporaryDirectory.appendingPathComponent("smbee-unit-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: localDirectory, withIntermediateDirectories: true)
        try Data("done".utf8).write(to: localDirectory.appendingPathComponent("done.txt"))
        try Data("update".utf8).write(to: localDirectory.appendingPathComponent("mismatch.txt"))
        defer { try? FileManager.default.removeItem(at: localDirectory) }

        let doneId = hexBytes("00112233445566778899aabbccddeeff")
        let mismatchId = hexBytes("102132435465768798a9babbdcddedef")
        let doneStatTransport = SMBValidateNegotiateScriptTransport(inbound: try framed(authenticatedTreeResponses() + [
            smb2CreateResponse(fileId: doneId, messageId: 4, treeId: 0x3344),
            smb2QueryInfoResponse(size: 4, messageId: 5, treeId: 0x3344),
            smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.close, messageId: 6, treeId: 0x3344),
            smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.treeDisconnect, messageId: 7, treeId: 0x3344),
            smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.logoff, messageId: 8, treeId: 0)
        ]))
        let mismatchStatTransport = SMBValidateNegotiateScriptTransport(inbound: try framed(authenticatedTreeResponses() + [
            smb2CreateResponse(fileId: mismatchId, messageId: 4, treeId: 0x3344),
            smb2QueryInfoResponse(size: 1, messageId: 5, treeId: 0x3344),
            smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.close, messageId: 6, treeId: 0x3344),
            smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.treeDisconnect, messageId: 7, treeId: 0x3344),
            smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.logoff, messageId: 8, treeId: 0)
        ]))
        let factory = TransportFactorySequence([doneStatTransport, mismatchStatTransport])
        let recorder = RecursiveActionRecorder()

        try await SMBClient.uploadDirectory(
            host: "server",
            share: "share",
            path: "",
            localDirectory: localDirectory,
            resume: true,
            dryRun: true,
            credential: SMBCredential(username: "user", password: "pass"),
            makeTransport: factory.make
        ) { recorder.append($0) }

        XCTAssertEqual(factory.makeCount, 2)
        XCTAssertFalse(try outboundFrames(doneStatTransport, containCommand: SMB2Commands.write))
        XCTAssertFalse(try outboundFrames(mismatchStatTransport, containCommand: SMB2Commands.write))
        XCTAssertEqual(recorder.actions, [
            SMBRecursiveAction(kind: .skip, path: "done.txt"),
            SMBRecursiveAction(kind: .upload, path: "mismatch.txt")
        ])
    }

    func testUploadDirectoryDryRunFiltersRecursiveFiles() async throws {
        let localDirectory = FileManager.default.temporaryDirectory.appendingPathComponent("smbee-unit-\(UUID().uuidString)")
        let nested = localDirectory.appendingPathComponent("nested")
        try FileManager.default.createDirectory(at: nested, withIntermediateDirectories: true)
        try Data("a".utf8).write(to: localDirectory.appendingPathComponent("keep.log"))
        try Data("b".utf8).write(to: localDirectory.appendingPathComponent("skip.tmp"))
        try Data("c".utf8).write(to: nested.appendingPathComponent("child.log"))
        try Data("d".utf8).write(to: nested.appendingPathComponent("skip.log"))
        defer { try? FileManager.default.removeItem(at: localDirectory) }
        let recorder = RecursiveActionRecorder()

        try await SMBClient.uploadDirectory(
            host: "server",
            share: "share",
            path: "remote",
            localDirectory: localDirectory,
            dryRun: true,
            include: ["*.log"],
            exclude: ["nested/skip*"],
            credential: SMBCredential(username: "user", password: "pass"),
            onAction: { recorder.append($0) }
        )

        XCTAssertEqual(recorder.actions, [
            SMBRecursiveAction(kind: .mkdir, path: "remote"),
            SMBRecursiveAction(kind: .upload, path: "remote\\keep.log"),
            SMBRecursiveAction(kind: .mkdir, path: "remote\\nested"),
            SMBRecursiveAction(kind: .upload, path: "remote\\nested\\child.log")
        ])
    }

    func testReadResponseAllowsZeroLengthData() throws {
        var response = try SMB2Header(command: SMB2Commands.read, messageId: 14).encode()
        response.append(contentsOf: Array(repeating: UInt8(0), count: 16))
        writeUInt16LE(17, to: &response, at: 64)
        response[66] = 80
        writeUInt32LE(0, to: &response, at: 68)

        XCTAssertEqual(try SMB2Read.decodeResponse(response), [])
    }

    func testReadResponseRejectsDataPastPacketEnd() throws {
        var response = try SMB2Header(command: SMB2Commands.read, messageId: 14).encode()
        response.append(contentsOf: Array(repeating: UInt8(0), count: 16))
        writeUInt16LE(17, to: &response, at: 64)
        response[66] = 80
        writeUInt32LE(1, to: &response, at: 68)

        XCTAssertThrowsError(try SMB2Read.decodeResponse(response)) { error in
            XCTAssertEqual(error as? SMBCodecError, .truncated)
        }
    }

    func testReadPositionRejectsOverReadAndOffsetOverflow() throws {
        let advanced = try SMBChunkedTransfer.advancedReadPosition(cursor: 10, remaining: 5, receivedCount: 5)
        XCTAssertEqual(advanced.cursor, 15)
        XCTAssertEqual(advanced.remaining, 0)

        XCTAssertThrowsError(try SMBChunkedTransfer.advancedReadPosition(cursor: 10, remaining: 5, receivedCount: 6)) { error in
            XCTAssertEqual(error as? SMBCodecError, .invalidValue("SMB read returned more data than requested"))
        }

        XCTAssertThrowsError(
            try SMBChunkedTransfer.advancedReadPosition(cursor: UInt64.max, remaining: 1, receivedCount: 1)
        ) { error in
            XCTAssertEqual(error as? SMBCodecError, .invalidValue("SMB read offset overflow"))
        }
    }

    func testFlushRequestUsesFileIdAndReservedFields() throws {
        let fileId = (0..<16).map(UInt8.init)
        let request = try SMB2Flush.encodeRequest(
            messageId: 17,
            sessionId: 0x1122_3344,
            treeId: 0x5566_7788,
            fileId: fileId
        )

        let header = try SMB2Header.decode(request)
        XCTAssertEqual(header.command, SMB2Commands.flush)
        XCTAssertEqual(header.messageId, 17)
        XCTAssertEqual(header.treeId, 0x5566_7788)
        XCTAssertEqual(header.sessionId, 0x1122_3344)
        XCTAssertEqual(request.count, 88)
        XCTAssertEqual(readUInt16LE(request, at: 64), 24)
        XCTAssertEqual(readUInt16LE(request, at: 66), 0)
        XCTAssertEqual(readUInt32LE(request, at: 68), 0)
        XCTAssertEqual(Array(request[72..<88]), fileId)
    }

    func testAsyncPendingInterimResponseIsDiscardedBeforeFinalResponse() throws {
        let pending = try SMB2Header.asyncHeader(
            status: SMB2Status.pending,
            command: SMB2Commands.flush,
            messageId: 17,
            asyncId: 0x5566_7788_0000_0001,
            sessionId: 0x1122_3344
        ).encode()
        let final = try SMB2Header(
            command: SMB2Commands.flush,
            messageId: 17,
            treeId: 0x5566_7788,
            sessionId: 0x1122_3344
        ).encode()
        var mockResponses = [pending, final]

        while try SMB2AsyncInterim.isInterim(SMB2Header.decode(mockResponses[0])) {
            mockResponses.removeFirst()
        }

        let header = try SMB2Header.decode(mockResponses[0])
        XCTAssertEqual(header.status, SMB2Status.success)
        XCTAssertEqual(header.command, SMB2Commands.flush)
        XCTAssertEqual(header.messageId, 17)
    }

    func testAsyncPendingRequiresAsyncCommandFlag() throws {
        let pending = try SMB2Header(
            status: SMB2Status.pending,
            command: SMB2Commands.write,
            messageId: 18
        ).encode()

        XCTAssertThrowsError(try SMB2AsyncInterim.isInterim(SMB2Header.decode(pending))) { error in
            XCTAssertEqual(error as? SMBCodecError, .invalidValue("SMB2 STATUS_PENDING response missing ASYNC_COMMAND flag"))
        }
    }

    func testTransferChunkSizeRespectsNegotiatedLimitsAndTransformOverhead() {
        XCTAssertEqual(
            SMBTransferLimits.negotiatedChunkSize(localLimit: 64 * 1024, negotiatedLimit: 1_048_576),
            64 * 1024
        )
        XCTAssertEqual(
            SMBTransferLimits.negotiatedChunkSize(localLimit: 64 * 1024, negotiatedLimit: 32 * 1024),
            32 * 1024
        )
        XCTAssertEqual(
            SMBTransferLimits.negotiatedChunkSize(
                localLimit: 64 * 1024,
                negotiatedLimit: UInt32(SMB3TransformHeader.encodedSize + 4096),
                transformOverhead: SMB3TransformHeader.encodedSize
            ),
            4096
        )
        XCTAssertEqual(
            SMBTransferLimits.negotiatedChunkSize(
                localLimit: 64 * 1024,
                negotiatedLimit: UInt32(SMB3TransformHeader.encodedSize),
                transformOverhead: SMB3TransformHeader.encodedSize
            ),
            1
        )
        XCTAssertEqual(
            SMBTransferLimits.creditWindowChunkSize(
                localLimit: 512 * 1024,
                negotiatedLimit: 1_048_576,
                availableCredits: 2
            ),
            128 * 1024
        )
        XCTAssertEqual(
            SMBTransferLimits.creditWindowChunkSize(
                localLimit: 512 * 1024,
                negotiatedLimit: 1_048_576,
                transformOverhead: SMB3TransformHeader.encodedSize,
                availableCredits: 1
            ),
            64 * 1024
        )
        XCTAssertEqual(
            SMBTransferLimits.creditWindowChunkSize(
                localLimit: 512 * 1024,
                negotiatedLimit: 1_048_576,
                availableCredits: 0
            ),
            64 * 1024
        )
    }

    func testCreditRequestGrowsWindowTowardTarget() {
        XCTAssertEqual(SMB2Credit.creditRequest(balance: 1, charge: 1, target: 256), 255)
        XCTAssertEqual(SMB2Credit.creditRequest(balance: 256, charge: 1, target: 256), 1)
        XCTAssertEqual(SMB2Credit.creditRequest(balance: 300, charge: 16, target: 256), 16)
        XCTAssertEqual(SMB2Credit.creditRequest(balance: 1, charge: 16, target: 256), 255)
    }

    func testPatchCreditRequestWritesFieldWithoutTouchingCharge() throws {
        // READ request header: command=8, creditCharge=1, credits(CreditRequest)=1.
        var packet = try SMB2Header(creditCharge: 1, command: SMB2Commands.read, credits: 1,
                                    messageId: 0, treeId: 0, sessionId: 0).encode()
        SMB2Credit.patchCreditRequest(into: &packet, balance: 1, target: 256)
        // CreditRequest (offset 14, LE) grown to deficit 255.
        XCTAssertEqual(UInt16(packet[14]) | (UInt16(packet[15]) << 8), 255)
        // CreditCharge (offset 6) and Command (offset 12) untouched.
        XCTAssertEqual(UInt16(packet[6]) | (UInt16(packet[7]) << 8), 1)
        XCTAssertEqual(UInt16(packet[12]) | (UInt16(packet[13]) << 8), SMB2Commands.read)
    }

    func testPatchCreditRequestPreservesLargeChargeAndHold() throws {
        // A 1 MiB read charges 16; below target it should still request the deficit.
        var big = try SMB2Header(creditCharge: 16, command: SMB2Commands.read, credits: 16,
                                 messageId: 0, treeId: 0, sessionId: 0).encode()
        SMB2Credit.patchCreditRequest(into: &big, balance: 1, target: 256)
        XCTAssertEqual(UInt16(big[14]) | (UInt16(big[15]) << 8), 255)
        XCTAssertEqual(UInt16(big[6]) | (UInt16(big[7]) << 8), 16)
        // At/above target it holds net-zero (request == charge).
        var held = try SMB2Header(creditCharge: 16, command: SMB2Commands.read, credits: 16,
                                  messageId: 0, treeId: 0, sessionId: 0).encode()
        SMB2Credit.patchCreditRequest(into: &held, balance: 256, target: 256)
        XCTAssertEqual(UInt16(held[14]) | (UInt16(held[15]) << 8), 16)
    }

    func testPatchCreditRequestSkipsCancel() throws {
        var cancel = try SMB2Header(creditCharge: 1, command: SMB2Commands.cancel, credits: 0,
                                    messageId: 0, treeId: 0, sessionId: 0).encode()
        SMB2Credit.patchCreditRequest(into: &cancel, balance: 1, target: 256)
        // CANCEL is credit-exempt: CreditRequest field must be left as encoded (0).
        XCTAssertEqual(UInt16(cancel[14]) | (UInt16(cancel[15]) << 8), 0)
    }

    func testPatchCreditRequestIgnoresShortPacket() {
        var shortPacket: [UInt8] = [0xfe, 0x53, 0x4d, 0x42, 0x40, 0x00]
        let before = shortPacket
        SMB2Credit.patchCreditRequest(into: &shortPacket, balance: 1, target: 256)
        XCTAssertEqual(shortPacket, before)
    }

    func testCreditWindowChunkSizeExpandsWithGrantedCredits() {
        XCTAssertEqual(
            SMBTransferLimits.creditWindowChunkSize(
                localLimit: 1_048_576,
                negotiatedLimit: 1_048_576,
                availableCredits: 1
            ),
            64 * 1024
        )
        XCTAssertEqual(
            SMBTransferLimits.creditWindowChunkSize(
                localLimit: 1_048_576,
                negotiatedLimit: 1_048_576,
                availableCredits: 16
            ),
            1_048_576
        )
    }

    func testSetInfoRenameRequestUsesFileRenameInformationBuffer() throws {
        let fileId = (0..<16).map(UInt8.init)
        let request = try SMB2SetInfo.encodeRenameRequest(
            messageId: 17,
            sessionId: 0x1122_3344,
            treeId: 0x5566_7788,
            fileId: fileId,
            newPath: "\\renamed.txt",
            replaceIfExists: true
        )
        let expectedName = NTLM.utf16le("renamed.txt")

        let header = try SMB2Header.decode(request)
        XCTAssertEqual(header.command, SMB2Commands.setInfo)
        XCTAssertEqual(readUInt16LE(request, at: 64), 33)
        XCTAssertEqual(request[66], 0x01)
        XCTAssertEqual(request[67], 10)
        XCTAssertEqual(readUInt32LE(request, at: 68), UInt32(20 + expectedName.count))
        XCTAssertEqual(readUInt16LE(request, at: 72), 96)
        XCTAssertEqual(Array(request[80..<96]), fileId)
        XCTAssertEqual(request[96], 1)
        XCTAssertEqual(Array(request[97..<104]), Array(repeating: 0, count: 7))
        XCTAssertEqual(readUInt64LE(request, at: 104), 0)
        XCTAssertEqual(readUInt32LE(request, at: 112), UInt32(expectedName.count))
        XCTAssertEqual(Array(request[116..<request.count]), expectedName)
    }

    func testNegotiateRequestRoundTripShape() throws {
        let request = try SMBNegotiateCodec.encodeRequest(
            clientGuid: UUID(uuidString: "00112233-4455-6677-8899-aabbccddeeff")!,
            salt: Array(repeating: 0xaa, count: 32)
        )
        let expectedHex =
            "fe534d4240000000000000000000010000000000000000000000000000000000" +
            "0000000000000000000000000000000000000000000000000000000000000000" +
            "24000500010000004000000000112233445566778899aabbccddeeff70000000" +
            "030000000202100200030203110300000100260000000000010020000100aaaaaaaaaaaaaaaaaaaa" +
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa000002000600000000000200020001000000" +
            "080004000000000001000200"
        XCTAssertEqual(hex(request), expectedHex)

        let header = try SMB2Header.decode(request)
        XCTAssertEqual(header.command, SMBNegotiateConstants.commandNegotiate)
        XCTAssertEqual(header.messageId, 0)

        var reader = SMBByteReader(bytes: Array(request.dropFirst(64)))
        XCTAssertEqual(try reader.readUInt16LE(), 36)
        XCTAssertEqual(try reader.readUInt16LE(), 5)
        try reader.skip(count: 2 + 2 + 4 + 16)
        XCTAssertEqual(try reader.readUInt32LE(), 112)
        XCTAssertEqual(try reader.readUInt16LE(), 3)
        try reader.skip(count: 2)
        XCTAssertEqual(try reader.readUInt16LE(), SMBNegotiateConstants.dialect202)
        XCTAssertEqual(try reader.readUInt16LE(), SMBNegotiateConstants.dialect210)
        XCTAssertEqual(try reader.readUInt16LE(), SMBNegotiateConstants.dialect300)
        XCTAssertEqual(try reader.readUInt16LE(), SMBNegotiateConstants.dialect302)
        XCTAssertEqual(try reader.readUInt16LE(), SMBNegotiateConstants.dialect311)
    }

    func testNegotiateRequestCanLimitDialectsForAuthenticatedConnect() throws {
        let request = try SMBNegotiateCodec.encodeRequest(
            clientGuid: UUID(uuidString: "00112233-4455-6677-8899-aabbccddeeff")!,
            salt: Array(repeating: 0xaa, count: 32),
            offeredDialects: SMBNegotiateCodec.authenticatedDialects
        )

        XCTAssertEqual(readUInt16LE(request, at: 66), 3)
        XCTAssertEqual(readUInt16LE(request, at: 100), SMBNegotiateConstants.dialect300)
        XCTAssertEqual(readUInt16LE(request, at: 102), SMBNegotiateConstants.dialect302)
        XCTAssertEqual(readUInt16LE(request, at: 104), SMBNegotiateConstants.dialect311)
        XCTAssertEqual(readUInt32LE(request, at: 92), 112)
    }

    func testNegotiateRequestContextAlignmentAndCount() throws {
        let request = try SMBNegotiateCodec.encodeRequest(
            clientGuid: UUID(uuidString: "00112233-4455-6677-8899-aabbccddeeff")!,
            salt: Array(repeating: 0xaa, count: 32)
        )

        let contextOffset = Int(readUInt32LE(request, at: 64 + 28))
        let contextCount = Int(readUInt16LE(request, at: 64 + 32))
        XCTAssertEqual(contextOffset, 112)
        XCTAssertEqual(contextOffset % 8, 0)
        XCTAssertEqual(contextCount, 3)
        XCTAssertEqual(Array(request[110..<112]), [0, 0])

        var offset = contextOffset
        var contextTypes: [UInt16] = []
        var encryptionData: [UInt8] = []
        for index in 0..<contextCount {
            XCTAssertEqual(offset % 8, 0)
            let type = readUInt16LE(request, at: offset)
            let length = Int(readUInt16LE(request, at: offset + 2))
            contextTypes.append(type)
            if type == SMBNegotiateConstants.encryptionContext {
                encryptionData = Array(request[(offset + 8)..<(offset + 8 + length)])
            }
            let dataEnd = offset + 8 + length
            let nextOffset: Int
            if index == contextCount - 1 {
                nextOffset = dataEnd
                XCTAssertEqual(dataEnd, request.count)
            } else {
                nextOffset = offset + 8 + ((length + 7) / 8) * 8
                XCTAssertEqual(
                    Array(request[dataEnd..<nextOffset]),
                    Array(repeating: 0, count: nextOffset - dataEnd)
                )
            }
            offset = nextOffset
        }

        XCTAssertEqual(contextTypes, [
            SMBNegotiateConstants.preauthContext,
            SMBNegotiateConstants.encryptionContext,
            SMBNegotiateConstants.signingContext
        ])
        XCTAssertEqual(encryptionData, [0x02, 0x00, 0x02, 0x00, 0x01, 0x00])
        XCTAssertEqual(offset, request.count)
    }

    func testNegotiateResponseRoundTrip() throws {
        let response = try makeNegotiateResponse()
        let parsed = try SMBNegotiateCodec.decodeResponse(response)
        XCTAssertEqual(parsed.dialect, SMBNegotiateConstants.dialect311)
        XCTAssertTrue(parsed.signingRequired)
        XCTAssertEqual(parsed.signingAlgorithm, SMBNegotiateConstants.aesGMAC)
        XCTAssertEqual(parsed.cipher, SMBNegotiateConstants.aes128GCM)
        XCTAssertEqual(parsed.preauthHashAlgorithm, SMBNegotiateConstants.sha512)
        XCTAssertEqual(parsed.serverGuid.uuidString, "00112233-4455-6677-8899-AABBCCDDEEFF")
        XCTAssertEqual(parsed.maxTransactSize, 1_048_576)
        XCTAssertEqual(parsed.maxReadSize, 1_048_576)
        XCTAssertEqual(parsed.maxWriteSize, 1_048_576)
    }

    func testNegotiateResponseAcceptsUnpaddedFinalContext() throws {
        let response = try makeNegotiateResponse(padFinalContext: false)
        let contextOffset = Int(readUInt32LE(response, at: 64 + 60))
        let signingOffset = contextOffset + 16 + 8 + 8

        XCTAssertEqual(readUInt16LE(response, at: signingOffset), SMBNegotiateConstants.signingContext)
        XCTAssertEqual(response.count, signingOffset + 8 + 4)

        let parsed = try SMBNegotiateCodec.decodeResponse(response)
        XCTAssertEqual(parsed.dialect, SMBNegotiateConstants.dialect311)
        XCTAssertEqual(parsed.signingAlgorithm, SMBNegotiateConstants.aesGMAC)
        XCTAssertEqual(parsed.cipher, SMBNegotiateConstants.aes128GCM)
        XCTAssertEqual(parsed.preauthHashAlgorithm, SMBNegotiateConstants.sha512)
    }

    func testNegotiateResponseBefore311HasNoContexts() throws {
        let response = try makeNegotiateResponse(
            dialect: SMBNegotiateConstants.dialect300,
            contextCount: 0,
            contextOffset: 0,
            includeContexts: false
        )
        let parsed = try SMBNegotiateCodec.decodeResponse(response)
        XCTAssertEqual(parsed.dialect, SMBNegotiateConstants.dialect300)
        XCTAssertTrue(parsed.signingRequired)
        XCTAssertNil(parsed.signingAlgorithm)
        XCTAssertNil(parsed.cipher)
        XCTAssertNil(parsed.preauthHashAlgorithm)
        XCTAssertEqual(parsed.serverGuid.uuidString, "00112233-4455-6677-8899-AABBCCDDEEFF")
        XCTAssertEqual(parsed.maxTransactSize, 1_048_576)
        XCTAssertEqual(parsed.maxReadSize, 1_048_576)
        XCTAssertEqual(parsed.maxWriteSize, 1_048_576)
    }

    func testNegotiateResponseRejectsInvalidContextOffset() throws {
        var response = try makeNegotiateResponse()
        writeUInt32LE(128, to: &response, at: 64 + 60)

        XCTAssertThrowsError(try SMBNegotiateCodec.decodeResponse(response)) { error in
            XCTAssertEqual(error as? SMBCodecError, .invalidValue("invalid NEGOTIATE context offset"))
        }
    }

    func testNegotiateResponseRejectsMalformedContextLength() throws {
        var response = try makeNegotiateResponse()
        let contextOffset = Int(readUInt32LE(response, at: 64 + 60))
        writeUInt16LE(5, to: &response, at: contextOffset + 2)

        XCTAssertThrowsError(try SMBNegotiateCodec.decodeResponse(response)) { error in
            XCTAssertEqual(error as? SMBCodecError, .invalidValue("invalid PREAUTH context length"))
        }
    }

    func testNegotiateResponseRejectsContextPastPacketEnd() throws {
        var response = try makeNegotiateResponse()
        let contextOffset = Int(readUInt32LE(response, at: 64 + 60))
        writeUInt16LE(0xff, to: &response, at: contextOffset + 2)

        XCTAssertThrowsError(try SMBNegotiateCodec.decodeResponse(response)) { error in
            XCTAssertEqual(error as? SMBCodecError, .truncated)
        }
    }

    private func makeNegotiateResponse(
        dialect: UInt16 = SMBNegotiateConstants.dialect311,
        contextCount: UInt16 = 3,
        contextOffset: UInt32 = 136,
        includeContexts: Bool = true,
        padFinalContext: Bool = true
    ) throws -> [UInt8] {
        let header = try SMB2Header(command: SMBNegotiateConstants.commandNegotiate, messageId: 0).encode()
        var body = SMBByteWriter()
        body.writeUInt16LE(65)
        body.writeUInt16LE(SMBNegotiateConstants.signingRequired)
        body.writeUInt16LE(dialect)
        body.writeUInt16LE(contextCount)
        body.writeBytes(UUID(uuidString: "00112233-4455-6677-8899-aabbccddeeff")!.smbWireBytes)
        body.writeUInt32LE(SMBNegotiateConstants.globalCapEncryption)
        body.writeUInt32LE(1_048_576)
        body.writeUInt32LE(1_048_576)
        body.writeUInt32LE(1_048_576)
        body.writeUInt64LE(0)
        body.writeUInt64LE(0)
        body.writeUInt16LE(0)
        body.writeUInt16LE(0)
        body.writeUInt32LE(contextOffset)
        var packet = header + body.bytes
        if includeContexts {
            packet.append(contentsOf: Array(repeating: 0, count: Int(contextOffset) - packet.count))

            appendContext(type: SMBNegotiateConstants.preauthContext, data: [1, 0, 0, 0, 1, 0], to: &packet)
            appendContext(type: SMBNegotiateConstants.encryptionContext, data: [1, 0, 2, 0], to: &packet)
            appendContext(type: SMBNegotiateConstants.signingContext, data: [1, 0, 2, 0], padTo8: padFinalContext, to: &packet)
        }
        return packet
    }

    private func appendContext(type: UInt16, data: [UInt8], padTo8: Bool = true, to bytes: inout [UInt8]) {
        var writer = SMBByteWriter()
        writer.writeUInt16LE(type)
        writer.writeUInt16LE(UInt16(data.count))
        writer.writeUInt32LE(0)
        writer.writeBytes(data)
        if padTo8 {
            writer.padTo8()
        }
        bytes.append(contentsOf: writer.bytes)
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

    private func decodeNTLMv2BlobAVPairs(_ blob: [UInt8]) throws -> [(id: UInt16, value: [UInt8])] {
        var offset = 28
        var pairs: [(id: UInt16, value: [UInt8])] = []
        while offset + 4 <= blob.count {
            let id = readUInt16LE(blob, at: offset)
            let length = Int(readUInt16LE(blob, at: offset + 2))
            offset += 4
            guard offset + length <= blob.count else { throw SMBCodecError.truncated }
            pairs.append((id, Array(blob[offset..<offset + length])))
            offset += length
            if id == 0 { return pairs }
        }
        throw SMBCodecError.invalidValue("NTLMv2 blob target info missing EOL")
    }

    private func appendAVPair(id: UInt16, value: [UInt8], to bytes: inout [UInt8]) {
        bytes.append(UInt8(id & 0xff))
        bytes.append(UInt8((id >> 8) & 0xff))
        bytes.append(UInt8(value.count & 0xff))
        bytes.append(UInt8((value.count >> 8) & 0xff))
        bytes.append(contentsOf: value)
    }

    private func appendNDRString(_ value: String, to bytes: inout [UInt8]) {
        let units = Array(value.utf16) + [0]
        appendUInt32LE(UInt32(units.count), to: &bytes)
        appendUInt32LE(0, to: &bytes)
        appendUInt32LE(UInt32(units.count), to: &bytes)
        for unit in units {
            bytes.append(UInt8(unit & 0xff))
            bytes.append(UInt8((unit >> 8) & 0xff))
        }
        while bytes.count % 4 != 0 {
            bytes.append(0)
        }
    }

    private func makeDfsReferralResponse(entries: [[UInt8]]) -> [UInt8] {
        var bytes: [UInt8] = []
        appendUInt16LE(44, to: &bytes)
        appendUInt16LE(UInt16(entries.count), to: &bytes)
        appendUInt32LE(0x0000_0002, to: &bytes)
        for entry in entries {
            bytes.append(contentsOf: entry)
        }
        return bytes
    }

    private func makeDfsReferralV3Entry(
        serverType: UInt16,
        flags: UInt16,
        ttl: UInt32,
        dfsPath: String?,
        alternatePath: String?,
        networkAddress: String?
    ) -> [UInt8] {
        var entry = Array(repeating: UInt8(0), count: 34)
        writeUInt16LE(3, to: &entry, at: 0)
        writeUInt16LE(serverType, to: &entry, at: 4)
        writeUInt16LE(flags, to: &entry, at: 6)
        writeUInt32LE(ttl, to: &entry, at: 8)
        writeUInt16LE(0, to: &entry, at: 18)
        writeUInt16LE(0, to: &entry, at: 20)
        writeUInt16LE(0, to: &entry, at: 22)
        writeUInt16LE(0, to: &entry, at: 24)
        writeUInt16LE(0, to: &entry, at: 26)
        writeUInt16LE(0, to: &entry, at: 28)
        writeUInt16LE(0, to: &entry, at: 30)
        writeUInt16LE(0, to: &entry, at: 32)

        if let dfsPath {
    writeUInt16LE(UInt16(entry.count), to: &entry, at: 12)
            appendNullTerminatedUTF16LE(dfsPath, to: &entry)
        }
        if let alternatePath {
    writeUInt16LE(UInt16(entry.count), to: &entry, at: 14)
            appendNullTerminatedUTF16LE(alternatePath, to: &entry)
        }
        if let networkAddress {
    writeUInt16LE(UInt16(entry.count), to: &entry, at: 16)
            appendNullTerminatedUTF16LE(networkAddress, to: &entry)
        }
    writeUInt16LE(UInt16(entry.count), to: &entry, at: 2)
        return entry
    }

    private func appendNullTerminatedUTF16LE(_ value: String, to bytes: inout [UInt8]) {
        bytes.append(contentsOf: NTLM.utf16le(value))
        bytes.append(0)
        bytes.append(0)
    }

    private func makeDirectoryEntry(
        name: String,
        isDirectory: Bool,
        fileSize: UInt64 = 0,
        nextOffset: UInt32,
        attributes: UInt32? = nil,
        fileId: UInt64 = 0,
        creationTime: UInt64 = 0,
        lastWriteTime: UInt64 = 0
    ) -> [UInt8] {
        let nameBytes = NTLM.utf16le(name)
        var bytes = Array(repeating: UInt8(0), count: 104 + nameBytes.count)
        writeUInt32LE(nextOffset, to: &bytes, at: 0)
        writeUInt64LE(creationTime, to: &bytes, at: 8)
        writeUInt64LE(lastWriteTime, to: &bytes, at: 24)
        writeUInt64LE(fileSize, to: &bytes, at: 40)
        writeUInt32LE(attributes ?? (isDirectory ? 0x10 : 0x80), to: &bytes, at: 56)
        writeUInt32LE(UInt32(nameBytes.count), to: &bytes, at: 60)
        writeUInt64LE(fileId, to: &bytes, at: 96)
        bytes.replaceSubrange(104..<104 + nameBytes.count, with: nameBytes)
        if Int(nextOffset) > bytes.count {
            bytes.append(contentsOf: Array(repeating: 0, count: Int(nextOffset) - bytes.count))
        }
        return bytes
    }

    private func makeFileNotifyEntry(action: UInt32, name: String, nextOffset: UInt32) -> [UInt8] {
        let nameBytes = NTLM.utf16le(name)
        var bytes = Array(repeating: UInt8(0), count: 12 + nameBytes.count)
        writeUInt32LE(nextOffset, to: &bytes, at: 0)
        writeUInt32LE(action, to: &bytes, at: 4)
        writeUInt32LE(UInt32(nameBytes.count), to: &bytes, at: 8)
        bytes.replaceSubrange(12..<12 + nameBytes.count, with: nameBytes)
        if Int(nextOffset) > bytes.count {
            bytes.append(contentsOf: Array(repeating: 0, count: Int(nextOffset) - bytes.count))
        }
        return bytes
    }

    private func hex(_ bytes: [UInt8]) -> String {
        bytes.map { String(format: "%02x", $0) }.joined()
    }

    private func hexBytes(_ value: String) -> [UInt8] {
        stride(from: 0, to: value.count, by: 2).map {
            let start = value.index(value.startIndex, offsetBy: $0)
            let end = value.index(start, offsetBy: 2)
            return UInt8(value[start..<end], radix: 16)!
        }
    }

    private func readUInt64LE(_ bytes: [UInt8], at offset: Int) -> UInt64 {
        UInt64(readUInt32LE(bytes, at: offset)) | (UInt64(readUInt32LE(bytes, at: offset + 4)) << 32)
    }

    private func writeTemporaryFile(bytes: [UInt8]) throws -> URL {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("smbee-stream-upload-\(UUID().uuidString)")
        try Data(bytes).write(to: url)
        return url
    }

    private func atomicStagingDirectories(in directory: URL, destinationName: String) throws -> [String] {
        try FileManager.default.contentsOfDirectory(atPath: directory.path).filter {
            $0.hasPrefix(".\(destinationName).smbee-") && $0.hasSuffix(".tmp")
        }
    }

    private func outboundFrames(_ transport: SMBValidateNegotiateScriptTransport, containCommand command: UInt16) throws -> Bool {
        try outboundFrames(transport.outbound, containCommand: command)
    }

    private func outboundFrames(_ bytes: [UInt8], containCommand command: UInt16) throws -> Bool {
        try unframed(bytes).contains { frame in
            guard frame.count >= 4, Array(frame.prefix(4)) == [0xfe, 0x53, 0x4d, 0x42] else {
                return false
            }
            return try SMB2Header.decode(frame).command == command
        }
    }

    private func assertOutboundContainsCreateRequest(
        _ transport: ScriptedBlockingReceiveTransport,
        file: StaticString = #filePath,
        line: UInt = #line
    ) throws {
        let containsCreate = try outboundFrames(transport.outbound, containCommand: SMB2Commands.create)
        let summary = try outboundFrameSummary(transport.outbound)
        XCTAssertTrue(
            containsCreate,
            summary,
            file: file,
            line: line
        )
    }

    private func outboundFrameSummary(_ bytes: [UInt8]) throws -> String {
        try unframed(bytes).map { frame in
            let prefix = frame.prefix(4).map { String(format: "%02x", $0) }.joined()
            let command = (try? SMB2Header.decode(frame).command).map(String.init) ?? "n/a"
            return "\(prefix):\(frame.count):\(command)"
        }.joined(separator: ",")
    }

    private func writePayload(from request: [UInt8]) throws -> [UInt8] {
        let dataOffset = Int(readUInt16LE(request, at: 66))
        let length = Int(readUInt32LE(request, at: 68))
        guard dataOffset >= 0, dataOffset + length <= request.count else {
            throw SMBCodecError.invalidValue("invalid WRITE payload bounds")
        }
        return Array(request[dataOffset..<(dataOffset + length)])
    }

    private func expectDERTag(_ expectedTag: UInt8, in bytes: [UInt8], cursor: inout Int) throws -> Int {
        XCTAssertLessThan(cursor, bytes.count)
        XCTAssertEqual(bytes[cursor], expectedTag)
        cursor += 1
        let length = try readDERLength(bytes, cursor: &cursor)
        let end = cursor + length
        XCTAssertLessThanOrEqual(end, bytes.count)
        return end
    }

    private func readDERLength(_ bytes: [UInt8], cursor: inout Int) throws -> Int {
        XCTAssertLessThan(cursor, bytes.count)
        let first = bytes[cursor]
        cursor += 1
        if first & 0x80 == 0 {
            return Int(first)
        }
        let byteCount = Int(first & 0x7f)
        XCTAssertGreaterThan(byteCount, 0)
        XCTAssertLessThanOrEqual(byteCount, 2)
        XCTAssertLessThanOrEqual(cursor + byteCount, bytes.count)
        var value = 0
        for _ in 0..<byteCount {
            value = (value << 8) | Int(bytes[cursor])
            cursor += 1
        }
        return value
    }

    // SESSION_SETUP success response body (MS-SMB2 §2.2.6): StructureSize=9, SessionFlags,
    // SecurityBufferOffset, SecurityBufferLength. The client decodes SessionFlags from the final response.
    private func sessionSetupSuccessResponse(
        messageId: UInt64,
        sessionFlags: UInt16 = 0,
        sessionId: UInt64 = 0
    ) throws -> [UInt8] {
        var response = try SMB2Header(
            command: SMB2Commands.sessionSetup,
            messageId: messageId,
            sessionId: sessionId
        ).encode()
        response.append(contentsOf: [9, 0, UInt8(sessionFlags & 0xff), UInt8(sessionFlags >> 8), 72, 0, 0, 0])
        return response
    }

    private func smb2StatusResponse(status: UInt32, command: UInt16, messageId: UInt64, treeId: UInt32, credits: UInt16 = 1) throws -> [UInt8] {
        try SMB2Header(status: status, command: command, credits: credits, messageId: messageId, treeId: treeId).encode()
    }

    private func smb2EchoResponse(messageId: UInt64, credits: UInt16 = 1) throws -> [UInt8] {
        var response = try SMB2Header(command: SMB2Commands.echo, credits: credits, messageId: messageId).encode()
        response.append(contentsOf: [4, 0, 0, 0])
        return response
    }

    // SMB2 ERROR Response (MS-SMB2 §2.2.2): StructureSize=9, ErrorContextCount, Reserved,
    // ByteCount, ErrorData. Servers return this (not the IOCTL response) when an IOCTL fails,
    // e.g. copychunk unsupported → STATUS_INVALID_DEVICE_REQUEST.
    private func smb2ErrorResponse(status: UInt32, command: UInt16, messageId: UInt64, treeId: UInt32) throws -> [UInt8] {
        var response = try SMB2Header(status: status, command: command, messageId: messageId, treeId: treeId).encode()
        response.append(contentsOf: [9, 0, 0, 0, 0, 0, 0, 0, 0])
        return response
    }

    private func smb2IoctlResponse(
        output: [UInt8],
        status: UInt32,
        messageId: UInt64,
        treeId: UInt32,
        fileId: [UInt8],
        ctlCode: UInt32 = SMB2Ioctl.fsctlPipeTransceive
    ) throws -> [UInt8] {
        var response = try SMB2Header(
            status: status,
            command: SMB2Commands.ioctl,
            messageId: messageId,
            treeId: treeId
        ).encode()
        response.append(contentsOf: Array(repeating: 0, count: 56))
        writeUInt16LE(49, to: &response, at: 64)
        writeUInt32LE(ctlCode, to: &response, at: 68)
        response.replaceSubrange(72..<88, with: fileId)
        writeUInt32LE(120, to: &response, at: 96)
        writeUInt32LE(UInt32(output.count), to: &response, at: 100)
        response.append(contentsOf: output)
        return response
    }

    private func reparseSymlinkBuffer(substituteName: String, printName: String, flags: UInt32 = 0) -> [UInt8] {
        let substitute = NTLM.utf16le(substituteName)
        let print = NTLM.utf16le(printName)
        let dataLength = 12 + substitute.count + print.count
        var bytes: [UInt8] = []
        bytes.append(contentsOf: [0x0c, 0x00, 0x00, 0xa0])
        bytes.append(contentsOf: [UInt8(dataLength & 0xff), UInt8((dataLength >> 8) & 0xff), 0, 0])
        bytes.append(contentsOf: [0, 0, UInt8(substitute.count & 0xff), UInt8((substitute.count >> 8) & 0xff)])
        bytes.append(contentsOf: [UInt8(substitute.count & 0xff), UInt8((substitute.count >> 8) & 0xff), UInt8(print.count & 0xff), UInt8((print.count >> 8) & 0xff)])
        bytes.append(contentsOf: [
            UInt8(flags & 0xff),
            UInt8((flags >> 8) & 0xff),
            UInt8((flags >> 16) & 0xff),
            UInt8((flags >> 24) & 0xff)
        ])
        bytes.append(contentsOf: substitute)
        bytes.append(contentsOf: print)
        return bytes
    }

    private func reparseMountPointBuffer(substituteName: String, printName: String) -> [UInt8] {
        let substitute = NTLM.utf16le(substituteName)
        let print = NTLM.utf16le(printName)
        let dataLength = 8 + substitute.count + print.count
        var bytes: [UInt8] = []
        bytes.append(contentsOf: [0x03, 0x00, 0x00, 0xa0])
        bytes.append(contentsOf: [UInt8(dataLength & 0xff), UInt8((dataLength >> 8) & 0xff), 0, 0])
        bytes.append(contentsOf: [0, 0, UInt8(substitute.count & 0xff), UInt8((substitute.count >> 8) & 0xff)])
        bytes.append(contentsOf: [UInt8(substitute.count & 0xff), UInt8((substitute.count >> 8) & 0xff), UInt8(print.count & 0xff), UInt8((print.count >> 8) & 0xff)])
        bytes.append(contentsOf: substitute)
        bytes.append(contentsOf: print)
        return bytes
    }

    private func waitForOutboundFrameCount(_ expectedCount: Int, transport: ControlledReceiveTransport) async throws {
        let eventClock = ManualSMBSleeper()
        try await awaitWithTimeout("outbound frame count (expectedCount)") {
            try await transport.waitForOutboundFrameCount(
                atLeast: expectedCount,
                timeout: .seconds(1),
                sleeper: { try await eventClock.sleep(for: $0) }
            )
        }
    }

    // 無制限に await するテスト内 Task (例: session.readChunk の Task.value) を、
    // 明示タイムアウトで包む安全網。順序前提の破れ等で continuation が resume されない
    // と CI job 全体が 10 分 hang する (issue 007) ので、テスト側で bound して即 fail させる。
    // hang は continuation 待ち (協調プールは空き) なので sleep タスクは確実に発火する。
    private func awaitWithTimeout<T: Sendable>(
        seconds: Double = 5,
        _ label: String,
        _ operation: @escaping @Sendable () async throws -> T
    ) async throws -> T {
        // NOT a task group: withThrowingTaskGroup awaits all children before returning, so an
        // operation stuck on an uncancellable await (e.g. `Task.value` of a task whose
        // continuation is never resumed) hangs the group even after the watchdog fires — the
        // exact CI-killing hole from issues/010 (and issues/done/007). Resume-once racing
        // lets the timeout win; a truly stuck operation task is leaked, which is acceptable
        // in tests and strictly better than hanging the whole job.
        let box = ResumeOnceBox<T>()
        let operationTask = Task { @Sendable in
            do {
                box.resume(.success(try await operation()))
            } catch {
                box.resume(.failure(error))
            }
        }
        let watchdogTask = Task { @Sendable in
            try? await Task.sleep(nanoseconds: UInt64(seconds * 1_000_000_000))
            operationTask.cancel()
            box.resume(.failure(SMBTestTimeoutError(label: label, seconds: seconds)))
        }
        defer { watchdogTask.cancel() }
        return try await withCheckedThrowingContinuation { continuation in
            box.install(continuation)
        }
    }

    /// Resumes an installed continuation with the first result; later results are dropped.
    private final class ResumeOnceBox<T: Sendable>: @unchecked Sendable {
        private let lock = NSLock()
        private var continuation: CheckedContinuation<T, Error>?
        private var pendingResult: Result<T, Error>?

        func install(_ continuation: CheckedContinuation<T, Error>) {
            lock.lock()
            if let result = pendingResult {
                lock.unlock()
                continuation.resume(with: result)
                return
            }
            self.continuation = continuation
            lock.unlock()
        }

        func resume(_ result: Result<T, Error>) {
            lock.lock()
            guard pendingResult == nil else {
                lock.unlock()
                return
            }
            pendingResult = result
            let continuation = self.continuation
            self.continuation = nil
            lock.unlock()
            continuation?.resume(with: result)
        }
    }

    private func smb2CreateResponse(fileId: [UInt8], messageId: UInt64, treeId: UInt32, credits: UInt16 = 1) throws -> [UInt8] {
        var response = try SMB2Header(command: SMB2Commands.create, credits: credits, messageId: messageId, treeId: treeId).encode()
        response.append(contentsOf: Array(repeating: UInt8(0), count: 88))
        writeUInt16LE(89, to: &response, at: 64)
        response.replaceSubrange(128..<144, with: fileId)
        return response
    }

    private func smb2ReadResponse(
        _ payload: [UInt8],
        messageId: UInt64,
        treeId: UInt32,
        credits: UInt16 = 1,
        sessionId: UInt64 = 0
    ) throws -> [UInt8] {
        var response = try SMB2Header(
            command: SMB2Commands.read,
            credits: credits,
            messageId: messageId,
            treeId: treeId,
            sessionId: sessionId
        ).encode()
        response.append(contentsOf: Array(repeating: UInt8(0), count: 16))
        writeUInt16LE(17, to: &response, at: 64)
        response[66] = 80
        writeUInt32LE(UInt32(payload.count), to: &response, at: 68)
        response.append(contentsOf: payload)
        return response
    }

    private func smb3CCMTransform(
        _ plaintext: [UInt8],
        key: [UInt8],
        nonce: [UInt8],
        sessionId: UInt64
    ) throws -> [UInt8] {
        var header = SMB3TransformHeader(
            signature: Array(repeating: 0, count: 16),
            nonce: nonce + Array(repeating: 0, count: 5),
            originalMessageSize: UInt32(plaintext.count),
            flags: SMB3TransformHeader.encryptedFlag,
            sessionId: sessionId
        )
        let sealed = try AESCCM.seal(
            key: key,
            nonce: nonce,
            plaintext: plaintext,
            authenticatedData: header.authenticatedData(),
            tagLength: 16
        )
        header.signature = sealed.tag
        return try header.encode() + sealed.ciphertext
    }

    private func dcerpcResponsePDU(stub: [UInt8], flags: UInt8, callId: UInt32 = 2) throws -> [UInt8] {
        var response: [UInt8] = [
            0x05, 0x00, DCERPC.pduTypeResponse, flags,
            0x10, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            UInt8(callId & 0xff), UInt8((callId >> 8) & 0xff), UInt8((callId >> 16) & 0xff), UInt8((callId >> 24) & 0xff)
        ]
        appendUInt32LE(UInt32(stub.count), to: &response)
        appendUInt16LE(0, to: &response)
        appendUInt16LE(0, to: &response)
        response.append(contentsOf: stub)
    writeUInt16LE(UInt16(response.count), to: &response, at: 8)
        return response
    }

    private func makeShareEnumStub(_ entries: [(name: String, type: UInt32, comment: String)]) -> [UInt8] {
        var stub: [UInt8] = []
        appendUInt32LE(1, to: &stub)
        appendUInt32LE(1, to: &stub)
        appendUInt32LE(0x0002_0000, to: &stub)
        appendUInt32LE(UInt32(entries.count), to: &stub)
        appendUInt32LE(0x0002_0001, to: &stub)
        appendUInt32LE(UInt32(entries.count), to: &stub)
        for (index, entry) in entries.enumerated() {
            appendUInt32LE(0x0002_0010 + UInt32(index * 2), to: &stub)
            appendUInt32LE(entry.type, to: &stub)
            appendUInt32LE(0x0002_0011 + UInt32(index * 2), to: &stub)
        }
        for entry in entries {
            appendNDRString(entry.name, to: &stub)
            appendNDRString(entry.comment, to: &stub)
        }
        appendUInt32LE(UInt32(entries.count), to: &stub)
        appendUInt32LE(0, to: &stub)
        appendUInt32LE(0, to: &stub)
        return stub
    }

    private func smb2WriteResponse(
        count: Int,
        messageId: UInt64,
        treeId: UInt32,
        credits: UInt16 = 1,
        sessionId: UInt64 = 0
    ) throws -> [UInt8] {
        var response = try SMB2Header(
            command: SMB2Commands.write,
            credits: credits,
            messageId: messageId,
            treeId: treeId,
            sessionId: sessionId
        ).encode()
        response.append(contentsOf: Array(repeating: UInt8(0), count: 16))
        writeUInt16LE(17, to: &response, at: 64)
        writeUInt32LE(UInt32(count), to: &response, at: 68)
        return response
    }

    private func smb2QueryInfoResponse(
        size: UInt64,
        messageId: UInt64,
        treeId: UInt32,
        creationTime: UInt64 = 0,
        lastAccessTime: UInt64 = 0,
        lastWriteTime: UInt64 = 0,
        changeTime: UInt64 = 0,
        attributes: UInt32 = 0
    ) throws -> [UInt8] {
        // FILE_NETWORK_OPEN_INFORMATION (MS-FSCC 2.4.65) の正しい layout で組む:
        // CreationTime 0 / LastAccessTime 8 / LastWriteTime 16 / ChangeTime 24 /
        // AllocationSize 32 / EndOfFile 40 / FileAttributes 48 / Reserved 52.
        var payload = Array(repeating: UInt8(0), count: 56)
        writeUInt64LE(creationTime, to: &payload, at: 0)
        writeUInt64LE(lastAccessTime, to: &payload, at: 8)
        writeUInt64LE(lastWriteTime, to: &payload, at: 16)
        writeUInt64LE(changeTime, to: &payload, at: 24)
        writeUInt64LE(size, to: &payload, at: 40)
        writeUInt32LE(attributes, to: &payload, at: 48)
        var response = try SMB2Header(command: SMB2Commands.queryInfo, messageId: messageId, treeId: treeId).encode()
        response.append(contentsOf: Array(repeating: UInt8(0), count: 8))
        writeUInt16LE(9, to: &response, at: 64)
        writeUInt16LE(72, to: &response, at: 66)
        writeUInt32LE(UInt32(payload.count), to: &response, at: 68)
        response.append(contentsOf: payload)
        return response
    }

    private func smb2QueryInfoResponse(payload: [UInt8], messageId: UInt64 = 12) throws -> [UInt8] {
        var response = try SMB2Header(command: SMB2Commands.queryInfo, messageId: messageId, treeId: 0x3344).encode()
        response.append(contentsOf: Array(repeating: UInt8(0), count: 8))
        writeUInt16LE(9, to: &response, at: 64)
        writeUInt16LE(72, to: &response, at: 66)
        writeUInt32LE(UInt32(payload.count), to: &response, at: 68)
        response.append(contentsOf: payload)
        return response
    }

    private func sidBytes(authority: UInt64, subAuthorities: [UInt32]) -> [UInt8] {
        var bytes: [UInt8] = [1, UInt8(subAuthorities.count)]
        for shift in stride(from: 40, through: 0, by: -8) {
            bytes.append(UInt8((authority >> UInt64(shift)) & 0xff))
        }
        for subAuthority in subAuthorities {
            bytes.append(UInt8(subAuthority & 0xff))
            bytes.append(UInt8((subAuthority >> 8) & 0xff))
            bytes.append(UInt8((subAuthority >> 16) & 0xff))
            bytes.append(UInt8((subAuthority >> 24) & 0xff))
        }
        return bytes
    }

    private func aceBytes(type: UInt8, flags: UInt8, accessMask: UInt32, sid: [UInt8]) -> [UInt8] {
        var bytes: [UInt8] = [type, flags]
        let size = UInt16(8 + sid.count)
        bytes.append(UInt8(size & 0xff))
        bytes.append(UInt8((size >> 8) & 0xff))
        bytes.append(UInt8(accessMask & 0xff))
        bytes.append(UInt8((accessMask >> 8) & 0xff))
        bytes.append(UInt8((accessMask >> 16) & 0xff))
        bytes.append(UInt8((accessMask >> 24) & 0xff))
        bytes.append(contentsOf: sid)
        return bytes
    }

    private func smb2TreeConnectResponse(
        treeId: UInt32,
        shareType: UInt8,
        shareFlags: UInt32,
        capabilities: UInt32,
        maximalAccess: UInt32,
        messageId: UInt64 = 3
    ) throws -> [UInt8] {
        var response = try SMB2Header(command: SMB2Commands.treeConnect, messageId: messageId, treeId: treeId).encode()
        response.append(contentsOf: Array(repeating: UInt8(0), count: 16))
        writeUInt16LE(16, to: &response, at: 64)
        response[66] = shareType
        writeUInt32LE(shareFlags, to: &response, at: 68)
        writeUInt32LE(capabilities, to: &response, at: 72)
        writeUInt32LE(maximalAccess, to: &response, at: 76)
        return response
    }

    private func authenticatedTreeResponses(
        treeId: UInt32 = 0x3344,
        credential: SMBCredential = SMBCredential(username: "user", password: "pass")
    ) throws -> [[UInt8]] {
        var responses = [
            try negotiateResponse(messageId: 0, dialect: SMBNegotiateConstants.dialect302),
            try sessionSetupChallengeResponse(messageId: 1, sessionId: 0x1122_3344_5566_7788),
            try sessionSetupSuccessResponse(messageId: 2),
            try smb2TreeConnectResponse(treeId: treeId, shareType: 1, shareFlags: 0, capabilities: 0, maximalAccess: 0x001f_01ff)
        ]
        if !credential.isAnonymous {
            responses.append(try SMBValidateNegotiateScript.responseTemplate(treeId: treeId))
        }
        return responses
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

    private func smb2ChangeNotifyResponse(entries: [[UInt8]], messageId: UInt64, treeId: UInt32) throws -> [UInt8] {
        let payload = entries.flatMap { $0 }
        var response = try SMB2Header(command: SMB2Commands.changeNotify, messageId: messageId, treeId: treeId).encode()
        response.append(contentsOf: Array(repeating: UInt8(0), count: 8))
        writeUInt16LE(9, to: &response, at: 64)
        writeUInt16LE(72, to: &response, at: 66)
        writeUInt32LE(UInt32(payload.count), to: &response, at: 68)
        response.append(contentsOf: payload)
        return response
    }

    private func referenceAESCMAC(key: [UInt8], message: [UInt8]) throws -> [UInt8] {
        func doubled(_ input: [UInt8]) -> [UInt8] {
            var output = [UInt8](repeating: 0, count: 16)
            var carry: UInt8 = 0
            for index in stride(from: 15, through: 0, by: -1) {
                output[index] = (input[index] << 1) | carry
                carry = input[index] & 0x80 == 0 ? 0 : 1
            }
            if carry != 0 { output[15] ^= 0x87 }
            return output
        }

        let expandedKey = try AES128.expandedKey(key)
        let l = try AES128.encryptBlock(expandedKey: expandedKey, block: [UInt8](repeating: 0, count: 16))
        let k1 = doubled(l)
        let k2 = doubled(k1)
        let blockCount = max(1, (message.count + 15) / 16)
        let complete = !message.isEmpty && message.count % 16 == 0
        var last = [UInt8](repeating: 0, count: 16)
        let lastStart = (blockCount - 1) * 16
        if complete {
            last = Array(message[lastStart..<(lastStart + 16)])
            for index in 0..<16 { last[index] ^= k1[index] }
        } else {
            if lastStart < message.count {
                for index in lastStart..<message.count { last[index - lastStart] = message[index] }
            }
            last[message.count - lastStart] = 0x80
            for index in 0..<16 { last[index] ^= k2[index] }
        }
        var chaining = [UInt8](repeating: 0, count: 16)
        for blockIndex in 0..<max(0, blockCount - 1) {
            var block = Array(message[(blockIndex * 16)..<(blockIndex * 16 + 16)])
            for index in 0..<16 { block[index] ^= chaining[index] }
            chaining = try AES128.encryptBlock(expandedKey: expandedKey, block: block)
        }
        for index in 0..<16 { last[index] ^= chaining[index] }
        return try AES128.encryptBlock(expandedKey: expandedKey, block: last)
    }

    private func negotiateResponse(
        messageId: UInt64, dialect: UInt16 = SMBNegotiateConstants.dialect302, capabilities: UInt32 = 0
    ) throws -> [UInt8] {
        var response = try SMB2Header(command: SMBNegotiateConstants.commandNegotiate, messageId: messageId).encode()
        response.append(contentsOf: Array(repeating: UInt8(0), count: 65))
        writeUInt16LE(65, to: &response, at: 64)
        writeUInt16LE(SMBNegotiateConstants.signingEnabled, to: &response, at: 66)
        writeUInt16LE(dialect, to: &response, at: 68)
        if dialect == SMBNegotiateConstants.dialect311 {
            writeUInt16LE(2, to: &response, at: 70)
        }
        response.replaceSubrange(72..<88, with: Array(repeating: UInt8(0x42), count: 16))
        writeUInt32LE(capabilities, to: &response, at: 88)
        writeUInt32LE(1_048_576, to: &response, at: 92)
        writeUInt32LE(1_048_576, to: &response, at: 96)
        writeUInt32LE(1_048_576, to: &response, at: 100)
        writeUInt16LE(UInt16(response.count), to: &response, at: 116)
        writeUInt16LE(0, to: &response, at: 118)
        if dialect == SMBNegotiateConstants.dialect311 {
            writeUInt32LE(136, to: &response, at: 124)
            response.append(contentsOf: Array(repeating: 0, count: 7))
            appendContext(type: SMBNegotiateConstants.preauthContext, data: [1, 0, 0, 0, 1, 0], to: &response)
            appendContext(type: SMBNegotiateConstants.signingContext, data: [1, 0, 2, 0], padTo8: false, to: &response)
        }
        return response
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
// swiftlint:disable:next file_length
}
