#if canImport(Network)
import Foundation
import Network
import XCTest
@testable import SMBee

final class NWConnectionTransportTests: XCTestCase {
    func testConnectPassesTCPNoDelayParametersToFactory() async throws {
        let fake = FakeNWConnection()
        let captured = NWParametersCapture()
        let transport = NWConnectionTransport(connectionFactory: { _, _, parameters in
            captured.store(parameters)
            return fake
        })
        defer { transport.close() }

        try await transport.connect(host: "127.0.0.1", port: 445)
        let parameters = try XCTUnwrap(captured.parameters)
        let tcpOptions = try XCTUnwrap(
            parameters.defaultProtocolStack.transportProtocol as? NWProtocolTCP.Options
        )
        XCTAssertTrue(tcpOptions.noDelay)
        transport.close()
    }

    func testSegmentedAndByteSendsShareFrameGateAndIndependentContexts() async throws {
        let sends = NWTransportTestCounter()
        let queuedSends = NWTransportTestCounter()
        let fake = FakeNWConnection(sendCount: sends)
        let transport = NWConnectionTransport(
            connectionFactory: { _, _, _ in fake },
            queuedSendCountChanged: { queuedSends.set($0) }
        )
        defer {
            transport.close()
            sends.reset()
            queuedSends.reset()
        }

        try await transport.connect(host: "server", port: 445)
        let first = Task { try await transport.send([[1, 2], [3], [], [4, 5]]) }
        try await smbIssue102AwaitWithTimeout("all first-frame segments enqueued") {
            try await sends.wait(atLeast: 3)
        }

        let firstFrame = fake.snapshots
        XCTAssertEqual(firstFrame.map(\.bytes), [[1, 2], [3], [4, 5]])
        XCTAssertEqual(firstFrame.map(\.isComplete), [false, false, true])
        XCTAssertTrue(firstFrame.allSatisfy { !$0.contextIsFinal })
        XCTAssertEqual(Set(firstFrame.map(\.contextIdentity)).count, 1)
        XCTAssertEqual(fake.pendingCompletionCount, 3)

        let second = Task { try await transport.send([9, 10]) }
        try await smbIssue102AwaitWithTimeout("second send queued behind first-frame completions") {
            try await queuedSends.wait(atLeast: 1)
        }

        XCTAssertEqual(fake.snapshots.count, 3, "B must enqueue nothing while A completions remain")
        XCTAssertEqual(fake.pendingCompletionCount, 3)
        fake.completeSend(at: 0)
        fake.completeSend(at: 1)
        fake.completeSend(at: 2)

        try await smbIssue102AwaitWithTimeout("byte send enqueued after first frame") {
            try await sends.wait(atLeast: 4)
        }
        let allFrames = fake.snapshots
        XCTAssertEqual(allFrames[3].bytes, [9, 10])
        XCTAssertTrue(allFrames[3].isComplete)
        XCTAssertFalse(allFrames[3].contextIsFinal)
        XCTAssertNotEqual(allFrames[0].contextIdentity, allFrames[3].contextIdentity)
        fake.completeSend(at: 3)

        try await smbIssue102AwaitWithTimeout("first segmented send completed") { try await first.value }
        try await smbIssue102AwaitWithTimeout("second byte send completed") { try await second.value }
        XCTAssertEqual(fake.batchCount, 2)
    }

    func testSegmentedSendCollectsEveryContentProcessedResult() async throws {
        let sends = NWTransportTestCounter()
        let fake = FakeNWConnection(sendCount: sends)
        let transport = NWConnectionTransport(connectionFactory: { _, _, _ in fake })
        defer {
            transport.close()
            sends.reset()
        }

        try await transport.connect(host: "server", port: 445)
        let send = Task { try await transport.send([[1], [2], [3]]) }
        try await smbIssue102AwaitWithTimeout("three segmented sends enqueued") {
            try await sends.wait(atLeast: 3)
        }

        fake.completeSend(at: 0)
        fake.completeSend(at: 1, error: .posix(.ECONNRESET))
        fake.completeSend(at: 2)

        do {
            try await smbIssue102AwaitWithTimeout("segmented send result") { try await send.value }
            XCTFail("send should report the error from the second contentProcessed callback")
        } catch let error as NWError {
            XCTAssertEqual(error, .posix(.ECONNRESET))
        }
        XCTAssertEqual(fake.pendingCompletionCount, 0)
    }

    func testCancellationAndCloseSettlePendingSegmentCompletions() async throws {
        let cancellationSends = NWTransportTestCounter()
        let cancellationFake = FakeNWConnection(sendCount: cancellationSends)
        let cancellationTransport = NWConnectionTransport(connectionFactory: { _, _, _ in cancellationFake })
        defer {
            cancellationTransport.close()
            cancellationSends.reset()
        }

        try await cancellationTransport.connect(host: "server", port: 445)
        let cancelledSend = Task { try await cancellationTransport.send([[1], [2]]) }
        try await smbIssue102AwaitWithTimeout("cancelled frame enqueued") {
            try await cancellationSends.wait(atLeast: 2)
        }
        cancelledSend.cancel()
        do {
            try await smbIssue102AwaitWithTimeout("active segmented send cancellation") { try await cancelledSend.value }
            XCTFail("cancelled active send should throw CancellationError")
        } catch is CancellationError {
        }
        XCTAssertEqual(cancellationFake.pendingCompletionCount, 0)
        XCTAssertEqual(cancellationFake.cancelCount, 1)

        let closeSends = NWTransportTestCounter()
        let closeFake = FakeNWConnection(sendCount: closeSends, cancelError: .posix(.ECANCELED))
        let closeTransport = NWConnectionTransport(connectionFactory: { _, _, _ in closeFake })
        defer {
            closeTransport.close()
            closeSends.reset()
        }

        try await closeTransport.connect(host: "server", port: 445)
        let closingSend = Task { try await closeTransport.send([[3], [4]]) }
        try await smbIssue102AwaitWithTimeout("closing frame enqueued") {
            try await closeSends.wait(atLeast: 2)
        }
        closeTransport.close()
        do {
            try await smbIssue102AwaitWithTimeout("active segmented send close") { try await closingSend.value }
            XCTFail("send completion error after close should propagate")
        } catch let error as NWError {
            XCTAssertEqual(error, .posix(.ECANCELED))
        }
        XCTAssertEqual(closeFake.pendingCompletionCount, 0)
        XCTAssertEqual(closeFake.cancelCount, 1)
    }

    func testEmptySendsStillCheckConnectionAndCancellation() async throws {
        let fake = FakeNWConnection()
        let transport = NWConnectionTransport(connectionFactory: { _, _, _ in fake })
        let emptySends: [@Sendable (NWConnectionTransport) async throws -> Void] = [
            { try await $0.send([UInt8]()) },
            { try await $0.send([[UInt8]]([[], []])) }
        ]
        defer { transport.close() }

        for send in emptySends {
            do {
                try await send(transport)
                XCTFail("empty send before connect should report connectionClosed")
            } catch SMBTransportError.connectionClosed {
            }
        }

        try await transport.connect(host: "server", port: 445)
        for send in emptySends {
            try await send(transport)
            let cancelledSend = Task {
                withUnsafeCurrentTask { $0?.cancel() }
                try await send(transport)
            }
            do {
                try await smbIssue102AwaitWithTimeout("cancelled empty send") { try await cancelledSend.value }
                XCTFail("pre-cancelled empty send should throw CancellationError")
            } catch is CancellationError {
            }
        }
        XCTAssertEqual(fake.snapshots.count, 0)

        transport.close()
        for send in emptySends {
            do {
                try await send(transport)
                XCTFail("empty send after close should report connectionClosed")
            } catch SMBTransportError.connectionClosed {
            }
        }
    }
}

private struct NWTransportSendSnapshot {
    let bytes: [UInt8]
    let context: NWConnection.ContentContext
    let isComplete: Bool

    var contextIdentity: ObjectIdentifier { ObjectIdentifier(context) }
    var contextIsFinal: Bool { context.isFinal }
}

private final class NWParametersCapture: @unchecked Sendable {
    private let lock = NSLock()
    private var storage: NWParameters?

    var parameters: NWParameters? { lock.withLock { storage } }

    func store(_ parameters: NWParameters) {
        lock.withLock { storage = parameters }
    }
}

private final class FakeNWConnection: NWConnectionTransportConnection, @unchecked Sendable {
    private struct PendingSend {
        let snapshot: NWTransportSendSnapshot
        var completion: (@Sendable (NWError?) -> Void)?
    }

    private let lock = NSLock()
    private var stateHandler: (@Sendable (NWConnection.State) -> Void)?
    private var pendingSends: [PendingSend] = []
    private var batchInvocationCount = 0
    private var cancellationCount = 0
    private let sendCount: NWTransportTestCounter?
    private let cancelError: NWError?

    init(sendCount: NWTransportTestCounter? = nil, cancelError: NWError? = nil) {
        self.sendCount = sendCount
        self.cancelError = cancelError
    }

    var stateUpdateHandler: (@Sendable (NWConnection.State) -> Void)? {
        get { lock.withLock { stateHandler } }
        set { lock.withLock { stateHandler = newValue } }
    }

    var snapshots: [NWTransportSendSnapshot] {
        lock.withLock { pendingSends.map(\.snapshot) }
    }

    var pendingCompletionCount: Int {
        lock.withLock { pendingSends.filter { $0.completion != nil }.count }
    }

    var batchCount: Int { lock.withLock { batchInvocationCount } }

    var cancelCount: Int { lock.withLock { cancellationCount } }

    func start(queue: DispatchQueue) {
        _ = queue
        stateUpdateHandler?(.ready)
    }

    func batch(_ body: () -> Void) {
        lock.withLock { batchInvocationCount += 1 }
        body()
    }

    func sendData(
        _ data: Data,
        contentContext: NWConnection.ContentContext,
        isComplete: Bool,
        completion: @escaping @Sendable (NWError?) -> Void
    ) {
        let count = lock.withLock { () -> Int in
            pendingSends.append(
                PendingSend(
                    snapshot: NWTransportSendSnapshot(
                        bytes: Array(data),
                        context: contentContext,
                        isComplete: isComplete
                    ),
                    completion: completion
                )
            )
            return pendingSends.count
        }
        sendCount?.set(count)
    }

    func receive(
        minimumIncompleteLength: Int,
        maximumLength: Int,
        completion: @escaping @Sendable (Data?, Bool, NWError?) -> Void
    ) {
        _ = minimumIncompleteLength
        _ = maximumLength
        completion(nil, true, nil)
    }

    func cancel() {
        let completions = lock.withLock { () -> [@Sendable (NWError?) -> Void] in
            cancellationCount += 1
            var callbacks: [@Sendable (NWError?) -> Void] = []
            for index in pendingSends.indices {
                if let callback = pendingSends[index].completion {
                    callbacks.append(callback)
                    pendingSends[index].completion = nil
                }
            }
            return callbacks
        }
        completions.forEach { $0(cancelError) }
    }

    func completeSend(at index: Int, error: NWError? = nil) {
        let completion = lock.withLock { () -> (@Sendable (NWError?) -> Void)? in
            guard pendingSends.indices.contains(index) else { return nil }
            let callback = pendingSends[index].completion
            pendingSends[index].completion = nil
            return callback
        }
        completion?(error)
    }
}

private final class NWTransportTestCounter: @unchecked Sendable {
    private struct Waiter {
        let target: Int
        let continuation: CheckedContinuation<Void, Error>
    }

    private let lock = NSLock()
    private var value = 0
    private var waiters: [UUID: Waiter] = [:]

    func set(_ value: Int) {
        let continuations = lock.withLock { () -> [CheckedContinuation<Void, Error>] in
            self.value = value
            let ready = waiters.filter { value >= $0.value.target }
            for key in ready.keys { waiters[key] = nil }
            return ready.map { $0.value.continuation }
        }
        continuations.forEach { $0.resume() }
    }

    func wait(atLeast target: Int) async throws {
        try Task.checkCancellation()
        let id = UUID()
        try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                let immediateResult: Result<Void, Error>? = lock.withLock {
                    if Task.isCancelled { return .failure(CancellationError()) }
                    if value >= target { return .success(()) }
                    waiters[id] = Waiter(target: target, continuation: continuation)
                    return nil
                }
                if let immediateResult { continuation.resume(with: immediateResult) }
            }
        } onCancel: {
            cancelWaiter(id)
        }
        try Task.checkCancellation()
    }

    func reset() {
        let continuations = lock.withLock { () -> [CheckedContinuation<Void, Error>] in
            value = 0
            let continuations = waiters.values.map(\.continuation)
            waiters.removeAll()
            return continuations
        }
        continuations.forEach { $0.resume(throwing: CancellationError()) }
    }

    private func cancelWaiter(_ id: UUID) {
        let continuation = lock.withLock { waiters.removeValue(forKey: id)?.continuation }
        continuation?.resume(throwing: CancellationError())
    }
}
#endif
