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

    func testSegmentedAndByteSendsShareFrameGateAndDefaultMessageContext() async throws {
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
        XCTAssertEqual(allFrames[0].contextIdentity, allFrames[3].contextIdentity)
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
        XCTAssertTrue(cancellationFake.isCancelled)

        do {
            try await cancellationTransport.send([5])
            XCTFail("send after connection cancellation should fail")
        } catch let error as NWError {
            XCTAssertEqual(error, .posix(.ECANCELED))
        }

        let closeSends = NWTransportTestCounter()
        let closeFake = FakeNWConnection(sendCount: closeSends)
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

final class NWConnectionTransportGateRegressionTests: XCTestCase {
    func testQueuedCancellationAndHolderFailureReleaseNextWaiter() async throws {
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
        let holder = Task { try await transport.send([[1], [2]]) }
        try await smbIssue102AwaitWithTimeout("holder segments enqueued") {
            try await sends.wait(atLeast: 2)
        }

        let cancelledWaiter = Task { try await transport.send([3]) }
        try await smbIssue102AwaitWithTimeout("B queued behind A") {
            try await queuedSends.wait(untilEqual: 1)
        }
        let nextWaiter = Task { try await transport.send([4]) }
        try await smbIssue102AwaitWithTimeout("C queued behind B") {
            try await queuedSends.wait(untilEqual: 2)
        }

        cancelledWaiter.cancel()
        try await smbIssue102AwaitWithTimeout("B removed from the gate") {
            try await queuedSends.wait(untilEqual: 1)
        }
        do {
            try await smbIssue102AwaitWithTimeout("cancelled B settles") { try await cancelledWaiter.value }
            XCTFail("cancelled queued send should throw CancellationError")
        } catch is CancellationError {
        }
        XCTAssertEqual(fake.cancelCount, 0, "cancelling a queued waiter must not cancel A's connection")
        XCTAssertEqual(fake.snapshots.map(\.bytes), [[1], [2]])

        fake.completeSend(at: 0, error: .posix(.ECONNRESET))
        fake.completeSend(at: 1)
        do {
            try await smbIssue102AwaitWithTimeout("A settles with its send error") { try await holder.value }
            XCTFail("holder A should report its contentProcessed error")
        } catch let error as NWError {
            XCTAssertEqual(error, .posix(.ECONNRESET))
        }

        try await smbIssue102AwaitWithTimeout("C enqueued after A releases the gate") {
            try await sends.wait(atLeast: 3)
        }
        XCTAssertEqual(fake.snapshots.map(\.bytes), [[1], [2], [4]])
        try await smbIssue102AwaitWithTimeout("gate queue drains after C is acquired") {
            try await queuedSends.wait(untilEqual: 0)
        }
        fake.completeSend(at: 2)
        try await smbIssue102AwaitWithTimeout("C completes") { try await nextWaiter.value }
        XCTAssertEqual(fake.cancelCount, 0)
    }

    func testQueuedCancellationRacingGateReleaseStillReleasesNextWaiter() async throws {
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
        let holder = Task { try await transport.send([1]) }
        try await smbIssue102AwaitWithTimeout("A enqueued before release race") {
            try await sends.wait(atLeast: 1)
        }
        let cancelledWaiter = Task { try await transport.send([2]) }
        try await smbIssue102AwaitWithTimeout("B queued before release race") {
            try await queuedSends.wait(untilEqual: 1)
        }
        let nextWaiter = Task { try await transport.send([3]) }
        try await smbIssue102AwaitWithTimeout("C queued before release race") {
            try await queuedSends.wait(untilEqual: 2)
        }

        let startBarrier = NWTransportTestStartBarrier(participantCount: 2)
        await withTaskGroup(of: Void.self) { group in
            group.addTask {
                await startBarrier.wait()
                fake.completeSend(at: 0)
            }
            group.addTask {
                await startBarrier.wait()
                cancelledWaiter.cancel()
            }
            await group.waitForAll()
        }

        try await smbIssue102AwaitWithTimeout("A succeeds after racing release") { try await holder.value }
        do {
            try await smbIssue102AwaitWithTimeout("B settles after racing cancellation") {
                try await cancelledWaiter.value
            }
            XCTFail("B should remain cancelled whichever actor event wins")
        } catch is CancellationError {
        }
        try await smbIssue102AwaitWithTimeout("C enqueued after release/cancel race") {
            try await sends.wait(atLeast: 2)
        }
        XCTAssertEqual(fake.snapshots.map(\.bytes), [[1], [3]])
        XCTAssertEqual(fake.cancelCount, 0)
        fake.completeSend(at: 1)
        try await smbIssue102AwaitWithTimeout("C completes after release/cancel race") {
            try await nextWaiter.value
        }
    }

    func testCloseReconnectDoesNotMoveQueuedOldFrameToNewConnection() async throws {
        let queuedSends = NWTransportTestCounter()
        let oldSends = NWTransportTestCounter()
        let oldConnection = FakeNWConnection(sendCount: oldSends, holdCancelCallbacks: true)
        let newConnection = FakeNWConnection(autoCompleteSends: true)
        let sequence = FakeNWConnectionSequence([oldConnection, newConnection])
        let transport = NWConnectionTransport(
            connectionFactory: { _, _, _ in sequence.next() },
            queuedSendCountChanged: { queuedSends.set($0) }
        )
        defer {
            transport.close()
            queuedSends.reset()
            oldSends.reset()
        }

        try await transport.connect(host: "old-server", port: 445)
        let holder = Task { try await transport.send([1]) }
        try await smbIssue102AwaitWithTimeout("old-connection holder enqueued") {
            try await oldSends.wait(atLeast: 1)
        }
        let queuedOldFrame = Task { try await transport.send([[9], [10]]) }
        try await smbIssue102AwaitWithTimeout("old frame waits behind old holder") {
            try await queuedSends.wait(untilEqual: 1)
        }

        transport.close()
        XCTAssertTrue(oldConnection.isCancelled)
        try await transport.connect(host: "new-server", port: 445)
        oldConnection.deliverCancelledSends()

        do {
            try await smbIssue102AwaitWithTimeout("old holder receives cancellation error") { try await holder.value }
            XCTFail("old holder should fail after its connection closes")
        } catch let error as NWError {
            XCTAssertEqual(error, .posix(.ECANCELED))
        }
        do {
            try await smbIssue102AwaitWithTimeout("queued old frame rejects new connection") {
                try await queuedOldFrame.value
            }
            XCTFail("frame captured on the old connection must not be sent on the new connection")
        } catch SMBTransportError.connectionClosed {
        }
        XCTAssertTrue(newConnection.snapshots.isEmpty)
        XCTAssertEqual(newConnection.cancelCount, 0)
    }
}

final class NWConnectionTransportLoopbackTests: XCTestCase {
    func testPublicAdapterWritesCompleteConcurrentFramesWithoutClosingPeerDirection() async throws {
        let server: LoopbackNWServer
        do {
            server = try LoopbackNWServer(echo: false)
        } catch {
            throw XCTSkip("NWListener could not be created in this environment: \(error)")
        }
        do {
            try await smbIssue102AwaitWithTimeout("start real NWListener") {
                try await server.start()
            }
        } catch {
            server.stop()
            throw XCTSkip("NWListener could not start in this environment: \(error)")
        }
        defer { server.stop() }

        let transport = NWConnectionTransport()
        defer { transport.close() }
        try await smbIssue102AwaitWithTimeout("connect public NWConnectionTransport initializer") {
            try await transport.connect(host: "127.0.0.1", port: server.port)
        }
        _ = try await smbIssue102AwaitWithTimeout("accept loopback transport connection") {
            await server.waitForConnection()
        }

        let frameA = [[UInt8](arrayLiteral: 0, 0, 0, 5, 0xFE, 0x53, 0x4D, 0x42, 0xA1)]
        let frameB = [[UInt8](arrayLiteral: 0, 0, 0, 5), [0xFE, 0x53, 0x4D, 0x42], [0xB2]]
        let frameC = [[UInt8](arrayLiteral: 0, 0, 0, 5), [0xFE, 0x53, 0x4D, 0x42], [0xC3]]
        let bytesA = frameA.flatMap { $0 }
        let bytesB = frameB.flatMap { $0 }
        let bytesC = frameC.flatMap { $0 }

        try await smbIssue102AwaitWithTimeout("send first segmented frame over real NWConnection") {
            try await transport.send(frameA)
        }
        let receivedA = try await smbIssue102AwaitWithTimeout("peer reads first complete frame") {
            await server.waitForReceivedBytes(atLeast: bytesA.count)
        }
        XCTAssertEqual(receivedA, bytesA, "peer must receive both the frame header and every payload segment")
        try await Task.sleep(for: .milliseconds(200))
        let allAfterA = await server.receivedBytes()
        XCTAssertEqual(allAfterA, bytesA)
        let closedAfterFirstFrame = await server.didPeerCloseSendDirection()
        XCTAssertFalse(closedAfterFirstFrame, "first frame must not send TCP FIN")

        let sendResults = try await smbIssue102AwaitWithTimeout(
            "send two more segmented frames concurrently",
            timeout: .seconds(8)
        ) {
            await withTaskGroup(of: String.self) { group in
                group.addTask {
                    do {
                        try await smbIssue102AwaitWithTimeout("concurrent frame B completion", timeout: .seconds(4)) {
                            try await transport.send(frameB)
                        }
                        return "B succeeded"
                    } catch {
                        return "B failed: \(error)"
                    }
                }
                group.addTask {
                    do {
                        try await smbIssue102AwaitWithTimeout("concurrent frame C completion", timeout: .seconds(4)) {
                            try await transport.send(frameC)
                        }
                        return "C succeeded"
                    } catch {
                        return "C failed: \(error)"
                    }
                }
                var values: [String] = []
                for await value in group { values.append(value) }
                return values
            }
        }
        XCTAssertEqual(Set(sendResults), ["B succeeded", "C succeeded"])
        let expectedBC = bytesA + bytesB + bytesC
        let expectedCB = bytesA + bytesC + bytesB
        _ = try await smbIssue102AwaitWithTimeout("peer reads both concurrent frames completely") {
            await server.waitForReceivedBytes(atLeast: expectedBC.count)
        }
        try await Task.sleep(for: .milliseconds(200))
        let receivedAll = await server.receivedBytes()
        XCTAssertTrue(
            receivedAll == expectedBC || receivedAll == expectedCB,
            "peer bytes must equal whole header+payload frames in either serialized order; got \(receivedAll)"
        )
        let closedAfterConcurrentFrames = await server.didPeerCloseSendDirection()
        XCTAssertFalse(closedAfterConcurrentFrames, "sending multiple frames must leave the stream open")
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
    private var cancelledSendCompletions: [@Sendable (NWError?) -> Void] = []
    private var batchInvocationCount = 0
    private var cancellationCount = 0
    private var cancelled = false
    private var startQueue: DispatchQueue?
    private let sendCount: NWTransportTestCounter?
    private let holdCancelCallbacks: Bool
    private let autoCompleteSends: Bool

    init(
        sendCount: NWTransportTestCounter? = nil,
        holdCancelCallbacks: Bool = false,
        autoCompleteSends: Bool = false
    ) {
        self.sendCount = sendCount
        self.holdCancelCallbacks = holdCancelCallbacks
        self.autoCompleteSends = autoCompleteSends
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

    var isCancelled: Bool { lock.withLock { cancelled } }

    func start(queue: DispatchQueue) {
        lock.withLock { startQueue = queue }
        queue.async { [weak self] in self?.stateUpdateHandler?(.ready) }
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
        let result = lock.withLock { () -> (count: Int, rejected: Bool) in
            let rejected = cancelled
            pendingSends.append(
                PendingSend(
                    snapshot: NWTransportSendSnapshot(
                        bytes: Array(data),
                        context: contentContext,
                        isComplete: isComplete
                    ),
                    completion: rejected ? nil : completion
                )
            )
            return (pendingSends.count, rejected)
        }
        sendCount?.set(result.count)
        if result.rejected {
            DispatchQueue.global().async { completion(.posix(.ECANCELED)) }
        } else if autoCompleteSends {
            DispatchQueue.global().async { [weak self] in self?.completeSend(at: result.count - 1) }
        }
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
        let result = lock.withLock { () -> ([ @Sendable (NWError?) -> Void], DispatchQueue?) in
            cancellationCount += 1
            cancelled = true
            var callbacks: [@Sendable (NWError?) -> Void] = []
            for index in pendingSends.indices {
                if let callback = pendingSends[index].completion {
                    callbacks.append(callback)
                    pendingSends[index].completion = nil
                }
            }
            if holdCancelCallbacks {
                cancelledSendCompletions.append(contentsOf: callbacks)
                callbacks.removeAll()
            }
            return (callbacks, startQueue)
        }
        if !result.0.isEmpty {
            DispatchQueue.global().async { result.0.forEach { $0(.posix(.ECANCELED)) } }
        }
        result.1?.async { [weak self] in self?.stateUpdateHandler?(.cancelled) }
    }

    func deliverCancelledSends() {
        let callbacks = lock.withLock { () -> [@Sendable (NWError?) -> Void] in
            defer { cancelledSendCompletions.removeAll() }
            return cancelledSendCompletions
        }
        DispatchQueue.global().async { callbacks.forEach { $0(.posix(.ECANCELED)) } }
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

private final class FakeNWConnectionSequence: @unchecked Sendable {
    private let lock = NSLock()
    private var connections: [FakeNWConnection]

    init(_ connections: [FakeNWConnection]) {
        self.connections = connections
    }

    func next() -> FakeNWConnection {
        lock.withLock { connections.removeFirst() }
    }
}

private actor NWTransportTestStartBarrier {
    private let participantCount: Int
    private var waiters: [CheckedContinuation<Void, Never>] = []

    init(participantCount: Int) {
        self.participantCount = participantCount
    }

    func wait() async {
        await withCheckedContinuation { continuation in
            waiters.append(continuation)
            guard waiters.count == participantCount else { return }
            let ready = waiters
            waiters.removeAll()
            ready.forEach { $0.resume() }
        }
    }
}

private final class NWTransportTestCounter: @unchecked Sendable {
    private struct Waiter {
        let target: Int
        let exact: Bool
        let continuation: CheckedContinuation<Void, Error>
    }

    private let lock = NSLock()
    private var value = 0
    private var waiters: [UUID: Waiter] = [:]

    func set(_ value: Int) {
        let continuations = lock.withLock { () -> [CheckedContinuation<Void, Error>] in
            self.value = value
            let ready = waiters.filter { waiter in
                waiter.value.exact ? value == waiter.value.target : value >= waiter.value.target
            }
            for key in ready.keys { waiters[key] = nil }
            return ready.map { $0.value.continuation }
        }
        continuations.forEach { $0.resume() }
    }

    func wait(atLeast target: Int) async throws {
        try await wait(for: target, exact: false)
    }

    func wait(untilEqual target: Int) async throws {
        try await wait(for: target, exact: true)
    }

    private func wait(for target: Int, exact: Bool) async throws {
        try Task.checkCancellation()
        let id = UUID()
        try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                let immediateResult: Result<Void, Error>? = lock.withLock {
                    if Task.isCancelled { return .failure(CancellationError()) }
                    if exact ? value == target : value >= target { return .success(()) }
                    waiters[id] = Waiter(target: target, exact: exact, continuation: continuation)
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
