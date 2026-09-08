import Foundation
import XCTest
@testable import SMBee

private let m1PollLimit = 50_000

private struct M1WaitError: Error, CustomStringConvertible {
    let label: String

    var description: String {
        "condition '\(label)' did not become true"
    }
}

private final class M1ResultBox<Value: Sendable>: @unchecked Sendable {
    private let lock = NSLock()
    private var storage: Result<Value, Error>?

    var result: Result<Value, Error>? {
        lock.withLock { storage }
    }

    func store(_ result: Result<Value, Error>) {
        lock.withLock {
            if storage == nil {
                storage = result
            }
        }
    }
}

private final class M1WireTransport: SMBTransport, @unchecked Sendable {
    private struct PendingReceive {
        let maxLength: Int
        let continuation: CheckedContinuation<[UInt8], Error>
    }

    private enum BlockedSendAction {
        case store
        case resume
        case cancel
    }

    private let lock = NSLock()
    private let blockFirstSend: Bool
    private var firstSend = true
    private var firstSendStartedStorage = false
    private var blockedSendContinuation: CheckedContinuation<Void, Error>?
    private var blockedSendReleaseRequested = false
    private var blockedSendCancellationRequested = false
    private var inbound: [UInt8] = []
    private var pendingReceive: PendingReceive?
    private var outboundStorage: [UInt8] = []
    private var receiveCallCountStorage = 0
    private var isClosed = false

    init(blockFirstSend: Bool = false) {
        self.blockFirstSend = blockFirstSend
    }

    var outbound: [UInt8] {
        lock.withLock { outboundStorage }
    }

    var didStartFirstSend: Bool {
        lock.withLock { firstSendStartedStorage }
    }

    var receiveCallCount: Int {
        lock.withLock { receiveCallCountStorage }
    }

    var inboundByteCount: Int {
        lock.withLock { inbound.count }
    }

    func connect(host: String, port: UInt16) async throws {
        try Task.checkCancellation()
        _ = host
        _ = port
        lock.withLock { isClosed = false }
    }

    func send(_ bytes: [UInt8]) async throws {
        try Task.checkCancellation()
        let shouldBlock = lock.withLock { () -> Bool in
            let isFirstSend = firstSend
            firstSend = false
            firstSendStartedStorage = true
            return blockFirstSend && isFirstSend
        }

        if shouldBlock {
            try await withTaskCancellationHandler {
                try await withCheckedThrowingContinuation { continuation in
                    let action = lock.withLock { () -> BlockedSendAction in
                        if blockedSendReleaseRequested {
                            return .resume
                        }
                        if blockedSendCancellationRequested || Task.isCancelled {
                            return .cancel
                        }
                        blockedSendContinuation = continuation
                        return .store
                    }
                    switch action {
                    case .store:
                        break
                    case .resume:
                        continuation.resume()
                    case .cancel:
                        continuation.resume(throwing: CancellationError())
                    }
                }
            } onCancel: {
                self.cancelBlockedSend()
            }
        }

        try Task.checkCancellation()
        if lock.withLock({ isClosed }) {
            throw SMBTransportError.connectionClosed
        }
        lock.withLock {
            outboundStorage.append(contentsOf: bytes)
        }
    }

    func receive(maxLength: Int) async throws -> [UInt8] {
        try await withTaskCancellationHandler {
            try Task.checkCancellation()
            return try await withCheckedThrowingContinuation { continuation in
                let action: Result<[UInt8], Error>?

                lock.lock()
                receiveCallCountStorage += 1
                if isClosed {
                    action = .failure(SMBTransportError.connectionClosed)
                } else if Task.isCancelled {
                    action = .failure(CancellationError())
                } else if !inbound.isEmpty {
                    let count = min(maxLength, inbound.count)
                    let chunk = Array(inbound.prefix(count))
                    inbound.removeFirst(count)
                    action = .success(chunk)
                } else {
                    pendingReceive = PendingReceive(maxLength: maxLength, continuation: continuation)
                    action = nil
                }
                lock.unlock()

                if let action {
                    continuation.resume(with: action)
                }
            }
        } onCancel: {
            self.cancelPendingReceive()
        }
    }

    func enqueueInbound(_ bytes: [UInt8]) {
        let receive: (CheckedContinuation<[UInt8], Error>, [UInt8])?

        lock.lock()
        inbound.append(contentsOf: bytes)
        if let pendingReceive {
            let count = min(pendingReceive.maxLength, inbound.count)
            let chunk = Array(inbound.prefix(count))
            inbound.removeFirst(count)
            self.pendingReceive = nil
            receive = (pendingReceive.continuation, chunk)
        } else {
            receive = nil
        }
        lock.unlock()

        if let (continuation, chunk) = receive {
            continuation.resume(returning: chunk)
        }
    }

    func releaseFirstSend() {
        let continuation = lock.withLock { () -> CheckedContinuation<Void, Error>? in
            blockedSendReleaseRequested = true
            let continuation = blockedSendContinuation
            blockedSendContinuation = nil
            return continuation
        }
        continuation?.resume()
    }

    func close() {
        let continuations = lock.withLock {
            () -> (
                CheckedContinuation<Void, Error>?,
                CheckedContinuation<[UInt8], Error>?
            ) in
            isClosed = true
            let send = blockedSendContinuation
            blockedSendContinuation = nil
            let receive = pendingReceive?.continuation
            pendingReceive = nil
            return (send, receive)
        }
        continuations.0?.resume(throwing: SMBTransportError.connectionClosed)
        continuations.1?.resume(throwing: SMBTransportError.connectionClosed)
    }

    private func cancelBlockedSend() {
        let continuation = lock.withLock { () -> CheckedContinuation<Void, Error>? in
            blockedSendCancellationRequested = true
            let continuation = blockedSendContinuation
            blockedSendContinuation = nil
            return continuation
        }
        continuation?.resume(throwing: CancellationError())
    }

    private func cancelPendingReceive() {
        let continuation = lock.withLock { () -> CheckedContinuation<[UInt8], Error>? in
            let continuation = pendingReceive?.continuation
            pendingReceive = nil
            return continuation
        }
        continuation?.resume(throwing: CancellationError())
    }
}

private func m1Start<Value: Sendable>(
    _ operation: @escaping @Sendable () async throws -> Value
) -> (Task<Void, Never>, M1ResultBox<Value>) {
    let result = M1ResultBox<Value>()
    let task = Task { @Sendable in
        do {
            result.store(.success(try await operation()))
        } catch {
            result.store(.failure(error))
        }
    }
    return (task, result)
}

private func m1WaitUntil(
    _ label: String,
    _ condition: @escaping @Sendable () -> Bool
) async throws {
    for _ in 0..<m1PollLimit {
        if condition() {
            return
        }
        try Task.checkCancellation()
        await Task.yield()
    }
    throw M1WaitError(label: label)
}

private func m1WaitForResult<Value: Sendable>(
    _ label: String,
    _ result: M1ResultBox<Value>
) async throws -> Result<Value, Error> {
    for _ in 0..<m1PollLimit {
        if let value = result.result {
            return value
        }
        try Task.checkCancellation()
        await Task.yield()
    }
    throw M1WaitError(label: label)
}

private func m1WaitForOutboundFrameCount(
    _ expectedCount: Int,
    transport: M1WireTransport
) async throws {
    try await m1WaitUntil("outbound frame count \(expectedCount)") {
        guard let frames = try? m1Unframed(transport.outbound) else { return false }
        return frames.count >= expectedCount
    }
}

private func m1WaitForReceiveCallCount(
    _ expectedCount: Int,
    transport: M1WireTransport
) async throws {
    try await m1WaitUntil("receive call count \(expectedCount)") {
        transport.receiveCallCount >= expectedCount
    }
}

private func m1WaitForInboundDrain(transport: M1WireTransport) async throws {
    try await m1WaitUntil("inbound wire bytes consumed") {
        transport.inboundByteCount == 0
    }
}

private func m1Framed(_ messages: [[UInt8]]) throws -> [UInt8] {
    try messages.reduce(into: []) { result, message in
        result.append(contentsOf: try DirectTCPFraming.frame(message))
    }
}

private func m1Unframed(_ bytes: [UInt8]) throws -> [[UInt8]] {
    var frames: [[UInt8]] = []
    var cursor = 0
    while cursor < bytes.count {
        guard cursor + 4 <= bytes.count else { throw SMBCodecError.truncated }
        let length = try DirectTCPFraming.length(from: Array(bytes[cursor..<(cursor + 4)]))
        let start = cursor + 4
        let end = start + length
        guard end <= bytes.count else { throw SMBCodecError.truncated }
        frames.append(Array(bytes[start..<end]))
        cursor = end
    }
    return frames
}

private func m1OutboundHeaders(_ transport: M1WireTransport) throws -> [SMB2Header] {
    try m1Unframed(transport.outbound).map(SMB2Header.decode)
}

private func m1Session(
    _ transport: M1WireTransport,
    initialCredits: UInt32 = 1
) -> SMBSession {
    SMBSession(
        host: "server",
        port: 445,
        credential: SMBCredential(username: "user", password: "pass"),
        transport: transport,
        signingKey: Array(repeating: UInt8(0x11), count: 16),
        initialCredits: initialCredits
    )
}

private func m1FileId() -> [UInt8] {
    [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
    ]
}

private func m1StatusResponse(
    status: UInt32 = SMB2Status.success,
    command: UInt16,
    messageId: UInt64,
    treeId: UInt32,
    credits: UInt16 = 1
) throws -> [UInt8] {
    try SMB2Header(
        status: status,
        command: command,
        credits: credits,
        messageId: messageId,
        treeId: treeId
    ).encode()
}

private func m1AsyncPendingResponse(
    command: UInt16,
    messageId: UInt64,
    asyncId: UInt64,
    credits: UInt16 = 1
) throws -> [UInt8] {
    var response = try SMB2Header.asyncHeader(
        status: SMB2Status.pending,
        command: command,
        credits: credits,
        messageId: messageId,
        asyncId: asyncId
    ).encode()
    response.append(contentsOf: [9, 0, 0, 0, 0, 0, 0, 0])
    return response
}

private func m1ReadResponse(
    _ payload: [UInt8],
    messageId: UInt64,
    treeId: UInt32,
    credits: UInt16 = 1
) throws -> [UInt8] {
    var response = try SMB2Header(
        command: SMB2Commands.read,
        credits: credits,
        messageId: messageId,
        treeId: treeId
    ).encode()
    response.append(contentsOf: [17, 0, 80, 0])
    response.append(contentsOf: [
        UInt8(payload.count & 0xff),
        UInt8((payload.count >> 8) & 0xff),
        UInt8((payload.count >> 16) & 0xff),
        UInt8((payload.count >> 24) & 0xff)
    ])
    response.append(contentsOf: Array(repeating: UInt8(0), count: 8))
    response.append(contentsOf: payload)
    return response
}

private func m1AsyncReadResponse(
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
    response.append(contentsOf: [17, 0, 80, 0])
    response.append(contentsOf: [
        UInt8(payload.count & 0xff),
        UInt8((payload.count >> 8) & 0xff),
        UInt8((payload.count >> 16) & 0xff),
        UInt8((payload.count >> 24) & 0xff)
    ])
    response.append(contentsOf: Array(repeating: UInt8(0), count: 8))
    response.append(contentsOf: payload)
    return response
}

private func m1AssertCancellation<Value: Sendable>(_ result: Result<Value, Error>) {
    switch result {
    case .success:
        XCTFail("cancelled operation unexpectedly completed")
    case .failure(let error):
        XCTAssertTrue(error is CancellationError, "expected CancellationError, got \(error)")
    }
}

final class SMBeeWireCharacterizationTests: XCTestCase {
    func testCancelBeforeSendCompletionEmitsNoWireCancelBeforeSendReturns() async throws {
        let transport = M1WireTransport(blockFirstSend: true)
        let session = m1Session(transport)
        let (readTask, result) = m1Start {
            try await session.readChunk(treeId: 0x3344, fileId: m1FileId(), offset: 0, length: 3)
        }
        defer {
            readTask.cancel()
            transport.releaseFirstSend()
        }

        try await m1WaitUntil("first request send started") {
            transport.didStartFirstSend
        }
        readTask.cancel()

        let cancellation = try await m1WaitForResult("cancelled pre-completion READ", result)
        m1AssertCancellation(cancellation)
        XCTAssertTrue(
            transport.outbound.isEmpty,
            "CANCEL and the request itself must not be visible before the first send completes"
        )

        transport.releaseFirstSend()
        try await m1WaitForOutboundFrameCount(2, transport: transport)
        let headers = try m1OutboundHeaders(transport)
        XCTAssertEqual(headers.map(\.command), [SMB2Commands.read, SMB2Commands.cancel])
        XCTAssertEqual(headers[1].messageId, headers[0].messageId)

        transport.enqueueInbound(try m1Framed([
            try m1ReadResponse([], messageId: headers[0].messageId, treeId: headers[0].treeId)
        ]))
        try await m1WaitForInboundDrain(transport: transport)
    }

    func testCancelAfterSendBeforeInterimSendsSyncCancel() async throws {
        let transport = M1WireTransport()
        let session = m1Session(transport)
        let (readTask, result) = m1Start {
            try await session.readChunk(treeId: 0x3344, fileId: m1FileId(), offset: 0, length: 3)
        }
        defer { readTask.cancel() }

        try await m1WaitForOutboundFrameCount(1, transport: transport)
        try await m1WaitForReceiveCallCount(1, transport: transport)
        let firstHeaders = try m1OutboundHeaders(transport)
        let readHeader = try XCTUnwrap(firstHeaders.first)

        readTask.cancel()
        try await m1WaitForOutboundFrameCount(2, transport: transport)
        let headers = try m1OutboundHeaders(transport)
        XCTAssertEqual(headers.count, 2)
        XCTAssertEqual(headers[0].command, SMB2Commands.read)
        XCTAssertEqual(headers[1].command, SMB2Commands.cancel)
        XCTAssertEqual(headers[1].messageId, readHeader.messageId)
        // MS-SMB2 §2.2.1.2: sync CANCEL uses TreeId 0 and correlates by MessageId.
        XCTAssertEqual(headers[1].treeId, 0)
        XCTAssertNil(headers[1].asyncId)
        XCTAssertFalse(headers[1].isAsync)

        let cancellation = try await m1WaitForResult("cancelled sync READ", result)
        m1AssertCancellation(cancellation)

        transport.enqueueInbound(try m1Framed([
            try m1StatusResponse(command: SMB2Commands.read, messageId: readHeader.messageId, treeId: readHeader.treeId)
        ]))
        try await m1WaitForInboundDrain(transport: transport)
    }

    func testCancelAfterInterimSendsAsyncCancel() async throws {
        let transport = M1WireTransport()
        let session = m1Session(transport)
        let asyncId: UInt64 = 0x5566_7788_0000_0001
        let (readTask, result) = m1Start {
            try await session.readChunk(treeId: 0x3344, fileId: m1FileId(), offset: 0, length: 3)
        }
        defer { readTask.cancel() }

        try await m1WaitForOutboundFrameCount(1, transport: transport)
        try await m1WaitForReceiveCallCount(1, transport: transport)
        let request = try XCTUnwrap(try m1OutboundHeaders(transport).first)

        transport.enqueueInbound(try m1Framed([
            try m1AsyncPendingResponse(
                command: SMB2Commands.read,
                messageId: request.messageId,
                asyncId: asyncId
            )
        ]))
        try await m1WaitForReceiveCallCount(3, transport: transport)

        readTask.cancel()
        try await m1WaitForOutboundFrameCount(2, transport: transport)
        let headers = try m1OutboundHeaders(transport)
        XCTAssertEqual(headers.count, 2)
        XCTAssertEqual(headers[0].command, SMB2Commands.read)
        XCTAssertEqual(headers[1].command, SMB2Commands.cancel)
        // MS-SMB2 §2.2.1.1 / §3.2.4.24: an async CANCEL carries the interim AsyncId.
        XCTAssertEqual(headers[1].messageId, request.messageId)
        XCTAssertTrue(headers[1].isAsync)
        XCTAssertEqual(headers[1].asyncId, asyncId)
        XCTAssertEqual(headers[1].treeId, 0)

        let cancellation = try await m1WaitForResult("cancelled async READ", result)
        m1AssertCancellation(cancellation)

        transport.enqueueInbound(try m1Framed([
            try m1AsyncReadResponse([], messageId: request.messageId, asyncId: asyncId)
        ]))
        try await m1WaitForInboundDrain(transport: transport)
    }

    func testLateFinalAfterCancelIsDroppedAndSessionRemainsUsable() async throws {
        let transport = M1WireTransport()
        let session = m1Session(transport)
        let (firstTask, firstResult) = m1Start {
            try await session.readChunk(treeId: 0x3344, fileId: m1FileId(), offset: 0, length: 3)
        }
        defer { firstTask.cancel() }

        try await m1WaitForOutboundFrameCount(1, transport: transport)
        try await m1WaitForReceiveCallCount(1, transport: transport)
        let firstRequest = try XCTUnwrap(try m1OutboundHeaders(transport).first)

        firstTask.cancel()
        try await m1WaitForOutboundFrameCount(2, transport: transport)
        let cancelledResult = try await m1WaitForResult("cancelled first READ", firstResult)
        m1AssertCancellation(cancelledResult)

        let headersAfterCancel = try m1OutboundHeaders(transport)
        XCTAssertEqual(headersAfterCancel.count, 2)
        XCTAssertEqual(headersAfterCancel[1].command, SMB2Commands.cancel)
        XCTAssertEqual(headersAfterCancel[1].messageId, firstRequest.messageId)

        transport.enqueueInbound(try m1Framed([
            try m1ReadResponse([0x6c, 0x61, 0x74, 0x65], messageId: firstRequest.messageId, treeId: firstRequest.treeId)
        ]))
        try await m1WaitForInboundDrain(transport: transport)
        XCTAssertEqual(try m1OutboundHeaders(transport).count, 2)

        let (secondTask, secondResult) = m1Start {
            try await session.readChunk(treeId: 0x3344, fileId: m1FileId(), offset: 3, length: 2)
        }
        defer { secondTask.cancel() }
        try await m1WaitForOutboundFrameCount(3, transport: transport)
        let headers = try m1OutboundHeaders(transport)
        XCTAssertEqual(headers.map(\.command), [SMB2Commands.read, SMB2Commands.cancel, SMB2Commands.read])
        let secondRequest = try XCTUnwrap(headers.last(where: { $0.command == SMB2Commands.read && $0.messageId != firstRequest.messageId }))

        transport.enqueueInbound(try m1Framed([
            try m1ReadResponse([0x6f, 0x6b], messageId: secondRequest.messageId, treeId: secondRequest.treeId)
        ]))
        let secondOutcome = try await m1WaitForResult("reused READ", secondResult)
        switch secondOutcome {
        case .success(let data):
            XCTAssertEqual(data, [0x6f, 0x6b])
        case .failure(let error):
            XCTFail("reused READ failed: \(error)")
        }
    }

    func testLiveRequestInterimThenFinalResumesOnceAtFinal() async throws {
        let transport = M1WireTransport()
        let session = m1Session(transport)
        let asyncId: UInt64 = 0xdead_beef_0000_0042
        let (readTask, result) = m1Start {
            try await session.readChunk(treeId: 0x3344, fileId: m1FileId(), offset: 0, length: 3)
        }
        defer { readTask.cancel() }

        try await m1WaitForOutboundFrameCount(1, transport: transport)
        try await m1WaitForReceiveCallCount(1, transport: transport)
        let request = try XCTUnwrap(try m1OutboundHeaders(transport).first)

        transport.enqueueInbound(try m1Framed([
            try m1AsyncPendingResponse(
                command: SMB2Commands.read,
                messageId: request.messageId,
                asyncId: asyncId
            )
        ]))
        try await m1WaitForReceiveCallCount(3, transport: transport)
        XCTAssertNil(result.result, "STATUS_PENDING must not resume the live READ")

        transport.enqueueInbound(try m1Framed([
            try m1AsyncReadResponse([0x61, 0x62, 0x63], messageId: request.messageId, asyncId: asyncId)
        ]))
        let outcome = try await m1WaitForResult("final async READ", result)
        switch outcome {
        case .success(let data):
            XCTAssertEqual(data, [0x61, 0x62, 0x63])
        case .failure(let error):
            XCTFail("live READ failed: \(error)")
        }
        XCTAssertEqual(try m1OutboundHeaders(transport).map(\.command), [SMB2Commands.read])
    }

    func testFutureReadResponseArrivingBeforeSendCompletesRequest() async throws {
        let transport = M1WireTransport(blockFirstSend: true)
        let session = m1Session(transport, initialCredits: 3)
        let (firstReadTask, firstResult) = m1Start {
            try await session.readChunk(treeId: 0x3344, fileId: m1FileId(), offset: 0, length: 3)
        }
        defer {
            firstReadTask.cancel()
            transport.releaseFirstSend()
        }

        try await m1WaitUntil("first request send started") {
            transport.didStartFirstSend
        }
        XCTAssertTrue(transport.outbound.isEmpty, "the first READ must still be blocked")

        let (secondReadTask, secondResult) = m1Start {
            try await session.readChunk(treeId: 0x3344, fileId: m1FileId(), offset: 3, length: 3)
        }
        defer { secondReadTask.cancel() }

        try await m1WaitForOutboundFrameCount(1, transport: transport)
        try await m1WaitForReceiveCallCount(1, transport: transport)

        // SMBSession starts message IDs at zero and advances by the one-credit charge of each
        // 3-byte READ. The blocked first READ is 0, the READ that starts the receive loop is 1,
        // and the next READ under test will deterministically use message ID 2.
        let futureReadMessageId: UInt64 = 2
        transport.enqueueInbound(try m1Framed([
            try m1ReadResponse([0x70, 0x72, 0x65], messageId: futureReadMessageId, treeId: 0x3344)
        ]))

        // Wait until the active receive loop has dispatched the future response as an orphan.
        try await m1WaitForReceiveCallCount(3, transport: transport)
        try await m1WaitForInboundDrain(transport: transport)

        transport.releaseFirstSend()
        try await m1WaitForOutboundFrameCount(2, transport: transport)

        let (futureReadTask, futureResult) = m1Start {
            try await session.readChunk(treeId: 0x3344, fileId: m1FileId(), offset: 6, length: 3)
        }
        defer { futureReadTask.cancel() }

        let outcome = try await m1WaitForResult("READ after pre-send response", futureResult)
        switch outcome {
        case .success(let data):
            XCTAssertEqual(data, [0x70, 0x72, 0x65])
        case .failure(let error):
            XCTFail("READ failed after pre-send response: \(error)")
        }
        let readMessageIds = try m1OutboundHeaders(transport)
            .filter { $0.command == SMB2Commands.read }
            .map(\.messageId)
            .sorted()
        XCTAssertEqual(readMessageIds, [0, 1, futureReadMessageId])

        transport.enqueueInbound(try m1Framed([
            try m1ReadResponse([0x66, 0x69, 0x72], messageId: 0, treeId: 0x3344),
            try m1ReadResponse([0x73, 0x65, 0x63], messageId: 1, treeId: 0x3344)
        ]))
        let firstOutcome = try await m1WaitForResult("first READ", firstResult)
        switch firstOutcome {
        case .success(let data):
            XCTAssertEqual(data, [0x66, 0x69, 0x72])
        case .failure(let error):
            XCTFail("first READ failed: \(error)")
        }
        let secondOutcome = try await m1WaitForResult("second READ", secondResult)
        switch secondOutcome {
        case .success(let data):
            XCTAssertEqual(data, [0x73, 0x65, 0x63])
        case .failure(let error):
            XCTFail("second READ failed: \(error)")
        }
        try await m1WaitForInboundDrain(transport: transport)
    }
}
