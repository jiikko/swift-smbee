import Foundation

#if canImport(Network)
import Network

protocol NWConnectionTransportConnection: AnyObject, Sendable {
    var stateUpdateHandler: (@Sendable (NWConnection.State) -> Void)? { get set }

    func start(queue: DispatchQueue)
    func batch(_ body: () -> Void)
    func sendData(
        _ data: Data,
        contentContext: NWConnection.ContentContext,
        isComplete: Bool,
        completion: @escaping @Sendable (NWError?) -> Void
    )
    func receive(
        minimumIncompleteLength: Int,
        maximumLength: Int,
        completion: @escaping @Sendable (Data?, Bool, NWError?) -> Void
    )
    func cancel()
}

typealias NWConnectionTransportFactory = @Sendable (
    NWEndpoint.Host,
    NWEndpoint.Port,
    NWParameters
) -> any NWConnectionTransportConnection

public final class NWConnectionTransport: SMBTransport, @unchecked Sendable {
    private let connectionLock = NSLock()
    private var connectionStorage: (any NWConnectionTransportConnection)?
    private let connectionFactory: NWConnectionTransportFactory
    private let queue = DispatchQueue(label: "dev.smbee.nwconnection")
    private let sendGate: NWConnectionSendGate

    private var connection: (any NWConnectionTransportConnection)? {
        get {
            connectionLock.lock()
            defer { connectionLock.unlock() }
            return connectionStorage
        }
        set {
            connectionLock.lock()
            connectionStorage = newValue
            connectionLock.unlock()
        }
    }

    private func takeConnection() -> (any NWConnectionTransportConnection)? {
        connectionLock.lock()
        let connection = connectionStorage
        connectionStorage = nil
        connectionLock.unlock()
        return connection
    }

    public convenience init() {
        self.init(
            connectionFactory: { host, port, parameters in
                NWConnectionTransportConnectionAdapter(
                    NWConnection(host: host, port: port, using: parameters)
                )
            },
            queuedSendCountChanged: nil
        )
    }

    init(
        connectionFactory: @escaping NWConnectionTransportFactory,
        queuedSendCountChanged: (@Sendable (Int) -> Void)? = nil
    ) {
        self.connectionFactory = connectionFactory
        sendGate = NWConnectionSendGate(queuedSendCountChanged: queuedSendCountChanged)
    }

    public func connect(host: String, port: UInt16) async throws {
        try Task.checkCancellation()

        let tcpOptions = NWProtocolTCP.Options()
        tcpOptions.noDelay = true
        let parameters = NWParameters(tls: nil, tcp: tcpOptions)
        let endpointPort = NWEndpoint.Port(rawValue: port)!
        let connection = connectionFactory(NWEndpoint.Host(host), endpointPort, parameters)
        self.connection = connection

        try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                let resumer = NWContinuationResumer<Void>()
                connection.stateUpdateHandler = { state in
                    switch state {
                    case .ready:
                        if resumer.resume(continuation, with: .success(())) {
                            connection.stateUpdateHandler = nil
                        }
                    case .failed(let error):
                        if resumer.resume(continuation, with: .failure(error)) {
                            connection.stateUpdateHandler = nil
                        }
                    case .cancelled:
                        if resumer.resume(continuation, with: .failure(CancellationError())) {
                            connection.stateUpdateHandler = nil
                        }
                    default:
                        break
                    }
                }
                connection.start(queue: queue)
            }
        } onCancel: {
            connection.cancel()
        }

        try Task.checkCancellation()
    }

    public func send(_ bytes: [UInt8]) async throws {
        try await send([bytes])
    }

    public func send(_ segments: [[UInt8]]) async throws {
        try Task.checkCancellation()
        guard connection != nil else { throw SMBTransportError.connectionClosed }

        // DataProtocol also accepts DispatchData, but per-segment Data keeps each
        // Swift-owned buffer's lifetime explicit while retaining segment-level enqueue.
        let buffers = segments.compactMap { segment in
            segment.isEmpty ? nil : Data(segment)
        }
        guard !buffers.isEmpty else { return }

        try await sendGate.acquire()
        do {
            try Task.checkCancellation()
            guard let connection else { throw SMBTransportError.connectionClosed }
            try await sendFrame(buffers, on: connection)
            try Task.checkCancellation()
            await sendGate.release()
        } catch {
            await sendGate.release()
            throw error
        }
    }

    private func sendFrame(
        _ buffers: [Data],
        on connection: any NWConnectionTransportConnection
    ) async throws {
        let context = NWConnection.ContentContext(
            identifier: UUID().uuidString,
            isFinal: false
        )

        try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                let completion = NWBatchSendCompletion(
                    expectedCount: buffers.count,
                    continuation: continuation
                )
                connection.batch {
                    for index in buffers.indices {
                        connection.sendData(
                            buffers[index],
                            contentContext: context,
                            isComplete: index == buffers.index(before: buffers.endIndex)
                        ) { error in
                            completion.record(error)
                        }
                    }
                }
            }
        } onCancel: {
            connection.cancel()
        }
    }

    public func receive(maxLength: Int) async throws -> [UInt8] {
        try Task.checkCancellation()
        guard let connection else { throw SMBTransportError.connectionClosed }

        let bytes: [UInt8] = try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                let resumer = NWContinuationResumer<[UInt8]>()
                connection.receive(minimumIncompleteLength: 1, maximumLength: maxLength) { data, isComplete, error in
                    if let error {
                        resumer.resume(continuation, with: .failure(error))
                    } else if let data, !data.isEmpty {
                        resumer.resume(continuation, with: .success(Array(data)))
                    } else if isComplete {
                        resumer.resume(continuation, with: .failure(SMBTransportError.connectionClosed))
                    } else {
                        resumer.resume(continuation, with: .success([]))
                    }
                }
            }
        } onCancel: {
            connection.cancel()
        }

        try Task.checkCancellation()
        return bytes
    }

    public func close() {
        takeConnection()?.cancel()
    }
}

private final class NWConnectionTransportConnectionAdapter: NWConnectionTransportConnection, @unchecked Sendable {
    private let connection: NWConnection

    init(_ connection: NWConnection) {
        self.connection = connection
    }

    var stateUpdateHandler: (@Sendable (NWConnection.State) -> Void)? {
        get { connection.stateUpdateHandler }
        set { connection.stateUpdateHandler = newValue }
    }

    func start(queue: DispatchQueue) {
        connection.start(queue: queue)
    }

    func batch(_ body: () -> Void) {
        connection.batch(body)
    }

    func sendData(
        _ data: Data,
        contentContext: NWConnection.ContentContext,
        isComplete: Bool,
        completion: @escaping @Sendable (NWError?) -> Void
    ) {
        connection.send(
            content: data,
            contentContext: contentContext,
            isComplete: isComplete,
            completion: .contentProcessed(completion)
        )
    }

    func receive(
        minimumIncompleteLength: Int,
        maximumLength: Int,
        completion: @escaping @Sendable (Data?, Bool, NWError?) -> Void
    ) {
        connection.receive(
            minimumIncompleteLength: minimumIncompleteLength,
            maximumLength: maximumLength
        ) { data, _, isComplete, error in
            completion(data, isComplete, error)
        }
    }

    func cancel() {
        connection.cancel()
    }
}

private actor NWConnectionSendGate {
    private struct Waiter {
        let id: UUID
        let continuation: CheckedContinuation<Void, Error>
    }

    private var held = false
    private var waiters: [Waiter] = []
    private let queuedSendCountChanged: (@Sendable (Int) -> Void)?

    init(queuedSendCountChanged: (@Sendable (Int) -> Void)?) {
        self.queuedSendCountChanged = queuedSendCountChanged
    }

    func acquire() async throws {
        try Task.checkCancellation()
        guard held else {
            held = true
            return
        }

        let id = UUID()
        try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                waiters.append(Waiter(id: id, continuation: continuation))
                queuedSendCountChanged?(waiters.count)
            }
        } onCancel: {
            Task { await self.cancelWaiter(id) }
        }
    }

    func release() {
        guard !waiters.isEmpty else {
            held = false
            return
        }

        let next = waiters.removeFirst()
        queuedSendCountChanged?(waiters.count)
        next.continuation.resume()
    }

    private func cancelWaiter(_ id: UUID) {
        guard let index = waiters.firstIndex(where: { $0.id == id }) else { return }
        let waiter = waiters.remove(at: index)
        queuedSendCountChanged?(waiters.count)
        waiter.continuation.resume(throwing: CancellationError())
    }
}

private final class NWBatchSendCompletion: @unchecked Sendable {
    private let lock = NSLock()
    private var remaining: Int
    private var firstError: NWError?
    private var continuation: CheckedContinuation<Void, Error>?

    init(expectedCount: Int, continuation: CheckedContinuation<Void, Error>) {
        remaining = expectedCount
        self.continuation = continuation
    }

    func record(_ error: NWError?) {
        let completion: (CheckedContinuation<Void, Error>, Result<Void, Error>)? = lock.withLock {
            guard remaining > 0 else { return nil }
            if firstError == nil { firstError = error }
            remaining -= 1
            guard remaining == 0, let continuation else { return nil }
            self.continuation = nil
            if let firstError {
                return (continuation, .failure(firstError))
            }
            return (continuation, .success(()))
        }

        guard let completion else { return }
        completion.0.resume(with: completion.1)
    }
}

private final class NWContinuationResumer<Success: Sendable>: @unchecked Sendable {
    private let lock = NSLock()
    private var didResume = false

    @discardableResult
    func resume(_ continuation: CheckedContinuation<Success, Error>, with result: Result<Success, Error>) -> Bool {
        lock.lock()
        if didResume {
            lock.unlock()
            return false
        }
        didResume = true
        lock.unlock()

        switch result {
        case .success(let value):
            continuation.resume(returning: value)
        case .failure(let error):
            continuation.resume(throwing: error)
        }
        return true
    }
}
#endif
