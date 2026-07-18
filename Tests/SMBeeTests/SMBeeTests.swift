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

private struct SMBTestTimeoutError: Error, CustomStringConvertible {
    let label: String
    let seconds: Double
    var description: String { "test await '\(label)' timed out after \(seconds)s (likely wire-transaction ordering deadlock)" }
}

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

private var streamSocketType: Int32 {
    #if os(Linux)
    Int32(SOCK_STREAM.rawValue)
    #else
    Int32(SOCK_STREAM)
    #endif
}

private func saFamily(_ value: Int32) -> sa_family_t {
    sa_family_t(value)
}

private func closeFD(_ fd: Int32) {
    #if os(Linux)
    _ = Glibc.close(fd)
    #else
    _ = Darwin.close(fd)
    #endif
}

private final class POSIXLoopbackServer: @unchecked Sendable {
    enum Mode {
        case echoOnce
        case acceptAndHold
    }

    let port: UInt16
    private let listenFD: Int32
    private let mode: Mode
    private let lock = NSLock()
    private var acceptedFD: Int32 = -1

    init(mode: Mode) throws {
        self.mode = mode
        let listenDescriptor = socket(AF_INET, streamSocketType, Int32(IPPROTO_TCP))
        guard listenDescriptor >= 0 else { throw SMBTransportError.socketFailure("socket failed") }

        var reuse: Int32 = 1
        _ = setsockopt(
            listenDescriptor,
            SOL_SOCKET,
            SO_REUSEADDR,
            &reuse,
            socklen_t(MemoryLayout<Int32>.size)
        )

        var address = sockaddr_in()
        address.sin_family = saFamily(AF_INET)
        address.sin_port = 0
        address.sin_addr = in_addr(s_addr: inet_addr("127.0.0.1"))

        let bindResult = withUnsafePointer(to: &address) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockaddrPointer in
                bind(listenDescriptor, sockaddrPointer, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        guard bindResult == 0 else {
            closeFD(listenDescriptor)
            throw SMBTransportError.socketFailure("bind failed")
        }
        guard listen(listenDescriptor, 1) == 0 else {
            closeFD(listenDescriptor)
            throw SMBTransportError.socketFailure("listen failed")
        }

        var boundAddress = sockaddr_in()
        var boundAddressLength = socklen_t(MemoryLayout<sockaddr_in>.size)
        let nameResult = withUnsafeMutablePointer(to: &boundAddress) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockaddrPointer in
                getsockname(listenDescriptor, sockaddrPointer, &boundAddressLength)
            }
        }
        guard nameResult == 0 else {
            closeFD(listenDescriptor)
            throw SMBTransportError.socketFailure("getsockname failed")
        }
        listenFD = listenDescriptor
        port = UInt16(bigEndian: boundAddress.sin_port)
    }

    func start() {
        DispatchQueue.global().async { [self] in
            let clientFD = accept(listenFD, nil, nil)
            guard clientFD >= 0 else { return }
            lock.lock()
            acceptedFD = clientFD
            lock.unlock()

            switch mode {
            case .echoOnce:
                var buffer = [UInt8](repeating: 0, count: 64)
                let bufferCount = buffer.count
                let count = buffer.withUnsafeMutableBytes { recv(clientFD, $0.baseAddress, bufferCount, 0) }
                if count > 0 {
                    _ = buffer.withUnsafeBytes { send(clientFD, $0.baseAddress, count, 0) }
                }
                closeAccepted()
            case .acceptAndHold:
                break
            }
        }
    }

    func close() {
        closeFD(listenFD)
        closeAccepted()
    }

    private func closeAccepted() {
        lock.lock()
        let descriptor = acceptedFD
        acceptedFD = -1
        lock.unlock()
        if descriptor >= 0 { closeFD(descriptor) }
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
        var maxLength: Int
        var continuation: CheckedContinuation<[UInt8], Error>
    }

    private let lock = NSLock()
    private var inbound: [UInt8] = []
    private var pending: PendingReceive?
    private var outboundStorage: [UInt8] = []

    var outbound: [UInt8] {
        lock.lock()
        defer { lock.unlock() }
        return outboundStorage
    }

    func connect(host: String, port: UInt16) async throws {
        try Task.checkCancellation()
        _ = host
        _ = port
    }

    func send(_ bytes: [UInt8]) async throws {
        try Task.checkCancellation()
        appendOutbound(bytes)
    }

    private func appendOutbound(_ bytes: [UInt8]) {
        lock.lock()
        outboundStorage.append(contentsOf: bytes)
        lock.unlock()
    }

    func receive(maxLength: Int) async throws -> [UInt8] {
        try Task.checkCancellation()
        return try await withCheckedThrowingContinuation { continuation in
            let chunk: [UInt8]?

            lock.lock()
            if inbound.isEmpty {
                pending = PendingReceive(maxLength: maxLength, continuation: continuation)
                chunk = nil
            } else {
                let count = min(maxLength, inbound.count)
                chunk = Array(inbound.prefix(count))
                inbound.removeFirst(count)
            }
            lock.unlock()

            if let chunk {
                continuation.resume(returning: chunk)
            }
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

    func close() {}
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
private final class LoopbackNWServer: @unchecked Sendable {
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

    func stop() {
        listener.cancel()
        Task { await state.cancelConnections() }
    }

    private func accept(_ connection: NWConnection) {
        Task { await state.accept(connection) }
        connection.start(queue: queue)
        if echo {
            receiveAndEcho(connection)
        }
    }

    private func receiveAndEcho(_ connection: NWConnection) {
        connection.receive(minimumIncompleteLength: 1, maximumLength: 65_536) { [weak self] data, _, isComplete, error in
            guard let self, error == nil, !isComplete else { return }
            if let data, !data.isEmpty {
                connection.send(content: data, completion: .contentProcessed { _ in
                    self.receiveAndEcho(connection)
                })
            } else {
                self.receiveAndEcho(connection)
            }
        }
    }
}

private actor LoopbackNWServerState {
    private var connections: [NWConnection] = []
    private var pendingConnectionWaiter: CheckedContinuation<NWConnection, Never>?

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
            try smb2EchoResponse(messageId: requestHeader.messageId + 1),
        ]))

        try await session.echo()
        XCTAssertFalse(transport.didObserveSendCancellation)
    }

    func testInMemoryTransportSupportsConcurrentSendAndReceive() async throws {
        let bytes = Array(UInt8(0)..<UInt8(128))
        let transport = InMemoryTransport(inbound: bytes)

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
            FailingConnectTransport(failure: SMBTransportError.connectionClosed),
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
            smb2StatusResponse(status: SMB2Status.logonFailure, command: SMB2Commands.sessionSetup, messageId: 1, treeId: 0),
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
            negotiateResponse(messageId: 0, dialect: SMBNegotiateConstants.dialect210),
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

    func testCredentialProviderIsResolvedOnceWhenConnectingPersistentSession() async throws {
        let inbound = try framed([
            negotiateResponse(messageId: 0),
            sessionSetupChallengeResponse(messageId: 1, sessionId: 0x1122_3344_5566_7788),
            smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.sessionSetup, messageId: 2, treeId: 0),
            smb2TreeConnectResponse(treeId: 0x3344, shareType: 1, shareFlags: 0, capabilities: 0, maximalAccess: 0x001f_01ff),
        ])
        let transport = InMemoryTransport(inbound: inbound)
        let providerCalls = LockedCounter()

        let session = try await SMBClient.connect(
            host: "server",
            share: "share",
            credentialProvider: {
                providerCalls.increment()
                return SMBCredential(username: "provider-user", password: "provider-pass", domain: "provider-domain")
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
        XCTAssertEqual(String(decoding: readSecurityBuffer(type1, at: 16), as: UTF8.self), "PROVIDER-DOMAIN")
    }

    func testCredentialProviderIsResolvedOnceForOneShotStat() async throws {
        let fileId = hexBytes("00112233445566778899aabbccddeeff")
        let inbound = try framed([
            negotiateResponse(messageId: 0),
            sessionSetupChallengeResponse(messageId: 1, sessionId: 0x1122_3344_5566_7788),
            smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.sessionSetup, messageId: 2, treeId: 0),
            smb2TreeConnectResponse(treeId: 0x3344, shareType: 1, shareFlags: 0, capabilities: 0, maximalAccess: 0x001f_01ff),
            smb2CreateResponse(fileId: fileId, messageId: 4, treeId: 0x3344),
            smb2QueryInfoResponse(size: 7, messageId: 5, treeId: 0x3344),
            smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.close, messageId: 6, treeId: 0x3344),
            smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.treeDisconnect, messageId: 7, treeId: 0x3344),
            smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.logoff, messageId: 8, treeId: 0),
        ])
        let transport = InMemoryTransport(inbound: inbound)
        let providerCalls = LockedCounter()

        let stat = try await SMBClient.stat(
            host: "server",
            share: "share",
            path: "known.txt",
            credentialProvider: {
                providerCalls.increment()
                return SMBCredential(username: "one-shot-user", password: "one-shot-pass", domain: "one-shot-domain")
            },
            makeTransport: { transport }
        )

        XCTAssertEqual(stat.size, 7)
        XCTAssertEqual(providerCalls.value, 1)
        let requests = try unframed(transport.outbound)
        XCTAssertGreaterThanOrEqual(requests.count, 3)
        let type1 = try SPNEGO.unwrapNTLMToken(Array(requests[1][88..<requests[1].count]))
        XCTAssertEqual(String(decoding: readSecurityBuffer(type1, at: 16), as: UTF8.self), "ONE-SHOT-DOMAIN")
    }

    func testSMBeeFacadeStatUsesTransportOverride() async throws {
        let fileId = hexBytes("00112233445566778899aabbccddeeff")
        let transport = InMemoryTransport(inbound: try framed(authenticatedTreeResponses() + [
            smb2CreateResponse(fileId: fileId, messageId: 4, treeId: 0x3344),
            smb2QueryInfoResponse(size: 7, messageId: 5, treeId: 0x3344),
            smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.close, messageId: 6, treeId: 0x3344),
            smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.treeDisconnect, messageId: 7, treeId: 0x3344),
            smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.logoff, messageId: 8, treeId: 0),
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
        XCTAssertEqual(requests.count, 9)
    }

    func testSMBeeFacadeCredentialProviderReadUsesTransportOverride() async throws {
        let fileId = hexBytes("00112233445566778899aabbccddeeff")
        let transport = InMemoryTransport(inbound: try framed(authenticatedTreeResponses() + [
            smb2CreateResponse(fileId: fileId, messageId: 4, treeId: 0x3344),
            smb2QueryInfoResponse(size: 5, messageId: 5, treeId: 0x3344),
            smb2ReadResponse(Array("hello".utf8), messageId: 6, treeId: 0x3344),
            smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.close, messageId: 7, treeId: 0x3344),
            smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.treeDisconnect, messageId: 8, treeId: 0x3344),
            smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.logoff, messageId: 9, treeId: 0),
        ]))
        SMBTransportTestOverride.factory = { transport }
        defer { SMBTransportTestOverride.factory = nil }
        let providerCalls = LockedCounter()

        let data = try await SMBee.read(
            host: "server",
            credentialProvider: {
                providerCalls.increment()
                return SMBCredential(username: "provider-user", password: "provider-pass")
            },
            share: "share",
            path: "hello.txt"
        )

        XCTAssertEqual(data, Array("hello".utf8))
        XCTAssertEqual(providerCalls.value, 1)
        let requests = try unframed(transport.outbound)
        XCTAssertEqual(requests.count, 10)
    }

    func testSMBeeFacadeListStreamsDirectoryEntriesUsingTransportOverride() async throws {
        let fileId = hexBytes("00112233445566778899aabbccddeeff")
        let transport = InMemoryTransport(inbound: try framed(authenticatedTreeResponses() + [
            smb2CreateResponse(fileId: fileId, messageId: 4, treeId: 0x3344),
            smb2QueryDirectoryResponse(entries: [
                makeDirectoryEntry(name: "a.txt", isDirectory: false, fileSize: 1, nextOffset: 0),
            ], messageId: 5, treeId: 0x3344),
            smb2StatusResponse(status: SMB2Status.noMoreFiles, command: SMB2Commands.queryDirectory, messageId: 6, treeId: 0x3344),
            smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.close, messageId: 7, treeId: 0x3344),
            smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.treeDisconnect, messageId: 8, treeId: 0x3344),
            smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.logoff, messageId: 9, treeId: 0),
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
        secondTransport.enqueueInbound(try framed(authenticatedTreeResponses() + [
            smb2CreateResponse(fileId: fileId, messageId: 4, treeId: 0x3344),
            smb2ChangeNotifyResponse(
                entries: [makeFileNotifyEntry(action: 1, name: "created.txt", nextOffset: 0)],
                messageId: 5,
                treeId: 0x3344
            ),
        ]))
        let factory = TransportFactorySequence([
            InMemoryTransport(inbound: try framed(authenticatedTreeResponses() + [
                smb2CreateResponse(fileId: fileId, messageId: 4, treeId: 0x3344),
            ])),
            secondTransport,
        ])
        SMBTransportTestOverride.factory = factory.make
        defer { SMBTransportTestOverride.factory = nil }

        let session = try await SMBee.connect(host: "server", credential: .anonymous, share: "share")
        let events = ChangeNotifyEventAccumulator()
        let watcher = Task {
            try await session.withChangeNotifications(path: "dir", autoReconnect: true) { event in
                await events.record(event)
            }
        }

        var sawAdded = false
        for _ in 0..<80 {
            if await events.containsChange(named: "created.txt") {
                sawAdded = true
                break
            }
            try await Task.sleep(nanoseconds: 25_000_000)
        }
        watcher.cancel()
        // Not calling session.close(): graceful teardown would await TREE_DISCONNECT/LOGOFF
        // replies that the parked mock transport never sends. The watcher task is cancelled;
        // its leaked parked receive is acceptable in a unit test.

        XCTAssertTrue(sawAdded, "expected the ADDED notification after reconnect")
        // Reconnect built a second transport, and an overflow was emitted before resubscribe.
        XCTAssertEqual(factory.makeCount, 2)
        let sawOverflow = await events.sawOverflow
        XCTAssertTrue(sawOverflow, "expected an overflow (full rescan) signal after reconnect")
    }

    func testSMBeeFacadeMutatingOperationsUseTransportOverride() async throws {
        let fileId = hexBytes("00112233445566778899aabbccddeeff")
        let factory = TransportFactorySequence([
            InMemoryTransport(inbound: try framed(authenticatedTreeResponses() + [
                smb2CreateResponse(fileId: fileId, messageId: 4, treeId: 0x3344),
                smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.close, messageId: 5, treeId: 0x3344),
                smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.treeDisconnect, messageId: 6, treeId: 0x3344),
                smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.logoff, messageId: 7, treeId: 0),
            ])),
            InMemoryTransport(inbound: try framed(authenticatedTreeResponses() + [
                smb2CreateResponse(fileId: fileId, messageId: 4, treeId: 0x3344),
                smb2WriteResponse(count: 3, messageId: 5, treeId: 0x3344),
                smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.flush, messageId: 6, treeId: 0x3344),
                smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.close, messageId: 7, treeId: 0x3344),
                smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.treeDisconnect, messageId: 8, treeId: 0x3344),
                smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.logoff, messageId: 9, treeId: 0),
            ])),
            InMemoryTransport(inbound: try framed(authenticatedTreeResponses() + [
                smb2CreateResponse(fileId: fileId, messageId: 4, treeId: 0x3344),
                smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.setInfo, messageId: 5, treeId: 0x3344),
                smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.close, messageId: 6, treeId: 0x3344),
                smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.treeDisconnect, messageId: 7, treeId: 0x3344),
                smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.logoff, messageId: 8, treeId: 0),
            ])),
            InMemoryTransport(inbound: try framed(authenticatedTreeResponses() + [
                smb2CreateResponse(fileId: fileId, messageId: 4, treeId: 0x3344),
                smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.close, messageId: 5, treeId: 0x3344),
                smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.treeDisconnect, messageId: 6, treeId: 0x3344),
                smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.logoff, messageId: 7, treeId: 0),
            ])),
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
        let transport = InMemoryTransport(inbound: try framed(authenticatedTreeResponses() + [
            smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.treeDisconnect, messageId: 4, treeId: 0x3344),
            smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.logoff, messageId: 5, treeId: 0),
        ]))
        SMBTransportTestOverride.factory = { transport }
        defer { SMBTransportTestOverride.factory = nil }

        let session = try await SMBee.connect(
            host: "server",
            credential: SMBCredential(username: "user", password: "pass"),
            share: "share"
        )
        await session.close()

        // handshake (NEGOTIATE + SESSION_SETUP x2 + TREE_CONNECT) + best-effort teardown.
        XCTAssertEqual(try unframed(transport.outbound).count, 6)
    }

    func testSMBeeFacadeEchoUsesTransportOverrideAndTeardown() async throws {
        let transport = InMemoryTransport(inbound: try framed(authenticatedTreeResponses() + [
            smb2EchoResponse(messageId: 4),
            smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.treeDisconnect, messageId: 5, treeId: 0x3344),
            smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.logoff, messageId: 6, treeId: 0),
        ]))
        SMBTransportTestOverride.factory = { transport }
        defer { SMBTransportTestOverride.factory = nil }

        try await SMBee.echo(
            host: "server",
            credential: SMBCredential(username: "user", password: "pass"),
            share: "share"
        )

        let requests = try unframed(transport.outbound)
        XCTAssertEqual(requests.count, 7)
        // Requests after TREE_CONNECT are transform-encrypted in this fixture.
    }

    func testSMBeeFacadeReadlinkUsesTransportOverrideAndTeardown() async throws {
        let fileId = hexBytes("00112233445566778899aabbccddeeff")
        let transport = InMemoryTransport(inbound: try framed(authenticatedTreeResponses() + [
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
            smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.logoff, messageId: 8, treeId: 0),
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
        XCTAssertEqual(try unframed(transport.outbound).count, 9)
    }

    func testSMBeeFacadeWithDirectoryStreamUsesTransportOverride() async throws {
        let fileId = hexBytes("00112233445566778899aabbccddeeff")
        let transport = InMemoryTransport(inbound: try framed(authenticatedTreeResponses() + [
            smb2CreateResponse(fileId: fileId, messageId: 4, treeId: 0x3344),
            smb2QueryDirectoryResponse(entries: [
                makeDirectoryEntry(name: "a.txt", isDirectory: false, fileSize: 1, nextOffset: 0),
            ], messageId: 5, treeId: 0x3344),
            smb2StatusResponse(status: SMB2Status.noMoreFiles, command: SMB2Commands.queryDirectory, messageId: 6, treeId: 0x3344),
            smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.close, messageId: 7, treeId: 0x3344),
            smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.treeDisconnect, messageId: 8, treeId: 0x3344),
            smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.logoff, messageId: 9, treeId: 0),
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

        let transport = InMemoryTransport(inbound: try framed(authenticatedTreeResponses() + [
            smb2CreateResponse(fileId: fileId, messageId: 4, treeId: 0x3344),
            smb2QueryInfoResponse(payload: fullSize.bytes, messageId: 5),
            smb2QueryInfoResponse(payload: attribute.bytes, messageId: 6),
            smb2QueryInfoResponse(payload: volume.bytes, messageId: 7),
            smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.close, messageId: 8, treeId: 0x3344),
            smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.treeDisconnect, messageId: 9, treeId: 0x3344),
            smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.logoff, messageId: 10, treeId: 0),
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
        let transport = InMemoryTransport(inbound: try framed(authenticatedTreeResponses() + [
            smb2CreateResponse(fileId: fileId, messageId: 4, treeId: 0x3344),
            smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.setInfo, messageId: 5, treeId: 0x3344),
            smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.close, messageId: 6, treeId: 0x3344),
            smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.treeDisconnect, messageId: 7, treeId: 0x3344),
            smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.logoff, messageId: 8, treeId: 0),
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

        // NEGOTIATE + SESSION_SETUP x2 + TREE_CONNECT + CREATE + SET_INFO + CLOSE + teardown x2.
        // Requests are transform-encrypted so we assert the frame count, not decoded headers.
        XCTAssertEqual(try unframed(transport.outbound).count, 9)
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

        let transport = InMemoryTransport(inbound: try framed(authenticatedTreeResponses() + [
            smb2CreateResponse(fileId: fileId, messageId: 4, treeId: 0x3344),
            smb2QueryInfoResponse(payload: sd.bytes, messageId: 5),
            smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.close, messageId: 6, treeId: 0x3344),
            smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.treeDisconnect, messageId: 7, treeId: 0x3344),
            smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.logoff, messageId: 8, treeId: 0),
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
                .unlock(offset: 0x30, length: 0x40),
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
            messageId: 22,
            sessionId: 0x1122_3344,
            treeId: 0x5566_7788
        )

        let header = try SMB2Header.decode(request)
        XCTAssertEqual(header.command, SMB2Commands.cancel)
        XCTAssertEqual(header.messageId, 22)
        XCTAssertEqual(header.treeId, 0x5566_7788)
        XCTAssertEqual(header.sessionId, 0x1122_3344)
        XCTAssertEqual(request.count, 68)
        XCTAssertEqual(readUInt16LE(request, at: 64), 4)
        XCTAssertEqual(readUInt16LE(request, at: 66), 0)
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
        let window = SMB2CreditWindow(initialCredits: 1)

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
        let window = SMB2CreditWindow(initialCredits: 1)

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
        let window = SMB2CreditWindow(initialCredits: 0)
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
        let transport = InMemoryTransport(inbound: try framed(authenticatedTreeResponses() + [
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
            smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.close, messageId: 12, treeId: 0x3344),
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
            SMB2Ioctl.fsctlQueryAllocatedRanges,
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
            SMBAllocatedRange(offset: 8192, length: 4096),
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
        let window = SMB2CreditWindow(initialCredits: 0)
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
        let window = SMB2CreditWindow(initialCredits: 0)
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
        let window = SMB2CreditWindow(initialCredits: 1)

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
            0x01, 0x00, 0x00, 0x00,
        ]
        ack.append(contentsOf: [
            0xb8, 0x10, 0xb8, 0x10, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00,
            0x00, 0x00,
            0x01, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
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
            0x02, 0x00, 0x00, 0x00,
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
            ("media", 0, "Media share"),
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
            SMBShareInfo(name: "IPC$", type: 0x8000_0000, comment: "Remote IPC"),
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
            ),
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
            ),
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
                SMB2CopyChunkRange(sourceOffset: 4, targetOffset: 5, length: 6),
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
            ("media", 0, "Media share"),
        ])
        let split = stub.count / 2
        let firstFragment = try dcerpcResponsePDU(stub: Array(stub[..<split]), flags: DCERPC.pfcFirstFrag)
        let lastFragment = try dcerpcResponsePDU(stub: Array(stub[split...]), flags: DCERPC.pfcLastFrag)
        let inbound = try framed([
            try smb2IoctlResponse(output: firstFragment, status: SMB2Status.bufferOverflow, messageId: 0, treeId: 0x3344, fileId: fileId),
            try smb2ReadResponse(lastFragment, messageId: 1, treeId: 0x3344),
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
            Array("SESSION_SETUP response fixture".utf8),
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
        XCTAssertEqual(String(decoding: type1[40..<43], as: UTF8.self), "DOM")
        XCTAssertEqual(String(decoding: type1[43..<47], as: UTF8.self), "WKST")
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
            try smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.close, messageId: 2, treeId: 0x3344),
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
            smb2CreateResponse(fileId: fileId, messageId: 1, treeId: 0x3344),
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
                makeFileNotifyEntry(action: 2, name: "old.txt", nextOffset: 0),
            ],
            messageId: 12,
            treeId: 0x3344
        )

        let changes = try SMB2ChangeNotify.decodeResponse(response)

        XCTAssertEqual(changes, [
            SMBFileChange(action: .added, name: "new.txt"),
            SMBFileChange(action: .removed, name: "old.txt"),
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
            try smb2StatusResponse(status: SMB2Status.notifyEnumDir, command: SMB2Commands.changeNotify, messageId: 0, treeId: 0x3344),
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
        XCTAssertEqual(cancelHeader.treeId, changeHeader.treeId)

        transport.enqueueInbound(try framed([
            try smb2StatusResponse(
                status: SMB2Status.cancelled,
                command: SMB2Commands.changeNotify,
                messageId: changeHeader.messageId,
                treeId: changeHeader.treeId
            ),
        ]))

        do {
            try await awaitWithTimeout("cancel CHANGE_NOTIFY") {
                try await task.value
            }
            XCTFail("cancelled CHANGE_NOTIFY unexpectedly completed")
        } catch is CancellationError {
        }
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
        XCTAssertEqual(cancelHeader.treeId, readHeader.treeId)

        transport.enqueueInbound(try framed([
            try smb2StatusResponse(
                status: SMB2Status.cancelled,
                command: SMB2Commands.read,
                messageId: readHeader.messageId,
                treeId: readHeader.treeId
            ),
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
        first.cancel()
        try await waitForOutboundFrameCount(2, transport: transport)
        transport.enqueueInbound(try framed([smb2EchoResponse(messageId: firstHeader.messageId)]))

        do {
            try await awaitWithTimeout("cancelled ECHO") { try await first.value }
            XCTFail("cancelled ECHO unexpectedly completed")
        } catch is CancellationError {
        }

        let second = Task { try await session.echo() }
        try await waitForOutboundFrameCount(3, transport: transport)
        let secondHeader = try SMB2Header.decode(try unframed(transport.outbound)[2])
        transport.enqueueInbound(try framed([smb2EchoResponse(messageId: secondHeader.messageId)]))
        try await awaitWithTimeout("ECHO after cancelled ECHO") { try await second.value }
    }

    func testChangeNotifyEventConvenienceProperties() {
        let changes = [
            SMBFileChange(action: .added, name: "new.txt"),
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
                    makeDirectoryEntry(name: "a.txt", isDirectory: false, fileSize: 1, nextOffset: 0),
                ],
                messageId: 0,
                treeId: 0x3344
            ),
            try smb2QueryDirectoryResponse(
                entries: [
                    makeDirectoryEntry(name: "b", isDirectory: true, nextOffset: 0),
                ],
                messageId: 1,
                treeId: 0x3344
            ),
            try smb2StatusResponse(status: SMB2Status.noMoreFiles, command: SMB2Commands.queryDirectory, messageId: 2, treeId: 0x3344),
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
            SMBDirectoryEntry(name: "b", fileSize: 0, isDirectory: true, attributes: 0x10),
        ])
        let requests = try unframed(transport.outbound)
        XCTAssertEqual(requests.map { try? SMB2Header.decode($0).command }, [
            SMB2Commands.queryDirectory,
            SMB2Commands.queryDirectory,
            SMB2Commands.queryDirectory,
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
                    makeDirectoryEntry(name: "a.txt", isDirectory: false, fileSize: 7, nextOffset: 0),
                ],
                messageId: 1,
                treeId: 0x3344
            ),
            try smb2StatusResponse(status: SMB2Status.noMoreFiles, command: SMB2Commands.queryDirectory, messageId: 2, treeId: 0x3344),
            try smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.close, messageId: 3, treeId: 0x3344),
            try smb2CreateResponse(fileId: statFileId, messageId: 4, treeId: 0x3344),
            try smb2QueryInfoResponse(size: 7, messageId: 5, treeId: 0x3344),
            try smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.close, messageId: 6, treeId: 0x3344),
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
            SMB2Commands.close,
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
                    makeDirectoryEntry(name: "b.txt", isDirectory: false, fileSize: 9, nextOffset: 0),
                ],
                messageId: 2,
                treeId: 0x7788
            ),
            try smb2StatusResponse(status: SMB2Status.noMoreFiles, command: SMB2Commands.queryDirectory, messageId: 3, treeId: 0x7788),
            try smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.close, messageId: 4, treeId: 0x7788),
            try smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.treeDisconnect, messageId: 5, treeId: 0x7788),
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
            SMB2Commands.treeDisconnect,
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
            try smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.close, messageId: 4, treeId: 0x3344),
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

    func testClientSessionUploadEmitsTransferProgressPerChunk() async throws {
        let fileId = hexBytes("00112233445566778899aabbccddeeff")
        let inbound = try framed([
            try smb2CreateResponse(fileId: fileId, messageId: 0, treeId: 0x3344),
            try smb2WriteResponse(count: 65_537, messageId: 1, treeId: 0x3344),
            try smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.flush, messageId: 3, treeId: 0x3344),
            try smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.close, messageId: 4, treeId: 0x3344),
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

    func testClientSessionStreamingUploadWritesTempFileInChunks() async throws {
        let fileId = hexBytes("00112233445566778899aabbccddeeff")
        let firstChunkSize = 65_536 + 11
        let inbound = try framed([
            try smb2CreateResponse(fileId: fileId, messageId: 0, treeId: 0x3344),
            try smb2WriteResponse(count: firstChunkSize, messageId: 1, treeId: 0x3344),
            try smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.flush, messageId: 3, treeId: 0x3344),
            try smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.close, messageId: 4, treeId: 0x3344),
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
            SMB2Commands.close,
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
            try smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.close, messageId: 6, treeId: 0x3344),
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
            SMB2Commands.close,
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
            try smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.close, messageId: 3, treeId: 0x3344),
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
            SMB2Commands.create, SMB2Commands.queryInfo, SMB2Commands.read, SMB2Commands.close,
        ])
    }

    func testClientSessionStreamingUploadRejectsLocalSourceMutation() async throws {
        let fileId = hexBytes("00112233445566778899aabbccddeeff")
        let payload = Array(repeating: UInt8(0x41), count: 65_537)
        let inbound = try framed([
            try smb2CreateResponse(fileId: fileId, messageId: 0, treeId: 0x3344),
            try smb2WriteResponse(count: payload.count, messageId: 1, treeId: 0x3344),
            try smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.close, messageId: 3, treeId: 0x3344),
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
            SMB2Commands.create, SMB2Commands.write, SMB2Commands.close,
        ])
    }

    func testClientSessionStreamingUploadEmptyTempFileSendsNoWrite() async throws {
        let fileId = hexBytes("00112233445566778899aabbccddeeff")
        let inbound = try framed([
            try smb2CreateResponse(fileId: fileId, messageId: 0, treeId: 0x3344),
            try smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.flush, messageId: 1, treeId: 0x3344),
            try smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.close, messageId: 2, treeId: 0x3344),
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
            SMB2Commands.close,
        ])
    }

    func testClientSessionCloseSendsTreeDisconnectAndLogoff() async throws {
        let inbound = try framed([
            try smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.treeDisconnect, messageId: 0, treeId: 0x3344),
            try smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.logoff, messageId: 1, treeId: 0),
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
        let closeTask = Task { await clientSession.close() }

        // Release the in-flight ECHO only after close has had a chance to cancel it.
        try await Task.sleep(nanoseconds: 20_000_000)
        transport.enqueueInbound(try framed([smb2EchoResponse(messageId: 0)]))
        try await waitForOutboundFrameCount(2, transport: transport)
        let outboundAfterEcho = try unframed(transport.outbound)
        let teardownCount = outboundAfterEcho.filter {
            let command = try? SMB2Header.decode($0).command
            return command == SMB2Commands.treeDisconnect || command == SMB2Commands.logoff
        }.count
        XCTAssertEqual(teardownCount, 0)

        transport.enqueueInbound(try framed([
            smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.treeDisconnect, messageId: 1, treeId: 0x3344),
            smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.logoff, messageId: 2, treeId: 0),
        ]))
        try await awaitWithTimeout("close after in-flight keepalive") { await closeTask.value }

        let commands = try unframed(transport.outbound).map { try SMB2Header.decode($0).command }
        XCTAssertEqual(commands.filter { $0 != SMB2Commands.cancel }, [
            SMB2Commands.echo, SMB2Commands.treeDisconnect, SMB2Commands.logoff,
        ])
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
        try await Task.sleep(nanoseconds: 20_000_000)
        XCTAssertEqual(try unframed(transport.outbound).count, 1, "second ECHO should be parked on credits")
        second.cancel()
        do {
            _ = try await awaitWithTimeout("cancel parked ECHO") { try await second.value }
            XCTFail("cancelled parked ECHO unexpectedly completed")
        } catch is CancellationError {
        }

        transport.enqueueInbound(try framed([
            smb2EchoResponse(messageId: firstHeader.messageId, credits: 1),
        ]))
        try await awaitWithTimeout("first ECHO") { try await first.value }
        try await Task.sleep(nanoseconds: 50_000_000)
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
            capabilities: SMBTreeConnectConstants.shareCapEncryptData,
            maximalAccess: 0x001f_01ff
        )

        let parsed = try SMB2TreeConnect.decodeResponse(response)

        XCTAssertEqual(parsed.treeId, 0x3344)
        XCTAssertEqual(parsed.shareType, 1)
        XCTAssertEqual(parsed.shareFlags, SMBTreeConnectConstants.shareFlagEncryptData)
        XCTAssertEqual(parsed.capabilities, SMBTreeConnectConstants.shareCapEncryptData)
        XCTAssertTrue(parsed.encryptionRequired)
        XCTAssertEqual(parsed.maximalAccess, 0x001f_01ff)
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
            try smb2ReadResponse(Array("lo".utf8), messageId: 1, treeId: 0x3344),
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
        let response = try signedSMB2Packet(
            try smb2ReadResponse(Array("ok".utf8), messageId: 0, treeId: 0x3344),
            key: key,
            algorithm: .aesGMAC,
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
        let inbound = try framed([
            try smb2ReadResponse(Array("hel".utf8), messageId: 0, treeId: 0x3344),
        ])
        let transport = InMemoryTransport(inbound: inbound)
        let session = SMBSession(
            host: "server",
            port: 445,
            credential: SMBCredential(username: "user", password: "pass"),
            transport: transport,
            signingKey: Array(repeating: UInt8(0x11), count: 16)
        )
        let first = try await session.readChunk(treeId: 0x3344, fileId: fileId, offset: 0, length: 5)
        XCTAssertEqual(first, Array("hel".utf8))

        do {
            _ = try await session.readChunk(treeId: 0x3344, fileId: fileId, offset: 3, length: 2)
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
        let transport = InMemoryTransport(inbound: try framed([
            try smb2ReadResponse(Array("hel".utf8), messageId: 0, treeId: 0x3344),
        ]))
        let session = SMBSession(
            host: "server",
            port: 445,
            credential: SMBCredential(username: "user", password: "pass"),
            transport: transport,
            signingKey: Array(repeating: UInt8(0x11), count: 16)
        )

        _ = try await session.readChunk(treeId: 0x3344, fileId: fileId, offset: 0, length: 3)
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
            try smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.close, messageId: 10, treeId: 0x3344),
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
            SMB2Commands.close,
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
            try smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.close, messageId: 11, treeId: 0x3344),
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
            SMB2Commands.close,
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
            try smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.close, messageId: 8, treeId: 0x3344),
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
            SMB2Commands.close,
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
            try smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.close, messageId: 10, treeId: 0x3344),
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
            try smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.close, messageId: 5, treeId: 0x3344),
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
            try smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.close, messageId: 3, treeId: 0x3344),
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
                    makeDirectoryEntry(name: "a.txt", isDirectory: false, fileSize: 4, nextOffset: 0),
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
                    makeDirectoryEntry(name: "child", isDirectory: true, nextOffset: 0),
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
            try smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.close, messageId: 20, treeId: 0x3344),
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
            SMB2Commands.close,
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
            try smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.close, messageId: 16, treeId: 0x3344),
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
            try smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.close, messageId: 8, treeId: 0x3344),
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
            try smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.close, messageId: 9, treeId: 0x3344),
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
            try smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.close, messageId: 3, treeId: 0x3344),
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
            SMBRecursiveAction(kind: .copy, path: "dst\\a.txt"),
        ])
        let requests = try unframed(transport.outbound)
        XCTAssertEqual(requests.map { try? SMB2Header.decode($0).command }, [
            SMB2Commands.create,
            SMB2Commands.queryDirectory,
            SMB2Commands.queryDirectory,
            SMB2Commands.close,
        ])
    }

    func testSessionCopyDirectoryDryRunFiltersRecursiveFiles() async throws {
        let sourceRootId = hexBytes("00000000000000000000000000000051")
        let sourceChildId = hexBytes("00000000000000000000000000000052")
        let inbound = try framed([
            try smb2CreateResponse(fileId: sourceRootId, messageId: 0, treeId: 0x3344),
            try smb2QueryDirectoryResponse(entries: [
                makeDirectoryEntry(name: "keep.log", isDirectory: false, fileSize: 0, nextOffset: 128),
                makeDirectoryEntry(name: "skip.tmp", isDirectory: false, fileSize: 0, nextOffset: 256),
                makeDirectoryEntry(name: "nested", isDirectory: true, nextOffset: 0),
            ], messageId: 1, treeId: 0x3344),
            try smb2CreateResponse(fileId: sourceChildId, messageId: 2, treeId: 0x3344),
            try smb2QueryDirectoryResponse(entries: [
                makeDirectoryEntry(name: "child.log", isDirectory: false, fileSize: 0, nextOffset: 128),
                makeDirectoryEntry(name: "skip.log", isDirectory: false, fileSize: 0, nextOffset: 0),
            ], messageId: 3, treeId: 0x3344),
            try smb2StatusResponse(status: SMB2Status.noMoreFiles, command: SMB2Commands.queryDirectory, messageId: 4, treeId: 0x3344),
            try smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.close, messageId: 5, treeId: 0x3344),
            try smb2StatusResponse(status: SMB2Status.noMoreFiles, command: SMB2Commands.queryDirectory, messageId: 6, treeId: 0x3344),
            try smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.close, messageId: 7, treeId: 0x3344),
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
            SMBRecursiveAction(kind: .copy, path: "dst\\nested\\child.log"),
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
            SMBDebug.packetSummary(bytes, traceWire: false),
            "<redacted; set SMBEE_TRACE_WIRE=1 to dump raw packet hex>"
        )
        XCTAssertEqual(SMBDebug.packetSummary(bytes, traceWire: true), "00010203")
    }

    func testWriteChunkRangesCoverBoundarySizes() throws {
        let chunkSize = 4
        let cases: [(Int, [Range<Int>])] = [
            (0, []),
            (chunkSize - 1, [0..<3]),
            (chunkSize, [0..<4]),
            (chunkSize + 1, [0..<4, 4..<5]),
            (chunkSize * 2 + 1, [0..<4, 4..<8, 8..<9]),
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
            try smb2WriteResponse(count: 65_536, messageId: 1, treeId: 0x3344),
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
        let prefixTransport = InMemoryTransport(inbound: try framed(authenticatedTreeResponses() + [
            smb2CreateResponse(fileId: fileId, messageId: 4, treeId: 0x3344),
            smb2QueryInfoResponse(size: 11, messageId: 5, treeId: 0x3344),
            smb2ReadResponse(Array("hello ".utf8), messageId: 6, treeId: 0x3344),
            smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.close, messageId: 7, treeId: 0x3344),
            smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.treeDisconnect, messageId: 8, treeId: 0x3344),
            smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.logoff, messageId: 9, treeId: 0),
        ]))
        let resumeTransport = InMemoryTransport(inbound: try framed(authenticatedTreeResponses() + [
            smb2CreateResponse(fileId: fileId, messageId: 4, treeId: 0x3344),
            smb2QueryInfoResponse(size: 11, messageId: 5, treeId: 0x3344),
            smb2ReadResponse(Array("world".utf8), messageId: 6, treeId: 0x3344),
            smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.close, messageId: 7, treeId: 0x3344),
            smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.treeDisconnect, messageId: 8, treeId: 0x3344),
            smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.logoff, messageId: 9, treeId: 0),
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
        let listTransport = InMemoryTransport(inbound: try framed(authenticatedTreeResponses() + [
            smb2CreateResponse(fileId: directoryId, messageId: 4, treeId: 0x3344),
            smb2QueryDirectoryResponse(entries: [
                makeDirectoryEntry(name: "a.txt", isDirectory: false, fileSize: 5, nextOffset: 0),
            ], messageId: 5, treeId: 0x3344),
            smb2QueryDirectoryResponse(entries: [
                makeDirectoryEntry(name: "b.txt", isDirectory: false, fileSize: 4, nextOffset: 0),
            ], messageId: 6, treeId: 0x3344),
            smb2StatusResponse(status: SMB2Status.noMoreFiles, command: SMB2Commands.queryDirectory, messageId: 7, treeId: 0x3344),
            smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.close, messageId: 8, treeId: 0x3344),
            smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.treeDisconnect, messageId: 9, treeId: 0x3344),
            smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.logoff, messageId: 10, treeId: 0),
        ]))
        let firstTransport = InMemoryTransport(inbound: try framed(authenticatedTreeResponses() + [
            smb2CreateResponse(fileId: firstId, messageId: 4, treeId: 0x3344),
            smb2QueryInfoResponse(size: 5, messageId: 5, treeId: 0x3344),
            smb2ReadResponse(Array("alpha".utf8), messageId: 6, treeId: 0x3344),
            smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.close, messageId: 7, treeId: 0x3344),
            smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.treeDisconnect, messageId: 8, treeId: 0x3344),
            smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.logoff, messageId: 9, treeId: 0),
        ]))
        let secondTransport = InMemoryTransport(inbound: try framed(authenticatedTreeResponses() + [
            smb2CreateResponse(fileId: secondId, messageId: 4, treeId: 0x3344),
            smb2QueryInfoResponse(size: 4, messageId: 5, treeId: 0x3344),
            smb2ReadResponse(Array("beta".utf8), messageId: 6, treeId: 0x3344),
            smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.close, messageId: 7, treeId: 0x3344),
            smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.treeDisconnect, messageId: 8, treeId: 0x3344),
            smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.logoff, messageId: 9, treeId: 0),
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

    func testDownloadDirectoryAtomicFailurePreservesExistingDestinationAndRemovesStaging() async throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("smbee-unit-\(UUID().uuidString)")
        let destination = root.appendingPathComponent("downloaded")
        try FileManager.default.createDirectory(at: destination, withIntermediateDirectories: true)
        try Data("old".utf8).write(to: destination.appendingPathComponent("keep.txt"))
        defer { try? FileManager.default.removeItem(at: root) }
        let firstId = hexBytes("00112233445566778899aabbccddeeff")
        let secondId = hexBytes("102132435465768798a9babbdcddedef")
        let directoryId = hexBytes("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        let listTransport = InMemoryTransport(inbound: try framed(authenticatedTreeResponses() + [
            smb2CreateResponse(fileId: directoryId, messageId: 4, treeId: 0x3344),
            smb2QueryDirectoryResponse(entries: [
                makeDirectoryEntry(name: "ok.txt", isDirectory: false, fileSize: 2, nextOffset: 0),
            ], messageId: 5, treeId: 0x3344),
            smb2QueryDirectoryResponse(entries: [
                makeDirectoryEntry(name: "bad.txt", isDirectory: false, fileSize: 3, nextOffset: 0),
            ], messageId: 6, treeId: 0x3344),
            smb2StatusResponse(status: SMB2Status.noMoreFiles, command: SMB2Commands.queryDirectory, messageId: 7, treeId: 0x3344),
            smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.close, messageId: 8, treeId: 0x3344),
            smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.treeDisconnect, messageId: 9, treeId: 0x3344),
            smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.logoff, messageId: 10, treeId: 0),
        ]))
        let firstTransport = InMemoryTransport(inbound: try framed(authenticatedTreeResponses() + [
            smb2CreateResponse(fileId: firstId, messageId: 4, treeId: 0x3344),
            smb2QueryInfoResponse(size: 2, messageId: 5, treeId: 0x3344),
            smb2ReadResponse(Array("ok".utf8), messageId: 6, treeId: 0x3344),
            smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.close, messageId: 7, treeId: 0x3344),
            smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.treeDisconnect, messageId: 8, treeId: 0x3344),
            smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.logoff, messageId: 9, treeId: 0),
        ]))
        let secondTransport = InMemoryTransport(inbound: try framed(authenticatedTreeResponses() + [
            smb2CreateResponse(fileId: secondId, messageId: 4, treeId: 0x3344),
            smb2QueryInfoResponse(size: 3, messageId: 5, treeId: 0x3344),
            smb2StatusResponse(status: SMB2Status.accessDenied, command: SMB2Commands.read, messageId: 6, treeId: 0x3344),
            smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.close, messageId: 7, treeId: 0x3344),
            smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.treeDisconnect, messageId: 8, treeId: 0x3344),
            smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.logoff, messageId: 9, treeId: 0),
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
        let transport = InMemoryTransport(inbound: try framed(authenticatedTreeResponses() + [
            smb2CreateResponse(fileId: directoryId, messageId: 4, treeId: 0x3344),
            smb2QueryDirectoryResponse(entries: [
                makeDirectoryEntry(name: "planned.txt", isDirectory: false, fileSize: 7, nextOffset: 0),
            ], messageId: 5, treeId: 0x3344),
            smb2StatusResponse(status: SMB2Status.noMoreFiles, command: SMB2Commands.queryDirectory, messageId: 6, treeId: 0x3344),
            smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.close, messageId: 7, treeId: 0x3344),
            smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.treeDisconnect, messageId: 8, treeId: 0x3344),
            smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.logoff, messageId: 9, treeId: 0),
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
            makeTransport: { transport }
        ) { action in
            recorder.append(action)
        }

        XCTAssertFalse(FileManager.default.fileExists(atPath: destination.path))
        XCTAssertEqual(try atomicStagingDirectories(in: root, destinationName: "downloaded"), [])
        XCTAssertEqual(recorder.actions, [
            SMBRecursiveAction(kind: .mkdir, path: destination.path),
            SMBRecursiveAction(kind: .download, path: destination.appendingPathComponent("planned.txt").path),
        ])
    }

    func testDownloadDirectoryDryRunFiltersRecursiveFiles() async throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("smbee-unit-\(UUID().uuidString)")
        let destination = root.appendingPathComponent("downloaded")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let rootId = hexBytes("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        let nestedId = hexBytes("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
        let listRootTransport = InMemoryTransport(inbound: try framed(authenticatedTreeResponses() + [
            smb2CreateResponse(fileId: rootId, messageId: 4, treeId: 0x3344),
            smb2QueryDirectoryResponse(entries: [
                makeDirectoryEntry(name: "keep.log", isDirectory: false, fileSize: 1, nextOffset: 128),
                makeDirectoryEntry(name: "skip.tmp", isDirectory: false, fileSize: 1, nextOffset: 256),
                makeDirectoryEntry(name: "nested", isDirectory: true, nextOffset: 0),
            ], messageId: 5, treeId: 0x3344),
            smb2StatusResponse(status: SMB2Status.noMoreFiles, command: SMB2Commands.queryDirectory, messageId: 6, treeId: 0x3344),
            smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.close, messageId: 7, treeId: 0x3344),
            smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.treeDisconnect, messageId: 8, treeId: 0x3344),
            smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.logoff, messageId: 9, treeId: 0),
        ]))
        let listNestedTransport = InMemoryTransport(inbound: try framed(authenticatedTreeResponses() + [
            smb2CreateResponse(fileId: nestedId, messageId: 4, treeId: 0x3344),
            smb2QueryDirectoryResponse(entries: [
                makeDirectoryEntry(name: "child.log", isDirectory: false, fileSize: 1, nextOffset: 128),
                makeDirectoryEntry(name: "skip.log", isDirectory: false, fileSize: 1, nextOffset: 0),
            ], messageId: 5, treeId: 0x3344),
            smb2StatusResponse(status: SMB2Status.noMoreFiles, command: SMB2Commands.queryDirectory, messageId: 6, treeId: 0x3344),
            smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.close, messageId: 7, treeId: 0x3344),
            smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.treeDisconnect, messageId: 8, treeId: 0x3344),
            smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.logoff, messageId: 9, treeId: 0),
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
            SMBRecursiveAction(kind: .download, path: destination.appendingPathComponent("nested/child.log").path),
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
        let listTransport = InMemoryTransport(inbound: try framed(authenticatedTreeResponses() + [
            smb2CreateResponse(fileId: directoryId, messageId: 4, treeId: 0x3344),
            smb2QueryDirectoryResponse(entries: [
                makeDirectoryEntry(name: "done.txt", isDirectory: false, fileSize: 4, nextOffset: 128),
                makeDirectoryEntry(name: "partial.txt", isDirectory: false, fileSize: 7, nextOffset: 0),
            ], messageId: 5, treeId: 0x3344),
            smb2StatusResponse(status: SMB2Status.noMoreFiles, command: SMB2Commands.queryDirectory, messageId: 6, treeId: 0x3344),
            smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.close, messageId: 7, treeId: 0x3344),
            smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.treeDisconnect, messageId: 8, treeId: 0x3344),
            smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.logoff, messageId: 9, treeId: 0),
        ]))
        let partialTransport = InMemoryTransport(inbound: try framed(authenticatedTreeResponses() + [
            smb2CreateResponse(fileId: partialId, messageId: 4, treeId: 0x3344),
            smb2QueryInfoResponse(size: 7, messageId: 5, treeId: 0x3344),
            smb2ReadResponse(Array("updated".utf8), messageId: 6, treeId: 0x3344),
            smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.close, messageId: 7, treeId: 0x3344),
            smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.treeDisconnect, messageId: 8, treeId: 0x3344),
            smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.logoff, messageId: 9, treeId: 0),
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
            SMBRecursiveAction(kind: .download, path: destination.appendingPathComponent("partial.txt").path),
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
        let transport = InMemoryTransport(inbound: try framed(authenticatedTreeResponses() + [
            smb2CreateResponse(fileId: directoryId, messageId: 4, treeId: 0x3344),
            smb2QueryDirectoryResponse(entries: [
                makeDirectoryEntry(name: "done.txt", isDirectory: false, fileSize: 4, nextOffset: 128),
                makeDirectoryEntry(name: "partial.txt", isDirectory: false, fileSize: 7, nextOffset: 0),
            ], messageId: 5, treeId: 0x3344),
            smb2StatusResponse(status: SMB2Status.noMoreFiles, command: SMB2Commands.queryDirectory, messageId: 6, treeId: 0x3344),
            smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.close, messageId: 7, treeId: 0x3344),
            smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.treeDisconnect, messageId: 8, treeId: 0x3344),
            smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.logoff, messageId: 9, treeId: 0),
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
            makeTransport: { transport }
        ) { recorder.append($0) }

        XCTAssertEqual(try String(contentsOf: destination.appendingPathComponent("partial.txt"), encoding: .utf8), "old")
        XCTAssertEqual(recorder.actions, [
            SMBRecursiveAction(kind: .mkdir, path: destination.path),
            SMBRecursiveAction(kind: .skip, path: destination.appendingPathComponent("done.txt").path),
            SMBRecursiveAction(kind: .download, path: destination.appendingPathComponent("partial.txt").path),
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
        let doneStatTransport = InMemoryTransport(inbound: try framed(authenticatedTreeResponses() + [
            smb2CreateResponse(fileId: doneId, messageId: 4, treeId: 0x3344),
            smb2QueryInfoResponse(size: 4, messageId: 5, treeId: 0x3344),
            smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.close, messageId: 6, treeId: 0x3344),
            smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.treeDisconnect, messageId: 7, treeId: 0x3344),
            smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.logoff, messageId: 8, treeId: 0),
        ]))
        let mismatchStatTransport = InMemoryTransport(inbound: try framed(authenticatedTreeResponses() + [
            smb2CreateResponse(fileId: mismatchStatId, messageId: 4, treeId: 0x3344),
            smb2QueryInfoResponse(size: 1, messageId: 5, treeId: 0x3344),
            smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.close, messageId: 6, treeId: 0x3344),
            smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.treeDisconnect, messageId: 7, treeId: 0x3344),
            smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.logoff, messageId: 8, treeId: 0),
        ]))
        let mismatchUploadTransport = InMemoryTransport(inbound: try framed(authenticatedTreeResponses() + [
            smb2CreateResponse(fileId: mismatchUploadId, messageId: 4, treeId: 0x3344),
            smb2WriteResponse(count: 6, messageId: 5, treeId: 0x3344),
            smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.flush, messageId: 6, treeId: 0x3344),
            smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.close, messageId: 7, treeId: 0x3344),
            smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.treeDisconnect, messageId: 8, treeId: 0x3344),
            smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.logoff, messageId: 9, treeId: 0),
        ]))
        let missingStatTransport = InMemoryTransport(inbound: try framed(authenticatedTreeResponses() + [
            smb2StatusResponse(status: SMB2Status.objectNameNotFound, command: SMB2Commands.create, messageId: 4, treeId: 0x3344),
            smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.treeDisconnect, messageId: 5, treeId: 0x3344),
            smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.logoff, messageId: 6, treeId: 0),
        ]))
        let missingUploadTransport = InMemoryTransport(inbound: try framed(authenticatedTreeResponses() + [
            smb2CreateResponse(fileId: missingUploadId, messageId: 4, treeId: 0x3344),
            smb2WriteResponse(count: 3, messageId: 5, treeId: 0x3344),
            smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.flush, messageId: 6, treeId: 0x3344),
            smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.close, messageId: 7, treeId: 0x3344),
            smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.treeDisconnect, messageId: 8, treeId: 0x3344),
            smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.logoff, messageId: 9, treeId: 0),
        ]))
        let factory = TransportFactorySequence([
            doneStatTransport,
            mismatchStatTransport,
            mismatchUploadTransport,
            missingStatTransport,
            missingUploadTransport,
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
            SMBRecursiveAction(kind: .upload, path: "missing.txt"),
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
        let doneStatTransport = InMemoryTransport(inbound: try framed(authenticatedTreeResponses() + [
            smb2CreateResponse(fileId: doneId, messageId: 4, treeId: 0x3344),
            smb2QueryInfoResponse(size: 4, messageId: 5, treeId: 0x3344),
            smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.close, messageId: 6, treeId: 0x3344),
            smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.treeDisconnect, messageId: 7, treeId: 0x3344),
            smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.logoff, messageId: 8, treeId: 0),
        ]))
        let mismatchStatTransport = InMemoryTransport(inbound: try framed(authenticatedTreeResponses() + [
            smb2CreateResponse(fileId: mismatchId, messageId: 4, treeId: 0x3344),
            smb2QueryInfoResponse(size: 1, messageId: 5, treeId: 0x3344),
            smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.close, messageId: 6, treeId: 0x3344),
            smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.treeDisconnect, messageId: 7, treeId: 0x3344),
            smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.logoff, messageId: 8, treeId: 0),
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
            SMBRecursiveAction(kind: .upload, path: "mismatch.txt"),
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
            SMBRecursiveAction(kind: .upload, path: "remote\\nested\\child.log"),
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
        let pending = try SMB2Header(
            status: SMB2Status.pending,
            command: SMB2Commands.flush,
            flags: SMB2Flags.asyncCommand,
            messageId: 17,
            treeId: 0x5566_7788,
            sessionId: 0x1122_3344
        ).encode()
        let final = try SMB2Header(
            command: SMB2Commands.flush,
            messageId: 17,
            treeId: 0x5566_7788,
            sessionId: 0x1122_3344
        ).encode()
        var mockResponses = [pending, final]

        while try SMB2AsyncInterim.shouldDiscard(mockResponses[0]) {
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

        XCTAssertThrowsError(try SMB2AsyncInterim.shouldDiscard(pending)) { error in
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
            SMBNegotiateConstants.signingContext,
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

    private func readSecurityBuffer(_ bytes: [UInt8], at offset: Int) -> [UInt8] {
        let length = Int(readUInt16LE(bytes, at: offset))
        let bufferOffset = Int(readUInt32LE(bytes, at: offset + 4))
        return Array(bytes[bufferOffset..<bufferOffset + length])
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

    private func appendUInt32LE(_ value: UInt32, to bytes: inout [UInt8]) {
        bytes.append(UInt8(value & 0xff))
        bytes.append(UInt8((value >> 8) & 0xff))
        bytes.append(UInt8((value >> 16) & 0xff))
        bytes.append(UInt8((value >> 24) & 0xff))
    }

    private func appendUInt16LE(_ value: UInt16, to bytes: inout [UInt8]) {
        bytes.append(UInt8(value & 0xff))
        bytes.append(UInt8((value >> 8) & 0xff))
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

    private func readUInt16LE(_ bytes: [UInt8], at offset: Int) -> UInt16 {
        UInt16(bytes[offset]) | (UInt16(bytes[offset + 1]) << 8)
    }

    private func readUInt32LE(_ bytes: [UInt8], at offset: Int) -> UInt32 {
        UInt32(bytes[offset])
            | (UInt32(bytes[offset + 1]) << 8)
            | (UInt32(bytes[offset + 2]) << 16)
            | (UInt32(bytes[offset + 3]) << 24)
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

    private func outboundFrames(_ transport: InMemoryTransport, containCommand command: UInt16) throws -> Bool {
        try unframed(transport.outbound).contains { frame in
            guard frame.count >= 4, Array(frame.prefix(4)) == [0xfe, 0x53, 0x4d, 0x42] else {
                return false
            }
            return try SMB2Header.decode(frame).command == command
        }
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
        writeUInt32LE(UInt32(value & 0xffff_ffff), to: &bytes, at: offset)
        writeUInt32LE(UInt32((value >> 32) & 0xffff_ffff), to: &bytes, at: offset + 4)
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
            UInt8((flags >> 24) & 0xff),
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
        for _ in 0..<100 {
            if try unframed(transport.outbound).count >= expectedCount {
                return
            }
            try await Task.sleep(nanoseconds: 10_000_000)
        }
        XCTFail("timed out waiting for \(expectedCount) outbound SMB frames")
    }

    private func waitForOutboundFrameCount(_ expectedCount: Int, transport: InMemoryTransport) async throws {
        for _ in 0..<100 {
            if try unframed(transport.outbound).count >= expectedCount {
                return
            }
            try await Task.sleep(nanoseconds: 10_000_000)
        }
        XCTFail("timed out waiting for \(expectedCount) outbound SMB frames")
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

    private func smb2ReadResponse(_ payload: [UInt8], messageId: UInt64, treeId: UInt32, credits: UInt16 = 1) throws -> [UInt8] {
        var response = try SMB2Header(command: SMB2Commands.read, credits: credits, messageId: messageId, treeId: treeId).encode()
        response.append(contentsOf: Array(repeating: UInt8(0), count: 16))
        writeUInt16LE(17, to: &response, at: 64)
        response[66] = 80
        writeUInt32LE(UInt32(payload.count), to: &response, at: 68)
        response.append(contentsOf: payload)
        return response
    }

    private func dcerpcResponsePDU(stub: [UInt8], flags: UInt8, callId: UInt32 = 2) throws -> [UInt8] {
        var response: [UInt8] = [
            0x05, 0x00, DCERPC.pduTypeResponse, flags,
            0x10, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            UInt8(callId & 0xff), UInt8((callId >> 8) & 0xff), UInt8((callId >> 16) & 0xff), UInt8((callId >> 24) & 0xff),
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

    private func smb2WriteResponse(count: Int, messageId: UInt64, treeId: UInt32, credits: UInt16 = 1) throws -> [UInt8] {
        var response = try SMB2Header(command: SMB2Commands.write, credits: credits, messageId: messageId, treeId: treeId).encode()
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

    private func authenticatedTreeResponses(treeId: UInt32 = 0x3344) throws -> [[UInt8]] {
        [
            try negotiateResponse(messageId: 0),
            try sessionSetupChallengeResponse(messageId: 1, sessionId: 0x1122_3344_5566_7788),
            try smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.sessionSetup, messageId: 2, treeId: 0),
            try smb2TreeConnectResponse(treeId: treeId, shareType: 1, shareFlags: 0, capabilities: 0, maximalAccess: 0x001f_01ff),
        ]
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

    private func signedSMB2Packet(
        _ packet: [UInt8],
        key: [UInt8],
        algorithm: SMBSessionSigningAlgorithm,
        sender: SMBSessionSigningSender
    ) throws -> [UInt8] {
        var signed = packet
        signed[16] |= UInt8(SMB2Flags.signed & 0xff)
        signed.replaceSubrange(48..<64, with: Array(repeating: 0, count: 16))
        let signature = try SMBSessionSigning.signature(algorithm: algorithm, key: key, packet: signed, sender: sender)
        signed.replaceSubrange(48..<64, with: signature)
        return signed
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

    private func negotiateResponse(messageId: UInt64, dialect: UInt16 = SMBNegotiateConstants.dialect302) throws -> [UInt8] {
        var response = try SMB2Header(command: SMBNegotiateConstants.commandNegotiate, messageId: messageId).encode()
        response.append(contentsOf: Array(repeating: UInt8(0), count: 65))
        writeUInt16LE(65, to: &response, at: 64)
        writeUInt16LE(SMBNegotiateConstants.signingEnabled, to: &response, at: 66)
        writeUInt16LE(dialect, to: &response, at: 68)
        response.replaceSubrange(72..<88, with: Array(repeating: UInt8(0x42), count: 16))
        writeUInt32LE(1_048_576, to: &response, at: 92)
        writeUInt32LE(1_048_576, to: &response, at: 96)
        writeUInt32LE(1_048_576, to: &response, at: 100)
    writeUInt16LE(UInt16(response.count), to: &response, at: 116)
        writeUInt16LE(0, to: &response, at: 118)
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
