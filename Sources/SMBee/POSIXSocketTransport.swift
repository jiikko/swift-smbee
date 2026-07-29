import Foundation

#if os(Linux)
import Glibc
#else
import Darwin
#endif

internal typealias POSIXSocketWriter = @Sendable (Int32, [UInt8], Int) throws -> Int
internal typealias POSIXSocketLifecycleHook = @Sendable (Int32) -> Void
internal typealias POSIXSocketSendEnqueueHook = @Sendable () -> Void

public final class POSIXSocketTransport: SMBTransport, @unchecked Sendable {
    private enum ConnectionState {
        case idle
        case connecting
        case open(Int32)
        case closed
        case poisoned
    }

    private let connectionLock = NSLock()
    private var connectionState: ConnectionState = .idle
    private var connectingDescriptor: Int32 = -1
    private let timeout: Duration?
    private let writer: POSIXSocketWriter
    private let shutdownDescriptor: POSIXSocketLifecycleHook
    private let closeDescriptor: POSIXSocketLifecycleHook
    private let sendEnqueueHook: POSIXSocketSendEnqueueHook
    private let sendQueue = DispatchQueue(label: "dev.smbee.posix.send")

    // POSIX is used instead of SwiftNIO for Phase 0 to keep the transport dependency-free
    // while still providing the Linux path required by the E2E plan.
    public init(timeout: Duration? = nil) {
        self.timeout = timeout
        self.writer = { descriptor, bytes, offset in
            bytes.withUnsafeBytes { buffer in
                DarwinOrGlibc.send(
                    descriptor,
                    buffer.baseAddress!.advanced(by: offset),
                    bytes.count - offset,
                    DarwinOrGlibc.sendFlagsSuppressingSIGPIPE
                )
            }
        }
        self.shutdownDescriptor = { descriptor in DarwinOrGlibc.shutdown(descriptor) }
        self.closeDescriptor = { descriptor in DarwinOrGlibc.close(descriptor) }
        self.sendEnqueueHook = {}
    }

    internal init(
        socketFileDescriptor: Int32 = 1,
        writer: @escaping POSIXSocketWriter,
        shutdown: @escaping POSIXSocketLifecycleHook = { _ in },
        close: @escaping POSIXSocketLifecycleHook = { _ in },
        sendEnqueued: @escaping POSIXSocketSendEnqueueHook = {}
    ) {
        self.timeout = nil
        self.writer = writer
        self.shutdownDescriptor = shutdown
        self.closeDescriptor = close
        self.sendEnqueueHook = sendEnqueued
        self.connectionState = .open(socketFileDescriptor)
    }

    public func connect(host: String, port: UInt16) async throws {
        try Task.checkCancellation()
        try beginConnect()
        try await withTaskCancellationHandler {
            do {
                try await Task.detached {
                    try self.connectBlocking(host: host, port: port)
                }.value
            } catch {
                self.resetFailedConnectionAttempt()
                if Task.isCancelled { throw CancellationError() }
                throw error
            }
        } onCancel: {
            self.interruptBlockingIO()
        }
        try Task.checkCancellation()
    }

    public func send(_ bytes: [UInt8]) async throws {
        try await enqueueSend(segments: [bytes])
    }

    public func send(_ segments: [[UInt8]]) async throws {
        try await enqueueSend(segments: segments)
    }

    public func receive(maxLength: Int) async throws -> [UInt8] {
        try Task.checkCancellation()
        let bytes = try await withTaskCancellationHandler {
            do {
                return try await Task.detached {
                    try self.receiveBlocking(maxLength: maxLength)
                }.value
            } catch {
                if Task.isCancelled { throw CancellationError() }
                throw error
            }
        } onCancel: {
            self.interruptBlockingIO()
        }
        try Task.checkCancellation()
        return bytes
    }

    public func close() {
        let descriptors = transitionToTerminal(.closed)
        closeDescriptors(descriptors)
    }

    // Task cancel 時に blocking syscall を「起こす」ための操作。
    // Linux では別スレッドが blocking recv()/send() 中の fd を close() しても
    // その syscall は起きない (POSIX 上、close は他スレッドの blocking I/O を
    // 中断する保証がない)。shutdown(SHUT_RDWR) は blocked recv/send を確実に
    // エラー復帰させるため、cancel 経路では close ではなく shutdown で起こしてから
    // fd を close する。fd は奪わず残すので、blocked syscall は自分が握る fd 値から
    // 正常にエラー復帰できる (その後 close() が実際の解放を行う)。
    private func interruptBlockingIO() {
        close()
    }

    deinit {
        close()
    }

    private func connectBlocking(host: String, port: UInt16) throws {
        // `addrinfo` のメンバ順は Darwin と glibc で異なる (Linux は ai_addr が
        // ai_canonname より前) ため、memberwise initializer は使わず zero 初期化 +
        // 個別代入でプラットフォーム非依存にする。
        var hints = addrinfo()
        hints.ai_family = AF_UNSPEC
        // glibc では `SOCK_STREAM` が `__socket_type` enum なので Int32 へ変換が要る。
        #if os(Linux)
        hints.ai_socktype = Int32(SOCK_STREAM.rawValue)
        #else
        hints.ai_socktype = SOCK_STREAM
        #endif
        // glibc では `IPPROTO_TCP` が `Int`、Darwin では `Int32`。両対応で Int32 に包む。
        hints.ai_protocol = Int32(IPPROTO_TCP)
        var result: UnsafeMutablePointer<addrinfo>?
        let service = String(port)
        guard getaddrinfo(host, service, &hints, &result) == 0, let first = result else {
            throw SMBTransportError.invalidAddress
        }
        defer { freeaddrinfo(result) }

        var current: UnsafeMutablePointer<addrinfo>? = first
        while let candidate = current {
            let descriptor = socket(candidate.pointee.ai_family, candidate.pointee.ai_socktype, candidate.pointee.ai_protocol)
            if descriptor >= 0 {
                guard installConnectingDescriptor(descriptor) else {
                    closeDescriptor(descriptor)
                    throw SMBTransportError.connectionClosed
                }
                do {
                    try disableSIGPIPEIfNeeded(descriptor)
                    try connectSocket(
                        descriptor,
                        address: candidate.pointee.ai_addr,
                        length: candidate.pointee.ai_addrlen
                    )
                    try applySocketTimeoutIfNeeded(descriptor)
                    guard promoteConnectedDescriptor(descriptor) else {
                        if clearConnectingDescriptor(descriptor) {
                            closeDescriptor(descriptor)
                        }
                        throw SMBTransportError.connectionClosed
                    }
                    return
                } catch {
                    if clearConnectingDescriptor(descriptor) {
                        closeDescriptor(descriptor)
                    }
                    if case SMBTransportError.timedOut = error { throw error }
                }
            }
            current = candidate.pointee.ai_next
        }
        throw SMBTransportError.socketFailure("connect failed")
    }

    private func sendBlocking(
        _ segments: [[UInt8]],
        beforeWriterCall: () -> Bool
    ) throws -> Int32 {
        guard let descriptor = currentSocketFileDescriptor() else { throw SMBTransportError.connectionClosed }
        for segment in segments where !segment.isEmpty {
            var sent = 0
            while sent < segment.count {
                guard isSocketOpen(descriptor), beforeWriterCall() else {
                    throw SMBTransportError.connectionClosed
                }
                let count = try writer(descriptor, segment, sent)
                if count < 0, DarwinOrGlibc.errnoValue == EINTR {
                    // EINTR is retryable; the next attempt rechecks cancellation/poison
                    // so an interrupted send cannot spin forever.
                    continue
                }
                guard count > 0, count <= segment.count - sent else {
                    throw socketError(operation: "send")
                }
                sent += count
            }
        }
        return descriptor
    }

    private func receiveBlocking(maxLength: Int) throws -> [UInt8] {
        guard let descriptor = currentSocketFileDescriptor() else { throw SMBTransportError.connectionClosed }
        var buffer = [UInt8](repeating: 0, count: maxLength)
        let count = buffer.withUnsafeMutableBytes { rawBuffer in
            DarwinOrGlibc.recv(descriptor, rawBuffer.baseAddress, maxLength, 0)
        }
        guard count > 0 else {
            if count == 0 { throw SMBTransportError.connectionClosed }
            throw socketError(operation: "recv")
        }
        return Array(buffer.prefix(count))
    }

    private func connectSocket(_ descriptor: Int32, address: UnsafePointer<sockaddr>?, length: socklen_t) throws {
        guard let timeout else {
            if DarwinOrGlibc.connect(descriptor, address, length) == 0 { return }
            throw socketError(operation: "connect", descriptor: descriptor)
        }

        let flags = DarwinOrGlibc.fcntl(descriptor, F_GETFL, 0)
        guard flags >= 0 else { throw socketError(operation: "fcntl(F_GETFL)", descriptor: descriptor) }
        guard DarwinOrGlibc.fcntl(descriptor, F_SETFL, flags | DarwinOrGlibc.oNonBlock) >= 0 else {
            throw socketError(operation: "fcntl(F_SETFL)", descriptor: descriptor)
        }
        defer { _ = DarwinOrGlibc.fcntl(descriptor, F_SETFL, flags) }

        if DarwinOrGlibc.connect(descriptor, address, length) == 0 { return }
        guard DarwinOrGlibc.errnoValue == EINPROGRESS else {
            throw socketError(operation: "connect", descriptor: descriptor)
        }

        var pollDescriptor = pollfd(fd: descriptor, events: Int16(POLLOUT), revents: 0)
        let pollResult = DarwinOrGlibc.poll(&pollDescriptor, 1, timeout.pollMilliseconds)
        if pollResult == 0 { throw SMBTransportError.timedOut }
        guard pollResult > 0 else { throw socketError(operation: "poll", descriptor: descriptor) }

        var socketErrorValue: Int32 = 0
        var socketErrorLength = socklen_t(MemoryLayout<Int32>.size)
        guard DarwinOrGlibc.getsockopt(
            descriptor,
            SOL_SOCKET,
            SO_ERROR,
            &socketErrorValue,
            &socketErrorLength
        ) == 0 else {
            throw socketError(operation: "getsockopt(SO_ERROR)", descriptor: descriptor)
        }
        guard socketErrorValue == 0 else {
            if socketErrorValue == ETIMEDOUT { throw SMBTransportError.timedOut }
            throw SMBTransportError.socketFailure("connect failed: errno \(socketErrorValue)")
        }
    }

    // ピアが切断済みのソケットへの send() は SIGPIPE を発生させ、デフォルト動作は
    // クラッシュレポート無しのプロセス即死 (Obaket で「切れた SMB セッションへの
    // preview read でアプリごと落ちる」として実際に発生)。Darwin では fd 単位の
    // SO_NOSIGPIPE で抑止し、send は EPIPE エラーとして返して SMBTransportError に
    // 正規化させる。Linux に SO_NOSIGPIPE は無いので send 側の MSG_NOSIGNAL で抑止する。
    private func disableSIGPIPEIfNeeded(_ descriptor: Int32) throws {
        #if !os(Linux)
        var enabled: Int32 = 1
        let length = socklen_t(MemoryLayout<Int32>.size)
        guard DarwinOrGlibc.setsockopt(descriptor, SOL_SOCKET, SO_NOSIGPIPE, &enabled, length) == 0 else {
            throw socketError(operation: "setsockopt(SO_NOSIGPIPE)", descriptor: descriptor)
        }
        #endif
    }

    private func applySocketTimeoutIfNeeded(_ descriptor: Int32) throws {
        guard let timeout else { return }
        var value = timeout.timevalValue
        let length = socklen_t(MemoryLayout<timeval>.size)
        guard DarwinOrGlibc.setsockopt(descriptor, SOL_SOCKET, SO_RCVTIMEO, &value, length) == 0 else {
            throw socketError(operation: "setsockopt(SO_RCVTIMEO)", descriptor: descriptor)
        }
        var sendValue = timeout.timevalValue
        guard DarwinOrGlibc.setsockopt(descriptor, SOL_SOCKET, SO_SNDTIMEO, &sendValue, length) == 0 else {
            throw socketError(operation: "setsockopt(SO_SNDTIMEO)", descriptor: descriptor)
        }
    }

    private func enqueueSend(segments: [[UInt8]]) async throws {
        try Task.checkCancellation()
        let operation = POSIXSendOperation()
        try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
                operation.install(continuation)
                sendEnqueueHook()
                sendQueue.async { [self] in
                    guard operation.activate() else { return }
                    do {
                        let descriptor = try sendBlocking(segments, beforeWriterCall: operation.beginWriterCall)
                        if isSocketOpen(descriptor), let continuation = operation.completeSuccessfully() {
                            continuation.resume()
                        } else if let continuation = operation.complete(with: SMBTransportError.connectionClosed) {
                            if operation.didCallWriter {
                                poison()
                            }
                            continuation.resume(throwing: SMBTransportError.connectionClosed)
                        }
                    } catch {
                        if let continuation = operation.complete(with: error) {
                            if operation.didCallWriter {
                                // A writer call that errors before writing any bytes still
                                // poisons conservatively: its write boundary is not observable,
                                // so a retry could duplicate data.
                                poison()
                            }
                            continuation.resume(throwing: error)
                        }
                    }
                }
            }
        } onCancel: {
            operation.cancel { [self] in
                if operation.didCallWriter {
                    poison()
                }
            }
        }
    }

    private func currentSocketFileDescriptor() -> Int32? {
        connectionLock.lock()
        defer { connectionLock.unlock() }
        guard case .open(let descriptor) = connectionState else { return nil }
        return descriptor
    }

    private func isSocketOpen(_ descriptor: Int32) -> Bool {
        connectionLock.lock()
        defer { connectionLock.unlock() }
        guard case .open(let currentDescriptor) = connectionState else { return false }
        return currentDescriptor == descriptor
    }

    private func beginConnect() throws {
        connectionLock.lock()
        defer { connectionLock.unlock() }
        guard case .idle = connectionState else { throw SMBTransportError.connectionClosed }
        connectionState = .connecting
    }

    private func installConnectingDescriptor(_ descriptor: Int32) -> Bool {
        connectionLock.lock()
        defer { connectionLock.unlock() }
        guard case .connecting = connectionState else { return false }
        connectingDescriptor = descriptor
        return true
    }

    private func clearConnectingDescriptor(_ descriptor: Int32) -> Bool {
        connectionLock.lock()
        defer { connectionLock.unlock() }
        if connectingDescriptor == descriptor {
            connectingDescriptor = -1
            return true
        }
        return false
    }

    private func promoteConnectedDescriptor(_ descriptor: Int32) -> Bool {
        connectionLock.lock()
        defer { connectionLock.unlock() }
        guard case .connecting = connectionState, connectingDescriptor == descriptor else { return false }
        connectingDescriptor = -1
        connectionState = .open(descriptor)
        return true
    }

    private func resetFailedConnectionAttempt() {
        connectionLock.lock()
        if case .connecting = connectionState {
            connectingDescriptor = -1
            connectionState = .idle
        }
        connectionLock.unlock()
    }

    private func transitionToTerminal(_ terminalState: ConnectionState) -> [Int32] {
        connectionLock.lock()
        defer { connectionLock.unlock() }
        switch connectionState {
        case .closed, .poisoned:
            return []
        case .idle, .connecting, .open:
            break
        }
        var descriptors: [Int32] = []
        if case .open(let descriptor) = connectionState, descriptor >= 0 {
            descriptors.append(descriptor)
        }
        if connectingDescriptor >= 0, !descriptors.contains(connectingDescriptor) {
            descriptors.append(connectingDescriptor)
        }
        connectingDescriptor = -1
        connectionState = terminalState
        return descriptors
    }

    private func poison() {
        closeDescriptors(transitionToTerminal(.poisoned))
    }

    private func closeDescriptors(_ descriptors: [Int32]) {
        for descriptor in descriptors {
            shutdownDescriptor(descriptor)
            closeDescriptor(descriptor)
        }
    }

    private func socketError(operation: String, descriptor: Int32? = nil) -> Error {
        let errnoValue = DarwinOrGlibc.errnoValue
        if errnoValue == EAGAIN || errnoValue == EWOULDBLOCK || errnoValue == ETIMEDOUT {
            return SMBTransportError.timedOut
        }
        if errnoValue == EBADF || errnoValue == EINTR || (descriptor == nil && currentSocketFileDescriptor() == nil) {
            return SMBTransportError.connectionClosed
        }
        return SMBTransportError.socketFailure("\(operation) failed: errno \(errnoValue)")
    }
}

private final class POSIXSendOperation: @unchecked Sendable {
    private enum State {
        case queued
        case active
        case completed
        case failed
        case cancelledBeforeStart
        case aborting
        case cancelled
    }

    private let lock = NSLock()
    private var state = State.queued
    private var continuation: CheckedContinuation<Void, Error>?
    private var writerCallCount = 0

    func install(_ continuation: CheckedContinuation<Void, Error>) {
        var resumeCancellation = false
        lock.lock()
        if case .cancelledBeforeStart = state {
            state = .cancelled
            resumeCancellation = true
        } else {
            self.continuation = continuation
        }
        lock.unlock()

        if resumeCancellation {
            continuation.resume(throwing: CancellationError())
        }
    }

    func activate() -> Bool {
        lock.lock()
        defer { lock.unlock() }
        guard case .queued = state else { return false }
        state = .active
        return true
    }

    func beginWriterCall() -> Bool {
        lock.lock()
        defer { lock.unlock() }
        guard case .active = state else { return false }
        writerCallCount += 1
        return true
    }

    var didCallWriter: Bool {
        lock.lock()
        defer { lock.unlock() }
        return writerCallCount > 0
    }

    func cancel(onActive: @escaping @Sendable () -> Void) {
        var continuationToResume: CheckedContinuation<Void, Error>?
        var abortActive = false

        lock.lock()
        switch state {
        case .queued:
            state = .cancelledBeforeStart
            continuationToResume = continuation
            continuation = nil
        case .active:
            state = .aborting
            abortActive = true
        case .completed, .failed, .cancelledBeforeStart, .aborting, .cancelled:
            break
        }
        lock.unlock()

        if abortActive {
            onActive()
            completeCancellation()
        } else {
            continuationToResume?.resume(throwing: CancellationError())
        }
    }

    func completeSuccessfully() -> CheckedContinuation<Void, Error>? {
        lock.lock()
        defer { lock.unlock() }
        guard case .active = state else { return nil }
        state = .completed
        let continuation = self.continuation
        self.continuation = nil
        return continuation
    }

    func complete(with error: Error) -> CheckedContinuation<Void, Error>? {
        _ = error
        lock.lock()
        defer { lock.unlock() }
        guard case .active = state else { return nil }
        state = .failed
        let continuation = self.continuation
        self.continuation = nil
        return continuation
    }

    private func completeCancellation() {
        lock.lock()
        guard case .aborting = state else {
            lock.unlock()
            return
        }
        state = .cancelled
        let continuation = self.continuation
        self.continuation = nil
        lock.unlock()

        continuation?.resume(throwing: CancellationError())
    }
}

private extension Duration {
    var timevalValue: timeval {
        let components = self.components
        let attosecondsPerMicrosecond: Int64 = 1_000_000_000_000
        let seconds = max(0, components.seconds)
        let microseconds = max(0, components.attoseconds / attosecondsPerMicrosecond)
        return timeval(tv_sec: DarwinOrGlibc.time(seconds), tv_usec: DarwinOrGlibc.suseconds(microseconds))
    }

    var pollMilliseconds: Int32 {
        let components = self.components
        let attosecondsPerMillisecond: Int64 = 1_000_000_000_000_000
        let secondsMilliseconds = max(0, components.seconds) * 1_000
        let fractionalMilliseconds = max(0, components.attoseconds / attosecondsPerMillisecond)
        let milliseconds = secondsMilliseconds + fractionalMilliseconds
        return Int32(min(milliseconds, Int64(Int32.max)))
    }
}

private enum DarwinOrGlibc {
    static var errnoValue: Int32 {
        #if os(Linux)
        Glibc.errno
        #else
        Darwin.errno
        #endif
    }

    // Linux は send フラグの MSG_NOSIGNAL で SIGPIPE を抑止する
    // (Darwin は fd 単位の SO_NOSIGPIPE で抑止済みなのでフラグ不要)。
    static var sendFlagsSuppressingSIGPIPE: Int32 {
        #if os(Linux)
        Int32(MSG_NOSIGNAL)
        #else
        0
        #endif
    }

    static var oNonBlock: Int32 {
        #if os(Linux)
        Int32(Glibc.O_NONBLOCK)
        #else
        Int32(Darwin.O_NONBLOCK)
        #endif
    }

    static func close(_ fd: Int32) {
        #if os(Linux)
        _ = Glibc.close(fd)
        #else
        _ = Darwin.close(fd)
        #endif
    }

    static func shutdown(_ fd: Int32) {
        // SHUT_RDWR で read/write 両方向を落とす。blocking recv/send を「起こす」ための操作。
        #if os(Linux)
        _ = Glibc.shutdown(fd, Int32(SHUT_RDWR))
        #else
        _ = Darwin.shutdown(fd, SHUT_RDWR)
        #endif
    }

    static func connect(_ fd: Int32, _ address: UnsafePointer<sockaddr>?, _ length: socklen_t) -> Int32 {
        #if os(Linux)
        Glibc.connect(fd, address, length)
        #else
        Darwin.connect(fd, address, length)
        #endif
    }

    static func send(_ fd: Int32, _ buffer: UnsafeRawPointer?, _ length: Int, _ flags: Int32) -> Int {
        #if os(Linux)
        Glibc.send(fd, buffer, length, flags)
        #else
        Darwin.send(fd, buffer, length, flags)
        #endif
    }

    static func recv(_ fd: Int32, _ buffer: UnsafeMutableRawPointer?, _ length: Int, _ flags: Int32) -> Int {
        #if os(Linux)
        Glibc.recv(fd, buffer, length, flags)
        #else
        Darwin.recv(fd, buffer, length, flags)
        #endif
    }

    static func fcntl(_ fd: Int32, _ command: Int32, _ value: Int32) -> Int32 {
        #if os(Linux)
        Glibc.fcntl(fd, command, value)
        #else
        Darwin.fcntl(fd, command, value)
        #endif
    }

    static func poll(_ fds: UnsafeMutablePointer<pollfd>?, _ nfds: nfds_t, _ timeout: Int32) -> Int32 {
        #if os(Linux)
        Glibc.poll(fds, nfds, timeout)
        #else
        Darwin.poll(fds, nfds, timeout)
        #endif
    }

    static func getsockopt(
        _ fd: Int32,
        _ level: Int32,
        _ optionName: Int32,
        _ optionValue: UnsafeMutableRawPointer?,
        _ optionLength: UnsafeMutablePointer<socklen_t>?
    ) -> Int32 {
        #if os(Linux)
        Glibc.getsockopt(fd, level, optionName, optionValue, optionLength)
        #else
        Darwin.getsockopt(fd, level, optionName, optionValue, optionLength)
        #endif
    }

    static func setsockopt(
        _ fd: Int32,
        _ level: Int32,
        _ optionName: Int32,
        _ optionValue: UnsafeRawPointer?,
        _ optionLength: socklen_t
    ) -> Int32 {
        #if os(Linux)
        Glibc.setsockopt(fd, level, optionName, optionValue, optionLength)
        #else
        Darwin.setsockopt(fd, level, optionName, optionValue, optionLength)
        #endif
    }

    static func time(_ value: Int64) -> time_t {
        time_t(value)
    }

    static func suseconds(_ value: Int64) -> suseconds_t {
        suseconds_t(value)
    }
}
