import Foundation

#if os(Linux)
import Glibc
#else
import Darwin
#endif

internal typealias POSIXSocketWriter = @Sendable (Int32, [UInt8], Int) throws -> Int
internal typealias POSIXSocketReader = @Sendable (Int32, UnsafeMutableRawPointer?, Int) -> Int
internal typealias POSIXSocketLifecycleHook = @Sendable (Int32) -> Void
internal typealias POSIXSocketSendEnqueueHook = @Sendable () -> Void

internal struct POSIXSocketCallResult<Value> {
    let value: Value
    let errno: Int32

    init(_ value: Value, errno: Int32 = 0) {
        self.value = value
        self.errno = errno
    }
}

internal struct POSIXSocketPollValue {
    let result: Int32
    let revents: Int16
}

internal struct POSIXSocketErrorValue {
    let result: Int32
    let socketError: Int32
}

/// The syscall boundary used while establishing a POSIX connection.
///
/// Each operation captures its return value and `errno` together so a test fake (and the
/// live implementation) cannot observe an `errno` subsequently changed by another call.
internal struct POSIXSocketSyscalls: @unchecked Sendable {
    let socket: @Sendable (Int32, Int32, Int32) -> POSIXSocketCallResult<Int32>
    let connect: @Sendable (
        Int32,
        UnsafePointer<sockaddr>?,
        socklen_t
    ) -> POSIXSocketCallResult<Int32>
    let fcntl: @Sendable (Int32, Int32, Int32) -> POSIXSocketCallResult<Int32>
    let poll: @Sendable (Int32, Int16, Int32) -> POSIXSocketCallResult<POSIXSocketPollValue>
    let getSocketError: @Sendable (Int32) -> POSIXSocketCallResult<POSIXSocketErrorValue>
    let setSocketOption: @Sendable (
        Int32,
        Int32,
        Int32,
        UnsafeRawPointer?,
        socklen_t
    ) -> POSIXSocketCallResult<Int32>
    let now: @Sendable () -> ContinuousClock.Instant

    static var live: POSIXSocketSyscalls {
        let clock = ContinuousClock()
        return POSIXSocketSyscalls(
            socket: { family, type, protocolValue in
                let value = DarwinOrGlibc.socket(family, type, protocolValue)
                return POSIXSocketCallResult(value, errno: value < 0 ? DarwinOrGlibc.errnoValue : 0)
            },
            connect: { descriptor, address, length in
                let value = DarwinOrGlibc.connect(descriptor, address, length)
                return POSIXSocketCallResult(value, errno: value < 0 ? DarwinOrGlibc.errnoValue : 0)
            },
            fcntl: { descriptor, command, value in
                let result = DarwinOrGlibc.fcntl(descriptor, command, value)
                return POSIXSocketCallResult(result, errno: result < 0 ? DarwinOrGlibc.errnoValue : 0)
            },
            poll: { descriptor, events, timeout in
                var pollDescriptor = pollfd(fd: descriptor, events: events, revents: 0)
                let result = DarwinOrGlibc.poll(&pollDescriptor, 1, timeout)
                return POSIXSocketCallResult(
                    POSIXSocketPollValue(result: result, revents: pollDescriptor.revents),
                    errno: result < 0 ? DarwinOrGlibc.errnoValue : 0
                )
            },
            getSocketError: { descriptor in
                var socketErrorValue: Int32 = 0
                var socketErrorLength = socklen_t(MemoryLayout<Int32>.size)
                let result = DarwinOrGlibc.getsockopt(
                    descriptor,
                    SOL_SOCKET,
                    SO_ERROR,
                    &socketErrorValue,
                    &socketErrorLength
                )
                return POSIXSocketCallResult(
                    POSIXSocketErrorValue(result: result, socketError: socketErrorValue),
                    errno: result < 0 ? DarwinOrGlibc.errnoValue : 0
                )
            },
            setSocketOption: { descriptor, level, name, value, length in
                let result = DarwinOrGlibc.setsockopt(descriptor, level, name, value, length)
                return POSIXSocketCallResult(result, errno: result < 0 ? DarwinOrGlibc.errnoValue : 0)
            },
            now: { clock.now }
        )
    }
}

public final class POSIXSocketTransport: SMBTransport, @unchecked Sendable {
    private enum ConnectionState {
        case idle
        case connecting
        case open(Int32)
        case closed
        case poisoned
    }

    private struct DescriptorLeaseRecord {
        var leaseCount = 0
        var retired = false
        var shutdownRequired = false
        // This records completion of the shutdown attempt, not shutdown success.
        var shutdownAttemptCompleted = true
        var closeClaimed = false
    }

    private let connectionLock = NSLock()
    private var connectionState: ConnectionState = .idle
    private var connectingDescriptor: Int32 = -1
    private var descriptorLeaseRecords: [Int32: DescriptorLeaseRecord] = [:]
    private let timeout: Duration?
    private let writer: POSIXSocketWriter
    private let reader: POSIXSocketReader
    private let shutdownDescriptor: POSIXSocketLifecycleHook
    private let closeDescriptor: POSIXSocketLifecycleHook
    private let sendEnqueueHook: POSIXSocketSendEnqueueHook
    private let syscalls: POSIXSocketSyscalls
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
        self.reader = { descriptor, buffer, maxLength in
            DarwinOrGlibc.recv(descriptor, buffer, maxLength, 0)
        }
        self.shutdownDescriptor = { descriptor in DarwinOrGlibc.shutdown(descriptor) }
        self.closeDescriptor = { descriptor in DarwinOrGlibc.close(descriptor) }
        self.sendEnqueueHook = {}
        self.syscalls = .live
    }

    internal init(
        timeout: Duration?,
        syscalls: POSIXSocketSyscalls,
        writer: @escaping POSIXSocketWriter = { descriptor, bytes, offset in
            bytes.withUnsafeBytes { buffer in
                DarwinOrGlibc.send(
                    descriptor,
                    buffer.baseAddress!.advanced(by: offset),
                    bytes.count - offset,
                    DarwinOrGlibc.sendFlagsSuppressingSIGPIPE
                )
            }
        },
        reader: @escaping POSIXSocketReader = { descriptor, buffer, maxLength in
            DarwinOrGlibc.recv(descriptor, buffer, maxLength, 0)
        },
        shutdown: @escaping POSIXSocketLifecycleHook,
        close: @escaping POSIXSocketLifecycleHook
    ) {
        self.timeout = timeout
        self.writer = writer
        self.reader = reader
        self.shutdownDescriptor = shutdown
        self.closeDescriptor = close
        self.sendEnqueueHook = {}
        self.syscalls = syscalls
    }

    internal init(
        socketFileDescriptor: Int32 = 1,
        writer: @escaping POSIXSocketWriter,
        reader: @escaping POSIXSocketReader = { descriptor, buffer, maxLength in
            DarwinOrGlibc.recv(descriptor, buffer, maxLength, 0)
        },
        shutdown: @escaping POSIXSocketLifecycleHook = { _ in },
        close: @escaping POSIXSocketLifecycleHook = { _ in },
        sendEnqueued: @escaping POSIXSocketSendEnqueueHook = {}
    ) {
        self.timeout = nil
        self.writer = writer
        self.reader = reader
        self.shutdownDescriptor = shutdown
        self.closeDescriptor = close
        self.sendEnqueueHook = sendEnqueued
        self.syscalls = .live
        self.connectionState = .open(socketFileDescriptor)
        self.descriptorLeaseRecords[socketFileDescriptor] = DescriptorLeaseRecord()
    }

    /// Connects to an SMB endpoint.
    ///
    /// Once address resolution has completed, cancellation/`close()` is observed by a
    /// nonblocking-connect heartbeat within about 100 ms plus scheduler delay. DNS
    /// resolution itself is performed by `getaddrinfo` and is not bounded by this guarantee.
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

    /// Makes this transport terminal and starts interrupting its blocking I/O.
    ///
    /// This instance is one-shot: `connect()` after `close()` always throws
    /// `connectionClosed`. The physical descriptor close happens after all in-flight
    /// descriptor leases drain; this method does not wait for that drain. Reopening the
    /// terminal state could let queued sends from the old connection reach a new socket,
    /// so reconnect creates a new transport instance instead.
    public func close() {
        retireAndInterruptDescriptors(transitionToTerminal(.closed))
    }

    // Task cancel 時に blocking syscall を「起こす」ための操作。
    // Linux では別スレッドが blocking recv()/send() 中の fd を close() しても
    // その syscall は起きない (POSIX 上、close は他スレッドの blocking I/O を
    // 中断する保証がない)。shutdown(SHUT_RDWR) は blocked recv/send を確実に
    // エラー復帰させるため、cancel 経路では close ではなく shutdown で起こしてから
    // physical close は lease が drain し、shutdown の試行が完了してから行う。
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
            let socketResult = syscalls.socket(
                candidate.pointee.ai_family,
                candidate.pointee.ai_socktype,
                candidate.pointee.ai_protocol
            )
            let descriptor = socketResult.value
            if descriptor >= 0 {
                guard installConnectingDescriptor(descriptor) else {
                    closeDescriptor(descriptor)
                    throw SMBTransportError.connectionClosed
                }
                do {
                    try connectInstalledCandidate(
                        descriptor,
                        address: candidate.pointee.ai_addr,
                        length: candidate.pointee.ai_addrlen
                    )
                    return
                } catch {
                    if isConnectionTerminal() { throw SMBTransportError.connectionClosed }
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
        let descriptor = try acquireOpenDescriptorLease()
        defer { releaseDescriptorLease(descriptor) }

        for segment in segments where !segment.isEmpty {
            var sent = 0
            while sent < segment.count {
                guard beforeWriterCall(), descriptorAllowsSyscall(descriptor) else {
                    throw SMBTransportError.connectionClosed
                }
                let count: Int
                do {
                    count = try writer(descriptor, segment, sent)
                } catch {
                    // The write boundary is unknown once the writer has been entered.
                    // Retire the connection before returning this lease so no new send
                    // can start in the partial-write failure window.
                    poison()
                    throw error
                }
                if count < 0, DarwinOrGlibc.errnoValue == EINTR {
                    // EINTR is retryable; the next attempt rechecks cancellation/poison
                    // so an interrupted send cannot spin forever.
                    continue
                }
                guard count > 0, count <= segment.count - sent else {
                    let error = socketError(operation: "send")
                    poison()
                    throw error
                }
                sent += count
            }
        }
        return descriptor
    }

    private func receiveBlocking(maxLength: Int) throws -> [UInt8] {
        let descriptor = try acquireOpenDescriptorLease()
        defer { releaseDescriptorLease(descriptor) }

        var buffer = [UInt8](repeating: 0, count: maxLength)
        guard descriptorAllowsSyscall(descriptor) else {
            throw SMBTransportError.connectionClosed
        }
        let count = buffer.withUnsafeMutableBytes { rawBuffer in
            reader(descriptor, rawBuffer.baseAddress, maxLength)
        }
        guard count > 0 else {
            if count == 0 { throw SMBTransportError.connectionClosed }
            throw socketError(operation: "recv")
        }
        return Array(buffer.prefix(count))
    }

    private func connectInstalledCandidate(
        _ descriptor: Int32,
        address: UnsafePointer<sockaddr>?,
        length: socklen_t
    ) throws {
        var candidateFinished = false
        defer {
            if !candidateFinished {
                let completion = finishConnectingCandidate(descriptor, promote: false)
                closeClaimedDescriptorIfNeeded(descriptor, claimed: completion.closeClaimed)
            }
        }

        try disableSIGPIPEIfNeeded(descriptor)
        try connectSocket(descriptor, address: address, length: length)
        try applySocketTimeoutIfNeeded(descriptor)

        let completion = finishConnectingCandidate(descriptor, promote: true)
        candidateFinished = true
        closeClaimedDescriptorIfNeeded(descriptor, claimed: completion.closeClaimed)
        guard completion.promoted else { throw SMBTransportError.connectionClosed }
    }

    private func connectSocket(_ descriptor: Int32, address: UnsafePointer<sockaddr>?, length: socklen_t) throws {
        let deadline = timeout.map { syscalls.now().advanced(by: $0) }
        guard descriptorAllowsSyscall(descriptor) else { throw SMBTransportError.connectionClosed }
        let getFlagsResult = syscalls.fcntl(descriptor, F_GETFL, 0)
        let flags = getFlagsResult.value
        guard flags >= 0 else {
            throw socketError(
                operation: "fcntl(F_GETFL)",
                descriptor: descriptor,
                errnoValue: getFlagsResult.errno
            )
        }
        guard descriptorAllowsSyscall(descriptor) else { throw SMBTransportError.connectionClosed }
        let setNonblockingResult = syscalls.fcntl(descriptor, F_SETFL, flags | DarwinOrGlibc.oNonBlock)
        guard setNonblockingResult.value >= 0 else {
            throw socketError(
                operation: "fcntl(F_SETFL)",
                descriptor: descriptor,
                errnoValue: setNonblockingResult.errno
            )
        }

        guard descriptorAllowsSyscall(descriptor) else { throw SMBTransportError.connectionClosed }
        let connectResult = syscalls.connect(descriptor, address, length)
        if connectResult.value == 0 || connectResult.errno == EISCONN {
            try restoreBlockingFlags(flags, descriptor: descriptor)
            return
        }
        switch connectResult.errno {
        case EINTR, EINPROGRESS, EALREADY:
            break
        default:
            throw socketError(
                operation: "connect",
                descriptor: descriptor,
                errnoValue: connectResult.errno
            )
        }

        while true {
            guard descriptorAllowsSyscall(descriptor) else { throw SMBTransportError.connectionClosed }
            let pollTimeout = try connectPollTimeout(deadline: deadline)
            let pollResult = syscalls.poll(descriptor, Int16(POLLOUT), pollTimeout)

            if pollResult.value.result == 0 {
                // For an unbounded connect this is only the 100 ms retirement heartbeat.
                // For a finite connect, an early poll timeout is likewise not terminal
                // until the absolute monotonic deadline has actually elapsed.
                guard descriptorAllowsSyscall(descriptor) else { throw SMBTransportError.connectionClosed }
                if let deadline, syscalls.now() >= deadline { throw SMBTransportError.timedOut }
                continue
            }
            if pollResult.value.result < 0 {
                guard descriptorAllowsSyscall(descriptor) else { throw SMBTransportError.connectionClosed }
                if pollResult.errno == EINTR {
                    if let deadline, syscalls.now() >= deadline { throw SMBTransportError.timedOut }
                    continue
                }
                // In particular, Darwin's poll(2) EAGAIN is a syscall failure, not a
                // connect timeout (the generic socket error normalizer maps EAGAIN).
                throw SMBTransportError.socketFailure("poll failed: errno \(pollResult.errno)")
            }

            let revents = pollResult.value.revents
            if revents & Int16(POLLNVAL) != 0 {
                throw SMBTransportError.socketFailure("poll lease invariant violated: POLLNVAL")
            }
            let completionEvents = Int16(POLLOUT | POLLERR | POLLHUP)
            guard revents & completionEvents != 0 else {
                throw SMBTransportError.socketFailure("poll returned unexpected events: \(revents)")
            }

            // SO_ERROR is meaningful only after poll reports a positive completion event.
            guard descriptorAllowsSyscall(descriptor) else { throw SMBTransportError.connectionClosed }
            let socketErrorResult = syscalls.getSocketError(descriptor)
            guard socketErrorResult.value.result == 0 else {
                throw socketError(
                    operation: "getsockopt(SO_ERROR)",
                    descriptor: descriptor,
                    errnoValue: socketErrorResult.errno
                )
            }
            let socketErrorValue = socketErrorResult.value.socketError
            guard socketErrorValue == 0 else {
                if socketErrorValue == ETIMEDOUT { throw SMBTransportError.timedOut }
                throw SMBTransportError.socketFailure("connect failed: errno \(socketErrorValue)")
            }

            try restoreBlockingFlags(flags, descriptor: descriptor)
            return
        }
    }

    private func connectPollTimeout(deadline: ContinuousClock.Instant?) throws -> Int32 {
        guard let deadline else { return 100 }
        let remaining = syscalls.now().duration(to: deadline)
        guard remaining > .zero else { throw SMBTransportError.timedOut }
        return remaining.pollMillisecondsCeiling(maximum: 100)
    }

    private func restoreBlockingFlags(_ flags: Int32, descriptor: Int32) throws {
        // Restoration is part of confirming the connection. A terminal transition
        // prevents a new restoration syscall, and a transition during the syscall is
        // detected before the caller can promote the candidate.
        guard descriptorAllowsSyscall(descriptor) else { throw SMBTransportError.connectionClosed }
        let restoreResult = syscalls.fcntl(descriptor, F_SETFL, flags)
        guard restoreResult.value >= 0 else {
            throw socketError(
                operation: "fcntl(F_SETFL restore)",
                descriptor: descriptor,
                errnoValue: restoreResult.errno
            )
        }
        guard descriptorAllowsSyscall(descriptor) else { throw SMBTransportError.connectionClosed }
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
        guard descriptorAllowsSyscall(descriptor) else { throw SMBTransportError.connectionClosed }
        let result = syscalls.setSocketOption(descriptor, SOL_SOCKET, SO_NOSIGPIPE, &enabled, length)
        guard result.value == 0 else {
            throw socketError(
                operation: "setsockopt(SO_NOSIGPIPE)",
                descriptor: descriptor,
                errnoValue: result.errno
            )
        }
        #endif
    }

    private func applySocketTimeoutIfNeeded(_ descriptor: Int32) throws {
        guard let timeout else { return }
        var value = timeout.timevalValue
        let length = socklen_t(MemoryLayout<timeval>.size)
        guard descriptorAllowsSyscall(descriptor) else { throw SMBTransportError.connectionClosed }
        let receiveResult = syscalls.setSocketOption(descriptor, SOL_SOCKET, SO_RCVTIMEO, &value, length)
        guard receiveResult.value == 0 else {
            throw socketError(
                operation: "setsockopt(SO_RCVTIMEO)",
                descriptor: descriptor,
                errnoValue: receiveResult.errno
            )
        }
        var sendValue = timeout.timevalValue
        guard descriptorAllowsSyscall(descriptor) else { throw SMBTransportError.connectionClosed }
        let sendResult = syscalls.setSocketOption(descriptor, SOL_SOCKET, SO_SNDTIMEO, &sendValue, length)
        guard sendResult.value == 0 else {
            throw socketError(
                operation: "setsockopt(SO_SNDTIMEO)",
                descriptor: descriptor,
                errnoValue: sendResult.errno
            )
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

    private func acquireOpenDescriptorLease() throws -> Int32 {
        connectionLock.lock()
        defer { connectionLock.unlock() }
        guard case .open(let descriptor) = connectionState,
              var record = descriptorLeaseRecords[descriptor],
              !record.retired else {
            throw SMBTransportError.connectionClosed
        }
        record.leaseCount += 1
        descriptorLeaseRecords[descriptor] = record
        return descriptor
    }

    private func releaseDescriptorLease(_ descriptor: Int32) {
        connectionLock.lock()
        guard var record = descriptorLeaseRecords[descriptor] else {
            connectionLock.unlock()
            assertionFailure("released an unknown POSIX descriptor lease")
            return
        }
        assert(record.leaseCount > 0, "POSIX descriptor lease count underflow")
        record.leaseCount -= 1
        let closeClaimed = claimCloseIfEligible(record: &record)
        descriptorLeaseRecords[descriptor] = record
        connectionLock.unlock()

        closeClaimedDescriptorIfNeeded(descriptor, claimed: closeClaimed)
    }

    /// Admission check for a syscall on a leased descriptor.
    ///
    /// This is deliberately not atomic with the syscall itself: a terminal transition can
    /// land between the check and the call, so one in-flight syscall may still run after
    /// retirement. That is safe for the race this lease machinery exists to prevent
    /// (issues/073) — the lease keeps the descriptor from being closed and reused, so the
    /// late syscall reaches the same, already shut-down open-file description rather than an
    /// unrelated fd. Making it strictly atomic would require holding `connectionLock` across
    /// a blocking syscall, which deadlocks the terminal transition that must interrupt it.
    private func descriptorAllowsSyscall(_ descriptor: Int32) -> Bool {
        connectionLock.lock()
        defer { connectionLock.unlock() }
        guard let record = descriptorLeaseRecords[descriptor] else { return false }
        return record.leaseCount > 0 && !record.retired
    }

    private func isSocketOpen(_ descriptor: Int32) -> Bool {
        connectionLock.lock()
        defer { connectionLock.unlock() }
        guard case .open(let currentDescriptor) = connectionState,
              currentDescriptor == descriptor,
              let record = descriptorLeaseRecords[descriptor] else {
            return false
        }
        return !record.retired
    }

    private func isConnectionTerminal() -> Bool {
        connectionLock.lock()
        defer { connectionLock.unlock() }
        switch connectionState {
        case .closed, .poisoned:
            return true
        case .idle, .connecting, .open:
            return false
        }
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
        descriptorLeaseRecords[descriptor] = DescriptorLeaseRecord(leaseCount: 1)
        return true
    }

    private func finishConnectingCandidate(
        _ descriptor: Int32,
        promote: Bool
    ) -> (promoted: Bool, closeClaimed: Bool) {
        connectionLock.lock()
        defer { connectionLock.unlock() }
        guard var record = descriptorLeaseRecords[descriptor] else {
            assertionFailure("finished an unknown POSIX connecting descriptor")
            return (false, false)
        }
        assert(record.leaseCount > 0, "POSIX candidate lease count underflow")

        let canPromote: Bool
        if case .connecting = connectionState {
            canPromote = promote && connectingDescriptor == descriptor && !record.retired
        } else {
            canPromote = false
        }

        if canPromote {
            connectingDescriptor = -1
            connectionState = .open(descriptor)
        } else {
            if connectingDescriptor == descriptor {
                connectingDescriptor = -1
            }
            if !record.retired {
                record.retired = true
                record.shutdownRequired = false
                record.shutdownAttemptCompleted = true
            }
        }

        record.leaseCount -= 1
        let closeClaimed = claimCloseIfEligible(record: &record)
        descriptorLeaseRecords[descriptor] = record
        return (canPromote, closeClaimed)
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

        for descriptor in descriptors {
            guard var record = descriptorLeaseRecords[descriptor] else {
                assertionFailure("terminal transition found an unknown POSIX descriptor")
                continue
            }
            record.retired = true
            record.shutdownRequired = true
            record.shutdownAttemptCompleted = false
            descriptorLeaseRecords[descriptor] = record
        }
        return descriptors
    }

    private func poison() {
        retireAndInterruptDescriptors(transitionToTerminal(.poisoned))
    }

    private func retireAndInterruptDescriptors(_ descriptors: [Int32]) {
        for descriptor in descriptors {
            shutdownDescriptor(descriptor)
            markShutdownAttemptCompleted(descriptor)
        }
    }

    private func markShutdownAttemptCompleted(_ descriptor: Int32) {
        connectionLock.lock()
        guard var record = descriptorLeaseRecords[descriptor] else {
            connectionLock.unlock()
            assertionFailure("completed shutdown for an unknown POSIX descriptor")
            return
        }
        assert(record.shutdownRequired, "completed an unrequired POSIX descriptor shutdown")
        record.shutdownAttemptCompleted = true
        let closeClaimed = claimCloseIfEligible(record: &record)
        descriptorLeaseRecords[descriptor] = record
        connectionLock.unlock()

        closeClaimedDescriptorIfNeeded(descriptor, claimed: closeClaimed)
    }

    private func claimCloseIfEligible(record: inout DescriptorLeaseRecord) -> Bool {
        guard record.retired,
              record.leaseCount == 0,
              record.shutdownAttemptCompleted,
              !record.closeClaimed else {
            return false
        }
        record.closeClaimed = true
        return true
    }

    private func closeClaimedDescriptorIfNeeded(_ descriptor: Int32, claimed: Bool) {
        guard claimed else { return }
        closeDescriptor(descriptor)

        connectionLock.lock()
        if descriptorLeaseRecords[descriptor]?.closeClaimed == true {
            descriptorLeaseRecords.removeValue(forKey: descriptor)
        }
        connectionLock.unlock()
    }

    private func socketError(
        operation: String,
        descriptor: Int32? = nil,
        errnoValue: Int32? = nil
    ) -> Error {
        let errnoValue = errnoValue ?? DarwinOrGlibc.errnoValue
        if isConnectionTerminal() {
            return SMBTransportError.connectionClosed
        }
        if errnoValue == EAGAIN || errnoValue == EWOULDBLOCK || errnoValue == ETIMEDOUT {
            return SMBTransportError.timedOut
        }
        if errnoValue == EBADF || errnoValue == EINTR {
            return SMBTransportError.connectionClosed
        }
        _ = descriptor
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

    func pollMillisecondsCeiling(maximum: Int32) -> Int32 {
        precondition(maximum > 0)
        guard self < .milliseconds(Int64(maximum)) else { return maximum }
        let attosecondsPerMillisecond: Int64 = 1_000_000_000_000_000
        let attoseconds = max(0, components.attoseconds)
        let roundedFraction = (attoseconds + attosecondsPerMillisecond - 1) / attosecondsPerMillisecond
        let milliseconds = max(1, max(0, components.seconds) * 1_000 + roundedFraction)
        return Int32(min(milliseconds, Int64(maximum)))
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

    static func socket(_ family: Int32, _ type: Int32, _ protocolValue: Int32) -> Int32 {
        #if os(Linux)
        Glibc.socket(family, type, protocolValue)
        #else
        Darwin.socket(family, type, protocolValue)
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
