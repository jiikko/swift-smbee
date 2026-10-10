import Foundation

public struct SMB2Header: Equatable, Sendable {
    public static let encodedSize = 64

    public var creditCharge: UInt16
    public var status: UInt32
    public var command: UInt16
    public var credits: UInt16
    public var flags: UInt32
    public var nextCommand: UInt32
    public var messageId: UInt64
    public var treeId: UInt32
    public var sessionId: UInt64
    public var signature: [UInt8]
    /// MS-SMB2 §2.2.1.1: with SMB2_FLAGS_ASYNC_COMMAND, header bytes 32–39 are a single
    /// 64-bit AsyncId — there is no TreeId in an async header. Invariant maintained by
    /// encode/decode: async headers carry `asyncId != nil` and `treeId == 0`; sync headers
    /// carry `asyncId == nil`.
    public var asyncId: UInt64?

    public var isAsync: Bool {
        (flags & SMB2Flags.asyncCommand) != 0
    }

    public init(
        creditCharge: UInt16 = 0,
        status: UInt32 = 0,
        command: UInt16,
        credits: UInt16 = 1,
        flags: UInt32 = 0,
        nextCommand: UInt32 = 0,
        messageId: UInt64,
        treeId: UInt32 = 0,
        sessionId: UInt64 = 0,
        signature: [UInt8] = Array(repeating: 0, count: 16),
        asyncId: UInt64? = nil
    ) {
        self.creditCharge = creditCharge
        self.status = status
        self.command = command
        self.credits = credits
        self.flags = flags
        self.nextCommand = nextCommand
        self.messageId = messageId
        self.treeId = treeId
        self.sessionId = sessionId
        self.signature = signature
        self.asyncId = asyncId
    }

    /// Builds an async-form header (SMB2_FLAGS_ASYNC_COMMAND set, AsyncId in bytes 32–39).
    public static func asyncHeader(
        creditCharge: UInt16 = 0,
        status: UInt32 = 0,
        command: UInt16,
        credits: UInt16 = 1,
        flags: UInt32 = 0,
        nextCommand: UInt32 = 0,
        messageId: UInt64,
        asyncId: UInt64,
        sessionId: UInt64 = 0,
        signature: [UInt8] = Array(repeating: 0, count: 16)
    ) -> SMB2Header {
        SMB2Header(
            creditCharge: creditCharge,
            status: status,
            command: command,
            credits: credits,
            flags: flags | SMB2Flags.asyncCommand,
            nextCommand: nextCommand,
            messageId: messageId,
            treeId: 0,
            sessionId: sessionId,
            signature: signature,
            asyncId: asyncId
        )
    }

    public func encode() throws -> [UInt8] {
        guard signature.count == 16 else {
            throw SMBCodecError.invalidValue("SMB2 signature must be 16 bytes")
        }
        if isAsync {
            // Client-side encoding only produces async headers for CANCEL, whose AsyncId
            // comes from a server interim; server-generated AsyncIds are nonzero
            // (MS-SMB2 §3.3.4.2), so zero here always means lost tracking.
            guard let asyncId, asyncId != 0 else {
                throw SMBCodecError.invalidValue("SMB2 async header requires a nonzero asyncId")
            }
            guard treeId == 0 else {
                throw SMBCodecError.invalidValue("SMB2 async header carries no TreeId")
            }
        } else if asyncId != nil {
            throw SMBCodecError.invalidValue("SMB2 sync header must not carry an asyncId")
        }
        var writer = SMBByteWriter()
        writer.writeBytes([0xfe, 0x53, 0x4d, 0x42])
        writer.writeUInt16LE(64)
        writer.writeUInt16LE(creditCharge)
        writer.writeUInt32LE(status)
        writer.writeUInt16LE(command)
        writer.writeUInt16LE(credits)
        writer.writeUInt32LE(flags)
        writer.writeUInt32LE(nextCommand)
        writer.writeUInt64LE(messageId)
        if let asyncId {
            writer.writeUInt64LE(asyncId)
        } else {
            writer.writeUInt32LE(0)
            writer.writeUInt32LE(treeId)
        }
        writer.writeUInt64LE(sessionId)
        writer.writeBytes(signature)
        return writer.bytes
    }

    public static func decode(_ bytes: [UInt8]) throws -> SMB2Header {
        guard bytes.count >= encodedSize else { throw SMBCodecError.truncated }
        guard bytes[0] == 0xfe, bytes[1] == 0x53, bytes[2] == 0x4d, bytes[3] == 0x42 else {
            throw SMBCodecError.invalidValue(
                "invalid SMB2 protocol id: length=\(bytes.count)"
            )
        }
        guard readUInt16LE(bytes, at: 4) == 64 else {
            throw SMBCodecError.invalidValue("invalid SMB2 header size")
        }
        let creditCharge = readUInt16LE(bytes, at: 6)
        let status = readUInt32LE(bytes, at: 8)
        let command = readUInt16LE(bytes, at: 12)
        let credits = readUInt16LE(bytes, at: 14)
        let flags = readUInt32LE(bytes, at: 16)
        let nextCommand = readUInt32LE(bytes, at: 20)
        let messageId = readUInt64LE(bytes, at: 24)
        let asyncId: UInt64?
        let treeId: UInt32
        if (flags & SMB2Flags.asyncCommand) != 0 {
            asyncId = readUInt64LE(bytes, at: 32)
            treeId = 0
        } else {
            treeId = readUInt32LE(bytes, at: 36)
            asyncId = nil
        }
        let sessionId = readUInt64LE(bytes, at: 40)
        let signature = Array(bytes[48..<64])
        return SMB2Header(
            creditCharge: creditCharge,
            status: status,
            command: command,
            credits: credits,
            flags: flags,
            nextCommand: nextCommand,
            messageId: messageId,
            treeId: treeId,
            sessionId: sessionId,
            signature: signature,
            asyncId: asyncId
        )
    }

    private static func readUInt16LE(_ bytes: [UInt8], at offset: Int) -> UInt16 {
        UInt16(bytes[offset]) | (UInt16(bytes[offset + 1]) << 8)
    }

    private static func readUInt32LE(_ bytes: [UInt8], at offset: Int) -> UInt32 {
        UInt32(bytes[offset])
            | (UInt32(bytes[offset + 1]) << 8)
            | (UInt32(bytes[offset + 2]) << 16)
            | (UInt32(bytes[offset + 3]) << 24)
    }

    private static func readUInt64LE(_ bytes: [UInt8], at offset: Int) -> UInt64 {
        UInt64(readUInt32LE(bytes, at: offset)) | (UInt64(readUInt32LE(bytes, at: offset + 4)) << 32)
    }
}

enum SMB2Credit {
    static let unitSize = 65_536
    // 256 credits permits approximately 16 MiB of outstanding read capacity while
    // remaining comfortably below typical per-connection server limits.
    static let targetWindowCredits: UInt32 = 256

    static func creditRequest(balance: UInt32, charge: UInt16, target: UInt32) -> UInt16 {
        guard balance < target else { return charge }
        let deficit = target - balance
        let requested = max(UInt32(charge), deficit)
        return UInt16(min(requested, min(target, UInt32(UInt16.max))))
    }

    // SMB2 header field offsets (little-endian): CreditCharge=6, Command=12, CreditRequest=14.
    static let creditChargeFieldOffset = 6
    static let commandFieldOffset = 12
    static let creditRequestFieldOffset = 14

    /// Patch the CreditRequest field (offset 14, UInt16 LE) of an outgoing *plaintext*
    /// SMB2 request toward `target`, so the credit window grows past its starved initial
    /// value. Returns without mutating when the packet is too short, or for CANCEL
    /// (credit-exempt, MS-SMB2 §3.2.4.1.2). Reads CreditCharge (offset 6) and Command
    /// (offset 12) but never mutates them. Must run *before* signing/encryption.
    static func patchCreditRequest(into packet: inout [UInt8], balance: UInt32, target: UInt32) {
        guard packet.count >= creditRequestFieldOffset + 2 else { return }
        let command = UInt16(packet[commandFieldOffset]) | (UInt16(packet[commandFieldOffset + 1]) << 8)
        guard command != SMB2Commands.cancel else { return }
        let charge = UInt16(packet[creditChargeFieldOffset]) | (UInt16(packet[creditChargeFieldOffset + 1]) << 8)
        let request = creditRequest(balance: balance, charge: charge, target: target)
        packet[creditRequestFieldOffset] = UInt8(request & 0xff)
        packet[creditRequestFieldOffset + 1] = UInt8((request >> 8) & 0xff)
    }

    static func charge(forPayloadLength length: UInt64) -> UInt16 {
        let charge = max(1, (length + UInt64(unitSize) - 1) / UInt64(unitSize))
        return UInt16(min(charge, UInt64(UInt16.max)))
    }

    static func charge(forPayloadLength length: Int) -> UInt16 {
        charge(forPayloadLength: UInt64(max(0, length)))
    }

    static func balanceAfterSending(current: UInt32, charge: UInt16) -> UInt32 {
        current > UInt32(charge) ? current - UInt32(charge) : 0
    }

    static func balanceAfterReceiving(current: UInt32, granted: UInt16) -> UInt32 {
        let (sum, overflow) = current.addingReportingOverflow(UInt32(granted))
        return overflow ? UInt32.max : sum
    }
}

private final class SMB2CreditWindowFastState: @unchecked Sendable {
    struct Reservation: Sendable {
        let charge: UInt16
        let remainingBalance: UInt32
    }

    private let lock = NSLock()
    private var available: UInt32
    private var failed = false
    private var waitersPending = false
    private var servicingWaiters = false
    private var acquisitionHookInstalled = false
    private var grantHookInstalled = false
    private var receivedGrantReceiptCount = 0

    init(initialCredits: UInt32) {
        available = initialCredits
    }

    var balance: UInt32 {
        lock.withLock { available }
    }

    var grantReceiptCount: Int {
        lock.withLock { receivedGrantReceiptCount }
    }

    func setAcquisitionHookInstalled(_ installed: Bool) {
        lock.withLock { acquisitionHookInstalled = installed }
    }

    func setGrantHookInstalled(_ installed: Bool) {
        lock.withLock { grantHookInstalled = installed }
    }

    func tryReserve(
        upTo requestedCharge: UInt16,
        minimumCharge: UInt16,
        onlyWithoutHooks: Bool
    ) -> Reservation? {
        lock.withLock {
            guard !failed, !servicingWaiters,
                  !onlyWithoutHooks || !acquisitionHookInstalled,
                  requestedCharge > 0, minimumCharge > 0,
                  available >= UInt32(minimumCharge) else {
                return nil
            }
            let charge = min(UInt32(requestedCharge), available)
            available -= charge
            return Reservation(charge: UInt16(charge), remainingBalance: available)
        }
    }

    func reserveForWaiter(upTo requestedCharge: UInt16) -> Reservation? {
        lock.withLock {
            guard !failed, requestedCharge > 0, available > 0 else { return nil }
            let charge = min(UInt32(requestedCharge), available)
            available -= charge
            return Reservation(charge: UInt16(charge), remainingBalance: available)
        }
    }

    func grantSynchronously(totalCredits: UInt64, receiptCount: Int) -> UInt32? {
        lock.withLock {
            guard !failed, !waitersPending, !servicingWaiters, !grantHookInstalled else { return nil }
            return applyGrant(totalCredits: totalCredits, receiptCount: receiptCount)
        }
    }

    func grantFromActor(totalCredits: UInt64, receiptCount: Int) -> UInt32 {
        lock.withLock {
            guard !failed else { return available }
            servicingWaiters = waitersPending
            return applyGrant(totalCredits: totalCredits, receiptCount: receiptCount)
        }
    }

    func refund(_ charge: UInt16) -> UInt32 {
        lock.withLock {
            guard !failed, charge > 0 else { return available }
            servicingWaiters = waitersPending
            available = SMB2Credit.balanceAfterReceiving(current: available, granted: charge)
            return available
        }
    }

    func setWaitersPending(_ pending: Bool) {
        lock.withLock { waitersPending = pending }
    }

    func beginWaiterDrain() {
        lock.withLock { servicingWaiters = waitersPending }
    }

    func endWaiterDrain(waitersPending: Bool) {
        lock.withLock {
            self.waitersPending = waitersPending
            servicingWaiters = false
        }
    }

    func markFailed() {
        lock.withLock { failed = true }
    }

    func reset(initialCredits: UInt32) {
        lock.withLock {
            available = initialCredits
            failed = false
            waitersPending = false
            servicingWaiters = false
            receivedGrantReceiptCount = 0
        }
    }

    private func applyGrant(totalCredits: UInt64, receiptCount: Int) -> UInt32 {
        let (sum, overflow) = UInt64(available).addingReportingOverflow(totalCredits)
        available = overflow || sum > UInt64(UInt32.max) ? UInt32.max : UInt32(sum)
        receivedGrantReceiptCount += receiptCount
        return available
    }
}

actor SMB2CreditWindow {
    private enum State {
        case active
        case failed(Error)
    }

    private struct Waiter {
        let charge: UInt16
        let minimumCharge: UInt16
        let id: UInt64
        let messageId: UInt64?
        let command: UInt16?
        let enqueuedAt: ContinuousClock.Instant?
        let continuation: CheckedContinuation<SMB2CreditWindowFastState.Reservation, Error>
    }

    private struct PendingWaiterCountObserver {
        let id: UInt64
        let target: Int
        let continuation: CheckedContinuation<Void, Never>
    }

    private nonisolated let fastState: SMB2CreditWindowFastState
    private var grantActorHookForTesting: (@Sendable () async -> Void)?
    private let diagnosticSessionId: String
    private var waiters: [Waiter] = []
    private var waiterCountWaiters: [PendingWaiterCountObserver] = []
    private var nextWaiterId: UInt64 = 0
    private var nextWaiterCountObserverId: UInt64 = 0
    private var state: State = .active
    private var reservationAcquiredHookForTesting: (@Sendable (UInt16) async -> Void)?

    init(initialCredits: UInt32 = 1, diagnosticSessionId: String) {
        fastState = SMB2CreditWindowFastState(initialCredits: initialCredits)
        self.diagnosticSessionId = diagnosticSessionId
    }

    var balance: UInt32 {
        fastState.balance
    }

    nonisolated var balanceSnapshot: UInt32 {
        fastState.balance
    }

    nonisolated func reserveIfAvailable(charge: UInt16) -> UInt32? {
        fastState.tryReserve(upTo: charge, minimumCharge: charge, onlyWithoutHooks: true)?.remainingBalance
    }

    nonisolated func reserveUpToIfAvailable(maximumCharge: UInt16) -> UInt16? {
        fastState.tryReserve(upTo: maximumCharge, minimumCharge: 1, onlyWithoutHooks: true)?.charge
    }

    nonisolated func grantIfUncontended(totalCredits: UInt64, receiptCount: Int) -> UInt32? {
        fastState.grantSynchronously(totalCredits: totalCredits, receiptCount: receiptCount)
    }

    var pendingWaiterCount: Int {
        waiters.count
    }

    func waitForPendingWaiterCount(atLeast count: Int) async {
        let id = nextWaiterCountObserverId
        nextWaiterCountObserverId &+= 1
        await withTaskCancellationHandler {
            await withCheckedContinuation { continuation in
                if Task.isCancelled || waiters.count >= count || isFailed {
                    continuation.resume()
                } else {
                    waiterCountWaiters.append(PendingWaiterCountObserver(
                        id: id,
                        target: count,
                        continuation: continuation
                    ))
                }
            }
        } onCancel: {
            Task { await self.cancelPendingWaiterCountObserver(id: id) }
        }
    }

    var pendingWaiterCountObserverCountForTesting: Int {
        waiterCountWaiters.count
    }

    func setReservationAcquiredHookForTesting(_ hook: (@Sendable (UInt16) async -> Void)?) {
        reservationAcquiredHookForTesting = hook
        fastState.setAcquisitionHookInstalled(hook != nil)
    }

    func reserve(
        charge requestedCharge: UInt16,
        messageId: UInt64? = nil,
        command: UInt16? = nil
    ) async throws -> UInt32 {
        let reservation = try await reserveCredits(
            upTo: requestedCharge,
            minimumCharge: requestedCharge,
            messageId: messageId,
            command: command
        )
        await reservationAcquiredHookForTesting?(reservation.charge)
        return reservation.remainingBalance
    }

    /// Atomically reserves up to `maximumCharge`, but wakes as soon as one credit is
    /// available. Variable length READ/WRITE callers then size the packet to the exact
    /// reservation. This avoids parking behind a stale multi-credit size estimate when a
    /// server grants fewer credits than the prior request consumed.
    func reserveUpTo(
        maximumCharge: UInt16,
        messageId: UInt64? = nil,
        command: UInt16? = nil
    ) async throws -> UInt16 {
        try await reserveUpTo(
            maximumCharge: maximumCharge,
            waitIfUnavailable: true,
            messageId: messageId,
            command: command
        )
    }

    /// Performs the same immediate reservation as `reserveUpTo`, but optionally returns
    /// charge zero instead of joining the FIFO waiter queue. A non-waiting attempt does not
    /// consume credits ahead of an already parked waiter.
    func reserveUpTo(
        maximumCharge: UInt16,
        waitIfUnavailable: Bool,
        messageId: UInt64? = nil,
        command: UInt16? = nil
    ) async throws -> UInt16 {
        try await reserveUpToResult(
            maximumCharge: maximumCharge,
            waitIfUnavailable: waitIfUnavailable,
            messageId: messageId,
            command: command
        ).charge
    }

    /// Reserves credits and returns the remaining shared balance from the same actor turn.
    /// READ admission uses the balance to avoid a second, empty reservation after consuming
    /// the last credit in a single-credit stream.
    func reserveUpToWithBalance(
        maximumCharge: UInt16,
        waitIfUnavailable: Bool,
        messageId: UInt64? = nil,
        command: UInt16? = nil
    ) async throws -> (charge: UInt16, balance: UInt32) {
        let reservation = try await reserveUpToResult(
            maximumCharge: maximumCharge,
            waitIfUnavailable: waitIfUnavailable,
            messageId: messageId,
            command: command
        )
        return (reservation.charge, reservation.remainingBalance)
    }

    private func reserveUpToResult(
        maximumCharge: UInt16,
        waitIfUnavailable: Bool,
        messageId: UInt64?,
        command: UInt16?
    ) async throws -> SMB2CreditWindowFastState.Reservation {
        let reservation = try await reserveCredits(
            upTo: maximumCharge,
            minimumCharge: 1,
            messageId: messageId,
            command: command,
            waitIfUnavailable: waitIfUnavailable,
            preserveWaiterFIFO: !waitIfUnavailable
        )
        if waitIfUnavailable || reservation.charge > 0 {
            await reservationAcquiredHookForTesting?(reservation.charge)
        }
        return reservation
    }

    private func reserveCredits(
        upTo requestedCharge: UInt16,
        minimumCharge: UInt16,
        messageId: UInt64?,
        command: UInt16?,
        waitIfUnavailable: Bool = true,
        preserveWaiterFIFO: Bool = false
    ) async throws -> SMB2CreditWindowFastState.Reservation {
        if case .failed(let error) = state {
            throw error
        }
        guard requestedCharge > 0, minimumCharge > 0 else {
            return SMB2CreditWindowFastState.Reservation(charge: 0, remainingBalance: balance)
        }
        if !preserveWaiterFIFO || waiters.isEmpty,
           let reservation = fastState.tryReserve(
               upTo: requestedCharge,
               minimumCharge: minimumCharge,
               onlyWithoutHooks: false
           ) {
            return reservation
        }
        guard waitIfUnavailable else {
            return SMB2CreditWindowFastState.Reservation(charge: 0, remainingBalance: balance)
        }
        let id = nextWaiterId
        nextWaiterId += 1
        // A waiter blocks until the server grants credits; if no response is coming
        // (cancelled operation, dead session) that wait must not outlive the task
        // (issues/013). Cancellation removes the waiter and throws.
        return try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                if Task.isCancelled {
                    continuation.resume(throwing: CancellationError())
                    return
                }
                if case .failed(let error) = state {
                    continuation.resume(throwing: error)
                    return
                }
                let enqueuedAt = SMBPerfLog.effectiveIsEnabled ? ContinuousClock.now : nil
                fastState.setWaitersPending(true)
                waiters.append(Waiter(
                    charge: requestedCharge,
                    minimumCharge: minimumCharge,
                    id: id,
                    messageId: messageId,
                    command: command,
                    enqueuedAt: enqueuedAt,
                    continuation: continuation
                ))
                resumeWaiterCountWaiters()
                SMBPerfLog.line(
                    "[wire] credit_wait session=\(diagnosticSessionId) " +
                        "\(Self.identityFields(messageId: messageId, command: command))" +
                        "charge=\(requestedCharge) available=\(balance) waiters=\(waiters.count) " +
                        "ts_ns=\(SMBPerfLog.timestampNanoseconds())"
                )
                resumeReadyWaiters()
            }
        } onCancel: {
            Task { await self.cancelWaiter(id: id) }
        }
    }

    /// Teardown drain: every parked waiter is resumed with `error`. Without this, waiters
    /// leak when the session dies while credits are exhausted (issues/010 §B — grant only
    /// arrives from received responses, which stop on transport failure).
    func failAllWaiters(_ error: Error) {
        SMBPerfLog.line("[wire] victim_credit_waiters session=\(diagnosticSessionId) count=\(waiters.count)")
        fastState.markFailed()
        state = .failed(error)
        let parked = waiters
        waiters.removeAll()
        fastState.setWaitersPending(false)
        resumeAllWaiterCountObservers()
        for waiter in parked {
            waiter.continuation.resume(throwing: error)
        }
    }

    func reset(initialCredits: UInt32) {
        let parked = waiters
        waiters.removeAll()
        fastState.setWaitersPending(false)
        resumeAllWaiterCountObservers()
        for waiter in parked {
            waiter.continuation.resume(throwing: CancellationError())
        }
        fastState.reset(initialCredits: initialCredits)
        state = .active
    }

    private func cancelWaiter(id: UInt64) {
        guard let index = waiters.firstIndex(where: { $0.id == id }) else { return }
        fastState.beginWaiterDrain()
        let waiter = waiters.remove(at: index)
        waiter.continuation.resume(throwing: CancellationError())
        resumeWaiterCountWaiters()
        resumeReadyWaiters()
    }

    func grant(_ credits: UInt16) async -> UInt32 {
        await grant(totalCredits: UInt64(credits), receiptCount: 1)
    }

    /// Applies all validated slices from one response chain in a single actor hop while
    /// retaining one receipt count per slice. Adding nonnegative grants in one saturated
    /// batch is equivalent to applying them individually in wire order.
    func grant(totalCredits: UInt64, receiptCount: Int) async -> UInt32 {
        await grantActorHookForTesting?()
        if case .failed = state { return balance }
        _ = fastState.grantFromActor(totalCredits: totalCredits, receiptCount: receiptCount)
        resumeReadyWaiters()
        return balance
    }

    func grantReceiptCountForTesting() -> Int {
        fastState.grantReceiptCount
    }

    func setGrantActorHookForTesting(_ hook: (@Sendable () async -> Void)?) {
        grantActorHookForTesting = hook
        fastState.setGrantHookInstalled(hook != nil)
    }

    func refund(charge requestedCharge: UInt16) -> UInt32 {
        if case .failed = state { return balance }
        let refundedBalance = fastState.refund(requestedCharge)
        resumeReadyWaiters()
        return refundedBalance
    }

    private func resumeReadyWaiters() {
        // FIFO on purpose: only the head waiter is considered, even when a later waiter's
        // smaller charge would fit the current balance. First-fit would let a stream of
        // small requests starve a large multi-credit READ/WRITE indefinitely; the cost is
        // head-of-line blocking while the window refills (issues/012 §3).
        fastState.beginWaiterDrain()
        while let waiter = waiters.first, balance >= UInt32(waiter.minimumCharge) {
            waiters.removeFirst()
            guard let reservation = fastState.reserveForWaiter(upTo: waiter.charge) else { break }
            if let enqueuedAt = waiter.enqueuedAt {
                SMBPerfLog.line(
                    "[wire] credit_granted session=\(diagnosticSessionId) " +
                        "\(Self.identityFields(messageId: waiter.messageId, command: waiter.command))" +
                        "charge=\(reservation.charge) " +
                        "waited_ms=\(SMBPerfLog.milliseconds(ContinuousClock.now - enqueuedAt)) " +
                        "ts_ns=\(SMBPerfLog.timestampNanoseconds())"
                )
            }
            waiter.continuation.resume(returning: reservation)
        }
        fastState.endWaiterDrain(waitersPending: !waiters.isEmpty)
        resumeWaiterCountWaiters()
    }

    private func resumeWaiterCountWaiters() {
        var remaining: [PendingWaiterCountObserver] = []
        for observer in waiterCountWaiters {
            if waiters.count >= observer.target {
                observer.continuation.resume()
            } else {
                remaining.append(observer)
            }
        }
        waiterCountWaiters = remaining
    }

    private func resumeAllWaiterCountObservers() {
        let observers = waiterCountWaiters
        waiterCountWaiters.removeAll()
        for observer in observers {
            observer.continuation.resume()
        }
    }

    private func cancelPendingWaiterCountObserver(id: UInt64) {
        guard let index = waiterCountWaiters.firstIndex(where: { $0.id == id }) else { return }
        let observer = waiterCountWaiters.remove(at: index)
        observer.continuation.resume()
    }

    private var isFailed: Bool {
        if case .failed = state { return true }
        return false
    }

    private static func identityFields(messageId: UInt64?, command: UInt16?) -> String {
        var fields = ""
        if let messageId {
            fields += "message_id=\(messageId) "
        }
        if let command {
            fields += "command=\(command) "
        }
        return fields
    }
}
