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
        signature: [UInt8] = Array(repeating: 0, count: 16)
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
    }

    public func encode() throws -> [UInt8] {
        guard signature.count == 16 else {
            throw SMBCodecError.invalidValue("SMB2 signature must be 16 bytes")
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
        writer.writeUInt32LE(0)
        writer.writeUInt32LE(treeId)
        writer.writeUInt64LE(sessionId)
        writer.writeBytes(signature)
        return writer.bytes
    }

    public static func decode(_ bytes: [UInt8]) throws -> SMB2Header {
        guard bytes.count >= encodedSize else { throw SMBCodecError.truncated }
        var reader = SMBByteReader(bytes: bytes)
        let protocolId = try reader.readBytes(count: 4)
        guard protocolId == [0xfe, 0x53, 0x4d, 0x42] else {
            throw SMBCodecError.invalidValue(
                "invalid SMB2 protocol id: firstBytes=\(SMBDebug.hexPrefix(bytes, count: 32)) length=\(bytes.count)"
            )
        }
        guard try reader.readUInt16LE() == 64 else {
            throw SMBCodecError.invalidValue("invalid SMB2 header size")
        }
        let creditCharge = try reader.readUInt16LE()
        let status = try reader.readUInt32LE()
        let command = try reader.readUInt16LE()
        let credits = try reader.readUInt16LE()
        let flags = try reader.readUInt32LE()
        let nextCommand = try reader.readUInt32LE()
        let messageId = try reader.readUInt64LE()
        try reader.skip(count: 4)
        let treeId = try reader.readUInt32LE()
        let sessionId = try reader.readUInt64LE()
        let signature = try reader.readBytes(count: 16)
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
            signature: signature
        )
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

actor SMB2CreditWindow {
    private enum State {
        case active
        case failed(Error)
    }

    private struct Waiter {
        let charge: UInt16
        let id: UInt64
        let continuation: CheckedContinuation<UInt32, Error>
    }

    private var available: UInt32
    private let diagnosticSessionId: String
    private var waiters: [Waiter] = []
    private var nextWaiterId: UInt64 = 0
    private var state: State = .active

    init(initialCredits: UInt32 = 1, diagnosticSessionId: String) {
        self.available = initialCredits
        self.diagnosticSessionId = diagnosticSessionId
    }

    var balance: UInt32 {
        available
    }

    var pendingWaiterCount: Int {
        waiters.count
    }

    func reserve(charge requestedCharge: UInt16) async throws -> UInt32 {
        if case .failed(let error) = state {
            throw error
        }
        guard requestedCharge > 0 else { return available }
        let charge = requestedCharge
        if available >= UInt32(charge) {
            available -= UInt32(charge)
            return available
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
                waiters.append(Waiter(charge: charge, id: id, continuation: continuation))
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
        state = .failed(error)
        let parked = waiters
        waiters.removeAll()
        for waiter in parked {
            waiter.continuation.resume(throwing: error)
        }
    }

    func reset(initialCredits: UInt32) {
        let parked = waiters
        waiters.removeAll()
        for waiter in parked {
            waiter.continuation.resume(throwing: CancellationError())
        }
        available = initialCredits
        state = .active
    }

    private func cancelWaiter(id: UInt64) {
        guard let index = waiters.firstIndex(where: { $0.id == id }) else { return }
        let waiter = waiters.remove(at: index)
        waiter.continuation.resume(throwing: CancellationError())
        resumeReadyWaiters()
    }

    func grant(_ credits: UInt16) -> UInt32 {
        if case .failed = state { return available }
        available = SMB2Credit.balanceAfterReceiving(current: available, granted: credits)
        resumeReadyWaiters()
        return available
    }

    func refund(charge requestedCharge: UInt16) -> UInt32 {
        if case .failed = state { return available }
        guard requestedCharge > 0 else { return available }
        available = SMB2Credit.balanceAfterReceiving(current: available, granted: requestedCharge)
        resumeReadyWaiters()
        return available
    }

    private func resumeReadyWaiters() {
        // FIFO on purpose: only the head waiter is considered, even when a later waiter's
        // smaller charge would fit the current balance. First-fit would let a stream of
        // small requests starve a large multi-credit READ/WRITE indefinitely; the cost is
        // head-of-line blocking while the window refills (issues/012 §3).
        while let waiter = waiters.first, available >= UInt32(waiter.charge) {
            waiters.removeFirst()
            available -= UInt32(waiter.charge)
            waiter.continuation.resume(returning: available)
        }
    }
}
