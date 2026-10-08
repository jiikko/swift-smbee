import Foundation
import XCTest
@testable import SMBee

#if os(Linux)
import Glibc
#else
import Darwin
#endif

final class POSIXSocketTransportReceiveTests: XCTestCase {
    func testReceiveReturnsOnlyBytesWrittenBySmallRead() async throws {
        let payload: [UInt8] = [0x12, 0x34]
        let reader = POSIXReceiveReaderScript(bytes: payload, returnedCount: payload.count)
        let lifecycle = POSIXReceiveLifecycleRecorder()
        let transport = makeTransport(reader: reader, lifecycle: lifecycle)

        let received = try await transport.receive(maxLength: 8)

        XCTAssertEqual(received, payload)
        XCTAssertEqual(received.count, payload.count)
        XCTAssertEqual(reader.maxLengths, [8])
        assertCloseRunsOnce(transport, lifecycle: lifecycle)
    }

    func testReceiveReturnsFullLengthRead() async throws {
        let payload: [UInt8] = [0x10, 0x20, 0x30, 0x40]
        let reader = POSIXReceiveReaderScript(bytes: payload, returnedCount: payload.count)
        let lifecycle = POSIXReceiveLifecycleRecorder()
        let transport = makeTransport(reader: reader, lifecycle: lifecycle)

        let received = try await transport.receive(maxLength: payload.count)

        XCTAssertEqual(received, payload)
        XCTAssertEqual(received.count, payload.count)
        XCTAssertEqual(reader.maxLengths, [payload.count])
        assertCloseRunsOnce(transport, lifecycle: lifecycle)
    }

    func testReceiveMapsEOFToConnectionClosed() async throws {
        let reader = POSIXReceiveReaderScript(bytes: [], returnedCount: 0)
        let lifecycle = POSIXReceiveLifecycleRecorder()
        let transport = makeTransport(reader: reader, lifecycle: lifecycle)

        do {
            _ = try await transport.receive(maxLength: 8)
            XCTFail("EOF unexpectedly returned a byte array")
        } catch SMBTransportError.connectionClosed {
        } catch {
            XCTFail("EOF returned unexpected error: \(error)")
        }

        XCTAssertEqual(reader.callCount, 1)
        assertCloseRunsOnce(transport, lifecycle: lifecycle)
    }

    func testReceiveMapsNegativeReadUsingErrnoFromReader() async throws {
        let reader = POSIXReceiveReaderScript(bytes: [], returnedCount: -1, errnoValue: EIO)
        let lifecycle = POSIXReceiveLifecycleRecorder()
        let transport = makeTransport(reader: reader, lifecycle: lifecycle)

        do {
            _ = try await transport.receive(maxLength: 8)
            XCTFail("negative recv unexpectedly returned a byte array")
        } catch SMBTransportError.socketFailure("recv failed: errno 5") {
        } catch {
            XCTFail("negative recv returned unexpected error: \(error)")
        }

        XCTAssertEqual(reader.callCount, 1)
        assertCloseRunsOnce(transport, lifecycle: lifecycle)
    }

    func testReceiveRejectsReaderCountGreaterThanMaxLength() async throws {
        let reader = POSIXReceiveReaderScript(bytes: [1, 2, 3, 4], returnedCount: 5)
        let lifecycle = POSIXReceiveLifecycleRecorder()
        let transport = makeTransport(reader: reader, lifecycle: lifecycle)

        do {
            _ = try await transport.receive(maxLength: 4)
            XCTFail("reader count above maxLength unexpectedly succeeded")
        } catch SMBTransportError.socketFailure("recv returned invalid byte count") {
        } catch {
            XCTFail("oversized reader count returned unexpected error: \(error)")
        }

        XCTAssertEqual(reader.maxLengths, [4])
        assertCloseRunsOnce(transport, lifecycle: lifecycle)
    }

    func testCloseImmediatelyBeforeReaderWorkWaitsForLeaseToDrain() async throws {
        let lifecycle = POSIXReceiveLifecycleRecorder()
        let transportReference = POSIXReceiveTransportReference()
        let closeCountDuringRead = POSIXReceiveInteger()
        let reader = POSIXReceiveReaderScript(
            bytes: [0xA5],
            returnedCount: 1,
            beforeRead: {
                transportReference.closeTransport()
                closeCountDuringRead.store(lifecycle.closeCount)
            }
        )
        let transport = makeTransport(reader: reader, lifecycle: lifecycle)
        transportReference.set(transport)

        let received = try await transport.receive(maxLength: 8)

        XCTAssertEqual(received, [0xA5])
        XCTAssertEqual(received.count, 1)
        XCTAssertEqual(closeCountDuringRead.value, 0, "physical close must wait for the receive lease")
        XCTAssertEqual(lifecycle.events, [.shutdown(1), .close(1)])
        XCTAssertEqual(lifecycle.closeCount, 1)
        XCTAssertEqual(reader.maxLengths, [8])
    }

    private func makeTransport(
        reader: POSIXReceiveReaderScript,
        lifecycle: POSIXReceiveLifecycleRecorder
    ) -> POSIXSocketTransport {
        POSIXSocketTransport(
            writer: { _, bytes, offset in bytes.count - offset },
            reader: reader.read,
            shutdown: lifecycle.shutdown,
            close: lifecycle.close
        )
    }

    private func assertCloseRunsOnce(
        _ transport: POSIXSocketTransport,
        lifecycle: POSIXReceiveLifecycleRecorder,
        file: StaticString = #filePath,
        line: UInt = #line
    ) {
        transport.close()
        transport.close()
        XCTAssertEqual(lifecycle.shutdownCount, 1, file: file, line: line)
        XCTAssertEqual(lifecycle.closeCount, 1, file: file, line: line)
    }
}

private final class POSIXReceiveReaderScript: @unchecked Sendable {
    private let lock = NSLock()
    private let bytes: [UInt8]
    private let returnedCount: Int
    private let errnoValue: Int32
    private let beforeRead: (@Sendable () -> Void)?
    private var callCountStorage = 0
    private var maxLengthsStorage: [Int] = []

    init(
        bytes: [UInt8],
        returnedCount: Int,
        errnoValue: Int32 = 0,
        beforeRead: (@Sendable () -> Void)? = nil
    ) {
        self.bytes = bytes
        self.returnedCount = returnedCount
        self.errnoValue = errnoValue
        self.beforeRead = beforeRead
    }

    var callCount: Int { lock.withLock { callCountStorage } }
    var maxLengths: [Int] { lock.withLock { maxLengthsStorage } }

    func read(_ descriptor: Int32, _ buffer: UnsafeMutableRawPointer?, _ maxLength: Int) -> Int {
        _ = descriptor
        lock.withLock {
            callCountStorage += 1
            maxLengthsStorage.append(maxLength)
        }
        if let beforeRead {
            beforeRead()
        }
        let copyCount = min(bytes.count, maxLength)
        if copyCount > 0 {
            if let buffer {
                bytes.withUnsafeBytes { source in
                    if let baseAddress = source.baseAddress {
                        buffer.copyMemory(from: baseAddress, byteCount: copyCount)
                    }
                }
            }
        }
        setPOSIXReceiveErrno(errnoValue)
        return returnedCount
    }
}

private final class POSIXReceiveLifecycleRecorder: @unchecked Sendable {
    private let lock = NSLock()
    private var eventsStorage: [POSIXReceiveLifecycleEvent] = []

    var events: [POSIXReceiveLifecycleEvent] { lock.withLock { eventsStorage } }
    var shutdownCount: Int { events.filter { if case .shutdown = $0 { true } else { false } }.count }
    var closeCount: Int { events.filter { if case .close = $0 { true } else { false } }.count }

    func shutdown(_ descriptor: Int32) {
        lock.withLock { eventsStorage.append(.shutdown(descriptor)) }
    }

    func close(_ descriptor: Int32) {
        lock.withLock { eventsStorage.append(.close(descriptor)) }
    }
}

private enum POSIXReceiveLifecycleEvent: Equatable {
    case shutdown(Int32)
    case close(Int32)
}

private final class POSIXReceiveTransportReference: @unchecked Sendable {
    private let lock = NSLock()
    private weak var transport: POSIXSocketTransport?

    func set(_ transport: POSIXSocketTransport) {
        lock.withLock { self.transport = transport }
    }

    func closeTransport() {
        let current = lock.withLock { transport }
        if let current {
            current.close()
        }
    }
}

private final class POSIXReceiveInteger: @unchecked Sendable {
    private let lock = NSLock()
    private var storage = 0

    var value: Int { lock.withLock { storage } }

    func store(_ value: Int) {
        lock.withLock { storage = value }
    }
}

private func setPOSIXReceiveErrno(_ value: Int32) {
    #if os(Linux)
    Glibc.errno = value
    #else
    Darwin.errno = value
    #endif
}
