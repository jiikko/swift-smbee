import XCTest
@testable import SMBee

final class SMBWireDiagnosticsTests: XCTestCase {
    func testFirstFaultIsLoggedOnce() async {
        let capture = SMBWireLogCapture()
        SMBPerfLog.enabledOverride = true
        SMBPerfLog.testSink = { capture.append($0) }
        defer {
            SMBPerfLog.testSink = nil
            SMBPerfLog.enabledOverride = nil
        }
        let session = SMBSession(
            host: "test", port: 445,
            credential: SMBCredential(username: "", password: ""),
            transport: InMemoryTransport()
        )
        await session.failWireForTesting(error: SMBTransportError.socketFailure("first"))
        await session.failWireForTesting(error: SMBTransportError.timedOut)
        let faults = capture.messages.filter { $0.hasPrefix("[wire] first_fault") }
        XCTAssertEqual(faults.count, 1)
        XCTAssertTrue(faults[0].contains("SMBTransportError"))
    }

    func testCloseCauseAndVictimSnapshotAreLogged() async {
        let capture = SMBWireLogCapture()
        SMBPerfLog.enabledOverride = true
        SMBPerfLog.testSink = { capture.append($0) }
        defer {
            SMBPerfLog.testSink = nil
            SMBPerfLog.enabledOverride = nil
        }
        let session = SMBSession(
            host: "test", port: 445,
            credential: SMBCredential(username: "", password: ""),
            transport: InMemoryTransport()
        )
        let first = Task { try await session.parkPendingForTesting(messageId: 1, command: 8) }
        let second = Task { try await session.parkPendingForTesting(messageId: 2, command: 9) }
        for _ in 0..<100 {
            if await session.pendingCountForTesting() == 2 { break }
            try? await Task.sleep(for: .milliseconds(1))
        }
        let pendingCount = await session.pendingCountForTesting()
        XCTAssertEqual(pendingCount, 2)
        await session.closeTransport(cause: "unit_test", diagnosticError: SMBTransportError.timedOut)
        _ = try? await first.value
        _ = try? await second.value

        XCTAssertTrue(capture.messages.contains { $0.contains("[wire] close_transport cause=unit_test") })
        XCTAssertTrue(capture.messages.contains { $0.contains("[wire] victim count=2") })
    }
}

private final class SMBWireLogCapture: @unchecked Sendable {
    private let lock = NSLock()
    private var storage: [String] = []

    var messages: [String] {
        lock.withLock { storage }
    }

    func append(_ message: String) {
        lock.withLock { storage.append(message) }
    }
}
