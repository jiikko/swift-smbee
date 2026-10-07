import Foundation
import XCTest
@testable import SMBee

/// issue 105 item 2: `POSIXSocketTransport(timeout:)` applies SO_RCVTIMEO to every recv. The
/// demand-driven session reader must not keep a recv pending while no response is outstanding,
/// otherwise an idle session longer than `timeout` is torn down by `.timedOut`.
final class SMBIdleReceiveTimeoutTests: XCTestCase {
    func testIdleSessionLongerThanSocketReceiveTimeoutStillServesTheNextRequest() async throws {
        let server = try POSIXLoopbackServer(mode: .serveFrames { request in
            let header = try SMB2Header.decode(request)
            guard header.command == SMB2Commands.echo else { return [] }
            var response = try SMB2Header(
                command: SMB2Commands.echo,
                credits: 1,
                messageId: header.messageId
            ).encode()
            response.append(contentsOf: [4, 0, 0, 0])
            return [response]
        })
        server.start()
        defer { server.close() }

        let receiveTimeout = Duration.milliseconds(100)
        let transport = POSIXSocketTransport(timeout: receiveTimeout)
        try await withHangGuard("connect") {
            try await transport.connect(host: "127.0.0.1", port: server.port)
        }
        let session = SMBSession(
            host: "127.0.0.1",
            port: server.port,
            credential: .anonymous,
            transport: transport
        )

        try await withHangGuard("first ECHO") { try await session.echo() }
        try await withHangGuard("reader becomes dormant") {
            while await session.receiveLoopRunningForTesting() {
                try await Task.sleep(for: .milliseconds(5))
            }
        }

        // sleep-ok: negative assertion: nothing must happen while the session is idle, so there
        // is no event to wait for. The idle span must exceed SO_RCVTIMEO for a pending recv to fail.
        try await Task.sleep(for: receiveTimeout * 4)

        try await withHangGuard("ECHO after idle longer than the receive timeout") {
            try await session.echo()
        }
        await session.closeTransportAndWait(cause: "test_idle_receive_timeout")
    }

    private func withHangGuard<T: Sendable>(
        _ label: String,
        operation: @escaping @Sendable () async throws -> T
    ) async throws -> T {
        try await withThrowingTaskGroup(of: T?.self) { group in
            group.addTask { try await operation() }
            group.addTask {
                try await Task.sleep(for: .seconds(5))
                return nil
            }
            defer { group.cancelAll() }
            guard let first = try await group.next(), let value = first else {
                throw SMBIdleReceiveTimeoutHang(label: label)
            }
            return value
        }
    }
}

private struct SMBIdleReceiveTimeoutHang: Error, CustomStringConvertible {
    let label: String
    var description: String { "hang guard expired: \(label)" }
}
