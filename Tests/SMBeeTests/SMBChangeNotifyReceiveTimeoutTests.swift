import XCTest
@testable import SMBee

/// issue 108, policy C: preserve and document the socket receive timeout behavior for a quiet
/// CHANGE_NOTIFY long poll. If that behavior changes, rewrite this characterization test.
final class SMBChangeNotifyReceiveTimeoutTests: XCTestCase {
    func testQuietChangeNotifyTimesOutAndEndsWatchWithoutAutoReconnect() async throws {
        let bootstrapResponses = try SMBIssue102WireFixtures.anonymousSessionResponses()
        let observation = SMBChangeNotifyRequestObservation()
        let server = try POSIXLoopbackServer(mode: .serveFrames { request in
            let header = try SMB2Header.decode(request)
            switch header.command {
            case SMBNegotiateConstants.commandNegotiate:
                return [bootstrapResponses[0]]
            case SMB2Commands.sessionSetup:
                return [bootstrapResponses[Int(header.messageId)]]
            case SMB2Commands.treeConnect:
                return [bootstrapResponses[3]]
            case SMB2Commands.create:
                return [try Self.createResponse(for: header)]
            case SMB2Commands.changeNotify:
                observation.recordChangeNotify()
                // Deliberately send neither STATUS_PENDING nor a final response.
                return []
            default:
                return []
            }
        })
        server.start()
        defer { server.close() }

        let receiveTimeout = Duration.milliseconds(200)
        let client = try await smbIssue102AwaitWithTimeout("connect watch session") {
            try await SMBClient.connect(
                host: "127.0.0.1",
                port: server.port,
                share: "share",
                credential: .anonymous,
                timeout: receiveTimeout,
                requestTimeout: .seconds(5)
            )
        }
        let watcher = Task {
            try await client.withChangeNotifications(path: "dir", autoReconnect: false) { _ in }
        }

        do {
            try await smbIssue102AwaitWithTimeout("quiet CHANGE_NOTIFY receive timeout") {
                try await watcher.value
            }
            XCTFail("expected the quiet CHANGE_NOTIFY receive to time out")
        } catch let error as SMBTransportError {
            XCTAssertEqual(error, .timedOut)
        } catch {
            XCTFail("expected SMBTransportError.timedOut, got \(error)")
        }

        XCTAssertTrue(observation.sawChangeNotify, "the server must have received the long-poll request")
        await client.close()
    }

    private static func createResponse(for request: SMB2Header) throws -> [UInt8] {
        var response = try SMB2Header(
            command: SMB2Commands.create,
            credits: 1,
            messageId: request.messageId,
            treeId: request.treeId,
            sessionId: request.sessionId
        ).encode()
        response.append(contentsOf: Array(repeating: 0, count: 88))
        writeUInt16LE(89, to: &response, at: 64)
        response.replaceSubrange(128..<144, with: Array(repeating: 0x55, count: 16))
        return response
    }
}

private final class SMBChangeNotifyRequestObservation: @unchecked Sendable {
    private let lock = NSLock()
    private var sawChangeNotifyStorage = false

    var sawChangeNotify: Bool {
        lock.withLock { sawChangeNotifyStorage }
    }

    func recordChangeNotify() {
        lock.withLock { sawChangeNotifyStorage = true }
    }
}
