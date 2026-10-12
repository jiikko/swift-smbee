import XCTest
@testable import SMBee

final class SMBeeResourceLifecycleTests: XCTestCase {
    private let sessionId: UInt64 = 0x1122_3344_5566_7788
    private let treeId: UInt32 = 0x3344

    func testOneShotSuccessClosesTransportAfterGracefulTeardown() async throws {
        var echoResponse = try SMB2Header(
            command: SMB2Commands.echo,
            messageId: 4,
            treeId: treeId,
            sessionId: sessionId
        ).encode()
        echoResponse.append(contentsOf: [4, 0, 0, 0])

        let transport = SMBValidateNegotiateScriptTransport(
            inbound: try SMBIssue102WireFixtures.framed(
                SMBIssue102WireFixtures.anonymousSessionResponses() + [
                    echoResponse,
                    try statusResponse(command: SMB2Commands.treeDisconnect, messageId: 5, treeId: treeId),
                    try statusResponse(command: SMB2Commands.logoff, messageId: 6, treeId: 0)
                ]
            ),
            credential: .anonymous
        )

        try await SMBClient.echo(
            host: "server",
            share: "share",
            credential: .anonymous,
            makeTransport: { transport }
        )

        XCTAssertEqual(transport.closeCount, 1, "a successful one-shot operation closes its transport")
        XCTAssertEqual(
            try outboundCommands(transport.outbound).suffix(3),
            [SMB2Commands.echo, SMB2Commands.treeDisconnect, SMB2Commands.logoff]
        )
    }

    func testOperationAfterSessionCloseFailsExplicitly() async throws {
        let transport = SMBValidateNegotiateScriptTransport(
            inbound: try SMBIssue102WireFixtures.framed(
                SMBIssue102WireFixtures.anonymousReconnectResponsesWithCleanup()
            ),
            credential: .anonymous
        )
        let session = try await SMBClient.connect(
            host: "server",
            share: "share",
            credential: .anonymous,
            makeTransport: { transport }
        )

        await session.close()
        XCTAssertEqual(transport.closeCount, 1)
        let outboundAfterClose = transport.outbound

        do {
            _ = try await session.stat(path: "after-close.txt")
            XCTFail("stat unexpectedly succeeded after SMBClientSession.close()")
        } catch SMBError.connectionLost(operation: "SESSION") {
            // Closed-session operations fail before sending another SMB request.
        } catch {
            XCTFail("expected connectionLost(operation: SESSION), got \(error)")
        }

        XCTAssertEqual(transport.outbound, outboundAfterClose)
        XCTAssertEqual(transport.closeCount, 1)
    }

    private func statusResponse(command: UInt16, messageId: UInt64, treeId: UInt32) throws -> [UInt8] {
        var response = try SMB2Header(
            command: command,
            messageId: messageId,
            treeId: treeId,
            sessionId: sessionId
        ).encode()
        response.append(contentsOf: [4, 0, 0, 0])
        return response
    }

    private func outboundCommands(_ bytes: [UInt8]) throws -> [UInt16] {
        var commands: [UInt16] = []
        var offset = 0
        while offset < bytes.count {
            let frameLength = try DirectTCPFraming.length(from: Array(bytes[offset..<(offset + 4)]))
            let packetStart = offset + 4
            let packetEnd = packetStart + frameLength
            guard packetEnd <= bytes.count else { throw SMBCodecError.truncated }
            commands.append(try SMB2Header.decode(Array(bytes[packetStart..<packetEnd])).command)
            offset = packetEnd
        }
        return commands
    }
}
