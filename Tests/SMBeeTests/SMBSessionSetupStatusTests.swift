import XCTest
@testable import SMBee

final class SMBSessionSetupStatusTests: XCTestCase {
    func testSessionSetupOneCancelledStatusThrowsCancellationError() async throws {
        let transport = try transportForSessionSetupOne(status: SMB2Status.cancelled)
        let session = makeSession(transport: transport)

        do {
            try await session.connect()
            XCTFail("expected STATUS_CANCELLED to become CancellationError")
        } catch is CancellationError {
            // The SESSION_SETUP#1 status now follows the shared error contract.
        }
    }

    func testSessionSetupOneMoreProcessingRequiredContinuesToSecondRequest() async throws {
        let transport = try transportForSuccessfulHandshake()
        let session = makeSession(transport: transport)

        try await session.connect()

        XCTAssertEqual(try outboundCommands(transport.outbound).filter { $0 == SMB2Commands.sessionSetup }.count, 2)
    }

    func testSessionSetupOneUnexpectedSuccessRetainsLegacyMappedError() async throws {
        let transport = try transportForSessionSetupOne(status: SMB2Status.success)
        let session = makeSession(transport: transport)

        do {
            try await session.connect()
            XCTFail("expected successful SESSION_SETUP#1 to remain an unexpected status")
        } catch let error as SMBError {
            XCTAssertEqual(error, .unsupported(status: SMB2Status.success, operation: "SESSION_SETUP#1"))
        }
    }

    private func makeSession(transport: InMemoryTransport) -> SMBSession {
        SMBSession(host: "server", port: 445, credential: .anonymous, transport: transport)
    }

    private func transportForSessionSetupOne(status: UInt32) throws -> InMemoryTransport {
        InMemoryTransport(inbound: try framed([
            negotiateResponse(),
            try SMB2Header(
                status: status,
                command: SMB2Commands.sessionSetup,
                messageId: 1,
                sessionId: 0x1122_3344_5566_7788
            ).encode()
        ]))
    }

    private func transportForSuccessfulHandshake() throws -> InMemoryTransport {
        InMemoryTransport(inbound: try framed([
            negotiateResponse(),
            sessionSetupChallengeResponse(),
            sessionSetupSuccessResponse()
        ]))
    }

    private func negotiateResponse() throws -> [UInt8] {
        var response = try SMB2Header(command: SMBNegotiateConstants.commandNegotiate, messageId: 0).encode()
        response.append(contentsOf: Array(repeating: 0, count: 65))
        writeUInt16LE(65, to: &response, at: 64)
        writeUInt16LE(SMBNegotiateConstants.signingEnabled, to: &response, at: 66)
        writeUInt16LE(SMBNegotiateConstants.dialect302, to: &response, at: 68)
        response.replaceSubrange(72..<88, with: Array(repeating: 0x42, count: 16))
        writeUInt32LE(0, to: &response, at: 88)
        writeUInt32LE(1_048_576, to: &response, at: 92)
        writeUInt32LE(1_048_576, to: &response, at: 96)
        writeUInt32LE(1_048_576, to: &response, at: 100)
        return response
    }

    private func sessionSetupChallengeResponse() throws -> [UInt8] {
        let targetInfo: [UInt8] = [7, 0, 8, 0, 0, 0x90, 0xd3, 0x36, 0xb7, 0x34, 0xc3, 1, 0, 0, 0, 0]
        let challenge = makeNTLMChallengeMessage(targetInfo: targetInfo)
        let blob = SPNEGO.wrapNegTokenResp(challenge)
        var response = try SMB2Header(
            status: SMB2Status.moreProcessingRequired,
            command: SMB2Commands.sessionSetup,
            messageId: 1,
            sessionId: 0x1122_3344_5566_7788
        ).encode()
        response.append(contentsOf: Array(repeating: 0, count: 8))
        writeUInt16LE(9, to: &response, at: 64)
        writeUInt16LE(72, to: &response, at: 68)
        writeUInt16LE(UInt16(blob.count), to: &response, at: 70)
        response.append(contentsOf: blob)
        return response
    }

    private func sessionSetupSuccessResponse() throws -> [UInt8] {
        var response = try SMB2Header(
            command: SMB2Commands.sessionSetup,
            messageId: 2,
            sessionId: 0x1122_3344_5566_7788
        ).encode()
        response.append(contentsOf: [9, 0, 0, 0, 72, 0, 0, 0])
        return response
    }

    private func makeNTLMChallengeMessage(targetInfo: [UInt8]) -> [UInt8] {
        let targetName = NTLM.utf16le("Server")
        let targetNameOffset: UInt32 = 48
        let targetInfoOffset = targetNameOffset + UInt32(targetName.count)
        var writer = SMBByteWriter()
        writer.writeBytes(Array("NTLMSSP\0".utf8))
        writer.writeUInt32LE(2)
        writer.writeUInt16LE(UInt16(targetName.count))
        writer.writeUInt16LE(UInt16(targetName.count))
        writer.writeUInt32LE(targetNameOffset)
        writer.writeUInt32LE(NTLM.negotiateFlags)
        writer.writeBytes(Array("0123456789abcdef".utf8))
        writer.writeBytes(Array(repeating: 0, count: 8))
        writer.writeUInt16LE(UInt16(targetInfo.count))
        writer.writeUInt16LE(UInt16(targetInfo.count))
        writer.writeUInt32LE(targetInfoOffset)
        writer.writeBytes(targetName)
        writer.writeBytes(targetInfo)
        return writer.bytes
    }

    private func framed(_ messages: [[UInt8]]) throws -> [UInt8] {
        try messages.reduce(into: []) { bytes, message in
            bytes.append(contentsOf: try DirectTCPFraming.frame(message))
        }
    }

    private func outboundCommands(_ bytes: [UInt8]) throws -> [UInt16] {
        var commands: [UInt16] = []
        var cursor = 0
        while cursor < bytes.count {
            let length = try DirectTCPFraming.length(from: Array(bytes[cursor..<(cursor + 4)]))
            let start = cursor + 4
            let end = start + length
            commands.append(try SMB2Header.decode(Array(bytes[start..<end])).command)
            cursor = end
        }
        return commands
    }
}
