import Foundation
import XCTest
@testable import SMBee

final class SMBNegotiateValidationTests: XCTestCase {
    private let sessionId: UInt64 = 0x1122_3344_5566_7788
    private let treeId: UInt32 = 0x3344
    private let signingKey = Array(repeating: UInt8(0x11), count: 16)
    private let serverGuidBytes = Array(repeating: UInt8(0x42), count: 16)

    func testValidateNegotiateInputAndIoctlRequestMatchFixedMSProtocolsBytes() throws {
        let snapshot = try requestSnapshot()
        let expectedInput: [UInt8] = [
            0x40, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x01, 0x00, 0x03, 0x00,
            0x00, 0x03, 0x02, 0x03, 0x11, 0x03
        ]
        XCTAssertEqual(try SMB2ValidateNegotiateInfo.encodeInput(snapshot: snapshot), expectedInput)

        let negotiate = try SMBNegotiateCodec.encodeRequest(snapshot: snapshot, messageId: 9)
        XCTAssertEqual(Array(negotiate[72..<76]), [0x40, 0x00, 0x00, 0x00])
        XCTAssertEqual(Array(negotiate[76..<92]), Array(repeating: 0, count: 16))
        XCTAssertEqual(Array(negotiate[68..<70]), [0x01, 0x00])
        XCTAssertEqual(Array(negotiate[100..<106]), [0x00, 0x03, 0x02, 0x03, 0x11, 0x03])

        let request = try SMB2ValidateNegotiateInfo.encodeRequest(
            messageId: 0x0807_0605_0403_0201,
            sessionId: sessionId,
            treeId: treeId,
            snapshot: snapshot
        )
        XCTAssertEqual(request.count, 150)
        XCTAssertEqual(try SMB2Header.decode(request).command, SMB2Commands.ioctl)
        XCTAssertEqual(Array(request[68..<72]), [0x04, 0x02, 0x14, 0x00])
        XCTAssertEqual(Array(request[72..<88]), Array(repeating: 0xff, count: 16))
        XCTAssertEqual(Array(request[88..<92]), [0x78, 0x00, 0x00, 0x00])
        XCTAssertEqual(Array(request[92..<96]), [0x1e, 0x00, 0x00, 0x00])
        XCTAssertEqual(Array(request[96..<100]), [0x00, 0x00, 0x00, 0x00])
        XCTAssertEqual(Array(request[100..<104]), [0x78, 0x00, 0x00, 0x00])
        XCTAssertEqual(Array(request[104..<108]), [0x00, 0x00, 0x00, 0x00])
        XCTAssertEqual(Array(request[108..<112]), [0x18, 0x00, 0x00, 0x00])
        XCTAssertEqual(Array(request[112..<116]), [0x01, 0x00, 0x00, 0x00])
        XCTAssertEqual(Array(request[116..<120]), [0x00, 0x00, 0x00, 0x00])
        XCTAssertEqual(Array(request[120..<150]), expectedInput)
    }

    func testValidateNegotiateAcceptsSignedExactAndLongerResponseBuffer() async throws {
        let run = await runTreeConnect(response: .signed(outputLength: 32))
        XCTAssertEqual(run.treeId, treeId)
        XCTAssertNil(run.error)
        XCTAssertEqual(run.counts.sent, 1)
        XCTAssertEqual(run.counts.succeeded, 1)
        XCTAssertFalse(run.wasClosed)
    }

    func testValidateNegotiateAcceptsSignedResponseWithOutputCountExactly24() async throws {
        let run = await runTreeConnect(response: .signed(outputLength: 24))
        XCTAssertEqual(run.treeId, treeId)
        XCTAssertNil(run.error)
        XCTAssertEqual(run.counts.sent, 1)
        XCTAssertEqual(run.counts.succeeded, 1)
        XCTAssertFalse(run.wasClosed)
    }

    func testValidateNegotiateRejectsEachNegotiatedFieldMismatch() async throws {
        let mismatches: [(String, UInt32, [UInt8], UInt16, UInt16)] = [
            ("capabilities", 0x41, serverGuidBytes, 0x0003, SMBNegotiateConstants.dialect302),
            ("server guid", 0x40, [0x43] + Array(repeating: UInt8(0x42), count: 15), 0x0003, SMBNegotiateConstants.dialect302),
            ("security mode", 0x40, serverGuidBytes, 0x0001, SMBNegotiateConstants.dialect302),
            ("dialect", 0x40, serverGuidBytes, 0x0003, SMBNegotiateConstants.dialect300)
        ]

        for mismatch in mismatches {
            let run = await runTreeConnect(
                response: .signed(outputLength: 24),
                responseCapabilities: mismatch.1,
                responseGuidBytes: mismatch.2,
                responseSecurityMode: mismatch.3,
                responseDialect: mismatch.4
            )
            XCTAssertNil(run.treeId, mismatch.0)
            XCTAssertNotNil(run.error, mismatch.0)
            XCTAssertEqual(run.counts.sent, 1, mismatch.0)
            XCTAssertEqual(run.counts.succeeded, 0, mismatch.0)
            XCTAssertTrue(run.wasClosed, mismatch.0)
        }
    }

    func testValidateNegotiateRejectsDowngradedNegotiateSecurityModeFixture() async throws {
        let credential = SMBCredential(username: "user", password: "pass")
        let transport = SMBValidateNegotiateScriptTransport(inbound: try frame([
            negotiateResponse(
                dialect: SMBNegotiateConstants.dialect302,
                securityMode: SMBNegotiateConstants.signingEnabled,
                capabilities: 0
            ),
            sessionSetupChallengeResponse(messageId: 1, sessionId: sessionId),
            sessionSetupSuccessResponse(messageId: 2, sessionId: sessionId, flags: 0),
            treeConnectResponse(messageId: 3, sessionId: sessionId),
            try SMBValidateNegotiateScript.responseTemplate(
                capabilities: 0,
                securityMode: SMBNegotiateConstants.signingEnabled | SMBNegotiateConstants.signingRequired
            )
        ]), credential: credential)

        do {
            _ = try await SMBClient.connect(
                host: "server",
                share: "share",
                credential: credential,
                makeTransport: { transport }
            )
            XCTFail("expected NEGOTIATE SecurityMode downgrade to fail")
        } catch {
            XCTAssertTrue(String(describing: error).contains("does not match NEGOTIATE"), String(describing: error))
        }

        let requests = try unframe(transport.outbound)
        let requestCommands = requests.compactMap { try? SMB2Header.decode($0).command }
        XCTAssertTrue(requests.contains { packet in
            (try? SMB2Header.decode(packet).command) == SMB2Commands.ioctl &&
                packet.count >= 72 && Array(packet[68..<72]) == [0x04, 0x02, 0x14, 0x00]
        }, "expected a VNI IOCTL, found SMB commands \(requestCommands)")
        XCTAssertGreaterThan(transport.closeCount, 0)
    }

    func testNegotiateResponseRetainsRawSecurityMode() throws {
        XCTAssertEqual(try serverResult(rawSecurityMode: 0x0003).rawSecurityMode, 0x0003)
        XCTAssertEqual(try serverResult(rawSecurityMode: 0x0001).rawSecurityMode, 0x0001)
    }

    func testValidateNegotiateRequiresSignedPlaintextEvenWhenSigningIsNotRequired() async throws {
        let unsigned = await runTreeConnect(
            response: .unsigned(outputLength: 24),
            negotiateSecurityMode: SMBNegotiateConstants.signingEnabled
        )
        XCTAssertNil(unsigned.treeId)
        XCTAssertTrue(unsigned.wasClosed)
        XCTAssertEqual(unsigned.counts.succeeded, 0)

        let corrupted = await runTreeConnect(
            response: .corruptSignature(outputLength: 24),
            negotiateSecurityMode: SMBNegotiateConstants.signingEnabled
        )
        XCTAssertNil(corrupted.treeId)
        XCTAssertTrue(corrupted.wasClosed)
        XCTAssertEqual(corrupted.counts.succeeded, 0)
    }

    func testValidateNegotiateRequiresValidAEADForEncryptedResponse() async throws {
        let valid = await runTreeConnect(response: .encrypted(outputLength: 24), encryptedSession: true)
        XCTAssertEqual(valid.treeId, treeId)
        XCTAssertEqual(valid.counts.succeeded, 1)
        XCTAssertFalse(valid.wasClosed)

        let invalid = await runTreeConnect(response: .corruptAEAD(outputLength: 24), encryptedSession: true)
        XCTAssertNil(invalid.treeId)
        XCTAssertNotNil(invalid.error)
        XCTAssertEqual(invalid.counts.succeeded, 0)
        XCTAssertTrue(invalid.wasClosed)
    }

    func testValidateNegotiateRejectsStatusesShortOutputAndOutOfRangeOutput() async throws {
        for status in [SMB2Status.accessDenied, SMB2Status.notSupported] {
            let run = await runTreeConnect(response: .error(status: status))
            XCTAssertNil(run.treeId)
            XCTAssertNotNil(run.error)
            XCTAssertEqual(run.counts.succeeded, 0)
            XCTAssertTrue(run.wasClosed)
        }

        let short = await runTreeConnect(response: .short)
        XCTAssertNil(short.treeId)
        XCTAssertTrue(short.wasClosed)

        let outOfRange = await runTreeConnect(response: .outOfRange)
        XCTAssertNil(outOfRange.treeId)
        XCTAssertTrue(outOfRange.wasClosed)
    }

    func testValidateNegotiateDoesNotRunForSMB311OrAnonymousCredentials() async throws {
        for (credential, dialect) in [
            (SMBCredential(username: "user", password: "pass"), SMBNegotiateConstants.dialect311),
            (.anonymous, SMBNegotiateConstants.dialect302)
        ] {
            let transport = InMemoryTransport(inbound: try frame([
                treeConnectResponse(messageId: 0, sessionId: sessionId)
            ]))
            let session = SMBSession(host: "server", port: 445, credential: credential, transport: transport)
            await session.installValidateNegotiateStateForTesting(
                snapshot: try requestSnapshot(),
                serverResult: try serverResult(dialect: dialect),
                sessionId: sessionId
            )

            let connectedTreeId = try await session.treeConnect(share: "share")
            XCTAssertEqual(connectedTreeId, treeId)
            let counts = await session.validateNegotiateCountsForTesting()
            XCTAssertEqual(counts.sent, 0)
            XCTAssertEqual(counts.succeeded, 0)
            await session.closeTransport(cause: "unit_test")
        }
    }

    func testCredentialMappedToGuestFailsSMB302TreeConnect() async throws {
        for sessionFlag in [SMB2SessionSetup.sessionFlagIsGuest, SMB2SessionSetup.sessionFlagIsNull] {
            let transport = InMemoryTransport(inbound: try frame([
                negotiateResponse(dialect: SMBNegotiateConstants.dialect302, securityMode: SMBNegotiateConstants.signingEnabled),
                sessionSetupChallengeResponse(messageId: 1, sessionId: sessionId),
                sessionSetupSuccessResponse(messageId: 2, sessionId: sessionId, flags: sessionFlag)
            ]))

            do {
                _ = try await SMBClient.connect(
                    host: "server",
                    share: "share",
                    credential: SMBCredential(username: "user", password: "pass"),
                    makeTransport: { transport }
                )
                XCTFail("expected SMB 3.0.2 guest/null mapping to fail")
            } catch SMBError.protocolError(let message) {
                XCTAssertTrue(message.contains("guest or null"), message)
            }

            let outbound = try unframe(transport.outbound)
            XCTAssertFalse(outbound.contains { (try? SMB2Header.decode($0).command) == SMB2Commands.treeConnect })
        }
    }

    func testSMB311GuestMappingRetainsFlagsAndHasNoSigningKey() async throws {
        let transport = InMemoryTransport(inbound: try frame([
            negotiateResponse(dialect: SMBNegotiateConstants.dialect311, securityMode: SMBNegotiateConstants.signingEnabled),
            sessionSetupChallengeResponse(messageId: 1, sessionId: sessionId),
            sessionSetupSuccessResponse(messageId: 2, sessionId: sessionId, flags: SMB2SessionSetup.sessionFlagIsGuest),
            treeConnectResponse(messageId: 3, sessionId: sessionId)
        ]))
        let clientSession = try await SMBClient.connect(
            host: "server",
            share: "share",
            credential: SMBCredential(username: "user", password: "pass"),
            makeTransport: { transport }
        )
        let session = await clientSession.wireSessionForTesting()
        let flags = await session.sessionFlagsForTesting()
        let hasSigningKey = await session.hasSigningKeyForTesting()
        let counts = await session.validateNegotiateCountsForTesting()
        XCTAssertEqual(flags, SMB2SessionSetup.sessionFlagIsGuest)
        XCTAssertFalse(hasSigningKey)
        XCTAssertEqual(counts.sent, 0)
        XCTAssertEqual(counts.succeeded, 0)
        await session.closeTransport(cause: "unit_test")
    }

    func testValidateNegotiateRequestIsSignedBeforeSessionEncryption() async throws {
        let run = await runTreeConnect(response: .encrypted(outputLength: 24), encryptedSession: true)
        XCTAssertEqual(run.treeId, treeId)
        let packets = try unframe(run.outbound)
        XCTAssertEqual(packets.count, 2)
        XCTAssertTrue(packets[1].starts(with: SMB3TransformHeader.protocolId))
        let transform = try SMB3TransformHeader.decode(packets[1])
        let ciphertext = Array(packets[1].dropFirst(SMB3TransformHeader.encodedSize))
        let request = try AESCCM.open(
            key: signingKey,
            nonce: Array(transform.nonce.prefix(11)),
            ciphertext: ciphertext,
            authenticatedData: transform.authenticatedData(),
            tag: transform.signature
        )
        let header = try SMB2Header.decode(request)
        XCTAssertEqual(header.command, SMB2Commands.ioctl)
        XCTAssertNotEqual(header.flags & SMB2Flags.signed, 0)
        XCTAssertNotEqual(header.signature, Array(repeating: 0, count: 16))
        let normalizedRequest = testPacketSignatureInput(request)
        let expectedSignature = try SMBSessionSigning.signature(
            algorithm: .aesCMAC,
            key: signingKey,
            packet: normalizedRequest,
            sender: .client
        )
        XCTAssertEqual(header.signature, expectedSignature)
    }

    func testValidateNegotiatePlaintextExceptionStillRedactsWhenEncryptionKeyExists() async throws {
        let capture = SMBTraceLogCapture()
        let logger = SMBSessionDebugLogger(
            configuration: SMBSessionDebugConfiguration(enabled: true, traceWire: true, traceWireFull: true),
            sink: { capture.append($0) }
        )
        let negotiateRequest = try requestSnapshot()
        let validationResponse = try validateResponse(
            protection: .signed(outputLength: 24),
            capabilities: SMBNegotiateConstants.globalCapEncryption,
            guidBytes: serverGuidBytes,
            securityMode: SMBNegotiateConstants.signingEnabled | SMBNegotiateConstants.signingRequired,
            dialect: SMBNegotiateConstants.dialect302
        )
        let inbound = try frame([
            try signedTestPacket(
                treeConnectResponse(messageId: 0, sessionId: sessionId),
                algorithm: .aesCMAC,
                key: signingKey,
                sender: .server
            ),
            validationResponse
        ])
        let transport = InMemoryTransport(inbound: inbound)
        let session = SMBSession(
            host: "server",
            port: 445,
            credential: SMBCredential(username: "user", password: "pass"),
            transport: transport,
            signingKey: signingKey,
            debugLogger: logger
        )
        await session.installValidateNegotiateStateForTesting(
            snapshot: negotiateRequest,
            serverResult: try serverResult(),
            sessionId: sessionId,
            sessionFlags: 0,
            encryptionKey: signingKey,
            decryptionKey: signingKey
        )

        let connectedTreeId = try await session.treeConnect(share: "share")
        XCTAssertEqual(connectedTreeId, treeId)
        let packets = try unframe(transport.outbound)
        XCTAssertEqual(packets.count, 2)
        XCTAssertTrue(packets[0].starts(with: SMB3TransformHeader.protocolId))
        XCTAssertFalse(packets[1].starts(with: SMB3TransformHeader.protocolId))
        let validationRequest = try SMB2ValidateNegotiateInfo.encodeRequest(
            messageId: 1,
            sessionId: sessionId,
            treeId: treeId,
            snapshot: negotiateRequest
        )
        XCTAssertEqual(try SMB2Header.decode(packets[1]).command, SMB2Commands.ioctl)
        XCTAssertTrue(capture.messages.contains {
            $0.hasPrefix("FSCTL_VALIDATE_NEGOTIATE_INFO request") &&
                $0.contains("<redacted; encrypted session plaintext>")
        })
        XCTAssertFalse(capture.messages.joined(separator: "\n").contains(SMBDebug.hex(validationRequest)))
        let counts = await session.validateNegotiateCountsForTesting()
        XCTAssertEqual(counts.sent, 1)
        XCTAssertEqual(counts.succeeded, 1)
        await session.closeTransport(cause: "validate_negotiate_trace_redaction_test")
    }

    private enum Protection {
        case signed(outputLength: Int)
        case short
        case unsigned(outputLength: Int)
        case corruptSignature(outputLength: Int)
        case encrypted(outputLength: Int)
        case corruptAEAD(outputLength: Int)
        case error(status: UInt32)
        case outOfRange
    }

    private struct RunResult {
        let treeId: UInt32?
        let error: String?
        let counts: (sent: Int, succeeded: Int)
        let wasClosed: Bool
        let outbound: [UInt8]
    }

    private func runTreeConnect(
        response protection: Protection,
        negotiateSecurityMode: UInt16 = 0x0003,
        responseCapabilities: UInt32 = 0x0000_0040,
        responseGuidBytes: [UInt8]? = nil,
        responseSecurityMode: UInt16? = nil,
        responseDialect: UInt16 = SMBNegotiateConstants.dialect302,
        encryptedSession: Bool = false
    ) async -> RunResult {
        do {
            let guidBytes = responseGuidBytes ?? serverGuidBytes
            let response = try validateResponse(
                protection: protection,
                capabilities: responseCapabilities,
                guidBytes: guidBytes,
                securityMode: responseSecurityMode ?? negotiateSecurityMode,
                dialect: responseDialect
            )
            let responses = try frame([
                try signedTestPacket(
                    treeConnectResponse(messageId: 0, sessionId: sessionId),
                    algorithm: .aesCMAC,
                    key: signingKey,
                    sender: .server
                ),
                response
            ])
            let transport = InMemoryTransport(inbound: responses)
            let session = SMBSession(
                host: "server",
                port: 445,
                credential: SMBCredential(username: "user", password: "pass"),
                transport: transport,
                signingKey: signingKey,
                signingRequired: (negotiateSecurityMode & SMBNegotiateConstants.signingRequired) != 0
            )
            await session.installValidateNegotiateStateForTesting(
                snapshot: try requestSnapshot(),
                serverResult: try serverResult(rawSecurityMode: negotiateSecurityMode),
                sessionId: sessionId,
                sessionFlags: encryptedSession ? SMB2SessionSetup.sessionFlagEncryptData : 0,
                encryptionKey: encryptedSession ? signingKey : nil,
                decryptionKey: encryptedSession ? signingKey : nil
            )

            var tree: UInt32?
            var errorDescription: String?
            do {
                tree = try await session.treeConnect(share: "share")
            } catch {
                errorDescription = String(describing: error)
            }
            let counts = await session.validateNegotiateCountsForTesting()
            let closed = await session.isTransportClosedForTesting()
            let outbound = transport.outbound
            await session.closeTransport(cause: "unit_test")
            return RunResult(treeId: tree, error: errorDescription, counts: counts, wasClosed: closed, outbound: outbound)
        } catch {
            return RunResult(treeId: nil, error: String(describing: error), counts: (0, 0), wasClosed: false, outbound: [])
        }
    }

    private func validateResponse(
        protection: Protection,
        capabilities: UInt32,
        guidBytes: [UInt8],
        securityMode: UInt16,
        dialect: UInt16
    ) throws -> [UInt8] {
        switch protection {
        case .error(let status):
            return try signedTestPacket(
                ioctlError(status: status, messageId: 1), algorithm: .aesCMAC, key: signingKey, sender: .server
            )
        case .outOfRange:
            let packet = try ioctlSuccess(
                capabilities: capabilities,
                guidBytes: guidBytes,
                securityMode: securityMode,
                dialect: dialect,
                outputOffset: 500,
                outputCount: 100
            )
            return try signedTestPacket(packet, algorithm: .aesCMAC, key: signingKey, sender: .server)
        case .signed(let outputLength):
            return try signedTestPacket(
                ioctlSuccess(capabilities: capabilities, guidBytes: guidBytes, securityMode: securityMode, dialect: dialect, outputLength: outputLength),
                algorithm: .aesCMAC,
                key: signingKey,
                sender: .server
            )
        case .short:
            return try signedTestPacket(
                ioctlSuccess(
                    capabilities: capabilities,
                    guidBytes: guidBytes,
                    securityMode: securityMode,
                    dialect: dialect,
                    outputLength: 24,
                    outputCount: 23
                ),
                algorithm: .aesCMAC,
                key: signingKey,
                sender: .server
            )
        case .unsigned(let outputLength):
            return try ioctlSuccess(capabilities: capabilities, guidBytes: guidBytes, securityMode: securityMode, dialect: dialect, outputLength: outputLength)
        case .corruptSignature(let outputLength):
            var packet = try signedTestPacket(
                ioctlSuccess(capabilities: capabilities, guidBytes: guidBytes, securityMode: securityMode, dialect: dialect, outputLength: outputLength),
                algorithm: .aesCMAC,
                key: signingKey,
                sender: .server
            )
            packet[48] ^= 0x01
            return packet
        case .encrypted(let outputLength):
            let packet = try ioctlSuccess(capabilities: capabilities, guidBytes: guidBytes, securityMode: securityMode, dialect: dialect, outputLength: outputLength)
            return try encryptServerPacket(packet, key: signingKey, invalidTag: false)
        case .corruptAEAD(let outputLength):
            let packet = try ioctlSuccess(capabilities: capabilities, guidBytes: guidBytes, securityMode: securityMode, dialect: dialect, outputLength: outputLength)
            return try encryptServerPacket(packet, key: signingKey, invalidTag: true)
        }
    }

    private func requestSnapshot() throws -> SMBNegotiateRequestSnapshot {
        try SMBNegotiateRequestSnapshot(
            clientGuid: Array(repeating: 0, count: 16),
            capabilities: SMBNegotiateConstants.globalCapEncryption,
            securityMode: SMBNegotiateConstants.signingEnabled,
            dialects: SMBNegotiateCodec.authenticatedDialects
        )
    }

    private func serverResult(
        dialect: UInt16 = SMBNegotiateConstants.dialect302,
        rawSecurityMode: UInt16 = 0x0003
    ) throws -> SMBProbeResult {
        try SMBNegotiateCodec.decodeResponse(negotiateResponse(dialect: dialect, securityMode: rawSecurityMode))
    }

    private func negotiateResponse(
        dialect: UInt16,
        securityMode: UInt16,
        capabilities: UInt32 = SMBNegotiateConstants.globalCapEncryption
    ) throws -> [UInt8] {
        var packet = try SMB2Header(command: SMBNegotiateConstants.commandNegotiate, messageId: 0).encode()
        packet += Array(repeating: 0, count: 65)
        writeUInt16LE(65, to: &packet, at: 64)
        writeUInt16LE(securityMode, to: &packet, at: 66)
        writeUInt16LE(dialect, to: &packet, at: 68)
        writeUInt16LE(dialect == SMBNegotiateConstants.dialect311 ? 2 : 0, to: &packet, at: 70)
        packet.replaceSubrange(72..<88, with: serverGuidBytes)
        writeUInt32LE(capabilities, to: &packet, at: 88)
        writeUInt32LE(1_048_576, to: &packet, at: 92)
        writeUInt32LE(1_048_576, to: &packet, at: 96)
        writeUInt32LE(1_048_576, to: &packet, at: 100)
        if dialect == SMBNegotiateConstants.dialect311 {
            writeUInt32LE(136, to: &packet, at: 124)
            packet += Array(repeating: 0, count: 7)
            appendNegotiateContext(type: SMBNegotiateConstants.preauthContext, data: [1, 0, 0, 0, 1, 0], padTo8: true, to: &packet)
            appendNegotiateContext(type: SMBNegotiateConstants.signingContext, data: [1, 0, 2, 0], padTo8: false, to: &packet)
        }
        return packet
    }

    private func sessionSetupChallengeResponse(messageId: UInt64, sessionId: UInt64) throws -> [UInt8] {
        let targetInfo: [UInt8] = [0x07, 0x00, 0x08, 0x00, 0x00, 0x90, 0xd3, 0x36, 0xb7, 0x34, 0xc3, 0x01, 0x00, 0x00, 0x00, 0x00]
        let targetName = NTLM.utf16le("Server")
        var type2 = SMBByteWriter()
        type2.writeBytes(Array("NTLMSSP\0".utf8))
        type2.writeUInt32LE(2)
        type2.writeUInt16LE(UInt16(targetName.count))
        type2.writeUInt16LE(UInt16(targetName.count))
        type2.writeUInt32LE(48)
        type2.writeUInt32LE(NTLM.negotiateFlags)
        type2.writeBytes([0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef])
        type2.writeBytes(Array(repeating: 0, count: 8))
        type2.writeUInt16LE(UInt16(targetInfo.count))
        type2.writeUInt16LE(UInt16(targetInfo.count))
        type2.writeUInt32LE(UInt32(48 + targetName.count))
        type2.writeBytes(targetName)
        type2.writeBytes(targetInfo)
        let blob = SPNEGO.wrapNegTokenResp(type2.bytes)
        var packet = try SMB2Header(
            status: SMB2Status.moreProcessingRequired,
            command: SMB2Commands.sessionSetup,
            messageId: messageId,
            sessionId: sessionId
        ).encode()
        packet += Array(repeating: 0, count: 8)
        writeUInt16LE(9, to: &packet, at: 64)
        writeUInt16LE(72, to: &packet, at: 68)
        writeUInt16LE(UInt16(blob.count), to: &packet, at: 70)
        packet += blob
        return packet
    }

    private func sessionSetupSuccessResponse(messageId: UInt64, sessionId: UInt64, flags: UInt16) throws -> [UInt8] {
        var packet = try SMB2Header(
            command: SMB2Commands.sessionSetup,
            messageId: messageId,
            sessionId: sessionId
        ).encode()
        packet += [9, 0, UInt8(flags & 0xff), UInt8(flags >> 8), 72, 0, 0, 0]
        return packet
    }

    private func appendNegotiateContext(type: UInt16, data: [UInt8], padTo8: Bool, to packet: inout [UInt8]) {
        appendUInt16LE(type, to: &packet)
        appendUInt16LE(UInt16(data.count), to: &packet)
        appendUInt32LE(0, to: &packet)
        packet += data
        if padTo8 {
            while packet.count % 8 != 0 { packet.append(0) }
        }
    }

    private func treeConnectResponse(
        messageId: UInt64,
        sessionId: UInt64,
        shareFlags: UInt32 = 0,
        capabilities: UInt32 = 0
    ) throws -> [UInt8] {
        var bytes = try SMB2Header(
            command: SMB2Commands.treeConnect,
            messageId: messageId,
            treeId: treeId,
            sessionId: sessionId
        ).encode()
        bytes.append(contentsOf: Array(repeating: 0, count: 16))
        writeUInt16LE(16, to: &bytes, at: 64)
        bytes[66] = 1
        writeUInt32LE(shareFlags, to: &bytes, at: 68)
        writeUInt32LE(capabilities, to: &bytes, at: 72)
        writeUInt32LE(0x001f_01ff, to: &bytes, at: 76)
        return bytes
    }

    private func ioctlSuccess(
        capabilities: UInt32,
        guidBytes: [UInt8],
        securityMode: UInt16,
        dialect: UInt16,
        outputLength: Int = 24,
        outputOffset: UInt32 = 112,
        outputCount: UInt32? = nil,
        output: [UInt8]? = nil
    ) throws -> [UInt8] {
        var data: [UInt8] = []
        appendUInt32LE(capabilities, to: &data)
        data.append(contentsOf: guidBytes)
        appendUInt16LE(securityMode, to: &data)
        appendUInt16LE(dialect, to: &data)
        if let output {
            data = output
        } else if outputLength > data.count {
            data += Array(repeating: 0xa5, count: outputLength - data.count)
        } else if outputLength < data.count {
            data = Array(data.prefix(outputLength))
        }

        var packet = try SMB2Header(
            status: SMB2Status.success,
            command: SMB2Commands.ioctl,
            messageId: 1,
            treeId: treeId,
            sessionId: sessionId
        ).encode()
        packet += Array(repeating: 0, count: 48)
        writeUInt16LE(49, to: &packet, at: 64)
        writeUInt32LE(SMB2ValidateNegotiateInfo.ctlCode, to: &packet, at: 68)
        packet.replaceSubrange(72..<88, with: SMB2ValidateNegotiateInfo.fileId)
        writeUInt32LE(outputOffset, to: &packet, at: 96)
        writeUInt32LE(outputCount ?? UInt32(data.count), to: &packet, at: 100)
        writeUInt32LE(0, to: &packet, at: 104)
        if packet.count < Int(outputOffset) {
            packet += Array(repeating: 0, count: Int(outputOffset) - packet.count)
        }
        packet += data
        return packet
    }

    private func ioctlError(status: UInt32, messageId: UInt64) throws -> [UInt8] {
        var packet = try ioctlSuccess(
            capabilities: SMBNegotiateConstants.globalCapEncryption,
            guidBytes: serverGuidBytes,
            securityMode: 0x0003,
            dialect: SMBNegotiateConstants.dialect302
        )
        writeUInt32LE(status, to: &packet, at: 8)
        writeUInt64LE(messageId, to: &packet, at: 24)
        return packet
    }

    private func encryptServerPacket(_ packet: [UInt8], key: [UInt8], invalidTag: Bool) throws -> [UInt8] {
        let nonce = Array(UInt8(0x00)...UInt8(0x0a))
        var header = SMB3TransformHeader(
            signature: Array(repeating: 0, count: 16),
            nonce: nonce + Array(repeating: 0, count: 5),
            originalMessageSize: UInt32(packet.count),
            flags: SMB3TransformHeader.encryptedFlag,
            sessionId: sessionId
        )
        let sealed = try AESCCM.seal(
            key: key,
            nonce: nonce,
            plaintext: packet,
            authenticatedData: header.authenticatedData(),
            tagLength: 16
        )
        header.signature = sealed.tag
        if invalidTag { header.signature[0] ^= 1 }
        return try header.encode() + sealed.ciphertext
    }

    private func frame(_ packets: [[UInt8]]) throws -> [UInt8] {
        try packets.reduce(into: []) { result, packet in
            result.append(contentsOf: try DirectTCPFraming.frame(packet))
        }
    }

    private func unframe(_ bytes: [UInt8]) throws -> [[UInt8]] {
        var packets: [[UInt8]] = []
        var cursor = 0
        while cursor < bytes.count {
            let length = try DirectTCPFraming.length(from: Array(bytes[cursor..<cursor + 4]))
            let start = cursor + 4
            let end = start + length
            packets.append(Array(bytes[start..<end]))
            cursor = end
        }
        return packets
    }

}
