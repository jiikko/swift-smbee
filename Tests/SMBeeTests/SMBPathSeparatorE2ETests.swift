import Foundation
import XCTest
@testable import SMBee

final class SMBPathSeparatorE2ETests: XCTestCase {
    func testRawCreateRecordsSambaHandlingOfSeparatorBeforeCombiningMark() async throws {
        let details = try connectionDetails()
        guard ProcessInfo.processInfo.environment["SMBEE_E2E_PROFILE"] == "smb311-signing-required" else {
            throw XCTSkip("raw signed CREATE coverage requires SMBEE_E2E_PROFILE=smb311-signing-required")
        }

        let probe = "issue103-\(UUID().uuidString)"
        var probeTreeNeedsCleanup = false
        var outcomeError: Error?
        do {
            try await createProbeTree(probe, details: details)
            probeTreeNeedsCleanup = true
            let plainStatus = try await sendRawCreate(path: "\(probe)\\x\\plain", details: details)
            let slashStatus = try await sendRawCreate(path: "\(probe)\\x/\u{0301}y", details: details)
            let backslashStatus = try await sendRawCreate(path: "\(probe)\\x\\\u{0301}z", details: details)
            // Old SMBPath.normalize sent these names unchanged: the hidden `..` reaches the server.
            let dotDotPath = "\(probe)\\x\\../\u{0301}w"
            let dotDotStatus = try await sendRawCreate(path: dotDotPath, details: details)
            let escapePath = "../\u{0301}\(probe)-escape"
            let escapeStatus = try await sendRawCreate(path: escapePath, details: details)

            let statusReport = [
                "profile=smb311-signing-required host=\(details.host):\(details.port) share=\(details.share)",
                "plain utf16le=\(hexUTF16("\(probe)\\x\\plain")) status=0x\(String(format: "%08x", plainStatus))",
                "slash+combining utf16le=\(hexUTF16("\(probe)\\x/\u{0301}y")) status=0x\(String(format: "%08x", slashStatus))",
                "backslash+combining utf16le=\(hexUTF16("\(probe)\\x\\\u{0301}z")) status=0x\(String(format: "%08x", backslashStatus))",
                "hidden-dotdot utf16le=\(hexUTF16(dotDotPath)) status=0x\(String(format: "%08x", dotDotStatus))",
                "hidden-dotdot-at-share-root utf16le=\(hexUTF16(escapePath)) status=0x\(String(format: "%08x", escapeStatus))"
            ].joined(separator: "\n")
            print("issue103 Samba CREATE status observation\n\(statusReport)")

            let placement = try await inspectAndCleanupProbeTree(probe, details: details)
            probeTreeNeedsCleanup = false
            let placementReport = [
                "probe entries=\(placement.rootNames)",
                "x entries=\(placement.childNames)",
                "share root escape entries=\(placement.shareRootProbeNames.map(\.debugDescription))"
            ].joined(separator: "\n")
            print("issue103 Samba CREATE placement observation\n\(placementReport)")
            // Samba 2026-10-09 (ubuntu:24.04 distro build): `/` stays a separator even before a
            // combining mark, so a `..` hidden by Character-based splitting resolves inside the
            // share. SMBPath must reject it client-side (issue 103). Leaving the share is refused.
            XCTAssertEqual(plainStatus, SMB2Status.success, "plain CREATE control must succeed")
            XCTAssertEqual(slashStatus, SMB2Status.success)
            XCTAssertEqual(backslashStatus, SMB2Status.success)
            XCTAssertEqual(dotDotStatus, SMB2Status.success)
            XCTAssertEqual(escapeStatus, 0xC000_003B, "STATUS_OBJECT_PATH_SYNTAX_BAD")
            XCTAssertEqual(placement.rootNames, ["x", "\u{0301}w"], "hidden `..` must resolve one level up")
            XCTAssertEqual(placement.childNames, ["plain", "\u{0301}y", "\u{0301}z"])
            XCTAssertEqual(placement.shareRootProbeNames, [])
        } catch {
            outcomeError = error
        }

        if probeTreeNeedsCleanup {
            do {
                try await cleanupProbeTree(probe, details: details)
            } catch {
                if case nil = outcomeError { outcomeError = error }
            }
        }
        if let outcomeError { throw outcomeError }
    }

    private struct ConnectionDetails {
        let host: String
        let port: UInt16
        let credential: SMBCredential
        let share: String
    }

    private struct ProbePlacement {
        let rootNames: [String]
        let childNames: [String]
        let shareRootProbeNames: [String]
    }

    private func connectionDetails() throws -> ConnectionDetails {
        let environment = ProcessInfo.processInfo.environment
        guard environment["SMBEE_E2E"] == "1" else {
            throw XCTSkip("Set SMBEE_E2E=1 to run Samba-backed E2E tests")
        }
        guard let port = UInt16(environment["SMBEE_E2E_PORT"] ?? "445") else {
            throw E2EConfigurationError.invalidPort
        }
        return ConnectionDetails(
            host: environment["SMBEE_E2E_HOST"] ?? "127.0.0.1",
            port: port,
            credential: SMBCredential(
                username: environment["SMBEE_E2E_USERNAME"] ?? "smbee",
                password: environment["SMBEE_E2E_PASSWORD"] ?? "smbee"
            ),
            share: environment["SMBEE_E2E_SHARE"] ?? "public"
        )
    }

    private func createProbeTree(_ path: String, details: ConnectionDetails) async throws {
        let session = try await SMBee.connect(
            host: details.host,
            port: details.port,
            credential: details.credential,
            share: details.share
        )
        do {
            try await session.makeDirectory(path: path)
            try await session.makeDirectory(path: "\(path)\\x")
            await session.close()
        } catch {
            await session.close()
            throw error
        }
    }

    private func sendRawCreate(path: String, details: ConnectionDetails) async throws -> UInt32 {
        let transport = SMBPathSeparatorRecordingTransport()
        let clientSession = try await SMBClient.connect(
            host: details.host,
            port: details.port,
            share: details.share,
            credential: details.credential,
            makeTransport: { transport }
        )
        let wireSession = await clientSession.wireSessionForTesting()

        do {
            let treeConnectRequest = try XCTUnwrap(
                try transport.outboundPackets.first { try SMB2Header.decode($0).command == SMB2Commands.treeConnect }
            )
            let treeConnectResponse = try XCTUnwrap(
                try transport.inboundPackets.first { try SMB2Header.decode($0).command == SMB2Commands.treeConnect }
            )
            let requestHeader = try SMB2Header.decode(treeConnectRequest)
            let responseHeader = try SMB2Header.decode(treeConnectResponse)
            let sentHeaders = try transport.outboundPackets.map(SMB2Header.decode)
            let nextMessageId = try XCTUnwrap(sentHeaders.map(\.messageId).max()) + 1
            let packet = try SMB2Create.encodeRequest(
                messageId: nextMessageId,
                sessionId: requestHeader.sessionId,
                treeId: responseHeader.treeId,
                request: .upload(path: "issue103-placeholder\\file", overwrite: false)
            )
            let rawPacket = try replacingCreateName(in: packet, with: path)
            let response = try await wireSession.validateNegotiateWireTransactionForTesting(packet: rawPacket)
            let status = try SMB2Header.decode(response).status
            let echoRequest = try SMB2Echo.encodeRequest(
                messageId: nextMessageId + 1,
                sessionId: requestHeader.sessionId
            )
            let echoResponse = try await wireSession.validateNegotiateWireTransactionForTesting(packet: echoRequest)
            try SMB2Echo.decodeResponse(echoResponse)
            await wireSession.closeTransportAndWait(cause: "issue103_raw_create_complete")
            return status
        } catch {
            await wireSession.closeTransportAndWait(cause: "issue103_raw_create_failed")
            throw error
        }
    }

    private func inspectAndCleanupProbeTree(_ path: String, details: ConnectionDetails) async throws -> ProbePlacement {
        let session = try await SMBee.connect(
            host: details.host,
            port: details.port,
            credential: details.credential,
            share: details.share
        )
        do {
            let rootEntries = try await session.list(path: path)
            let childEntries = try await session.list(path: "\(path)\\x")
            let shareRootProbeNames = try await session.list(path: "")
                .map(\.name)
                .filter { $0.hasSuffix("\(path)-escape") }
            for name in shareRootProbeNames {
                try await session.delete(path: name, directory: false, recursive: false, continueOnError: true)
            }
            try await session.delete(path: path, directory: true, recursive: true, continueOnError: true)
            await session.close()
            return ProbePlacement(
                rootNames: rootEntries.map(\.name).sorted(),
                childNames: childEntries.map(\.name).sorted(),
                shareRootProbeNames: shareRootProbeNames
            )
        } catch {
            await session.close()
            throw error
        }
    }

    private func cleanupProbeTree(_ path: String, details: ConnectionDetails) async throws {
        let session = try await SMBee.connect(
            host: details.host,
            port: details.port,
            credential: details.credential,
            share: details.share
        )
        do {
            try await session.delete(path: path, directory: true, recursive: true, continueOnError: true)
            await session.close()
        } catch {
            await session.close()
            throw error
        }
    }

    private func replacingCreateName(in packet: [UInt8], with path: String) throws -> [UInt8] {
        let nameOffset = Int(readUInt16LE(packet, at: 108))
        let oldNameLength = Int(readUInt16LE(packet, at: 110))
        guard nameOffset + oldNameLength <= packet.count else { throw SMBCodecError.truncated }
        let rawName = NTLM.utf16le(path)
        guard rawName.count <= Int(UInt16.max) else {
            throw SMBCodecError.invalidValue("issue103 raw CREATE name is too long")
        }
        var result = packet
        result.replaceSubrange(nameOffset..<nameOffset + oldNameLength, with: rawName)
        writeUInt16LE(UInt16(rawName.count), to: &result, at: 110)
        return result
    }

    private func readUInt16LE(_ bytes: [UInt8], at offset: Int) -> UInt16 {
        UInt16(bytes[offset]) | (UInt16(bytes[offset + 1]) << 8)
    }

    private func writeUInt16LE(_ value: UInt16, to bytes: inout [UInt8], at offset: Int) {
        bytes[offset] = UInt8(value & 0xff)
        bytes[offset + 1] = UInt8((value >> 8) & 0xff)
    }

    private func hexUTF16(_ value: String) -> String {
        NTLM.utf16le(value).map { String(format: "%02x", $0) }.joined()
    }
}

private final class SMBPathSeparatorRecordingTransport: SMBTransport, @unchecked Sendable {
    private let transport = POSIXSocketTransport()
    private let lock = NSLock()
    private var sentBytes: [UInt8] = []
    private var receivedBytes: [UInt8] = []

    var outboundPackets: [[UInt8]] {
        lock.withLock { Self.unframe(sentBytes) }
    }

    var inboundPackets: [[UInt8]] {
        lock.withLock { Self.unframe(receivedBytes) }
    }

    func connect(host: String, port: UInt16) async throws {
        try await transport.connect(host: host, port: port)
    }

    func send(_ bytes: [UInt8]) async throws {
        lock.withLock { sentBytes.append(contentsOf: bytes) }
        try await transport.send(bytes)
    }

    func send(_ segments: [[UInt8]]) async throws {
        lock.withLock {
            for segment in segments {
                sentBytes.append(contentsOf: segment)
            }
        }
        try await transport.send(segments)
    }

    func receive(maxLength: Int) async throws -> [UInt8] {
        let bytes = try await transport.receive(maxLength: maxLength)
        lock.withLock { receivedBytes.append(contentsOf: bytes) }
        return bytes
    }

    func close() {
        transport.close()
    }

    private static func unframe(_ bytes: [UInt8]) -> [[UInt8]] {
        var packets: [[UInt8]] = []
        var offset = 0
        while bytes.count - offset >= 4 {
            let length = (Int(bytes[offset + 1]) << 16)
                | (Int(bytes[offset + 2]) << 8)
                | Int(bytes[offset + 3])
            guard length <= bytes.count - offset - 4 else { break }
            packets.append(Array(bytes[offset + 4..<offset + 4 + length]))
            offset += length + 4
        }
        return packets
    }
}

private enum E2EConfigurationError: Error {
    case invalidPort
}
