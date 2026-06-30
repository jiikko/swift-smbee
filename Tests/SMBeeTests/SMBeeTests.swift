import Crypto
import Foundation
import XCTest
@testable import SMBee

private final class BlockingReceiveTransport: SMBTransport, @unchecked Sendable {
    private let receiveState = ReceiveState()

    func connect(host: String, port: UInt16) async throws {
        try Task.checkCancellation()
        _ = host
        _ = port
    }

    func send(_ bytes: [UInt8]) async throws {
        try Task.checkCancellation()
        _ = bytes
    }

    func receive(maxLength: Int) async throws -> [UInt8] {
        try Task.checkCancellation()
        _ = maxLength

        return try await withTaskCancellationHandler {
            try await receiveState.waitForCancellation()
        } onCancel: {
            receiveState.cancel()
        }
    }

    func close() {
        receiveState.cancel()
    }
}

private final class FailingReceiveTransport: SMBTransport, @unchecked Sendable {
    let failure: Error

    init(failure: Error) {
        self.failure = failure
    }

    func connect(host: String, port: UInt16) async throws {
        try Task.checkCancellation()
        _ = host
        _ = port
    }

    func send(_ bytes: [UInt8]) async throws {
        try Task.checkCancellation()
        _ = bytes
    }

    func receive(maxLength: Int) async throws -> [UInt8] {
        try Task.checkCancellation()
        _ = maxLength
        throw failure
    }

    func close() {}
}

private final class FailingConnectTransport: SMBTransport, @unchecked Sendable {
    let failure: Error

    init(failure: Error) {
        self.failure = failure
    }

    func connect(host: String, port: UInt16) async throws {
        try Task.checkCancellation()
        _ = host
        _ = port
        throw failure
    }

    func send(_ bytes: [UInt8]) async throws {
        try Task.checkCancellation()
        _ = bytes
    }

    func receive(maxLength: Int) async throws -> [UInt8] {
        try Task.checkCancellation()
        _ = maxLength
        return []
    }

    func close() {}
}

private final class TransportFactorySequence: @unchecked Sendable {
    private let lock = NSLock()
    private var transports: [SMBTransport]
    private(set) var makeCount = 0

    init(_ transports: [SMBTransport]) {
        self.transports = transports
    }

    func make() -> SMBTransport {
        lock.lock()
        defer { lock.unlock() }
        makeCount += 1
        return transports.removeFirst()
    }
}

private final class ControlledReceiveTransport: SMBTransport, @unchecked Sendable {
    private struct PendingReceive {
        var maxLength: Int
        var continuation: CheckedContinuation<[UInt8], Error>
    }

    private let lock = NSLock()
    private var inbound: [UInt8] = []
    private var pending: PendingReceive?
    private var outboundStorage: [UInt8] = []

    var outbound: [UInt8] {
        lock.lock()
        defer { lock.unlock() }
        return outboundStorage
    }

    func connect(host: String, port: UInt16) async throws {
        try Task.checkCancellation()
        _ = host
        _ = port
    }

    func send(_ bytes: [UInt8]) async throws {
        try Task.checkCancellation()
        appendOutbound(bytes)
    }

    private func appendOutbound(_ bytes: [UInt8]) {
        lock.lock()
        outboundStorage.append(contentsOf: bytes)
        lock.unlock()
    }

    func receive(maxLength: Int) async throws -> [UInt8] {
        try Task.checkCancellation()
        return try await withCheckedThrowingContinuation { continuation in
            let chunk: [UInt8]?

            lock.lock()
            if inbound.isEmpty {
                pending = PendingReceive(maxLength: maxLength, continuation: continuation)
                chunk = nil
            } else {
                let count = min(maxLength, inbound.count)
                chunk = Array(inbound.prefix(count))
                inbound.removeFirst(count)
            }
            lock.unlock()

            if let chunk {
                continuation.resume(returning: chunk)
            }
        }
    }

    func enqueueInbound(_ bytes: [UInt8]) {
        let pendingReceive: PendingReceive?
        let chunk: [UInt8]?

        lock.lock()
        inbound.append(contentsOf: bytes)
        if let pending {
            let count = min(pending.maxLength, inbound.count)
            chunk = Array(inbound.prefix(count))
            inbound.removeFirst(count)
            pendingReceive = pending
            self.pending = nil
        } else {
            chunk = nil
            pendingReceive = nil
        }
        lock.unlock()

        if let pendingReceive, let chunk {
            pendingReceive.continuation.resume(returning: chunk)
        }
    }

    func close() {}
}

private final class ReceiveState: @unchecked Sendable {
    private let lock = NSLock()
    private var continuation: CheckedContinuation<[UInt8], Error>?
    private var isCancelled = false

    func waitForCancellation() async throws -> [UInt8] {
        try await withCheckedThrowingContinuation { continuation in
            let continuationToResume: CheckedContinuation<[UInt8], Error>?

            lock.lock()
            if isCancelled {
                continuationToResume = continuation
            } else {
                self.continuation = continuation
                continuationToResume = nil
            }
            lock.unlock()

            continuationToResume?.resume(throwing: CancellationError())
        }
    }

    func cancel() {
        let continuationToResume: CheckedContinuation<[UInt8], Error>?

        lock.lock()
        isCancelled = true
        continuationToResume = continuation
        continuation = nil
        lock.unlock()

        continuationToResume?.resume(throwing: CancellationError())
    }
}

private final class TestDirectoryEntryCollector: @unchecked Sendable {
    private let lock = NSLock()
    private var storage: [SMBDirectoryEntry] = []

    var entries: [SMBDirectoryEntry] {
        lock.lock()
        defer { lock.unlock() }
        return storage
    }

    func append(_ entry: SMBDirectoryEntry) {
        lock.lock()
        storage.append(entry)
        lock.unlock()
    }
}

final class SMBeeTests: XCTestCase {
    func testVersionIsNotEmpty() {
        XCTAssertFalse(SMBee.version.isEmpty)
    }

    func testReadURLParserKeepsUserInfoPassword() throws {
        let endpoint = try SMBURLParser.parseReadURL("smb://user:pass@server:1445/share/path/to/file.txt")

        XCTAssertEqual(endpoint.username, "user")
        XCTAssertEqual(endpoint.password, "pass")
        XCTAssertEqual(endpoint.host, "server")
        XCTAssertEqual(endpoint.port, 1445)
        XCTAssertEqual(endpoint.share, "share")
        XCTAssertEqual(endpoint.path, "path\\to\\file.txt")
    }

    func testReadURLParserDecodesPercentEncodedComponents() throws {
        let endpoint = try SMBURLParser.parseReadURL("smb://user%40domain:p%40ss@server/share%20name/dir%20one/file%23.txt")

        XCTAssertEqual(endpoint.username, "user@domain")
        XCTAssertEqual(endpoint.password, "p@ss")
        XCTAssertEqual(endpoint.share, "share name")
        XCTAssertEqual(endpoint.path, "dir one\\file#.txt")
    }

    func testReadURLParserRejectsDotDotAndSeparatorComponents() {
        XCTAssertThrowsError(try SMBURLParser.parseReadURL("smb://user@server/share/../file.txt"))
        XCTAssertThrowsError(try SMBURLParser.parseReadURL("smb://user@server/share/dir%2Ffile.txt"))
        XCTAssertThrowsError(try SMBURLParser.parseReadURL("smb://user@server/share/dir%5Cfile.txt"))
    }

    func testSMBPathNormalizesPublicAPIPaths() throws {
        XCTAssertEqual(try SMBPath.normalize("\\dir/child\\"), "dir\\child")
        XCTAssertEqual(try SMBPath.normalize(""), "")
        XCTAssertEqual(try SMBPath.join("\\dir", "/child"), "dir\\child")
        XCTAssertThrowsError(try SMBPath.normalize("dir//child"))
        XCTAssertThrowsError(try SMBPath.normalize("dir/./child"))
        XCTAssertThrowsError(try SMBPath.normalize("dir/../child"))
    }

    func testSMBShareNameRejectsPathSeparators() {
        XCTAssertThrowsError(try SMBShareName(""))
        XCTAssertThrowsError(try SMBShareName("a/b"))
        XCTAssertThrowsError(try SMBShareName("a\\b"))
        XCTAssertThrowsError(try SMBShareName(".."))
    }

    func testSMBErrorMapperMapsRepresentativeNTSTATUSValues() {
        XCTAssertEqual(
            SMBErrorMapper.map(status: SMB2Status.objectNameNotFound, operation: "CREATE"),
            .notFound(status: SMB2Status.objectNameNotFound, operation: "CREATE")
        )
        XCTAssertEqual(
            SMBErrorMapper.map(status: SMB2Status.objectPathNotFound, operation: "CREATE"),
            .notFound(status: SMB2Status.objectPathNotFound, operation: "CREATE")
        )
        XCTAssertEqual(
            SMBErrorMapper.map(status: SMB2Status.accessDenied, operation: "READ"),
            .accessDenied(status: SMB2Status.accessDenied, operation: "READ")
        )
        XCTAssertEqual(
            SMBErrorMapper.map(status: SMB2Status.sharingViolation, operation: "CREATE"),
            .sharingViolation(status: SMB2Status.sharingViolation, operation: "CREATE")
        )
        XCTAssertEqual(
            SMBErrorMapper.map(status: SMB2Status.objectNameCollision, operation: "CREATE"),
            .nameCollision(status: SMB2Status.objectNameCollision, operation: "CREATE")
        )
        XCTAssertEqual(
            SMBErrorMapper.map(status: SMB2Status.directoryNotEmpty, operation: "CLOSE"),
            .directoryNotEmpty(status: SMB2Status.directoryNotEmpty, operation: "CLOSE")
        )
        XCTAssertEqual(
            SMBErrorMapper.map(status: SMB2Status.fileIsADirectory, operation: "READ"),
            .fileIsADirectory(status: SMB2Status.fileIsADirectory, operation: "READ")
        )
        XCTAssertEqual(
            SMBErrorMapper.map(status: SMB2Status.notADirectory, operation: "QUERY_DIRECTORY"),
            .notADirectory(status: SMB2Status.notADirectory, operation: "QUERY_DIRECTORY")
        )
        XCTAssertEqual(
            SMBErrorMapper.map(status: SMB2Status.diskFull, operation: "WRITE"),
            .diskFull(status: SMB2Status.diskFull, operation: "WRITE")
        )
        XCTAssertEqual(
            SMBErrorMapper.map(status: SMB2Status.networkNameDeleted, operation: "TREE_CONNECT"),
            .networkNameDeleted(status: SMB2Status.networkNameDeleted, operation: "TREE_CONNECT")
        )
        XCTAssertEqual(
            SMBErrorMapper.map(status: SMB2Status.logonFailure, operation: "SESSION_SETUP"),
            .logonFailure(status: SMB2Status.logonFailure, operation: "SESSION_SETUP")
        )
        XCTAssertEqual(
            SMBErrorMapper.map(status: SMB2Status.objectNameInvalid, operation: "CREATE"),
            .objectNameInvalid(status: SMB2Status.objectNameInvalid, operation: "CREATE")
        )
        XCTAssertEqual(
            SMBErrorMapper.map(status: SMB2Status.endOfFile, operation: "READ"),
            .endOfFile(status: SMB2Status.endOfFile, operation: "READ")
        )
        XCTAssertEqual(
            SMBErrorMapper.map(status: 0xc000_000d, operation: "QUERY_INFO"),
            .unsupported(status: 0xc000_000d, operation: "QUERY_INFO")
        )
    }

    func testTransportCancellationPropagatesCancellationError() async {
        let transport = BlockingReceiveTransport()
        let task = Task {
            try await transport.receive(maxLength: 1)
        }
        task.cancel()

        do {
            _ = try await task.value
            XCTFail("expected CancellationError")
        } catch is CancellationError {
        } catch {
            XCTFail("expected CancellationError, got \(error)")
        }
    }

    func testProbeRetriesConnectionLossOnceAndSucceedsWithNewTransport() async throws {
        let first = FailingReceiveTransport(failure: SMBTransportError.connectionClosed)
        let second = InMemoryTransport(inbound: try framed([negotiateResponse(messageId: 0)]))
        let factory = TransportFactorySequence([first, second])

        let result = try await SMBProbe.probe(host: "server", makeTransport: factory.make)

        XCTAssertEqual(result.dialect, SMBNegotiateConstants.dialect302)
        XCTAssertEqual(factory.makeCount, 2)
    }

    func testDeleteDoesNotRetryConnectionLossAndThrowsConnectionLost() async {
        let factory = TransportFactorySequence([
            FailingConnectTransport(failure: SMBTransportError.connectionClosed),
        ])

        do {
            try await SMBClient.delete(
                host: "server",
                share: "share",
                path: "dead.txt",
                credential: SMBCredential(username: "user", password: "pass"),
                makeTransport: factory.make
            )
            XCTFail("expected connectionLost")
        } catch SMBError.connectionLost(operation: "DELETE") {
            XCTAssertEqual(factory.makeCount, 1)
        } catch {
            XCTFail("expected connectionLost, got \(error)")
        }
    }

    func testSessionSetupLogonFailureDoesNotRetry() async throws {
        let inbound = try framed([
            negotiateResponse(messageId: 0),
            smb2StatusResponse(status: SMB2Status.logonFailure, command: SMB2Commands.sessionSetup, messageId: 1, treeId: 0),
        ])
        let factory = TransportFactorySequence([InMemoryTransport(inbound: inbound)])

        do {
            _ = try await SMBClient.list(
                host: "server",
                share: "share",
                credential: SMBCredential(username: "user", password: "pass"),
                makeTransport: factory.make
            )
            XCTFail("expected logonFailure")
        } catch SMBError.logonFailure(status: SMB2Status.logonFailure, operation: "SESSION_SETUP#1") {
            XCTAssertEqual(factory.makeCount, 1)
        } catch {
            XCTFail("expected logonFailure, got \(error)")
        }
    }

    func testSMB2HeaderRoundTrip() throws {
        let header = SMB2Header(
            creditCharge: 7,
            status: 0x1122_3344,
            command: 0,
            credits: 9,
            flags: 0x5566_7788,
            nextCommand: 0,
            messageId: 42,
            treeId: 0xaabb_ccdd,
            sessionId: 0x0102_0304_0506_0708,
            signature: Array(0..<16)
        )

        let encoded = try header.encode()
        XCTAssertEqual(encoded.count, 64)
        XCTAssertEqual(try SMB2Header.decode(encoded), header)
    }

    func testMD4RFC1320Vectors() {
        XCTAssertEqual(hex(MD4.hash([])), "31d6cfe0d16ae931b73c59d7e0c089c0")
        XCTAssertEqual(hex(MD4.hash(Array("a".utf8))), "bde52cb31de33e46245e05fbdbd6fb24")
        XCTAssertEqual(hex(MD4.hash(Array("abc".utf8))), "a448017aaf21d8525fc10ae87aa6729d")
        XCTAssertEqual(hex(MD4.hash(Array("message digest".utf8))), "d9130a8164549fe818874806e1c7014b")
    }

    func testHMACAndSHAUsingSwiftCryptoVectors() {
        let hmacMD5 = HMAC<Insecure.MD5>.authenticationCode(
            for: Array("Hi There".utf8),
            using: SymmetricKey(data: Array(repeating: 0x0b, count: 16))
        )
        XCTAssertEqual(hex(Array(hmacMD5)), "9294727a3638bb1c13f48ef8158bfc9d")

        let hmacSHA256 = SMBCrypto.hmacSHA256(
            key: Array(repeating: 0x0b, count: 20),
            message: Array("Hi There".utf8)
        )
        XCTAssertEqual(
            hex(hmacSHA256),
            "b0344c61d8db38535ca8afceaf0bf12b"
                + "881dc200c9833da726e9376c2e32cff7"
        )

        XCTAssertEqual(
            hex(SMBCrypto.sha512(Array("abc".utf8))),
            "ddaf35a193617abacc417349ae204131"
                + "12e6fa4e89a97ea20a9eeee64b55d39a"
                + "2192992a274fc1a836ba3c23a3feebbd"
                + "454d4423643ce80e2a9ac94fa54ca49f"
        )
    }

    func testRC4KnownVectors() {
        XCTAssertEqual(hex(RC4.crypt(key: Array("Key".utf8), message: Array("Plaintext".utf8))), "bbf316e8d940af0ad3")
        XCTAssertEqual(hex(RC4.crypt(key: Array("Wiki".utf8), message: Array("pedia".utf8))), "1021bf0420")
    }

    func testAESGCMAndGMACNISTVectors() throws {
        let key = Array(repeating: UInt8(0), count: 16)
        let nonce = Array(repeating: UInt8(0), count: 12)
        let gcm = try SMBCrypto.aesGCMSeal(key: key, nonce: nonce, plaintext: [], authenticatedData: [])
        XCTAssertEqual(gcm.ciphertext, [])
        XCTAssertEqual(hex(gcm.tag), "58e2fccefa7e3061367f1d57a4e7455a")

        let gmac = try SMBCrypto.aesGMAC(key: key, nonce: nonce, authenticatedData: [])
        XCTAssertEqual(hex(gmac), "58e2fccefa7e3061367f1d57a4e7455a")
    }

    func testAESCMACRFC4493Vectors() throws {
        let key = hexBytes("2b7e151628aed2a6abf7158809cf4f3c")
        let message = hexBytes(
            "6bc1bee22e409f96e93d7e117393172a" +
            "ae2d8a571e03ac9c9eb76fac45af8e51" +
            "30c81c46a35ce411"
        )
        XCTAssertEqual(hex(try AES128.encryptBlock(key: key, block: hexBytes("6bc1bee22e409f96e93d7e117393172a"))), "3ad77bb40d7a3660a89ecaf32466ef97")
        XCTAssertEqual(hex(try AESCMAC.authenticationCode(key: key, message: [])), "bb1d6929e95937287fa37d129b756746")
        XCTAssertEqual(hex(try AESCMAC.authenticationCode(key: key, message: Array(message[0..<16]))), "070a16b46b4d4144f79bdd9dd04a287c")
        XCTAssertEqual(hex(try AESCMAC.authenticationCode(key: key, message: message)), "dfa66747de9ae63030ca32611497c827")
        XCTAssertEqual(
            hex(try AESCMAC.authenticationCode(key: key, message: hexBytes(
                "6bc1bee22e409f96e93d7e117393172a" +
                "ae2d8a571e03ac9c9eb76fac45af8e51" +
                "30c81c46a35ce411e5fbc1191a0a52ef" +
                "f69f2445df4f9b17ad2b417be66c3710"
            ))),
            "51f0bebf7e3b9d92fc49741779363cfe"
        )
    }

    func testAESCCMRFC3610Vector() throws {
        let key = hexBytes("c0c1c2c3c4c5c6c7c8c9cacbcccdcecf")
        let nonce = hexBytes("00000003020100a0a1a2a3a4a5")
        let aad = hexBytes("0001020304050607")
        let plaintext = hexBytes("08090a0b0c0d0e0f101112131415161718191a1b1c1d1e")
        let sealed = try AESCCM.seal(
            key: key,
            nonce: nonce,
            plaintext: plaintext,
            authenticatedData: aad,
            tagLength: 8
        )
        XCTAssertEqual(hex(sealed.ciphertext + sealed.tag), "588c979a61c663d2f066d0c2c0f989806d5f6b61dac38417e8d12cfdf926e0")
        XCTAssertEqual(
            try AESCCM.open(key: key, nonce: nonce, ciphertext: sealed.ciphertext, authenticatedData: aad, tag: sealed.tag),
            plaintext
        )
    }

    func testSMB3TransformHeaderRoundTripAndCCM() throws {
        let key = hexBytes("000102030405060708090a0b0c0d0e0f")
        let plaintext = Array("plain SMB2 message".utf8)
        let nonce11 = hexBytes("00112233445566778899aa")
        var header = SMB3TransformHeader(
            signature: Array(repeating: 0, count: 16),
            nonce: nonce11 + Array(repeating: 0, count: 5),
            originalMessageSize: UInt32(plaintext.count),
            flags: SMB3TransformHeader.aes128CCM,
            sessionId: 0x0102_0304_0506_0708
        )
        let sealed = try AESCCM.seal(
            key: key,
            nonce: nonce11,
            plaintext: plaintext,
            authenticatedData: header.authenticatedData(),
            tagLength: 16
        )
        header.signature = sealed.tag
        let encoded = try header.encode()
        let authenticatedData = try header.authenticatedData()
        XCTAssertEqual(encoded.count, SMB3TransformHeader.encodedSize)
        XCTAssertEqual(try SMB3TransformHeader.decode(encoded), header)
        XCTAssertEqual(authenticatedData, Array(encoded[20..<52]))
        XCTAssertEqual(authenticatedData.count, 32)
        XCTAssertEqual(Array(header.nonce.prefix(11)), nonce11)
        XCTAssertEqual(Array(header.nonce.dropFirst(11)), Array(repeating: 0, count: 5))
        XCTAssertEqual(
            try AESCCM.open(
                key: key,
                nonce: nonce11,
                ciphertext: sealed.ciphertext,
                authenticatedData: header.authenticatedData(),
                tag: header.signature
            ),
            plaintext
        )
    }

    func testSMB3TransformHeaderRoundTripAndGCM() throws {
        let key = hexBytes("000102030405060708090a0b0c0d0e0f")
        let plaintext = Array("SMB 3.1.1 encrypted message".utf8)
        let nonce12 = hexBytes("00112233445566778899aabb")
        var header = SMB3TransformHeader(
            signature: Array(repeating: 0, count: 16),
            nonce: nonce12 + Array(repeating: 0, count: 4),
            originalMessageSize: UInt32(plaintext.count),
            flags: SMB3TransformHeader.aes128GCM,
            sessionId: 0x0102_0304_0506_0708
        )
        let sealed = try SMBCrypto.aesGCMSeal(
            key: key,
            nonce: nonce12,
            plaintext: plaintext,
            authenticatedData: header.authenticatedData()
        )
        header.signature = sealed.tag
        let encoded = try header.encode()

        XCTAssertEqual(encoded.count, SMB3TransformHeader.encodedSize)
        XCTAssertEqual(try SMB3TransformHeader.decode(encoded), header)
        XCTAssertEqual(try header.authenticatedData(), Array(encoded[20..<52]))
        XCTAssertEqual(Array(header.nonce.prefix(12)), nonce12)
        XCTAssertEqual(Array(header.nonce.dropFirst(12)), Array(repeating: 0, count: 4))
        XCTAssertEqual(hex(sealed.ciphertext), "be9e094aa4ce9f28c84a63e967be3521f7d7e06e17fc8b098a59ce")
        XCTAssertEqual(hex(header.signature), "43a216b82c24b2f2740b885b2af8d013")
        XCTAssertEqual(
            try SMBCrypto.aesGCMOpen(
                key: key,
                nonce: nonce12,
                ciphertext: sealed.ciphertext,
                authenticatedData: header.authenticatedData(),
                tag: header.signature
            ),
            plaintext
        )
    }

    func testSMB302KeyDerivationLabelAndContextBytes() {
        XCTAssertEqual(hex(SMBCrypto.smb3SigningLabel), "534d4232414553434d414300")
        XCTAssertEqual(hex(SMBCrypto.smb3SigningContext), "536d625369676e00")
        XCTAssertEqual(hex(SMBCrypto.smb302EncryptionLabel), "534d423241455343434d00")
        XCTAssertEqual(hex(SMBCrypto.smb302EncryptionContext), "536572766572496e2000")
        XCTAssertEqual(hex(SMBCrypto.smb302DecryptionContext), "5365727665724f757400")
    }

    func testSMB311PreauthIntegrityHashAndKDFLabels() {
        let messages = [
            Array("NEGOTIATE request fixture".utf8),
            Array("SESSION_SETUP response fixture".utf8),
        ]
        let preauthHash = SMBCrypto.smb311PreauthIntegrityHash(messages)
        let sessionKey = Array(UInt8(0)...UInt8(15))

        XCTAssertEqual(hex(SMBCrypto.smb311SigningLabel), "534d425369676e696e674b6579")
        XCTAssertEqual(hex(SMBCrypto.smb311EncryptionLabel), "534d424332534369706865724b6579")
        XCTAssertEqual(hex(SMBCrypto.smb311DecryptionLabel), "534d425332434369706865724b6579")
        XCTAssertEqual(hex(SMBCrypto.smb311ApplicationLabel), "534d424170704b6579")
        XCTAssertEqual(
            hex(preauthHash),
            "304e5266d152ea390203ff2ebd32632669f607debb5af2f85ece3932fd6d7091" +
                "42f9e1c44900c1a8e2bf509791c11af65a77fd48f61ddf8a7000ae694ebfb7d2"
        )
        XCTAssertEqual(hex(SMBCrypto.smb311SigningKey(sessionKey: sessionKey, preauthIntegrityHash: preauthHash)), "dae2715960a353373c17f4081ce84a3e")
        XCTAssertEqual(hex(SMBCrypto.smb311EncryptionKey(sessionKey: sessionKey, preauthIntegrityHash: preauthHash)), "651c2ddb43d0d8efa327d5fe8a755c29")
        XCTAssertEqual(hex(SMBCrypto.smb311DecryptionKey(sessionKey: sessionKey, preauthIntegrityHash: preauthHash)), "e851efe5671dfd7dd362cec27539128b")
        XCTAssertEqual(hex(SMBCrypto.smb311ApplicationKey(sessionKey: sessionKey, preauthIntegrityHash: preauthHash)), "4eabeb1151ac8d2d4fb3445781419c41")
    }

    func testSMB302EncryptionKeyDerivationLabels() {
        let sessionKey = hexBytes("00112233445566778899aabbccddeeff")
        let encryptionKey = SMBCrypto.smb302EncryptionKey(sessionKey: sessionKey)
        let decryptionKey = SMBCrypto.smb302DecryptionKey(sessionKey: sessionKey)
        XCTAssertEqual(encryptionKey.count, 16)
        XCTAssertEqual(decryptionKey.count, 16)
        XCTAssertNotEqual(encryptionKey, decryptionKey)
        XCTAssertEqual(
            encryptionKey,
            SMBCrypto.sp800108CounterModeHMACSHA256(
                key: sessionKey,
                label: SMBCrypto.smb302EncryptionLabel,
                context: SMBCrypto.smb302EncryptionContext,
                length: 16
            )
        )
        XCTAssertEqual(
            decryptionKey,
            SMBCrypto.sp800108CounterModeHMACSHA256(
                key: sessionKey,
                label: SMBCrypto.smb302EncryptionLabel,
                context: SMBCrypto.smb302DecryptionContext,
                length: 16
            )
        )
        XCTAssertNotEqual(
            decryptionKey,
            SMBCrypto.sp800108CounterModeHMACSHA256(
                key: sessionKey,
                label: SMBCrypto.smb302EncryptionLabel,
                context: Array("ServerOut ".utf8) + [0],
                length: 16
            )
        )
    }

    func testNTLMv2KnownVectors() {
        let ntowfv2 = NTLM.ntowfv2(password: "SecREt01", username: "User", domain: "Domain")
        XCTAssertEqual(hex(ntowfv2), "54993fb8ba7bc2d6eacaef6bdc226c49")
        let serverChallenge = hexBytes("0123456789abcdef")
        let blob = hexBytes(
            "01010000000000000090d336b734c301ffffff001122334400000000" +
            "02000c0044004f004d00410049004e00" +
            "01000c00530045005200560045005200" +
            "0400140064006f006d00610069006e002e0063006f006d00" +
            "030022007300650072007600650072002e0064006f006d00610069006e002e0063006f006d00" +
            "0000000000000000"
        )
        XCTAssertEqual(hex(NTLM.ntProofStr(ntowfv2: ntowfv2, serverChallenge: serverChallenge, blob: blob)), "2a8e1bc8a06222ed5301c3fbd2154d0b")
    }

    func testNTLMv2CredentialCanUseNTHashInsteadOfPassword() throws {
        let ntHash = MD4.hash(NTLM.utf16le("Password"))
        let credential = try SMBCredential(username: "User", ntHash: ntHash, domain: "Domain")

        XCTAssertEqual(credential.password, "")
        XCTAssertEqual(credential.ntHash, ntHash)
        XCTAssertEqual(
            try NTLM.ntowfv2(credential: credential),
            NTLM.ntowfv2(password: "Password", username: "User", domain: "Domain")
        )
    }

    func testNTLMv2CredentialRejectsInvalidNTHashLength() {
        XCTAssertThrowsError(try SMBCredential(username: "User", ntHash: [0], domain: "Domain"))
    }

    func testMSNLMPSection424NTLMv2SessionKeyExchangeRegressionVector() throws {
        // Regression vector for this implementation's fixed inputs. This is not the
        // literal MS-NLMP 4.2.4 published vector: timestamp and client challenge differ.
        let targetInfo = hexBytes(
            "02000c0044004f004d00410049004e00" +
            "01000c00530045005200560045005200" +
            "0000000000000000"
        )
        let challenge = NTLMChallenge(
            targetName: NTLM.utf16le("Server"),
            flags: NTLM.negotiateFlags,
            serverChallenge: hexBytes("0123456789abcdef"),
            targetInfo: targetInfo
        )
        let authenticate = try NTLM.makeType3(
            credential: SMBCredential(username: "User", password: "Password", domain: "Domain"),
            challenge: challenge,
            timestamp: 0x01c334b736d39000,
            clientChallenge: hexBytes("ffffff0011223344"),
            exportedSessionKey: hexBytes("55555555555555555555555555555555")
        )

        XCTAssertEqual(hex(NTLM.ntowfv2(password: "Password", username: "User", domain: "Domain")), "0c868a403bfd7a93a3001ef22ef02e3f")
        let ntChallengeResponseOffset = Int(readUInt32LE(authenticate.message, at: 24))
        XCTAssertEqual(
            hex(Array(authenticate.message[ntChallengeResponseOffset..<ntChallengeResponseOffset + 16])),
            "11a818b18b5ecd85485ae35d27f6a3df"
        )
        XCTAssertEqual(hex(authenticate.sessionBaseKey), "6e03ecfd4e8b43789dcd872557efa026")
        XCTAssertEqual(readUInt32LE(authenticate.message, at: 60) & NTLM.negotiateKeyExchange, NTLM.negotiateKeyExchange)
        XCTAssertEqual(readUInt16LE(authenticate.message, at: 52), 16)
        XCTAssertEqual(hex(readSecurityBuffer(authenticate.message, at: 52)), "531734fe4e46f82f46a28fadaaaf0e49")
        XCTAssertEqual(authenticate.exportedSessionKey, hexBytes("55555555555555555555555555555555"))
    }

    func testNTLMMICUsesExportedSessionKeyAndZeroedMICField() throws {
        let type1 = NTLM.makeType1()
        let type2 = makeNTLMChallengeMessage(targetInfo: hexBytes("070008000090d336b734c30100000000"))
        let challenge = try NTLM.parseChallenge(type2)
        let exportedSessionKey = hexBytes("00112233445566778899aabbccddeeff")
        let authenticate = try NTLM.makeType3(
            credential: SMBCredential(username: "User", password: "Password", domain: "Domain"),
            challenge: challenge,
            negotiateMessage: type1,
            challengeMessage: type2,
            timestamp: 0x01c334b736d39000,
            clientChallenge: hexBytes("ffffff0011223344"),
            exportedSessionKey: exportedSessionKey
        )

        XCTAssertEqual(authenticate.message.count >= 88, true)
        XCTAssertEqual(readUInt32LE(authenticate.message, at: 60) & NTLM.negotiateKeyExchange, NTLM.negotiateKeyExchange)
        XCTAssertEqual(readUInt32LE(authenticate.message, at: 60) & NTLM.negotiateSeal, 0)
        XCTAssertNotEqual(Array(authenticate.message[72..<88]), Array(repeating: 0, count: 16))
        var zeroed = authenticate.message
        zeroed.replaceSubrange(72..<88, with: Array(repeating: 0, count: 16))
        XCTAssertEqual(
            Array(authenticate.message[72..<88]),
            SMBCrypto.hmacMD5(key: exportedSessionKey, message: type1 + type2 + zeroed)
        )
    }

    func testNTLMType3MICPathAddsRequiredAVPairs() throws {
        let type1 = NTLM.makeType1()
        var targetInfo: [UInt8] = []
        appendAVPair(id: 1, value: NTLM.utf16le("SERVER"), to: &targetInfo)
        appendAVPair(id: 2, value: NTLM.utf16le("DOMAIN"), to: &targetInfo)
        appendAVPair(id: 3, value: NTLM.utf16le("server.domain.com"), to: &targetInfo)
        appendAVPair(id: 4, value: NTLM.utf16le("domain.com"), to: &targetInfo)
        appendAVPair(id: 7, value: hexBytes("0090d336b734c301"), to: &targetInfo)
        appendAVPair(id: 0, value: [], to: &targetInfo)
        let type2 = makeNTLMChallengeMessage(targetInfo: targetInfo)
        let challenge = try NTLM.parseChallenge(type2)
        let authenticate = try NTLM.makeType3(
            credential: SMBCredential(username: "User", password: "Password", domain: "Domain"),
            challenge: challenge,
            serverName: "169.254.69.111",
            negotiateMessage: type1,
            challengeMessage: type2,
            timestamp: 0x01c334b736d39000,
            clientChallenge: hexBytes("ffffff0011223344"),
            exportedSessionKey: hexBytes("00112233445566778899aabbccddeeff")
        )
        let ntChallengeResponse = readSecurityBuffer(authenticate.message, at: 20)
        let blob = Array(ntChallengeResponse.dropFirst(16))
        let avPairs = try decodeNTLMv2BlobAVPairs(blob)

        XCTAssertEqual(avPairs.map { $0.id }, [1, 2, 3, 4, 7, 6, 9, 10, 0])
        XCTAssertEqual(avPairs.first { $0.id == 6 }?.value, [0x02, 0x00, 0x00, 0x00])
        XCTAssertEqual(avPairs.first { $0.id == 9 }?.value, NTLM.utf16le("cifs/169.254.69.111"))
        XCTAssertEqual(avPairs.first { $0.id == 10 }?.value, Array(repeating: 0, count: 16))
    }

    func testNTLMType3MICPathUpdatesExistingRequiredAVPairsWithoutDuplicates() throws {
        let type1 = NTLM.makeType1()
        var targetInfo: [UInt8] = []
        appendAVPair(id: 1, value: NTLM.utf16le("SERVER"), to: &targetInfo)
        appendAVPair(id: 6, value: [0x01, 0x00, 0x00, 0x00], to: &targetInfo)
        appendAVPair(id: 7, value: hexBytes("0090d336b734c301"), to: &targetInfo)
        appendAVPair(id: 9, value: NTLM.utf16le("server-sent-target"), to: &targetInfo)
        appendAVPair(id: 10, value: Array(repeating: 0xff, count: 16), to: &targetInfo)
        appendAVPair(id: 0, value: [], to: &targetInfo)
        let type2 = makeNTLMChallengeMessage(targetInfo: targetInfo)
        let challenge = try NTLM.parseChallenge(type2)
        let authenticate = try NTLM.makeType3(
            credential: SMBCredential(username: "User", password: "Password", domain: "Domain"),
            challenge: challenge,
            serverName: "169.254.69.111",
            negotiateMessage: type1,
            challengeMessage: type2,
            timestamp: 0x01c334b736d39000,
            clientChallenge: hexBytes("ffffff0011223344"),
            exportedSessionKey: hexBytes("00112233445566778899aabbccddeeff")
        )
        let ntChallengeResponse = readSecurityBuffer(authenticate.message, at: 20)
        let blob = Array(ntChallengeResponse.dropFirst(16))
        let avPairs = try decodeNTLMv2BlobAVPairs(blob)

        XCTAssertEqual(avPairs.map { $0.id }, [1, 6, 7, 9, 10, 0])
        XCTAssertEqual(avPairs.filter { $0.id == 6 }.count, 1)
        XCTAssertEqual(readUInt32LE(avPairs.first { $0.id == 6 }!.value, at: 0), 0x00000003)
        XCTAssertEqual(avPairs.filter { $0.id == 9 }.count, 1)
        XCTAssertEqual(avPairs.first { $0.id == 9 }?.value, NTLM.utf16le("cifs/169.254.69.111"))
        XCTAssertEqual(avPairs.filter { $0.id == 10 }.count, 1)
        XCTAssertEqual(avPairs.first { $0.id == 10 }?.value, Array(repeating: 0, count: 16))
    }

    func testNTLMClientSigningKeyAndMechListMICUseFixedVectors() throws {
        let exportedSessionKey = hexBytes("00112233445566778899aabbccddeeff")
        let signingKey = NTLM.clientSigningKey(exportedSessionKey: exportedSessionKey)
        let sealingKey = NTLM.clientSealingKey(exportedSessionKey: exportedSessionKey)
        let mic = NTLM.makeMechListMIC(exportedSessionKey: exportedSessionKey)

        XCTAssertEqual(hex(signingKey), "59d6baefd8fb9cfe7c66605162a2b238")
        XCTAssertEqual(hex(sealingKey), "248e660b070223ef5f92354062032e48")
        XCTAssertEqual(SPNEGO.ntlmMechTypeListDER, hexBytes("300c060a2b06010401823702020a"))
        XCTAssertEqual(hex(mic), "01000000549d70fe51ab6ebd00000000")
    }

    func testNTLMType1FixedBytesAndSecurityBuffers() {
        let type1 = NTLM.makeType1()

        XCTAssertEqual(type1.count, 40)
        XCTAssertEqual(Array(type1[0..<8]), Array("NTLMSSP\0".utf8))
        XCTAssertEqual(readUInt32LE(type1, at: 8), 1)
        XCTAssertEqual(readUInt32LE(type1, at: 12), NTLM.negotiateFlags)
        XCTAssertEqual(hex(Array(type1[12..<16])), "358288e2")
        XCTAssertEqual(readUInt16LE(type1, at: 16), 0)
        XCTAssertEqual(readUInt16LE(type1, at: 18), 0)
        XCTAssertEqual(readUInt32LE(type1, at: 20), 40)
        XCTAssertEqual(readUInt16LE(type1, at: 24), 0)
        XCTAssertEqual(readUInt16LE(type1, at: 26), 0)
        XCTAssertEqual(readUInt32LE(type1, at: 28), 40)
        XCTAssertEqual(hex(Array(type1[32..<40])), "0601b11d0000000f")
    }

    func testNTLMType1DomainAndWorkstationSecurityBuffers() {
        let type1 = NTLM.makeType1(domain: "dom", workstation: "wkst")

        XCTAssertEqual(readUInt16LE(type1, at: 16), 3)
        XCTAssertEqual(readUInt16LE(type1, at: 18), 3)
        XCTAssertEqual(readUInt32LE(type1, at: 20), 40)
        XCTAssertEqual(readUInt16LE(type1, at: 24), 4)
        XCTAssertEqual(readUInt16LE(type1, at: 26), 4)
        XCTAssertEqual(readUInt32LE(type1, at: 28), 43)
        XCTAssertEqual(String(decoding: type1[40..<43], as: UTF8.self), "DOM")
        XCTAssertEqual(String(decoding: type1[43..<47], as: UTF8.self), "WKST")
    }

    func testSPNEGONegTokenInitDERStructure() throws {
        let type1 = NTLM.makeType1()
        let token = SPNEGO.wrapNegTokenInit(type1)

        var cursor = 0
        let applicationEnd = try expectDERTag(0x60, in: token, cursor: &cursor)

        let spnegoOIDEnd = try expectDERTag(0x06, in: token, cursor: &cursor)
        XCTAssertEqual(Array(token[cursor..<spnegoOIDEnd]), [0x2b, 0x06, 0x01, 0x05, 0x05, 0x02])
        cursor = spnegoOIDEnd

        let negTokenInitEnd = try expectDERTag(0xa0, in: token, cursor: &cursor)
        let sequenceEnd = try expectDERTag(0x30, in: token, cursor: &cursor)
        let mechTypesEnd = try expectDERTag(0xa0, in: token, cursor: &cursor)
        let listEnd = try expectDERTag(0x30, in: token, cursor: &cursor)
        let ntlmOIDEnd = try expectDERTag(0x06, in: token, cursor: &cursor)
        XCTAssertEqual(Array(token[cursor..<ntlmOIDEnd]), [0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a])
        cursor = ntlmOIDEnd
        XCTAssertEqual(cursor, listEnd)
        XCTAssertEqual(cursor, mechTypesEnd)

        let mechTokenEnd = try expectDERTag(0xa2, in: token, cursor: &cursor)
        let octetEnd = try expectDERTag(0x04, in: token, cursor: &cursor)
        XCTAssertEqual(Array(token[cursor..<octetEnd]), type1)
        cursor = octetEnd
        XCTAssertEqual(cursor, mechTokenEnd)
        XCTAssertEqual(cursor, sequenceEnd)
        XCTAssertEqual(cursor, negTokenInitEnd)
        XCTAssertEqual(cursor, applicationEnd)
        XCTAssertEqual(cursor, token.count)
    }

    func testSPNEGONegTokenRespDERLengthMatchesSessionSetupSecurityBuffer() throws {
        let challenge = NTLMChallenge(
            targetName: [],
            flags: NTLM.negotiateFlags,
            serverChallenge: hexBytes("0123456789abcdef"),
            targetInfo: hexBytes(
                "02000c0044004f004d00410049004e00" +
                "01000c00530045005200560045005200" +
                "00000000"
            )
        )
        let type3 = try NTLM.makeType3(
            credential: SMBCredential(username: "User", password: "Password", domain: "Domain"),
            challenge: challenge,
            timestamp: 0,
            clientChallenge: hexBytes("ffffff0011223344")
        ).message
        let blob = SPNEGO.wrapNegTokenResp(type3)

        var cursor = 0
        let negTokenRespEnd = try expectDERTag(0xa1, in: blob, cursor: &cursor)
        let sequenceEnd = try expectDERTag(0x30, in: blob, cursor: &cursor)
        let responseTokenEnd = try expectDERTag(0xa2, in: blob, cursor: &cursor)
        let octetEnd = try expectDERTag(0x04, in: blob, cursor: &cursor)
        XCTAssertEqual(octetEnd - cursor, type3.count)
        XCTAssertEqual(Array(blob[cursor..<octetEnd]), type3)
        cursor = octetEnd
        XCTAssertEqual(cursor, responseTokenEnd)
        XCTAssertEqual(cursor, sequenceEnd)
        XCTAssertEqual(cursor, negTokenRespEnd)
        XCTAssertEqual(cursor, blob.count)

        let request = try SMB2SessionSetup.encodeRequest(
            messageId: 8,
            sessionId: 0x1122,
            securityBlob: blob,
            signed: false
        )
        XCTAssertEqual(readUInt16LE(request, at: 78), UInt16(blob.count))
        XCTAssertEqual(Array(request[88..<request.count]), blob)
    }

    func testSPNEGONegTokenRespIncludesMechListMIC() throws {
        let type3 = Array("type3".utf8)
        let mechListMIC = hexBytes("01000000549d70fe51ab6ebd00000000")
        let blob = SPNEGO.wrapNegTokenResp(type3, mechListMIC: mechListMIC)

        var cursor = 0
        let negTokenRespEnd = try expectDERTag(0xa1, in: blob, cursor: &cursor)
        let sequenceEnd = try expectDERTag(0x30, in: blob, cursor: &cursor)
        let responseTokenEnd = try expectDERTag(0xa2, in: blob, cursor: &cursor)
        let tokenEnd = try expectDERTag(0x04, in: blob, cursor: &cursor)
        XCTAssertEqual(Array(blob[cursor..<tokenEnd]), type3)
        cursor = tokenEnd
        XCTAssertEqual(cursor, responseTokenEnd)

        let micContextStart = cursor
        let mechListMICEnd = try expectDERTag(0xa3, in: blob, cursor: &cursor)
        let octetStart = cursor
        let octetEnd = try expectDERTag(0x04, in: blob, cursor: &cursor)
        XCTAssertEqual(octetEnd - cursor, 16)
        XCTAssertEqual(Array(blob[cursor..<octetEnd]), mechListMIC)
        XCTAssertEqual(Array(blob[micContextStart..<octetStart]), [0xa3, 0x12])
        cursor = octetEnd
        XCTAssertEqual(cursor, mechListMICEnd)
        XCTAssertEqual(cursor, sequenceEnd)
        XCTAssertEqual(cursor, negTokenRespEnd)
        XCTAssertEqual(cursor, blob.count)
    }

    func testSessionSetupRequestFixedFieldsAndSecurityBuffer() throws {
        let blob = SPNEGO.wrapNegTokenInit(NTLM.makeType1())
        let request = try SMB2SessionSetup.encodeRequest(
            messageId: 7,
            sessionId: 0,
            securityBlob: blob,
            signed: false
        )

        let header = try SMB2Header.decode(request)
        XCTAssertEqual(header.command, SMB2Commands.sessionSetup)
        XCTAssertEqual(header.messageId, 7)
        XCTAssertEqual(header.sessionId, 0)
        XCTAssertEqual(readUInt16LE(request, at: 64), 25)
        XCTAssertEqual(request[66], 0)
        XCTAssertEqual(request[67], 1)
        XCTAssertEqual(readUInt32LE(request, at: 68), 0)
        XCTAssertEqual(readUInt32LE(request, at: 72), 0)
        XCTAssertEqual(readUInt16LE(request, at: 76), 88)
        XCTAssertEqual(readUInt16LE(request, at: 78), UInt16(blob.count))
        XCTAssertEqual(readUInt64LE(request, at: 80), 0)
        XCTAssertEqual(Array(request[88..<request.count]), blob)
    }

    func testCreateRootDirectoryRequestFixedFieldsAndEmptyNameBuffer() throws {
        let request = try SMB2Create.encodeRequest(
            messageId: 9,
            sessionId: 0x1122_3344_5566_7788,
            treeId: 0xaabb_ccdd,
            path: "",
            directory: true
        )

        let header = try SMB2Header.decode(request)
        XCTAssertEqual(header.command, SMB2Commands.create)
        XCTAssertEqual(header.messageId, 9)
        XCTAssertEqual(header.treeId, 0xaabb_ccdd)
        XCTAssertEqual(header.sessionId, 0x1122_3344_5566_7788)
        XCTAssertEqual(request.count, 121)
        XCTAssertEqual(readUInt16LE(request, at: 64), 57)
        XCTAssertEqual(request[66], 0)
        XCTAssertEqual(request[67], 0)
        XCTAssertEqual(readUInt32LE(request, at: 68), 2)
        XCTAssertEqual(readUInt64LE(request, at: 72), 0)
        XCTAssertEqual(readUInt64LE(request, at: 80), 0)
        XCTAssertEqual(readUInt32LE(request, at: 88), 0x0000_0089)
        XCTAssertEqual(readUInt32LE(request, at: 92), 0)
        XCTAssertEqual(readUInt32LE(request, at: 96), 0x0000_0007)
        XCTAssertEqual(readUInt32LE(request, at: 100), 0x0000_0001)
        XCTAssertEqual(readUInt32LE(request, at: 104), 0x0000_0001)
        XCTAssertEqual(readUInt16LE(request, at: 108), 120)
        XCTAssertEqual(readUInt16LE(request, at: 110), 0)
        XCTAssertEqual(readUInt32LE(request, at: 112), 0)
        XCTAssertEqual(readUInt32LE(request, at: 116), 0)
        XCTAssertEqual(request[120], 0)
    }

    func testCreateSubpathRequestUsesRelativeUtf16NameAfterFixedPart() throws {
        let request = try SMB2Create.encodeRequest(
            messageId: 10,
            sessionId: 0x1122,
            treeId: 0x3344,
            path: "\\dir\\child",
            directory: true
        )
        let expectedName = NTLM.utf16le("dir\\child")

        XCTAssertEqual(readUInt16LE(request, at: 108), 120)
        XCTAssertEqual(readUInt16LE(request, at: 110), UInt16(expectedName.count))
        XCTAssertEqual(request.count, 120 + expectedName.count)
        XCTAssertEqual(Array(request[120..<request.count]), expectedName)
    }

    func testCreateRequestRejectsUnsafeRelativePathComponents() {
        XCTAssertThrowsError(try SMB2Create.encodeRequest(
            messageId: 10,
            sessionId: 0x1122,
            treeId: 0x3344,
            request: .read(path: "dir\\..\\child", directory: false)
        ))
        XCTAssertThrowsError(try SMB2Create.encodeRequest(
            messageId: 10,
            sessionId: 0x1122,
            treeId: 0x3344,
            request: .read(path: "dir//child", directory: false)
        ))
    }

    func testCreateFileRequestUsesReadDataAndReadAttributesAccess() throws {
        let request = try SMB2Create.encodeRequest(
            messageId: 10,
            sessionId: 0x1122,
            treeId: 0x3344,
            path: "known.txt",
            directory: false
        )

        XCTAssertEqual(readUInt32LE(request, at: 88), 0x0000_0081)
        XCTAssertEqual(readUInt32LE(request, at: 104), 0x0000_0040)
    }

    func testCreateDirectoryRequestUsesFileCreateAndDirectoryOption() throws {
        let request = try SMB2Create.encodeRequest(
            messageId: 10,
            sessionId: 0x1122,
            treeId: 0x3344,
            request: .makeDirectory(path: "newdir")
        )

        XCTAssertEqual(readUInt32LE(request, at: 88), 0x0000_0085)
        XCTAssertEqual(readUInt32LE(request, at: 100), 0x0000_0002)
        XCTAssertEqual(readUInt32LE(request, at: 104), 0x0000_0001)
    }

    func testCreateUploadRequestUsesOverwriteDispositionWhenRequested() throws {
        let request = try SMB2Create.encodeRequest(
            messageId: 10,
            sessionId: 0x1122,
            treeId: 0x3344,
            request: .upload(path: "out.txt", overwrite: true)
        )

        XCTAssertEqual(readUInt32LE(request, at: 88), 0x0000_0082)
        XCTAssertEqual(readUInt32LE(request, at: 100), 0x0000_0005)
        XCTAssertEqual(readUInt32LE(request, at: 104), 0x0000_0040)
    }

    func testCreateDeleteRequestUsesDeleteAccessAndDeleteOnClose() throws {
        let request = try SMB2Create.encodeRequest(
            messageId: 10,
            sessionId: 0x1122,
            treeId: 0x3344,
            request: .delete(path: "out.txt", directory: false)
        )

        XCTAssertEqual(readUInt32LE(request, at: 88), 0x0001_0000)
        XCTAssertEqual(readUInt32LE(request, at: 100), 0x0000_0001)
        XCTAssertEqual(readUInt32LE(request, at: 104), 0x0000_1040)
    }

    func testDeleteNonRecursiveRetriesAsDirectoryWhenCreateReportsFileIsADirectory() async throws {
        let fileId = hexBytes("00112233445566778899aabbccddeeff")
        let inbound = try framed([
            try smb2StatusResponse(status: SMB2Status.fileIsADirectory, command: SMB2Commands.create, messageId: 0, treeId: 0x3344),
            try smb2CreateResponse(fileId: fileId, messageId: 1, treeId: 0x3344),
            try smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.close, messageId: 2, treeId: 0x3344),
        ])
        let transport = InMemoryTransport(inbound: inbound)
        let session = SMBSession(
            host: "server",
            port: 445,
            credential: SMBCredential(username: "user", password: "pass"),
            transport: transport,
            signingKey: Array(repeating: UInt8(0x11), count: 16)
        )

        try await session.deleteNonRecursive(treeId: 0x3344, path: "dir", directory: false)

        let requests = try unframed(transport.outbound)
        XCTAssertEqual(requests.count, 3)
        XCTAssertEqual(try SMB2Header.decode(requests[0]).command, SMB2Commands.create)
        XCTAssertEqual(readUInt32LE(requests[0], at: 104), 0x0000_1040)
        XCTAssertEqual(try SMB2Header.decode(requests[1]).command, SMB2Commands.create)
        XCTAssertEqual(readUInt32LE(requests[1], at: 104), 0x0000_1001)
        XCTAssertEqual(try SMB2Header.decode(requests[2]).command, SMB2Commands.close)
        XCTAssertEqual(Array(requests[2][72..<88]), fileId)
    }

    func testCreateResponseDecodesFileIdAtResponseStructureOffset64() throws {
        var response = try SMB2Header(
            command: SMB2Commands.create,
            messageId: 10,
            treeId: 0x3344,
            sessionId: 0x1122
        ).encode()
        response.append(contentsOf: Array(repeating: UInt8(0), count: 88))
        let expectedFileId = hexBytes("0123456789abcdeffedcba9876543210")

        writeUInt16LE(89, to: &response, at: 64)
        response.replaceSubrange(128..<144, with: expectedFileId)

        XCTAssertEqual(response.count, 152)
        XCTAssertEqual(try SMB2Create.decodeFileId(response), expectedFileId)
    }

    func testQueryDirectoryRequestUsesWildcardSearchPattern() throws {
        let fileId = (0..<16).map(UInt8.init)
        let request = try SMB2QueryDirectory.encodeRequest(
            messageId: 11,
            sessionId: 0x1122_3344,
            treeId: 0x5566_7788,
            fileId: fileId
        )

        let header = try SMB2Header.decode(request)
        XCTAssertEqual(header.command, SMB2Commands.queryDirectory)
        XCTAssertEqual(header.messageId, 11)
        XCTAssertEqual(header.treeId, 0x5566_7788)
        XCTAssertEqual(header.sessionId, 0x1122_3344)
        XCTAssertEqual(request.count, 98)
        XCTAssertEqual(readUInt16LE(request, at: 64), 33)
        XCTAssertEqual(request[66], 37)
        XCTAssertEqual(request[67], 0x01)
        XCTAssertEqual(readUInt32LE(request, at: 68), 0)
        XCTAssertEqual(Array(request[72..<88]), fileId)
        XCTAssertEqual(readUInt16LE(request, at: 88), 96)
        XCTAssertEqual(readUInt16LE(request, at: 90), 2)
        XCTAssertEqual(readUInt32LE(request, at: 92), 65_536)
        XCTAssertEqual(Array(request[96..<98]), [0x2a, 0x00])
    }

    func testQueryDirectoryContinuationRequestClearsRestartScanFlag() throws {
        let fileId = (0..<16).map(UInt8.init)
        let request = try SMB2QueryDirectory.encodeRequest(
            messageId: 11,
            sessionId: 0x1122_3344,
            treeId: 0x5566_7788,
            fileId: fileId,
            restartScan: false
        )

        XCTAssertEqual(request[67], 0x00)
    }

    func testSessionQueryDirectoryStreamsPagesUntilNoMoreFiles() async throws {
        let fileId = hexBytes("00112233445566778899aabbccddeeff")
        let inbound = try framed([
            try smb2QueryDirectoryResponse(
                entries: [
                    makeDirectoryEntry(name: "a.txt", isDirectory: false, fileSize: 1, nextOffset: 0),
                ],
                messageId: 0,
                treeId: 0x3344
            ),
            try smb2QueryDirectoryResponse(
                entries: [
                    makeDirectoryEntry(name: "b", isDirectory: true, nextOffset: 0),
                ],
                messageId: 1,
                treeId: 0x3344
            ),
            try smb2StatusResponse(status: SMB2Status.noMoreFiles, command: SMB2Commands.queryDirectory, messageId: 2, treeId: 0x3344),
        ])
        let transport = InMemoryTransport(inbound: inbound)
        let session = SMBSession(
            host: "server",
            port: 445,
            credential: SMBCredential(username: "user", password: "pass"),
            transport: transport,
            signingKey: Array(repeating: UInt8(0x11), count: 16)
        )

        let streamed = TestDirectoryEntryCollector()
        try await session.queryDirectory(treeId: 0x3344, fileId: fileId) { entry in
            streamed.append(entry)
        }

        XCTAssertEqual(streamed.entries, [
            SMBDirectoryEntry(name: "a.txt", fileSize: 1, isDirectory: false, attributes: 0x80),
            SMBDirectoryEntry(name: "b", fileSize: 0, isDirectory: true, attributes: 0x10),
        ])
        let requests = try unframed(transport.outbound)
        XCTAssertEqual(requests.map { try? SMB2Header.decode($0).command }, [
            SMB2Commands.queryDirectory,
            SMB2Commands.queryDirectory,
            SMB2Commands.queryDirectory,
        ])
        XCTAssertEqual(requests[0][67], 0x01)
        XCTAssertEqual(requests[1][67], 0x00)
        XCTAssertEqual(requests[2][67], 0x00)
    }

    func testClientSessionReusesConnectedTreeForMultipleOperations() async throws {
        let directoryFileId = hexBytes("00112233445566778899aabbccddeeff")
        let statFileId = hexBytes("ffeeddccbbaa99887766554433221100")
        let inbound = try framed([
            try smb2CreateResponse(fileId: directoryFileId, messageId: 0, treeId: 0x3344),
            try smb2QueryDirectoryResponse(
                entries: [
                    makeDirectoryEntry(name: "a.txt", isDirectory: false, fileSize: 7, nextOffset: 0),
                ],
                messageId: 1,
                treeId: 0x3344
            ),
            try smb2StatusResponse(status: SMB2Status.noMoreFiles, command: SMB2Commands.queryDirectory, messageId: 2, treeId: 0x3344),
            try smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.close, messageId: 3, treeId: 0x3344),
            try smb2CreateResponse(fileId: statFileId, messageId: 4, treeId: 0x3344),
            try smb2QueryInfoResponse(size: 7, messageId: 5, treeId: 0x3344),
            try smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.close, messageId: 6, treeId: 0x3344),
        ])
        let transport = InMemoryTransport(inbound: inbound)
        let session = SMBSession(
            host: "server",
            port: 445,
            credential: SMBCredential(username: "user", password: "pass"),
            transport: transport,
            signingKey: Array(repeating: UInt8(0x11), count: 16)
        )
        let clientSession = SMBClientSession(session: session, treeId: 0x3344)

        let entries = try await clientSession.list(path: "")
        let stat = try await clientSession.stat(path: "a.txt")

        XCTAssertEqual(entries, [SMBDirectoryEntry(name: "a.txt", fileSize: 7, isDirectory: false, attributes: 0x80)])
        XCTAssertEqual(stat.size, 7)
        let requests = try unframed(transport.outbound)
        XCTAssertEqual(requests.map { try? SMB2Header.decode($0).command }, [
            SMB2Commands.create,
            SMB2Commands.queryDirectory,
            SMB2Commands.queryDirectory,
            SMB2Commands.close,
            SMB2Commands.create,
            SMB2Commands.queryInfo,
            SMB2Commands.close,
        ])
        XCTAssertTrue(requests.allSatisfy { (try? SMB2Header.decode($0).treeId) == 0x3344 })
    }

    func testClientSessionCloseSendsTreeDisconnectAndLogoff() async throws {
        let inbound = try framed([
            try smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.treeDisconnect, messageId: 0, treeId: 0x3344),
            try smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.logoff, messageId: 1, treeId: 0),
        ])
        let transport = InMemoryTransport(inbound: inbound)
        let session = SMBSession(
            host: "server",
            port: 445,
            credential: SMBCredential(username: "user", password: "pass"),
            transport: transport,
            signingKey: Array(repeating: UInt8(0x11), count: 16)
        )
        let clientSession = SMBClientSession(session: session, treeId: 0x3344)

        await clientSession.close()
        await clientSession.close()

        let requests = try unframed(transport.outbound)
        XCTAssertEqual(requests.count, 2)
        let treeDisconnect = try SMB2Header.decode(requests[0])
        XCTAssertEqual(treeDisconnect.command, SMB2Commands.treeDisconnect)
        XCTAssertEqual(treeDisconnect.treeId, 0x3344)
        XCTAssertEqual(readUInt16LE(requests[0], at: 64), 4)
        let logoff = try SMB2Header.decode(requests[1])
        XCTAssertEqual(logoff.command, SMB2Commands.logoff)
        XCTAssertEqual(logoff.treeId, 0)
        XCTAssertEqual(readUInt16LE(requests[1], at: 64), 4)
    }

    func testQueryDirectoryResponseDropsDotEntriesForRecursiveDeleteWalks() throws {
        var response = try SMB2Header(command: SMB2Commands.queryDirectory, messageId: 11).encode()
        let payload = makeDirectoryEntry(name: ".", isDirectory: true, nextOffset: 112)
            + makeDirectoryEntry(name: "..", isDirectory: true, nextOffset: 112)
            + makeDirectoryEntry(name: "child.txt", isDirectory: false, fileSize: 7, nextOffset: 0)
        response.append(contentsOf: Array(repeating: UInt8(0), count: 8))
        writeUInt16LE(9, to: &response, at: 64)
        writeUInt16LE(72, to: &response, at: 66)
        writeUInt32LE(UInt32(payload.count), to: &response, at: 68)
        response.append(contentsOf: payload)

        XCTAssertEqual(
            try SMB2QueryDirectory.decodeResponse(response),
            [SMBDirectoryEntry(name: "child.txt", fileSize: 7, isDirectory: false, attributes: 0x80)]
        )
    }

    func testQueryDirectoryResponsePreservesFileAttributes() throws {
        var response = try SMB2Header(command: SMB2Commands.queryDirectory, messageId: 11).encode()
        let payload = makeDirectoryEntry(name: "hidden.txt", isDirectory: false, fileSize: 7, nextOffset: 0, attributes: 0x82)
        response.append(contentsOf: Array(repeating: UInt8(0), count: 8))
        writeUInt16LE(9, to: &response, at: 64)
        writeUInt16LE(72, to: &response, at: 66)
        writeUInt32LE(UInt32(payload.count), to: &response, at: 68)
        response.append(contentsOf: payload)

        let entries = try SMB2QueryDirectory.decodeResponse(response)
        XCTAssertEqual(entries.first?.attributes, 0x82)
        XCTAssertEqual(entries.first?.isDirectory, false)
    }

    func testQueryDirectoryResponseRejectsInvalidNextEntryOffset() throws {
        var response = try SMB2Header(command: SMB2Commands.queryDirectory, messageId: 11).encode()
        let payload = makeDirectoryEntry(name: "child", isDirectory: true, nextOffset: 1)
        response.append(contentsOf: Array(repeating: UInt8(0), count: 8))
        writeUInt16LE(9, to: &response, at: 64)
        writeUInt16LE(72, to: &response, at: 66)
        writeUInt32LE(UInt32(payload.count), to: &response, at: 68)
        response.append(contentsOf: payload)

        XCTAssertThrowsError(try SMB2QueryDirectory.decodeResponse(response)) { error in
            XCTAssertEqual(error as? SMBCodecError, .truncated)
        }
    }

    func testQueryInfoRequestUsesFileNetworkOpenInformationAndOneByteBuffer() throws {
        let fileId = (0..<16).map(UInt8.init)
        let request = try SMB2QueryInfo.encodeRequest(
            messageId: 12,
            sessionId: 0x1122_3344,
            treeId: 0x5566_7788,
            fileId: fileId
        )

        let header = try SMB2Header.decode(request)
        XCTAssertEqual(header.command, SMB2Commands.queryInfo)
        XCTAssertEqual(header.messageId, 12)
        XCTAssertEqual(header.treeId, 0x5566_7788)
        XCTAssertEqual(header.sessionId, 0x1122_3344)
        XCTAssertEqual(request.count, 105)
        XCTAssertEqual(readUInt16LE(request, at: 64), 41)
        XCTAssertEqual(request[66], 0x01)
        XCTAssertEqual(request[67], 34)
        XCTAssertEqual(readUInt32LE(request, at: 68), 65_536)
        XCTAssertEqual(readUInt16LE(request, at: 72), 104)
        XCTAssertEqual(readUInt16LE(request, at: 74), 0)
        XCTAssertEqual(readUInt32LE(request, at: 76), 0)
        XCTAssertEqual(readUInt32LE(request, at: 80), 0)
        XCTAssertEqual(readUInt32LE(request, at: 84), 0)
        XCTAssertEqual(Array(request[88..<104]), fileId)
        XCTAssertEqual(request[104], 0)
    }

    func testQueryInfoResponsePreservesFileAttributes() throws {
        let response = try smb2QueryInfoResponse(size: 7, messageId: 12, treeId: 0x3344, attributes: 0x82)

        let stat = try SMB2QueryInfo.decodeNetworkOpenInformation(response)

        XCTAssertEqual(stat.size, 7)
        XCTAssertEqual(stat.attributes, 0x82)
        XCTAssertFalse(stat.isDirectory)
    }

    func testReadRequestUsesOffsetLengthFileIdAndOneByteBuffer() throws {
        let fileId = (0..<16).map(UInt8.init)
        let request = try SMB2Read.encodeRequest(
            messageId: 13,
            sessionId: 0x1122_3344,
            treeId: 0x5566_7788,
            fileId: fileId,
            offset: 0x0102_0304_0506_0708,
            length: 4096
        )

        let header = try SMB2Header.decode(request)
        XCTAssertEqual(header.command, SMB2Commands.read)
        XCTAssertEqual(header.messageId, 13)
        XCTAssertEqual(header.treeId, 0x5566_7788)
        XCTAssertEqual(header.sessionId, 0x1122_3344)
        XCTAssertEqual(request.count, 113)
        XCTAssertEqual(readUInt16LE(request, at: 64), 49)
        XCTAssertEqual(request[66], 0x50)
        XCTAssertEqual(request[67], 0)
        XCTAssertEqual(readUInt32LE(request, at: 68), 4096)
        XCTAssertEqual(readUInt64LE(request, at: 72), 0x0102_0304_0506_0708)
        XCTAssertEqual(Array(request[80..<96]), fileId)
        XCTAssertEqual(readUInt32LE(request, at: 96), 0)
        XCTAssertEqual(readUInt32LE(request, at: 100), 0)
        XCTAssertEqual(readUInt32LE(request, at: 104), 0)
        XCTAssertEqual(readUInt16LE(request, at: 108), 0)
        XCTAssertEqual(readUInt16LE(request, at: 110), 0)
        XCTAssertEqual(request[112], 0)
    }

    func testReadResponseDecodesDataOffsetAndLength() throws {
        var response = try SMB2Header(command: SMB2Commands.read, messageId: 14).encode()
        response.append(contentsOf: Array(repeating: UInt8(0), count: 16))
        let payload = Array("hello".utf8)
        writeUInt16LE(17, to: &response, at: 64)
        response[66] = 80
        writeUInt32LE(UInt32(payload.count), to: &response, at: 68)
        response.append(contentsOf: payload)

        XCTAssertEqual(try SMB2Read.decodeResponse(response), payload)
    }

    func testSessionReadChunkReadsOneResponseAtRequestedOffset() async throws {
        let fileId = hexBytes("00112233445566778899aabbccddeeff")
        let inbound = try framed([
            try smb2ReadResponse(Array("hel".utf8), messageId: 0, treeId: 0x3344),
            try smb2ReadResponse(Array("lo".utf8), messageId: 1, treeId: 0x3344),
        ])
        let transport = InMemoryTransport(inbound: inbound)
        let session = SMBSession(
            host: "server",
            port: 445,
            credential: SMBCredential(username: "user", password: "pass"),
            transport: transport,
            signingKey: Array(repeating: UInt8(0x11), count: 16)
        )

        let first = try await session.readChunk(treeId: 0x3344, fileId: fileId, offset: 10, length: 5)
        let second = try await session.readChunk(treeId: 0x3344, fileId: fileId, offset: 13, length: 2)

        XCTAssertEqual(first, Array("hel".utf8))
        XCTAssertEqual(second, Array("lo".utf8))
        let requests = try unframed(transport.outbound)
        XCTAssertEqual(requests.count, 2)
        XCTAssertEqual(try SMB2Header.decode(requests[0]).command, SMB2Commands.read)
        XCTAssertEqual(readUInt64LE(requests[0], at: 72), 10)
        XCTAssertEqual(readUInt32LE(requests[0], at: 68), 5)
        XCTAssertEqual(try SMB2Header.decode(requests[1]).command, SMB2Commands.read)
        XCTAssertEqual(readUInt64LE(requests[1], at: 72), 13)
        XCTAssertEqual(readUInt32LE(requests[1], at: 68), 2)
    }

    func testSessionReadChunkDoesNotReplayPreviousChunkAfterConnectionLoss() async throws {
        let fileId = hexBytes("00112233445566778899aabbccddeeff")
        let inbound = try framed([
            try smb2ReadResponse(Array("hel".utf8), messageId: 0, treeId: 0x3344),
        ])
        let transport = InMemoryTransport(inbound: inbound)
        let session = SMBSession(
            host: "server",
            port: 445,
            credential: SMBCredential(username: "user", password: "pass"),
            transport: transport,
            signingKey: Array(repeating: UInt8(0x11), count: 16)
        )
        let first = try await session.readChunk(treeId: 0x3344, fileId: fileId, offset: 0, length: 5)
        XCTAssertEqual(first, Array("hel".utf8))

        do {
            _ = try await session.readChunk(treeId: 0x3344, fileId: fileId, offset: 3, length: 2)
            XCTFail("expected connectionClosed")
        } catch SMBTransportError.connectionClosed {
            let requests = try unframed(transport.outbound)
            XCTAssertEqual(requests.count, 2)
            XCTAssertEqual(readUInt64LE(requests[1], at: 72), 3)
        } catch {
            XCTFail("expected connectionClosed, got \(error)")
        }
    }

    func testConcurrentReadChunksSerializeWireTransactions() async throws {
        let fileId = hexBytes("00112233445566778899aabbccddeeff")
        let transport = ControlledReceiveTransport()
        let session = SMBSession(
            host: "server",
            port: 445,
            credential: SMBCredential(username: "user", password: "pass"),
            transport: transport,
            signingKey: Array(repeating: UInt8(0x11), count: 16)
        )

        let first = Task {
            try await session.readChunk(treeId: 0x3344, fileId: fileId, offset: 0, length: 3)
        }
        let second = Task {
            try await session.readChunk(treeId: 0x3344, fileId: fileId, offset: 3, length: 2)
        }

        try await waitForOutboundFrameCount(1, transport: transport)
        XCTAssertEqual(try unframed(transport.outbound).count, 1)
        transport.enqueueInbound(try framed([smb2ReadResponse(Array("hel".utf8), messageId: 0, treeId: 0x3344)]))
        let firstData = try await first.value
        XCTAssertEqual(firstData, Array("hel".utf8))

        try await waitForOutboundFrameCount(2, transport: transport)
        let requests = try unframed(transport.outbound)
        XCTAssertEqual(requests.count, 2)
        XCTAssertEqual(readUInt64LE(requests[0], at: 72), 0)
        XCTAssertEqual(readUInt64LE(requests[1], at: 72), 3)
        transport.enqueueInbound(try framed([smb2ReadResponse(Array("lo".utf8), messageId: 1, treeId: 0x3344)]))
        let secondData = try await second.value
        XCTAssertEqual(secondData, Array("lo".utf8))
    }

    func testSessionCopyFileReadsAndWritesChunksWithCloseAndFlush() async throws {
        let sourceFileId = hexBytes("00112233445566778899aabbccddeeff")
        let destinationFileId = hexBytes("ffeeddccbbaa99887766554433221100")
        let inbound = try framed([
            try smb2CreateResponse(fileId: sourceFileId, messageId: 0, treeId: 0x3344),
            try smb2QueryInfoResponse(size: 5, messageId: 1, treeId: 0x3344),
            try smb2CreateResponse(fileId: destinationFileId, messageId: 2, treeId: 0x3344),
            try smb2ReadResponse(Array("hel".utf8), messageId: 3, treeId: 0x3344),
            try smb2WriteResponse(count: 3, messageId: 4, treeId: 0x3344),
            try smb2ReadResponse(Array("lo".utf8), messageId: 5, treeId: 0x3344),
            try smb2WriteResponse(count: 2, messageId: 6, treeId: 0x3344),
            try smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.flush, messageId: 7, treeId: 0x3344),
            try smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.close, messageId: 8, treeId: 0x3344),
            try smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.close, messageId: 9, treeId: 0x3344),
        ])
        let transport = InMemoryTransport(inbound: inbound)
        let session = SMBSession(
            host: "server",
            port: 445,
            credential: SMBCredential(username: "user", password: "pass"),
            transport: transport,
            signingKey: Array(repeating: UInt8(0x11), count: 16)
        )

        try await session.copyFile(treeId: 0x3344, fromPath: "source.txt", toPath: "copy.txt", overwrite: false)

        let requests = try unframed(transport.outbound)
        XCTAssertEqual(requests.map { try? SMB2Header.decode($0).command }, [
            SMB2Commands.create,
            SMB2Commands.queryInfo,
            SMB2Commands.create,
            SMB2Commands.read,
            SMB2Commands.write,
            SMB2Commands.read,
            SMB2Commands.write,
            SMB2Commands.flush,
            SMB2Commands.close,
            SMB2Commands.close,
        ])
        XCTAssertEqual(readUInt32LE(requests[2], at: 100), 0x0000_0002)
        XCTAssertEqual(readUInt64LE(requests[3], at: 72), 0)
        XCTAssertEqual(readUInt32LE(requests[3], at: 68), 5)
        XCTAssertEqual(readUInt64LE(requests[4], at: 72), 0)
        XCTAssertEqual(Array(requests[4][112..<requests[4].count]), Array("hel".utf8))
        XCTAssertEqual(readUInt64LE(requests[5], at: 72), 3)
        XCTAssertEqual(readUInt32LE(requests[5], at: 68), 2)
        XCTAssertEqual(readUInt64LE(requests[6], at: 72), 3)
        XCTAssertEqual(Array(requests[6][112..<requests[6].count]), Array("lo".utf8))
        XCTAssertEqual(Array(requests[8][72..<88]), destinationFileId)
        XCTAssertEqual(Array(requests[9][72..<88]), sourceFileId)
    }

    func testSessionCopyFileUsesOverwriteDispositionWhenRequested() async throws {
        let sourceFileId = hexBytes("00112233445566778899aabbccddeeff")
        let destinationFileId = hexBytes("ffeeddccbbaa99887766554433221100")
        let inbound = try framed([
            try smb2CreateResponse(fileId: sourceFileId, messageId: 0, treeId: 0x3344),
            try smb2QueryInfoResponse(size: 0, messageId: 1, treeId: 0x3344),
            try smb2CreateResponse(fileId: destinationFileId, messageId: 2, treeId: 0x3344),
            try smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.flush, messageId: 3, treeId: 0x3344),
            try smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.close, messageId: 4, treeId: 0x3344),
            try smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.close, messageId: 5, treeId: 0x3344),
        ])
        let transport = InMemoryTransport(inbound: inbound)
        let session = SMBSession(
            host: "server",
            port: 445,
            credential: SMBCredential(username: "user", password: "pass"),
            transport: transport,
            signingKey: Array(repeating: UInt8(0x11), count: 16)
        )

        try await session.copyFile(treeId: 0x3344, fromPath: "source.txt", toPath: "copy.txt", overwrite: true)

        let requests = try unframed(transport.outbound)
        XCTAssertEqual(readUInt32LE(requests[2], at: 100), 0x0000_0005)
    }

    func testSessionCopyFileClosesSourceWhenDestinationCreateFails() async throws {
        let sourceFileId = hexBytes("00112233445566778899aabbccddeeff")
        let inbound = try framed([
            try smb2CreateResponse(fileId: sourceFileId, messageId: 0, treeId: 0x3344),
            try smb2QueryInfoResponse(size: 5, messageId: 1, treeId: 0x3344),
            try smb2StatusResponse(status: SMB2Status.objectNameCollision, command: SMB2Commands.create, messageId: 2, treeId: 0x3344),
            try smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.close, messageId: 3, treeId: 0x3344),
        ])
        let transport = InMemoryTransport(inbound: inbound)
        let session = SMBSession(
            host: "server",
            port: 445,
            credential: SMBCredential(username: "user", password: "pass"),
            transport: transport,
            signingKey: Array(repeating: UInt8(0x11), count: 16)
        )

        do {
            try await session.copyFile(treeId: 0x3344, fromPath: "source.txt", toPath: "copy.txt", overwrite: false)
            XCTFail("expected nameCollision")
        } catch SMBError.nameCollision {
            let requests = try unframed(transport.outbound)
            XCTAssertEqual(requests.count, 4)
            XCTAssertEqual(try SMB2Header.decode(requests[3]).command, SMB2Commands.close)
            XCTAssertEqual(Array(requests[3][72..<88]), sourceFileId)
        } catch {
            XCTFail("expected nameCollision, got \(error)")
        }
    }

    func testSessionCopyDirectoryRecursivelyCopiesEntries() async throws {
        let sourceRootId = hexBytes("00000000000000000000000000000001")
        let destinationRootId = hexBytes("00000000000000000000000000000002")
        let sourceFileId = hexBytes("00000000000000000000000000000003")
        let destinationFileId = hexBytes("00000000000000000000000000000004")
        let sourceChildDirectoryId = hexBytes("00000000000000000000000000000005")
        let destinationChildDirectoryId = hexBytes("00000000000000000000000000000006")
        let inbound = try framed([
            try smb2CreateResponse(fileId: sourceRootId, messageId: 0, treeId: 0x3344),
            try smb2CreateResponse(fileId: destinationRootId, messageId: 1, treeId: 0x3344),
            try smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.close, messageId: 2, treeId: 0x3344),
            try smb2QueryDirectoryResponse(
                entries: [
                    makeDirectoryEntry(name: "a.txt", isDirectory: false, fileSize: 4, nextOffset: 0),
                ],
                messageId: 3,
                treeId: 0x3344
            ),
            try smb2CreateResponse(fileId: sourceFileId, messageId: 4, treeId: 0x3344),
            try smb2QueryInfoResponse(size: 4, messageId: 5, treeId: 0x3344),
            try smb2CreateResponse(fileId: destinationFileId, messageId: 6, treeId: 0x3344),
            try smb2ReadResponse(Array("data".utf8), messageId: 7, treeId: 0x3344),
            try smb2WriteResponse(count: 4, messageId: 8, treeId: 0x3344),
            try smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.flush, messageId: 9, treeId: 0x3344),
            try smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.close, messageId: 10, treeId: 0x3344),
            try smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.close, messageId: 11, treeId: 0x3344),
            try smb2QueryDirectoryResponse(
                entries: [
                    makeDirectoryEntry(name: "child", isDirectory: true, nextOffset: 0),
                ],
                messageId: 12,
                treeId: 0x3344
            ),
            try smb2CreateResponse(fileId: sourceChildDirectoryId, messageId: 13, treeId: 0x3344),
            try smb2CreateResponse(fileId: destinationChildDirectoryId, messageId: 14, treeId: 0x3344),
            try smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.close, messageId: 15, treeId: 0x3344),
            try smb2StatusResponse(status: SMB2Status.noMoreFiles, command: SMB2Commands.queryDirectory, messageId: 16, treeId: 0x3344),
            try smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.close, messageId: 17, treeId: 0x3344),
            try smb2StatusResponse(status: SMB2Status.noMoreFiles, command: SMB2Commands.queryDirectory, messageId: 18, treeId: 0x3344),
            try smb2StatusResponse(status: SMB2Status.success, command: SMB2Commands.close, messageId: 19, treeId: 0x3344),
        ])
        let transport = InMemoryTransport(inbound: inbound)
        let session = SMBSession(
            host: "server",
            port: 445,
            credential: SMBCredential(username: "user", password: "pass"),
            transport: transport,
            signingKey: Array(repeating: UInt8(0x11), count: 16)
        )

        try await session.copyDirectory(treeId: 0x3344, fromPath: "src", toPath: "dst", overwrite: false)

        let requests = try unframed(transport.outbound)
        XCTAssertEqual(requests.map { try? SMB2Header.decode($0).command }, [
            SMB2Commands.create,
            SMB2Commands.create,
            SMB2Commands.close,
            SMB2Commands.queryDirectory,
            SMB2Commands.create,
            SMB2Commands.queryInfo,
            SMB2Commands.create,
            SMB2Commands.read,
            SMB2Commands.write,
            SMB2Commands.flush,
            SMB2Commands.close,
            SMB2Commands.close,
            SMB2Commands.queryDirectory,
            SMB2Commands.create,
            SMB2Commands.create,
            SMB2Commands.close,
            SMB2Commands.queryDirectory,
            SMB2Commands.close,
            SMB2Commands.queryDirectory,
            SMB2Commands.close,
        ])
        XCTAssertEqual(readUInt32LE(requests[1], at: 100), 0x0000_0002)
        XCTAssertEqual(readUInt32LE(requests[6], at: 100), 0x0000_0002)
        XCTAssertEqual(Array(requests[8][112..<requests[8].count]), Array("data".utf8))
        XCTAssertEqual(readUInt32LE(requests[14], at: 100), 0x0000_0002)
    }

    func testWriteRequestUsesOffsetLengthFileIdAndDataBuffer() throws {
        let fileId = (0..<16).map(UInt8.init)
        let payload = Array("hello".utf8)
        let request = try SMB2Write.encodeRequest(
            messageId: 15,
            sessionId: 0x1122_3344,
            treeId: 0x5566_7788,
            fileId: fileId,
            offset: 0x0102_0304_0506_0708,
            data: payload
        )

        let header = try SMB2Header.decode(request)
        XCTAssertEqual(header.command, SMB2Commands.write)
        XCTAssertEqual(header.messageId, 15)
        XCTAssertEqual(header.treeId, 0x5566_7788)
        XCTAssertEqual(header.sessionId, 0x1122_3344)
        XCTAssertEqual(readUInt16LE(request, at: 64), 49)
        XCTAssertEqual(readUInt16LE(request, at: 66), 112)
        XCTAssertEqual(readUInt32LE(request, at: 68), UInt32(payload.count))
        XCTAssertEqual(readUInt64LE(request, at: 72), 0x0102_0304_0506_0708)
        XCTAssertEqual(Array(request[80..<96]), fileId)
        XCTAssertEqual(readUInt32LE(request, at: 96), 0)
        XCTAssertEqual(readUInt32LE(request, at: 100), 0)
        XCTAssertEqual(readUInt16LE(request, at: 104), 0)
        XCTAssertEqual(readUInt16LE(request, at: 106), 0)
        XCTAssertEqual(readUInt32LE(request, at: 108), 0)
        XCTAssertEqual(Array(request[112..<request.count]), payload)
    }

    func testWriteResponseDecodesCount() throws {
        var response = try SMB2Header(command: SMB2Commands.write, messageId: 16).encode()
        response.append(contentsOf: Array(repeating: UInt8(0), count: 16))
        writeUInt16LE(17, to: &response, at: 64)
        writeUInt32LE(5, to: &response, at: 68)

        XCTAssertEqual(try SMB2Write.decodeResponseCount(response), 5)
    }

    func testHexSummaryCapsLargeDebugPayloads() {
        let bytes = (0..<80).map(UInt8.init)

        XCTAssertEqual(
            SMBDebug.hexSummary(bytes),
            "000102030405060708090a0b0c0d0e0f" +
                "101112131415161718191a1b1c1d1e1f" +
                "202122232425262728292a2b2c2d2e2f" +
                "303132333435363738393a3b3c3d3e3f" +
                "... totalBytes=80"
        )
    }

    func testPacketSummaryRedactsUnlessWireTraceIsEnabled() {
        let bytes = (0..<4).map(UInt8.init)

        XCTAssertEqual(
            SMBDebug.packetSummary(bytes, traceWire: false),
            "<redacted; set SMBEE_TRACE_WIRE=1 to dump raw packet hex>"
        )
        XCTAssertEqual(SMBDebug.packetSummary(bytes, traceWire: true), "00010203")
    }

    func testWriteChunkRangesCoverBoundarySizes() throws {
        let chunkSize = 4
        let cases: [(Int, [Range<Int>])] = [
            (0, []),
            (chunkSize - 1, [0..<3]),
            (chunkSize, [0..<4]),
            (chunkSize + 1, [0..<4, 4..<5]),
            (chunkSize * 2 + 1, [0..<4, 4..<8, 8..<9]),
        ]

        for (dataCount, expectedRanges) in cases {
            var cursor = 0
            var ranges: [Range<Int>] = []
            while let range = try SMBChunkedTransfer.nextWriteRange(
                cursor: cursor,
                dataCount: dataCount,
                chunkSize: chunkSize
            ) {
                ranges.append(range)
                cursor = range.upperBound
            }

            XCTAssertEqual(ranges.map { "\($0.lowerBound)..<\($0.upperBound)" }, expectedRanges.map { "\($0.lowerBound)..<\($0.upperBound)" })
            XCTAssertEqual(cursor, dataCount)
        }
    }

    func testDownloadRejectsExistingDestinationWhenOverwriteIsFalse() async throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("smbee-unit-\(UUID().uuidString)")
        let destination = directory.appendingPathComponent("download.txt")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        try Data("existing".utf8).write(to: destination)
        defer { try? FileManager.default.removeItem(at: directory) }

        do {
            try await SMBClient.download(
                host: "server",
                share: "share",
                path: "remote.txt",
                localFile: destination,
                overwrite: false,
                credential: SMBCredential(username: "user", password: "pass")
            )
            XCTFail("expected local destination error")
        } catch SMBCodecError.invalidValue("local destination already exists") {
            XCTAssertEqual(try Data(contentsOf: destination), Data("existing".utf8))
        } catch {
            XCTFail("expected local destination error, got \(error)")
        }
    }

    func testReadResponseAllowsZeroLengthData() throws {
        var response = try SMB2Header(command: SMB2Commands.read, messageId: 14).encode()
        response.append(contentsOf: Array(repeating: UInt8(0), count: 16))
        writeUInt16LE(17, to: &response, at: 64)
        response[66] = 80
        writeUInt32LE(0, to: &response, at: 68)

        XCTAssertEqual(try SMB2Read.decodeResponse(response), [])
    }

    func testReadResponseRejectsDataPastPacketEnd() throws {
        var response = try SMB2Header(command: SMB2Commands.read, messageId: 14).encode()
        response.append(contentsOf: Array(repeating: UInt8(0), count: 16))
        writeUInt16LE(17, to: &response, at: 64)
        response[66] = 80
        writeUInt32LE(1, to: &response, at: 68)

        XCTAssertThrowsError(try SMB2Read.decodeResponse(response)) { error in
            XCTAssertEqual(error as? SMBCodecError, .truncated)
        }
    }

    func testReadPositionRejectsOverReadAndOffsetOverflow() throws {
        let advanced = try SMBChunkedTransfer.advancedReadPosition(cursor: 10, remaining: 5, receivedCount: 5)
        XCTAssertEqual(advanced.cursor, 15)
        XCTAssertEqual(advanced.remaining, 0)

        XCTAssertThrowsError(try SMBChunkedTransfer.advancedReadPosition(cursor: 10, remaining: 5, receivedCount: 6)) { error in
            XCTAssertEqual(error as? SMBCodecError, .invalidValue("SMB read returned more data than requested"))
        }

        XCTAssertThrowsError(
            try SMBChunkedTransfer.advancedReadPosition(cursor: UInt64.max, remaining: 1, receivedCount: 1)
        ) { error in
            XCTAssertEqual(error as? SMBCodecError, .invalidValue("SMB read offset overflow"))
        }
    }

    func testFlushRequestUsesFileIdAndReservedFields() throws {
        let fileId = (0..<16).map(UInt8.init)
        let request = try SMB2Flush.encodeRequest(
            messageId: 17,
            sessionId: 0x1122_3344,
            treeId: 0x5566_7788,
            fileId: fileId
        )

        let header = try SMB2Header.decode(request)
        XCTAssertEqual(header.command, SMB2Commands.flush)
        XCTAssertEqual(header.messageId, 17)
        XCTAssertEqual(header.treeId, 0x5566_7788)
        XCTAssertEqual(header.sessionId, 0x1122_3344)
        XCTAssertEqual(request.count, 88)
        XCTAssertEqual(readUInt16LE(request, at: 64), 24)
        XCTAssertEqual(readUInt16LE(request, at: 66), 0)
        XCTAssertEqual(readUInt32LE(request, at: 68), 0)
        XCTAssertEqual(Array(request[72..<88]), fileId)
    }

    func testAsyncPendingInterimResponseIsDiscardedBeforeFinalResponse() throws {
        let pending = try SMB2Header(
            status: SMB2Status.pending,
            command: SMB2Commands.flush,
            flags: SMB2Flags.asyncCommand,
            messageId: 17,
            treeId: 0x5566_7788,
            sessionId: 0x1122_3344
        ).encode()
        let final = try SMB2Header(
            command: SMB2Commands.flush,
            messageId: 17,
            treeId: 0x5566_7788,
            sessionId: 0x1122_3344
        ).encode()
        var mockResponses = [pending, final]

        while try SMB2AsyncInterim.shouldDiscard(mockResponses[0]) {
            mockResponses.removeFirst()
        }

        let header = try SMB2Header.decode(mockResponses[0])
        XCTAssertEqual(header.status, SMB2Status.success)
        XCTAssertEqual(header.command, SMB2Commands.flush)
        XCTAssertEqual(header.messageId, 17)
    }

    func testAsyncPendingRequiresAsyncCommandFlag() throws {
        let pending = try SMB2Header(
            status: SMB2Status.pending,
            command: SMB2Commands.write,
            messageId: 18
        ).encode()

        XCTAssertThrowsError(try SMB2AsyncInterim.shouldDiscard(pending)) { error in
            XCTAssertEqual(error as? SMBCodecError, .invalidValue("SMB2 STATUS_PENDING response missing ASYNC_COMMAND flag"))
        }
    }

    func testTransferChunkSizeRespectsNegotiatedLimitsAndTransformOverhead() {
        XCTAssertEqual(
            SMBTransferLimits.negotiatedChunkSize(localLimit: 64 * 1024, negotiatedLimit: 1_048_576),
            64 * 1024
        )
        XCTAssertEqual(
            SMBTransferLimits.negotiatedChunkSize(localLimit: 64 * 1024, negotiatedLimit: 32 * 1024),
            32 * 1024
        )
        XCTAssertEqual(
            SMBTransferLimits.negotiatedChunkSize(
                localLimit: 64 * 1024,
                negotiatedLimit: UInt32(SMB3TransformHeader.encodedSize + 4096),
                transformOverhead: SMB3TransformHeader.encodedSize
            ),
            4096
        )
        XCTAssertEqual(
            SMBTransferLimits.negotiatedChunkSize(
                localLimit: 64 * 1024,
                negotiatedLimit: UInt32(SMB3TransformHeader.encodedSize),
                transformOverhead: SMB3TransformHeader.encodedSize
            ),
            1
        )
    }

    func testSetInfoRenameRequestUsesFileRenameInformationBuffer() throws {
        let fileId = (0..<16).map(UInt8.init)
        let request = try SMB2SetInfo.encodeRenameRequest(
            messageId: 17,
            sessionId: 0x1122_3344,
            treeId: 0x5566_7788,
            fileId: fileId,
            newPath: "\\renamed.txt",
            replaceIfExists: true
        )
        let expectedName = NTLM.utf16le("renamed.txt")

        let header = try SMB2Header.decode(request)
        XCTAssertEqual(header.command, SMB2Commands.setInfo)
        XCTAssertEqual(readUInt16LE(request, at: 64), 33)
        XCTAssertEqual(request[66], 0x01)
        XCTAssertEqual(request[67], 10)
        XCTAssertEqual(readUInt32LE(request, at: 68), UInt32(20 + expectedName.count))
        XCTAssertEqual(readUInt16LE(request, at: 72), 96)
        XCTAssertEqual(Array(request[80..<96]), fileId)
        XCTAssertEqual(request[96], 1)
        XCTAssertEqual(Array(request[97..<104]), Array(repeating: 0, count: 7))
        XCTAssertEqual(readUInt64LE(request, at: 104), 0)
        XCTAssertEqual(readUInt32LE(request, at: 112), UInt32(expectedName.count))
        XCTAssertEqual(Array(request[116..<request.count]), expectedName)
    }

    func testNegotiateRequestRoundTripShape() throws {
        let request = try SMBNegotiateCodec.encodeRequest(
            clientGuid: UUID(uuidString: "00112233-4455-6677-8899-aabbccddeeff")!,
            salt: Array(repeating: 0xaa, count: 32)
        )
        let expectedHex =
            "fe534d4240000000000000000000010000000000000000000000000000000000" +
            "0000000000000000000000000000000000000000000000000000000000000000" +
            "24000500010000004000000000112233445566778899aabbccddeeff70000000" +
            "030000000202100200030203110300000100260000000000010020000100aaaaaaaaaaaaaaaaaaaa" +
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa000002000600000000000200020001000000" +
            "080004000000000001000200"
        XCTAssertEqual(hex(request), expectedHex)

        let header = try SMB2Header.decode(request)
        XCTAssertEqual(header.command, SMBNegotiateConstants.commandNegotiate)
        XCTAssertEqual(header.messageId, 0)

        var reader = SMBByteReader(bytes: Array(request.dropFirst(64)))
        XCTAssertEqual(try reader.readUInt16LE(), 36)
        XCTAssertEqual(try reader.readUInt16LE(), 5)
        try reader.skip(count: 2 + 2 + 4 + 16)
        XCTAssertEqual(try reader.readUInt32LE(), 112)
        XCTAssertEqual(try reader.readUInt16LE(), 3)
        try reader.skip(count: 2)
        XCTAssertEqual(try reader.readUInt16LE(), SMBNegotiateConstants.dialect202)
        XCTAssertEqual(try reader.readUInt16LE(), SMBNegotiateConstants.dialect210)
        XCTAssertEqual(try reader.readUInt16LE(), SMBNegotiateConstants.dialect300)
        XCTAssertEqual(try reader.readUInt16LE(), SMBNegotiateConstants.dialect302)
        XCTAssertEqual(try reader.readUInt16LE(), SMBNegotiateConstants.dialect311)
    }

    func testNegotiateRequestCanLimitDialectsForAuthenticatedConnect() throws {
        let request = try SMBNegotiateCodec.encodeRequest(
            clientGuid: UUID(uuidString: "00112233-4455-6677-8899-aabbccddeeff")!,
            salt: Array(repeating: 0xaa, count: 32),
            offeredDialects: SMBNegotiateCodec.authenticatedDialects
        )

        XCTAssertEqual(readUInt16LE(request, at: 66), 3)
        XCTAssertEqual(readUInt16LE(request, at: 100), SMBNegotiateConstants.dialect300)
        XCTAssertEqual(readUInt16LE(request, at: 102), SMBNegotiateConstants.dialect302)
        XCTAssertEqual(readUInt16LE(request, at: 104), SMBNegotiateConstants.dialect311)
        XCTAssertEqual(readUInt32LE(request, at: 92), 112)
    }

    func testNegotiateRequestContextAlignmentAndCount() throws {
        let request = try SMBNegotiateCodec.encodeRequest(
            clientGuid: UUID(uuidString: "00112233-4455-6677-8899-aabbccddeeff")!,
            salt: Array(repeating: 0xaa, count: 32)
        )

        let contextOffset = Int(readUInt32LE(request, at: 64 + 28))
        let contextCount = Int(readUInt16LE(request, at: 64 + 32))
        XCTAssertEqual(contextOffset, 112)
        XCTAssertEqual(contextOffset % 8, 0)
        XCTAssertEqual(contextCount, 3)
        XCTAssertEqual(Array(request[110..<112]), [0, 0])

        var offset = contextOffset
        var contextTypes: [UInt16] = []
        var encryptionData: [UInt8] = []
        for index in 0..<contextCount {
            XCTAssertEqual(offset % 8, 0)
            let type = readUInt16LE(request, at: offset)
            let length = Int(readUInt16LE(request, at: offset + 2))
            contextTypes.append(type)
            if type == SMBNegotiateConstants.encryptionContext {
                encryptionData = Array(request[(offset + 8)..<(offset + 8 + length)])
            }
            let dataEnd = offset + 8 + length
            let nextOffset: Int
            if index == contextCount - 1 {
                nextOffset = dataEnd
                XCTAssertEqual(dataEnd, request.count)
            } else {
                nextOffset = offset + 8 + ((length + 7) / 8) * 8
                XCTAssertEqual(
                    Array(request[dataEnd..<nextOffset]),
                    Array(repeating: 0, count: nextOffset - dataEnd)
                )
            }
            offset = nextOffset
        }

        XCTAssertEqual(contextTypes, [
            SMBNegotiateConstants.preauthContext,
            SMBNegotiateConstants.encryptionContext,
            SMBNegotiateConstants.signingContext,
        ])
        XCTAssertEqual(encryptionData, [0x02, 0x00, 0x02, 0x00, 0x01, 0x00])
        XCTAssertEqual(offset, request.count)
    }

    func testNegotiateResponseRoundTrip() throws {
        let response = try makeNegotiateResponse()
        let parsed = try SMBNegotiateCodec.decodeResponse(response)
        XCTAssertEqual(parsed.dialect, SMBNegotiateConstants.dialect311)
        XCTAssertTrue(parsed.signingRequired)
        XCTAssertEqual(parsed.signingAlgorithm, SMBNegotiateConstants.aesGMAC)
        XCTAssertEqual(parsed.cipher, SMBNegotiateConstants.aes128GCM)
        XCTAssertEqual(parsed.preauthHashAlgorithm, SMBNegotiateConstants.sha512)
        XCTAssertEqual(parsed.serverGuid.uuidString, "00112233-4455-6677-8899-AABBCCDDEEFF")
        XCTAssertEqual(parsed.maxTransactSize, 1_048_576)
        XCTAssertEqual(parsed.maxReadSize, 1_048_576)
        XCTAssertEqual(parsed.maxWriteSize, 1_048_576)
    }

    func testNegotiateResponseAcceptsUnpaddedFinalContext() throws {
        let response = try makeNegotiateResponse(padFinalContext: false)
        let contextOffset = Int(readUInt32LE(response, at: 64 + 60))
        let signingOffset = contextOffset + 16 + 8 + 8

        XCTAssertEqual(readUInt16LE(response, at: signingOffset), SMBNegotiateConstants.signingContext)
        XCTAssertEqual(response.count, signingOffset + 8 + 4)

        let parsed = try SMBNegotiateCodec.decodeResponse(response)
        XCTAssertEqual(parsed.dialect, SMBNegotiateConstants.dialect311)
        XCTAssertEqual(parsed.signingAlgorithm, SMBNegotiateConstants.aesGMAC)
        XCTAssertEqual(parsed.cipher, SMBNegotiateConstants.aes128GCM)
        XCTAssertEqual(parsed.preauthHashAlgorithm, SMBNegotiateConstants.sha512)
    }

    func testNegotiateResponseBefore311HasNoContexts() throws {
        let response = try makeNegotiateResponse(
            dialect: SMBNegotiateConstants.dialect300,
            contextCount: 0,
            contextOffset: 0,
            includeContexts: false
        )
        let parsed = try SMBNegotiateCodec.decodeResponse(response)
        XCTAssertEqual(parsed.dialect, SMBNegotiateConstants.dialect300)
        XCTAssertTrue(parsed.signingRequired)
        XCTAssertNil(parsed.signingAlgorithm)
        XCTAssertNil(parsed.cipher)
        XCTAssertNil(parsed.preauthHashAlgorithm)
        XCTAssertEqual(parsed.serverGuid.uuidString, "00112233-4455-6677-8899-AABBCCDDEEFF")
        XCTAssertEqual(parsed.maxTransactSize, 1_048_576)
        XCTAssertEqual(parsed.maxReadSize, 1_048_576)
        XCTAssertEqual(parsed.maxWriteSize, 1_048_576)
    }

    func testNegotiateResponseRejectsInvalidContextOffset() throws {
        var response = try makeNegotiateResponse()
        writeUInt32LE(128, to: &response, at: 64 + 60)

        XCTAssertThrowsError(try SMBNegotiateCodec.decodeResponse(response)) { error in
            XCTAssertEqual(error as? SMBCodecError, .invalidValue("invalid NEGOTIATE context offset"))
        }
    }

    func testNegotiateResponseRejectsMalformedContextLength() throws {
        var response = try makeNegotiateResponse()
        let contextOffset = Int(readUInt32LE(response, at: 64 + 60))
        writeUInt16LE(5, to: &response, at: contextOffset + 2)

        XCTAssertThrowsError(try SMBNegotiateCodec.decodeResponse(response)) { error in
            XCTAssertEqual(error as? SMBCodecError, .invalidValue("invalid PREAUTH context length"))
        }
    }

    func testNegotiateResponseRejectsContextPastPacketEnd() throws {
        var response = try makeNegotiateResponse()
        let contextOffset = Int(readUInt32LE(response, at: 64 + 60))
        writeUInt16LE(0xff, to: &response, at: contextOffset + 2)

        XCTAssertThrowsError(try SMBNegotiateCodec.decodeResponse(response)) { error in
            XCTAssertEqual(error as? SMBCodecError, .truncated)
        }
    }

    private func makeNegotiateResponse(
        dialect: UInt16 = SMBNegotiateConstants.dialect311,
        contextCount: UInt16 = 3,
        contextOffset: UInt32 = 136,
        includeContexts: Bool = true,
        padFinalContext: Bool = true
    ) throws -> [UInt8] {
        let header = try SMB2Header(command: SMBNegotiateConstants.commandNegotiate, messageId: 0).encode()
        var body = SMBByteWriter()
        body.writeUInt16LE(65)
        body.writeUInt16LE(SMBNegotiateConstants.signingRequired)
        body.writeUInt16LE(dialect)
        body.writeUInt16LE(contextCount)
        body.writeBytes(UUID(uuidString: "00112233-4455-6677-8899-aabbccddeeff")!.smbWireBytes)
        body.writeUInt32LE(SMBNegotiateConstants.globalCapEncryption)
        body.writeUInt32LE(1_048_576)
        body.writeUInt32LE(1_048_576)
        body.writeUInt32LE(1_048_576)
        body.writeUInt64LE(0)
        body.writeUInt64LE(0)
        body.writeUInt16LE(0)
        body.writeUInt16LE(0)
        body.writeUInt32LE(contextOffset)
        var packet = header + body.bytes
        if includeContexts {
            packet.append(contentsOf: Array(repeating: 0, count: Int(contextOffset) - packet.count))

            appendContext(type: SMBNegotiateConstants.preauthContext, data: [1, 0, 0, 0, 1, 0], to: &packet)
            appendContext(type: SMBNegotiateConstants.encryptionContext, data: [1, 0, 2, 0], to: &packet)
            appendContext(type: SMBNegotiateConstants.signingContext, data: [1, 0, 2, 0], padTo8: padFinalContext, to: &packet)
        }
        return packet
    }

    private func appendContext(type: UInt16, data: [UInt8], padTo8: Bool = true, to bytes: inout [UInt8]) {
        var writer = SMBByteWriter()
        writer.writeUInt16LE(type)
        writer.writeUInt16LE(UInt16(data.count))
        writer.writeUInt32LE(0)
        writer.writeBytes(data)
        if padTo8 {
            writer.padTo8()
        }
        bytes.append(contentsOf: writer.bytes)
    }

    private func makeNTLMChallengeMessage(targetInfo: [UInt8]) -> [UInt8] {
        let targetName = NTLM.utf16le("Server")
        let targetNameOffset = UInt32(48)
        let targetInfoOffset = targetNameOffset + UInt32(targetName.count)
        var writer = SMBByteWriter()
        writer.writeBytes(Array("NTLMSSP\0".utf8))
        writer.writeUInt32LE(2)
        writer.writeUInt16LE(UInt16(targetName.count))
        writer.writeUInt16LE(UInt16(targetName.count))
        writer.writeUInt32LE(targetNameOffset)
        writer.writeUInt32LE(NTLM.negotiateFlags)
        writer.writeBytes(hexBytes("0123456789abcdef"))
        writer.writeBytes(Array(repeating: 0, count: 8))
        writer.writeUInt16LE(UInt16(targetInfo.count))
        writer.writeUInt16LE(UInt16(targetInfo.count))
        writer.writeUInt32LE(targetInfoOffset)
        writer.writeBytes(targetName)
        writer.writeBytes(targetInfo)
        return writer.bytes
    }

    private func readSecurityBuffer(_ bytes: [UInt8], at offset: Int) -> [UInt8] {
        let length = Int(readUInt16LE(bytes, at: offset))
        let bufferOffset = Int(readUInt32LE(bytes, at: offset + 4))
        return Array(bytes[bufferOffset..<bufferOffset + length])
    }

    private func decodeNTLMv2BlobAVPairs(_ blob: [UInt8]) throws -> [(id: UInt16, value: [UInt8])] {
        var offset = 28
        var pairs: [(id: UInt16, value: [UInt8])] = []
        while offset + 4 <= blob.count {
            let id = readUInt16LE(blob, at: offset)
            let length = Int(readUInt16LE(blob, at: offset + 2))
            offset += 4
            guard offset + length <= blob.count else { throw SMBCodecError.truncated }
            pairs.append((id, Array(blob[offset..<offset + length])))
            offset += length
            if id == 0 { return pairs }
        }
        throw SMBCodecError.invalidValue("NTLMv2 blob target info missing EOL")
    }

    private func appendAVPair(id: UInt16, value: [UInt8], to bytes: inout [UInt8]) {
        bytes.append(UInt8(id & 0xff))
        bytes.append(UInt8((id >> 8) & 0xff))
        bytes.append(UInt8(value.count & 0xff))
        bytes.append(UInt8((value.count >> 8) & 0xff))
        bytes.append(contentsOf: value)
    }

    private func makeDirectoryEntry(
        name: String,
        isDirectory: Bool,
        fileSize: UInt64 = 0,
        nextOffset: UInt32,
        attributes: UInt32? = nil
    ) -> [UInt8] {
        let nameBytes = NTLM.utf16le(name)
        var bytes = Array(repeating: UInt8(0), count: 104 + nameBytes.count)
        writeUInt32LE(nextOffset, to: &bytes, at: 0)
        writeUInt64LE(fileSize, to: &bytes, at: 40)
        writeUInt32LE(attributes ?? (isDirectory ? 0x10 : 0x80), to: &bytes, at: 56)
        writeUInt32LE(UInt32(nameBytes.count), to: &bytes, at: 60)
        bytes.replaceSubrange(104..<104 + nameBytes.count, with: nameBytes)
        if Int(nextOffset) > bytes.count {
            bytes.append(contentsOf: Array(repeating: 0, count: Int(nextOffset) - bytes.count))
        }
        return bytes
    }

    private func hex(_ bytes: [UInt8]) -> String {
        bytes.map { String(format: "%02x", $0) }.joined()
    }

    private func hexBytes(_ value: String) -> [UInt8] {
        stride(from: 0, to: value.count, by: 2).map {
            let start = value.index(value.startIndex, offsetBy: $0)
            let end = value.index(start, offsetBy: 2)
            return UInt8(value[start..<end], radix: 16)!
        }
    }

    private func readUInt16LE(_ bytes: [UInt8], at offset: Int) -> UInt16 {
        UInt16(bytes[offset]) | (UInt16(bytes[offset + 1]) << 8)
    }

    private func readUInt32LE(_ bytes: [UInt8], at offset: Int) -> UInt32 {
        UInt32(bytes[offset])
            | (UInt32(bytes[offset + 1]) << 8)
            | (UInt32(bytes[offset + 2]) << 16)
            | (UInt32(bytes[offset + 3]) << 24)
    }

    private func readUInt64LE(_ bytes: [UInt8], at offset: Int) -> UInt64 {
        UInt64(readUInt32LE(bytes, at: offset)) | (UInt64(readUInt32LE(bytes, at: offset + 4)) << 32)
    }

    private func expectDERTag(_ expectedTag: UInt8, in bytes: [UInt8], cursor: inout Int) throws -> Int {
        XCTAssertLessThan(cursor, bytes.count)
        XCTAssertEqual(bytes[cursor], expectedTag)
        cursor += 1
        let length = try readDERLength(bytes, cursor: &cursor)
        let end = cursor + length
        XCTAssertLessThanOrEqual(end, bytes.count)
        return end
    }

    private func readDERLength(_ bytes: [UInt8], cursor: inout Int) throws -> Int {
        XCTAssertLessThan(cursor, bytes.count)
        let first = bytes[cursor]
        cursor += 1
        if first & 0x80 == 0 {
            return Int(first)
        }
        let byteCount = Int(first & 0x7f)
        XCTAssertGreaterThan(byteCount, 0)
        XCTAssertLessThanOrEqual(byteCount, 2)
        XCTAssertLessThanOrEqual(cursor + byteCount, bytes.count)
        var value = 0
        for _ in 0..<byteCount {
            value = (value << 8) | Int(bytes[cursor])
            cursor += 1
        }
        return value
    }

    private func writeUInt16LE(_ value: UInt16, to bytes: inout [UInt8], at offset: Int) {
        bytes[offset] = UInt8(value & 0xff)
        bytes[offset + 1] = UInt8((value >> 8) & 0xff)
    }

    private func writeUInt32LE(_ value: UInt32, to bytes: inout [UInt8], at offset: Int) {
        bytes[offset] = UInt8(value & 0xff)
        bytes[offset + 1] = UInt8((value >> 8) & 0xff)
        bytes[offset + 2] = UInt8((value >> 16) & 0xff)
        bytes[offset + 3] = UInt8((value >> 24) & 0xff)
    }

    private func writeUInt64LE(_ value: UInt64, to bytes: inout [UInt8], at offset: Int) {
        writeUInt32LE(UInt32(value & 0xffff_ffff), to: &bytes, at: offset)
        writeUInt32LE(UInt32((value >> 32) & 0xffff_ffff), to: &bytes, at: offset + 4)
    }

    private func smb2StatusResponse(status: UInt32, command: UInt16, messageId: UInt64, treeId: UInt32) throws -> [UInt8] {
        try SMB2Header(status: status, command: command, messageId: messageId, treeId: treeId).encode()
    }

    private func waitForOutboundFrameCount(_ expectedCount: Int, transport: ControlledReceiveTransport) async throws {
        for _ in 0..<100 {
            if try unframed(transport.outbound).count >= expectedCount {
                return
            }
            try await Task.sleep(nanoseconds: 10_000_000)
        }
        XCTFail("timed out waiting for \(expectedCount) outbound SMB frames")
    }

    private func smb2CreateResponse(fileId: [UInt8], messageId: UInt64, treeId: UInt32) throws -> [UInt8] {
        var response = try SMB2Header(command: SMB2Commands.create, messageId: messageId, treeId: treeId).encode()
        response.append(contentsOf: Array(repeating: UInt8(0), count: 88))
        writeUInt16LE(89, to: &response, at: 64)
        response.replaceSubrange(128..<144, with: fileId)
        return response
    }

    private func smb2ReadResponse(_ payload: [UInt8], messageId: UInt64, treeId: UInt32) throws -> [UInt8] {
        var response = try SMB2Header(command: SMB2Commands.read, messageId: messageId, treeId: treeId).encode()
        response.append(contentsOf: Array(repeating: UInt8(0), count: 16))
        writeUInt16LE(17, to: &response, at: 64)
        response[66] = 80
        writeUInt32LE(UInt32(payload.count), to: &response, at: 68)
        response.append(contentsOf: payload)
        return response
    }

    private func smb2WriteResponse(count: Int, messageId: UInt64, treeId: UInt32) throws -> [UInt8] {
        var response = try SMB2Header(command: SMB2Commands.write, messageId: messageId, treeId: treeId).encode()
        response.append(contentsOf: Array(repeating: UInt8(0), count: 16))
        writeUInt16LE(17, to: &response, at: 64)
        writeUInt32LE(UInt32(count), to: &response, at: 68)
        return response
    }

    private func smb2QueryInfoResponse(
        size: UInt64,
        messageId: UInt64,
        treeId: UInt32,
        attributes: UInt32 = 0
    ) throws -> [UInt8] {
        var payload = Array(repeating: UInt8(0), count: 56)
        writeUInt64LE(size, to: &payload, at: 40)
        writeUInt32LE(attributes, to: &payload, at: 52)
        var response = try SMB2Header(command: SMB2Commands.queryInfo, messageId: messageId, treeId: treeId).encode()
        response.append(contentsOf: Array(repeating: UInt8(0), count: 8))
        writeUInt16LE(9, to: &response, at: 64)
        writeUInt16LE(72, to: &response, at: 66)
        writeUInt32LE(UInt32(payload.count), to: &response, at: 68)
        response.append(contentsOf: payload)
        return response
    }

    private func smb2QueryDirectoryResponse(entries: [[UInt8]], messageId: UInt64, treeId: UInt32) throws -> [UInt8] {
        let payload = entries.flatMap { $0 }
        var response = try SMB2Header(command: SMB2Commands.queryDirectory, messageId: messageId, treeId: treeId).encode()
        response.append(contentsOf: Array(repeating: UInt8(0), count: 8))
        writeUInt16LE(9, to: &response, at: 64)
        writeUInt16LE(72, to: &response, at: 66)
        writeUInt32LE(UInt32(payload.count), to: &response, at: 68)
        response.append(contentsOf: payload)
        return response
    }

    private func negotiateResponse(messageId: UInt64) throws -> [UInt8] {
        var response = try SMB2Header(command: SMBNegotiateConstants.commandNegotiate, messageId: messageId).encode()
        response.append(contentsOf: Array(repeating: UInt8(0), count: 65))
        writeUInt16LE(65, to: &response, at: 64)
        writeUInt16LE(SMBNegotiateConstants.signingEnabled, to: &response, at: 66)
        writeUInt16LE(SMBNegotiateConstants.dialect302, to: &response, at: 68)
        response.replaceSubrange(72..<88, with: Array(repeating: UInt8(0x42), count: 16))
        writeUInt32LE(1_048_576, to: &response, at: 92)
        writeUInt32LE(1_048_576, to: &response, at: 96)
        writeUInt32LE(1_048_576, to: &response, at: 100)
        writeUInt16LE(UInt16(response.count), to: &response, at: 116)
        writeUInt16LE(0, to: &response, at: 118)
        return response
    }

    private func framed(_ messages: [[UInt8]]) throws -> [UInt8] {
        try messages.reduce(into: []) { result, message in
            result.append(contentsOf: try DirectTCPFraming.frame(message))
        }
    }

    private func unframed(_ bytes: [UInt8]) throws -> [[UInt8]] {
        var frames: [[UInt8]] = []
        var cursor = 0
        while cursor < bytes.count {
            let length = try DirectTCPFraming.length(from: Array(bytes[cursor..<cursor + 4]))
            let start = cursor + 4
            let end = start + length
            frames.append(Array(bytes[start..<end]))
            cursor = end
        }
        return frames
    }
}
