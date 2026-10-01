#if canImport(CryptoExtras) && !canImport(CommonCrypto)
import Foundation
import Crypto
import CryptoExtras

enum AESCCMCryptoExtras {
    // This backend is limited to the 11-byte SMB 3.0.2 nonce because only its q=4 counter blocks map to the chosen GCM nonce.
    static func sealValidated(
        key: [UInt8],
        nonce: [UInt8],
        plaintext: [UInt8],
        authenticatedData: [UInt8],
        tagLength: Int
    ) throws -> (ciphertext: [UInt8], tag: [UInt8]) {
        let operationKey = SymmetricKey(data: key)
        let k1 = try cmacSubkey(key: operationKey)
        let mac = try cbcMAC(
            key: operationKey,
            k1: k1,
            nonce: nonce,
            message: plaintext,
            authenticatedData: authenticatedData,
            tagLength: tagLength
        )
        let ciphertext = try ctrCrypt(key: operationKey, nonce: nonce, input: plaintext)
        let s0 = try encrypt(counterBlock(nonce: nonce, counter: 0), key: operationKey)
        var tag = Array(mac.prefix(tagLength))
        for index in 0..<tagLength { tag[index] ^= s0[index] }
        return (ciphertext, tag)
    }

    static func openValidated(
        key: [UInt8],
        nonce: [UInt8],
        ciphertext: [UInt8],
        authenticatedData: [UInt8],
        tag: [UInt8]
    ) throws -> [UInt8] {
        let operationKey = SymmetricKey(data: key)
        let plaintext = try ctrCrypt(key: operationKey, nonce: nonce, input: ciphertext)
        let k1 = try cmacSubkey(key: operationKey)
        let mac = try cbcMAC(
            key: operationKey,
            k1: k1,
            nonce: nonce,
            message: plaintext,
            authenticatedData: authenticatedData,
            tagLength: tag.count
        )
        let s0 = try encrypt(counterBlock(nonce: nonce, counter: 0), key: operationKey)
        var expected = Array(mac.prefix(tag.count))
        for index in 0..<tag.count { expected[index] ^= s0[index] }
        guard AESCCM.constantTimeEqual(expected, tag) else {
            throw SMBCodecError.invalidValue("AES-CCM authentication failed")
        }
        return plaintext
    }

    private static func cmacSubkey(key: SymmetricKey) throws -> [UInt8] {
        var l = [UInt8](repeating: 0, count: 16)
        try AES.permute(&l, key: key)
        var k1 = [UInt8](repeating: 0, count: 16)
        var carry: UInt8 = 0
        for index in stride(from: 15, through: 0, by: -1) {
            let byte = l[index]
            k1[index] = (byte &<< 1) | carry
            carry = byte >> 7
        }
        let reductionMask = UInt8(0) &- carry
        k1[15] ^= 0x87 & reductionMask
        return k1
    }

    private static func cbcMAC(
        key: SymmetricKey,
        k1: [UInt8],
        nonce: [UInt8],
        message: [UInt8],
        authenticatedData: [UInt8],
        tagLength: Int
    ) throws -> [UInt8] {
        var flags = UInt8(((tagLength - 2) / 2) << 3) | 0x03
        if !authenticatedData.isEmpty { flags |= 0x40 }
        let b0 = [flags] + nonce + AESCCM.encodeLength(message.count, bytes: 4)
        // AES.CMAC computes the CCM CBC-MAC value here; its CMAC tag is never exposed (SP 800-38B / 38C).
        var stream = try CMACBlockStream(key: key, k1: k1)
        stream.append(b0)
        if !authenticatedData.isEmpty {
            stream.append(try AESCCM.encodeAADLength(authenticatedData.count))
            stream.append(authenticatedData)
            stream.padToBlockBoundary()
        }
        stream.append(message)
        stream.padToBlockBoundary()
        return stream.finalize()
    }

    private static func ctrCrypt(key: SymmetricKey, nonce: [UInt8], input: [UInt8]) throws -> [UInt8] {
        guard !input.isEmpty else { return [] }
        var output = input
        let firstBlockCount = min(16, input.count)
        let firstCounter = try encrypt(counterBlock(nonce: nonce, counter: 1), key: key)
        for index in 0..<firstBlockCount { output[index] ^= firstCounter[index] }
        guard input.count > 16 else { return output }

        // GCM restarts its payload counter at 2 on every call; one suffix call prevents keystream reuse.
        let gcmNonce = try AES.GCM.Nonce(data: Data([0x03] + nonce))
        // The suffix copy, the GCM output and `output` coexist (about 4x the input at peak). Accepted: SMB frames are
        // bounded by the negotiated MaxRead/MaxWriteSize, and avoiding the copy needs Data(bytesNoCopy:) lifetime tricks.
        let suffix = Data(input.dropFirst(16))
        let sealed = try AES.GCM.seal(suffix, using: key, nonce: gcmNonce)
        output.replaceSubrange(16..<input.count, with: sealed.ciphertext)
        return output
    }

    private static func counterBlock(nonce: [UInt8], counter: Int) -> [UInt8] {
        [0x03] + nonce + AESCCM.encodeLength(counter, bytes: 4)
    }

    private static func encrypt(_ block: [UInt8], key: SymmetricKey) throws -> [UInt8] {
        var encrypted = block
        try AES.permute(&encrypted, key: key)
        return encrypted
    }
}

private struct CMACBlockStream {
    private var authenticator: AES.CMAC
    private let k1: [UInt8]
    private var partialBlock = [UInt8](repeating: 0, count: 16)
    private var partialCount = 0
    private var completeBlockBatch: [UInt8] = []

    init(key: SymmetricKey, k1: [UInt8]) throws {
        self.authenticator = try AES.CMAC(key: key)
        self.k1 = k1
        self.completeBlockBatch.reserveCapacity(8_208)
    }

    mutating func append(_ bytes: [UInt8]) {
        var offset = 0
        while offset < bytes.count {
            let amount = min(16 - partialCount, bytes.count - offset)
            for index in 0..<amount {
                partialBlock[partialCount + index] = bytes[offset + index]
            }
            partialCount += amount
            offset += amount
            if partialCount == 16 { appendCompleteBlock() }
        }
    }

    mutating func padToBlockBoundary() {
        guard partialCount > 0 else { return }
        partialCount = 16
        appendCompleteBlock()
    }

    mutating func finalize() -> [UInt8] {
        precondition(partialCount == 0 && completeBlockBatch.count >= 16)
        let lastBlockStart = completeBlockBatch.count - 16
        for index in 0..<16 { completeBlockBatch[lastBlockStart + index] ^= k1[index] }
        completeBlockBatch.withUnsafeBytes { authenticator.update(bufferPointer: $0) }
        return Array(authenticator.finalize())
    }

    private mutating func appendCompleteBlock() {
        completeBlockBatch.append(contentsOf: partialBlock)
        for index in 0..<16 { partialBlock[index] = 0 }
        partialCount = 0
        if completeBlockBatch.count >= 8_192 {
            flushAllButLastBlock()
        }
    }

    private mutating func flushAllButLastBlock() {
        let flushCount = completeBlockBatch.count - 16
        guard flushCount > 0 else { return }
        let completeBlocks = Array(completeBlockBatch[..<flushCount])
        completeBlocks.withUnsafeBytes { authenticator.update(bufferPointer: $0) }
        completeBlockBatch.removeFirst(flushCount)
    }
}

// Side channels (checked against the swift-crypto 4.5.0 checkout): BCM_aes_encrypt in aes.cc.inc picks AES instructions
// (aes_hw), then vpaes, then aes_nohw, whose header calls it a constant-time bitsliced implementation; gcm_nohw's
// header calls its GHASH constant-time. SMBee itself adds no table lookup. Re-check these files when swift-crypto's
// BoringSSL changes; the guarantee is BoringSSL's, not SMBee's.

#endif
