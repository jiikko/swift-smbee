import Crypto
import Foundation

public enum SMBCrypto {
    static let smb3SigningLabel = Array("SMB2AESCMAC".utf8) + [0]
    static let smb3SigningContext = Array("SmbSign".utf8) + [0]
    static let smb302EncryptionLabel = Array("SMB2AESCCM".utf8) + [0]
    static let smb302EncryptionContext = Array("ServerIn ".utf8) + [0]
    static let smb302DecryptionContext = Array("ServerOut".utf8) + [0]

    public static func sha512(_ bytes: [UInt8]) -> [UInt8] {
        Array(SHA512.hash(data: bytes))
    }

    public static func hmacSHA256(key: [UInt8], message: [UInt8]) -> [UInt8] {
        let authenticationCode = HMAC<SHA256>.authenticationCode(
            for: message,
            using: SymmetricKey(data: key)
        )
        return Array(authenticationCode)
    }

    public static func hmacMD5(key: [UInt8], message: [UInt8]) -> [UInt8] {
        let authenticationCode = HMAC<Insecure.MD5>.authenticationCode(
            for: message,
            using: SymmetricKey(data: key)
        )
        return Array(authenticationCode)
    }

    public static func md5(_ bytes: [UInt8]) -> [UInt8] {
        Array(Insecure.MD5.hash(data: bytes))
    }

    public static func aesGCMSeal(
        key: [UInt8],
        nonce: [UInt8],
        plaintext: [UInt8],
        authenticatedData: [UInt8]
    ) throws -> (ciphertext: [UInt8], tag: [UInt8]) {
        let sealedBox = try AES.GCM.seal(
            plaintext,
            using: SymmetricKey(data: key),
            nonce: AES.GCM.Nonce(data: nonce),
            authenticating: authenticatedData
        )
        return (Array(sealedBox.ciphertext), Array(sealedBox.tag))
    }

    public static func aesGMAC(key: [UInt8], nonce: [UInt8], authenticatedData: [UInt8]) throws -> [UInt8] {
        // MS-SMB2 AES-GMAC signing is GCM authentication with zero-length plaintext and the SMB packet as AAD.
        try aesGCMSeal(key: key, nonce: nonce, plaintext: [], authenticatedData: authenticatedData).tag
    }

    public static func smb3SigningKey(sessionKey: [UInt8]) -> [UInt8] {
        // MS-SMB2 3.1.4.2 derives the SMB 3.0.x signing key with SP800-108 CTR HMAC-SHA256.
        sp800108CounterModeHMACSHA256(
            key: sessionKey,
            label: smb3SigningLabel,
            context: smb3SigningContext,
            length: 16
        )
    }

    public static func smb302EncryptionKey(sessionKey: [UInt8]) -> [UInt8] {
        // MS-SMB2 3.1.4.3 SMB 3.0.x client-to-server AES-128-CCM key.
        sp800108CounterModeHMACSHA256(
            key: sessionKey,
            label: smb302EncryptionLabel,
            context: smb302EncryptionContext,
            length: 16
        )
    }

    public static func smb302DecryptionKey(sessionKey: [UInt8]) -> [UInt8] {
        // MS-SMB2 3.1.4.3 SMB 3.0.x server-to-client AES-128-CCM key.
        sp800108CounterModeHMACSHA256(
            key: sessionKey,
            label: smb302EncryptionLabel,
            context: smb302DecryptionContext,
            length: 16
        )
    }

    static func sp800108CounterModeHMACSHA256(key: [UInt8], label: [UInt8], context: [UInt8], length: Int) -> [UInt8] {
        var output: [UInt8] = []
        var counter: UInt32 = 1
        while output.count < length {
            var input: [UInt8] = [
                UInt8((counter >> 24) & 0xff),
                UInt8((counter >> 16) & 0xff),
                UInt8((counter >> 8) & 0xff),
                UInt8(counter & 0xff)
            ]
            input += label
            input += [0]
            input += context
            let bits = UInt32(length * 8)
            input += [
                UInt8((bits >> 24) & 0xff),
                UInt8((bits >> 16) & 0xff),
                UInt8((bits >> 8) & 0xff),
                UInt8(bits & 0xff)
            ]
            output += hmacSHA256(key: key, message: input)
            counter += 1
        }
        return Array(output.prefix(length))
    }
}
