enum SMBSessionSigningAlgorithm {
    case aesCMAC
    case aesGMAC
}

enum SMBSessionEncryptionAlgorithm {
    case aes128CCM
    case aes128GCM
}

enum SMBSessionSigning {
    /// Signs a packet whose SMB2 signature field (bytes 48..<64) is already zeroed.
    /// Outbound packets are normalized before this call, so avoiding a second full
    /// packet copy keeps signing on the hot path focused on the CMAC/GMAC operation.
    static func signatureForNormalizedPacket(
        algorithm: SMBSessionSigningAlgorithm,
        key: [UInt8],
        packet: [UInt8],
        sender: SMBSessionSigningSender
    ) throws -> [UInt8] {
        switch algorithm {
        case .aesCMAC:
            return try AESCMAC.authenticationCode(key: key, message: packet)
        case .aesGMAC:
            let header = try SMB2Header.decode(packet)
            return try SMBCrypto.aesGMAC(
                key: key,
                nonce: gmacNonce(messageId: header.messageId, command: header.command, sender: sender),
                authenticatedData: packet
            )
        }
    }

    static func signature(
        algorithm: SMBSessionSigningAlgorithm,
        key: [UInt8],
        packet: [UInt8],
        sender: SMBSessionSigningSender
    ) throws -> [UInt8] {
        var normalized = packet
        normalized.replaceSubrange(48..<64, with: Array(repeating: 0, count: 16))
        return try signatureForNormalizedPacket(
            algorithm: algorithm, key: key, packet: normalized, sender: sender
        )
    }

    static func gmacNonce(messageId: UInt64, command: UInt16, sender: SMBSessionSigningSender) -> [UInt8] {
        // MS-SMB2 3.1.4.1: RFC4543 nonce = MessageId(8 LE) + sender/CANCEL flags(4 LE).
        var writer = SMBByteWriter()
        writer.writeUInt64LE(messageId)
        var flags: UInt32 = sender == .server ? 0x0000_0001 : 0
        if command == SMB2Commands.cancel {
            flags |= 0x0000_0002
        }
        writer.writeUInt32LE(flags)
        return writer.bytes
    }
}

enum SMBSessionSigningSender {
    case client
    case server
}
