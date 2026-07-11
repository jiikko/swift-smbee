import Foundation

enum DCERPC {
    static let pduTypeRequest: UInt8 = 0
    static let pduTypeResponse: UInt8 = 2
    static let pduTypeBind: UInt8 = 11
    static let pduTypeBindAck: UInt8 = 12
    static let pduTypeFault: UInt8 = 3
    static let pfcFirstFrag: UInt8 = 0x01
    static let pfcLastFrag: UInt8 = 0x02
    static let firstFragLastFrag: UInt8 = 0x03
    static let dataRepresentation: [UInt8] = [0x10, 0x00, 0x00, 0x00]
    static let ndrTransferSyntax = UUID(uuidString: "8a885d04-1ceb-11c9-9fe8-08002b104860")!

    static func encodeBind(callId: UInt32, abstractSyntax: UUID, abstractVersion: UInt32) throws -> [UInt8] {
        var body = SMBByteWriter()
        body.writeUInt16LE(4_280)
        body.writeUInt16LE(4_280)
        body.writeUInt32LE(0)
        body.writeUInt8(1)
        body.writeUInt8(0)
        body.writeUInt16LE(0)
        body.writeUInt16LE(0)
        body.writeUInt8(1)
        body.writeUInt8(0)
        body.writeBytes(encodeSyntax(uuid: abstractSyntax, version: abstractVersion))
        body.writeBytes(encodeSyntax(uuid: ndrTransferSyntax, version: 2))
        return try encodeHeader(type: pduTypeBind, callId: callId, body: body.bytes)
    }

    static func decodeBindAck(_ bytes: [UInt8]) throws {
        let header = try decodeHeader(bytes)
        guard header.type == pduTypeBindAck else {
            throw SMBCodecError.invalidValue("expected DCE/RPC bind_ack, got pdu type \(header.type)")
        }
        guard bytes.count >= 24 else { throw SMBCodecError.truncated }
        var cursor = 16
        cursor += 2 // max_xmit_frag
        cursor += 2 // max_recv_frag
        cursor += 4 // assoc_group_id
        let secAddrLength = Int(readUInt16LE(bytes, at: cursor))
        cursor += 2 + secAddrLength
        cursor = align(cursor, to: 4)
        guard cursor + 4 <= bytes.count else { throw SMBCodecError.truncated }
        let resultCount = Int(bytes[cursor])
        cursor += 4
        guard resultCount > 0, cursor + 24 <= bytes.count else { throw SMBCodecError.truncated }
        let result = readUInt16LE(bytes, at: cursor)
        guard result == 0 else {
            throw SMBCodecError.invalidValue("DCE/RPC bind rejected presentation context result \(result)")
        }
    }

    static func encodeRequest(callId: UInt32, opnum: UInt16, stub: [UInt8], contextId: UInt16 = 0) throws -> [UInt8] {
        var body = SMBByteWriter()
        body.writeUInt32LE(UInt32(stub.count))
        body.writeUInt16LE(contextId)
        body.writeUInt16LE(opnum)
        body.writeBytes(stub)
        return try encodeHeader(type: pduTypeRequest, callId: callId, body: body.bytes)
    }

    static func decodeResponseStub(_ bytes: [UInt8]) throws -> [UInt8] {
        var cursor = 0
        var stub: [UInt8] = []
        while true {
            let header = try decodeHeader(Array(bytes[cursor...]))
            guard header.fragLength >= 16 else { throw SMBCodecError.truncated }
            let fragmentEnd = cursor + Int(header.fragLength)
            if header.type == pduTypeFault {
                guard fragmentEnd >= cursor + 24 else { throw SMBCodecError.truncated }
                throw SMBCodecError.invalidValue("DCE/RPC fault status 0x\(String(format: "%08x", readUInt32LE(bytes, at: cursor + 20)))")
            }
            guard header.type == pduTypeResponse else {
                throw SMBCodecError.invalidValue("expected DCE/RPC response, got pdu type \(header.type)")
            }
            guard fragmentEnd >= cursor + 24 else { throw SMBCodecError.truncated }
            let allocHint = Int(readUInt32LE(bytes, at: cursor + 16))
            let stubOffset = cursor + 24
            let stubLength = min(allocHint, fragmentEnd - stubOffset)
            guard stubLength >= 0, stubOffset + stubLength <= bytes.count else { throw SMBCodecError.truncated }
            stub.append(contentsOf: bytes[stubOffset..<stubOffset + stubLength])
            if (header.flags & pfcLastFrag) != 0 {
                return stub
            }
            cursor = fragmentEnd
        }
    }

    static func responseHasLastFragment(_ bytes: [UInt8]) throws -> Bool {
        guard !bytes.isEmpty else { throw SMBCodecError.truncated }
        var cursor = 0
        while true {
            guard cursor < bytes.count else { return false }
            let header = try decodeHeader(Array(bytes[cursor...]))
            guard header.fragLength >= 16 else { throw SMBCodecError.truncated }
            if (header.flags & pfcLastFrag) != 0 {
                return true
            }
            cursor += Int(header.fragLength)
        }
    }

    static func validateResponseFragments(_ bytes: [UInt8], expectedCallId: UInt32? = nil, maxBytes: Int = 16 * 1024 * 1024) throws -> Bool {
        guard !bytes.isEmpty, bytes.count <= maxBytes else { throw SMBCodecError.invalidValue("DCE/RPC response exceeds size limit") }
        var cursor = 0
        var first = true
        var fragments = 0
        while cursor < bytes.count {
            let header = try decodeHeader(Array(bytes[cursor...]))
            let length = Int(header.fragLength)
            guard header.type == pduTypeResponse, length >= 24,
                  (expectedCallId == nil || header.callId == expectedCallId),
                  bytes[cursor + 4..<cursor + 8] == dataRepresentation[0..<4]
            else { throw SMBCodecError.invalidValue("invalid DCE/RPC response fragment correlation") }
            guard first ? (header.flags & pfcFirstFrag) != 0 : (header.flags & pfcFirstFrag) == 0 else {
                throw SMBCodecError.invalidValue("invalid DCE/RPC FIRST fragment flag")
            }
            first = false
            fragments += 1
            guard fragments <= 256 else { throw SMBCodecError.invalidValue("too many DCE/RPC response fragments") }
            cursor += length
            if (header.flags & pfcLastFrag) != 0 {
                guard cursor == bytes.count else { throw SMBCodecError.invalidValue("data follows DCE/RPC LAST fragment") }
                return true
            }
        }
        return false
    }

    static func callId(_ bytes: [UInt8]) throws -> UInt32 {
        guard bytes.count >= 16 else { throw SMBCodecError.truncated }
        return readUInt32LE(bytes, at: 12)
    }

    private static func encodeHeader(type: UInt8, callId: UInt32, body: [UInt8]) throws -> [UInt8] {
        var writer = SMBByteWriter()
        writer.writeUInt8(5)
        writer.writeUInt8(0)
        writer.writeUInt8(type)
        writer.writeUInt8(firstFragLastFrag)
        writer.writeBytes(dataRepresentation)
        try writer.writeUInt16LE(count: 16 + body.count, of: "DCE/RPC fragment")
        writer.writeUInt16LE(0)
        writer.writeUInt32LE(callId)
        writer.writeBytes(body)
        return writer.bytes
    }

    private struct PDUHeader {
        var type: UInt8
        var flags: UInt8
        var fragLength: UInt16
        var callId: UInt32
    }

    private static func decodeHeader(_ bytes: [UInt8]) throws -> PDUHeader {
        guard bytes.count >= 16 else { throw SMBCodecError.truncated }
        guard bytes[0] == 5 else { throw SMBCodecError.invalidValue("unsupported DCE/RPC version") }
        let fragLength = readUInt16LE(bytes, at: 8)
        guard Int(fragLength) <= bytes.count else { throw SMBCodecError.truncated }
        return PDUHeader(type: bytes[2], flags: bytes[3], fragLength: fragLength, callId: readUInt32LE(bytes, at: 12))
    }

    private static func encodeSyntax(uuid: UUID, version: UInt32) -> [UInt8] {
        let bytes = uuid.uuid
        var writer = SMBByteWriter()
        writer.writeUInt32LE((UInt32(bytes.0) << 24) | (UInt32(bytes.1) << 16) | (UInt32(bytes.2) << 8) | UInt32(bytes.3))
        writer.writeUInt16LE((UInt16(bytes.4) << 8) | UInt16(bytes.5))
        writer.writeUInt16LE((UInt16(bytes.6) << 8) | UInt16(bytes.7))
        writer.writeBytes([bytes.8, bytes.9, bytes.10, bytes.11, bytes.12, bytes.13, bytes.14, bytes.15])
        writer.writeUInt32LE(version)
        return writer.bytes
    }

    private static func align(_ value: Int, to alignment: Int) -> Int {
        let remainder = value % alignment
        return remainder == 0 ? value : value + alignment - remainder
    }

    private static func readUInt16LE(_ bytes: [UInt8], at offset: Int) -> UInt16 {
        UInt16(bytes[offset]) | (UInt16(bytes[offset + 1]) << 8)
    }

    private static func readUInt32LE(_ bytes: [UInt8], at offset: Int) -> UInt32 {
        UInt32(bytes[offset])
            | (UInt32(bytes[offset + 1]) << 8)
            | (UInt32(bytes[offset + 2]) << 16)
            | (UInt32(bytes[offset + 3]) << 24)
    }
}

enum SRVSVC {
    static let interfaceUUID = UUID(uuidString: "4b324fc8-1670-01d3-1278-5a47bf6ee188")!
    static let interfaceVersion: UInt32 = 3
    static let netrShareEnumOpnum: UInt16 = 15
    static let maxPreferredLength: UInt32 = 0xffff_ffff

    static func encodeNetrShareEnumRequest() -> [UInt8] {
        var writer = NDRWriter()
        writer.writeUInt32(0) // ServerName unique pointer: NULL = local server for this binding.
        writer.writeUInt32(1) // SHARE_ENUM_STRUCT.Level
        writer.writeUInt32(1) // union discriminant
        // SHARE_INFO_1_CONTAINER unique pointer (referent id). Level=1 なのに NULL を送ると
        // サーバは ERROR_INVALID_PARAMETER (87) を返す (Samba / Windows とも)。decode 側
        // (`decodeNetrShareEnumResponse`) が containerReferent を読むのと対称の位置。
        writer.writeUInt32(0x0002_0000)
        writer.writeUInt32(0) // SHARE_INFO_1_CONTAINER.EntriesRead
        writer.writeUInt32(0) // SHARE_INFO_1_CONTAINER.Buffer NULL
        writer.writeUInt32(maxPreferredLength)
        writer.writeUInt32(0) // ResumeHandle unique pointer: NULL
        return writer.bytes
    }

    static func decodeNetrShareEnumResponse(_ stub: [UInt8]) throws -> [SMBShareInfo] {
        var reader = NDRReader(stub)
        let level = try reader.readUInt32()
        guard level == 1 else { throw SMBCodecError.invalidValue("unexpected NetrShareEnum level \(level)") }
        let discriminant = try reader.readUInt32()
        guard discriminant == 1 else { throw SMBCodecError.invalidValue("unexpected NetrShareEnum union \(discriminant)") }
        let containerReferent = try reader.readUInt32()
        guard containerReferent != 0 else {
            _ = try reader.readUInt32() // TotalEntries
            let resumeReferent = try reader.readUInt32()
            if resumeReferent != 0 {
                _ = try reader.readUInt32()
            }
            let status = try reader.readUInt32()
            guard status == 0 else {
                throw SMBError.unsupported(status: status, operation: "NetrShareEnum")
            }
            return []
        }
        let entriesRead = try reader.readUInt32()
        let bufferReferent = try reader.readUInt32()
        var shares: [SMBShareInfo] = []
        if entriesRead > 0 && bufferReferent != 0 {
            let conformantCount = try reader.readUInt32()
            let count = Int(min(entriesRead, conformantCount))
            var headers: [(nameRef: UInt32, type: UInt32, remarkRef: UInt32)] = []
            for _ in 0..<count {
                headers.append((try reader.readUInt32(), try reader.readUInt32(), try reader.readUInt32()))
            }
            for header in headers {
                let name = header.nameRef == 0 ? "" : try reader.readConformantVaryingString()
                let remark = header.remarkRef == 0 ? nil : try reader.readConformantVaryingString()
                if !name.isEmpty {
                    shares.append(SMBShareInfo(name: name, type: header.type, comment: remark))
                }
            }
        }
        _ = try reader.readUInt32() // TotalEntries
        let resumeReferent = try reader.readUInt32()
        if resumeReferent != 0 {
            _ = try reader.readUInt32()
        }
        let status = try reader.readUInt32()
        guard status == 0 else {
            throw SMBError.unsupported(status: status, operation: "NetrShareEnum")
        }
        return shares
    }
}

struct NDRWriter {
    private(set) var bytes: [UInt8] = []

    mutating func writeUInt16(_ value: UInt16) {
        bytes.append(UInt8(value & 0xff))
        bytes.append(UInt8((value >> 8) & 0xff))
    }

    mutating func writeUInt32(_ value: UInt32) {
        bytes.append(UInt8(value & 0xff))
        bytes.append(UInt8((value >> 8) & 0xff))
        bytes.append(UInt8((value >> 16) & 0xff))
        bytes.append(UInt8((value >> 24) & 0xff))
    }

    mutating func writeBytes(_ value: [UInt8]) {
        bytes.append(contentsOf: value)
    }
}

struct NDRReader {
    private let bytes: [UInt8]
    private var cursor: Int = 0

    init(_ bytes: [UInt8]) {
        self.bytes = bytes
    }

    mutating func readUInt32() throws -> UInt32 {
        try align(to: 4)
        guard cursor + 4 <= bytes.count else { throw SMBCodecError.truncated }
        defer { cursor += 4 }
        return UInt32(bytes[cursor])
            | (UInt32(bytes[cursor + 1]) << 8)
            | (UInt32(bytes[cursor + 2]) << 16)
            | (UInt32(bytes[cursor + 3]) << 24)
    }

    mutating func readConformantVaryingString() throws -> String {
        let maxCount = try readUInt32()
        let offset = try readUInt32()
        let actualCount = try readUInt32()
        guard offset == 0 else { throw SMBCodecError.invalidValue("unsupported non-zero NDR string offset") }
        guard actualCount <= maxCount else { throw SMBCodecError.invalidValue("invalid NDR string counts") }
        let byteCount = Int(actualCount) * 2
        guard cursor + byteCount <= bytes.count else { throw SMBCodecError.truncated }
        let raw = Array(bytes[cursor..<cursor + byteCount])
        cursor += byteCount
        try align(to: 4)
        var units = stride(from: 0, to: raw.count - 1, by: 2).map {
            UInt16(raw[$0]) | (UInt16(raw[$0 + 1]) << 8)
        }
        if units.last == 0 {
            units.removeLast()
        }
        return String(decoding: units, as: UTF16.self)
    }

    mutating func readUInt16() throws -> UInt16 {
        try align(to: 2)
        guard cursor + 2 <= bytes.count else { throw SMBCodecError.truncated }
        defer { cursor += 2 }
        return UInt16(bytes[cursor]) | (UInt16(bytes[cursor + 1]) << 8)
    }

    /// RPC_UNICODE_STRING header: Length (bytes), MaximumLength (bytes), Buffer pointer.
    /// The buffer contents are deferred (read later with `readRPCUnicodeStringBuffer`).
    mutating func readRPCUnicodeStringHeader() throws -> (length: UInt16, maximumLength: UInt16, referent: UInt32) {
        let length = try readUInt16()
        let maximumLength = try readUInt16()
        let referent = try readUInt32()
        guard length <= maximumLength, length % 2 == 0, maximumLength % 2 == 0 else {
            throw SMBCodecError.invalidValue("invalid RPC_UNICODE_STRING lengths")
        }
        return (length, maximumLength, referent)
    }

    /// Deferred RPC_UNICODE_STRING buffer: conformant varying UInt16 array. Counts are in
    /// characters; `lengthInBytes` (from the header) bounds the significant characters
    /// because the buffer is not guaranteed to be null-terminated.
    mutating func readRPCUnicodeStringBuffer(lengthInBytes: UInt16) throws -> String {
        let maxCount = try readUInt32()
        let offset = try readUInt32()
        let actualCount = try readUInt32()
        guard offset == 0 else { throw SMBCodecError.invalidValue("unsupported non-zero NDR string offset") }
        guard actualCount <= maxCount, actualCount <= UInt32(lengthInBytes / 2) else {
            throw SMBCodecError.invalidValue("invalid NDR string counts")
        }
        let byteCount = Int(actualCount) * 2
        guard cursor + byteCount <= bytes.count else { throw SMBCodecError.truncated }
        let significant = min(byteCount, Int(lengthInBytes))
        let raw = Array(bytes[cursor..<cursor + significant])
        cursor += byteCount
        try align(to: 4)
        let units = stride(from: 0, to: max(raw.count - 1, 0), by: 2).map {
            UInt16(raw[$0]) | (UInt16(raw[$0 + 1]) << 8)
        }
        return String(decoding: units, as: UTF16.self)
    }

    /// Deferred SID: conformant count (sub-authority count) followed by the SID body.
    mutating func skipConformantSID() throws {
        let conformantCount = try readUInt32()
        guard cursor + 2 <= bytes.count else { throw SMBCodecError.truncated }
        let subAuthorityCount = Int(bytes[cursor + 1])
        guard subAuthorityCount == Int(conformantCount) else {
            throw SMBCodecError.invalidValue("SID sub-authority count mismatch")
        }
        let size = 8 + subAuthorityCount * 4
        guard cursor + size <= bytes.count else { throw SMBCodecError.truncated }
        cursor += size
        try align(to: 4)
    }

    private mutating func align(to alignment: Int) throws {
        let remainder = cursor % alignment
        if remainder != 0 {
            cursor += alignment - remainder
        }
        guard cursor <= bytes.count else { throw SMBCodecError.truncated }
    }
}
