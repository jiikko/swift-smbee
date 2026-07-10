import Foundation

/// Resolved account name for a SID (MS-LSAT LsarLookupSids).
public struct SMBResolvedSIDName: Equatable, Sendable {
    /// SID_NAME_USE (MS-SAMR): 1=user, 2=group, 4=alias, 5=well-known group, 8=unknown...
    public let use: UInt16
    public let domain: String?
    public let name: String

    public init(use: UInt16, domain: String?, name: String) {
        self.use = use
        self.domain = domain
        self.name = name
    }

    /// `DOMAIN\name` when a domain is present, otherwise just the name.
    public var qualifiedName: String {
        guard let domain, !domain.isEmpty else { return name }
        return "\(domain)\\\(name)"
    }
}

/// Minimal MS-LSAT client surface over the `lsarpc` named pipe:
/// LsarOpenPolicy2 (POLICY_LOOKUP_NAMES) → LsarLookupSids (level 1) → LsarClose.
enum LSARPC {
    static let interfaceUUID = UUID(uuidString: "12345778-1234-abcd-ef00-0123456789ab")!
    static let interfaceVersion: UInt32 = 0
    static let opnumClose: UInt16 = 0
    static let opnumLookupSids: UInt16 = 15
    static let opnumOpenPolicy2: UInt16 = 44
    static let policyLookupNames: UInt32 = 0x0000_0800
    static let statusSomeNotMapped: UInt32 = 0x0000_0107
    static let statusNoneMapped: UInt32 = 0xc000_0073

    static func encodeOpenPolicy2Request() -> [UInt8] {
        var writer = NDRWriter()
        writer.writeUInt32(0) // SystemName unique pointer: NULL
        // LSAPR_OBJECT_ATTRIBUTES: all-null attributes are sufficient for lookups.
        writer.writeUInt32(24) // Length
        writer.writeUInt32(0)  // RootDirectory
        writer.writeUInt32(0)  // ObjectName
        writer.writeUInt32(0)  // Attributes
        writer.writeUInt32(0)  // SecurityDescriptor
        writer.writeUInt32(0)  // SecurityQualityOfService
        writer.writeUInt32(policyLookupNames)
        return writer.bytes
    }

    static func decodePolicyHandleResponse(_ stub: [UInt8], operation: String) throws -> [UInt8] {
        guard stub.count >= 24 else { throw SMBCodecError.truncated }
        let handle = Array(stub[0..<20])
        let status = readUInt32LE(stub, at: stub.count - 4)
        try SMBErrorMapper.throwIfFailure(status: status, operation: operation)
        return handle
    }

    static func encodeLookupSidsRequest(handle: [UInt8], sids: [String]) throws -> [UInt8] {
        guard handle.count == 20 else { throw SMBCodecError.invalidValue("LSA policy handle must be 20 bytes") }
        guard !sids.isEmpty else { throw SMBCodecError.invalidValue("LsarLookupSids requires at least one SID") }
        var writer = NDRWriter()
        writer.writeBytes(handle)
        // LSAPR_SID_ENUM_BUFFER
        writer.writeUInt32(UInt32(sids.count))
        var referent: UInt32 = 0x0002_0000
        writer.writeUInt32(referent) // SidInfo pointer
        referent += 4
        writer.writeUInt32(UInt32(sids.count)) // conformant count
        for _ in sids {
            writer.writeUInt32(referent) // per-SID unique pointer
            referent += 4
        }
        for sid in sids {
            let encoded = try SMB2SetInfo.encodeSID(sid)
            writer.writeUInt32(UInt32(encoded[1])) // conformant count = SubAuthorityCount
            writer.writeBytes(encoded)
        }
        // LSAPR_TRANSLATED_NAMES (in/out): Entries=0, Names=NULL
        writer.writeUInt32(0)
        writer.writeUInt32(0)
        writer.writeUInt16(1) // LookupLevel = LsapLookupWksta
        writer.writeUInt16(0) // alignment padding
        writer.writeUInt32(0) // MappedCount
        return writer.bytes
    }

    /// Returns resolved names positionally matching the requested SID order; unmapped
    /// entries are nil. Accepts STATUS_SOME_NOT_MAPPED / STATUS_NONE_MAPPED.
    static func decodeLookupSidsResponse(_ stub: [UInt8]) throws -> [SMBResolvedSIDName?] {
        var reader = NDRReader(stub)
        var domains: [String] = []
        let domainsReferent = try reader.readUInt32()
        if domainsReferent != 0 {
            let entries = try reader.readUInt32()
            let arrayReferent = try reader.readUInt32()
            _ = try reader.readUInt32() // MaxEntries
            if arrayReferent != 0 {
                let count = Int(try reader.readUInt32()) // conformant count
                guard count == Int(entries) else { throw SMBCodecError.invalidValue("invalid domain count") }
                var nameHeaders: [(length: UInt16, maximumLength: UInt16, referent: UInt32)] = []
                for _ in 0..<count {
                    let header = try reader.readRPCUnicodeStringHeader()
                    let sidReferent = try reader.readUInt32()
                    _ = sidReferent
                    nameHeaders.append(header)
                }
                for header in nameHeaders {
                    let name = header.referent == 0 ? "" : try reader.readRPCUnicodeStringBuffer(lengthInBytes: header.length)
                    domains.append(name)
                    // Deferred domain SID follows its name.
                    try reader.skipConformantSID()
                }
            }
        }
        // LSAPR_TRANSLATED_NAMES
        let translatedEntries = try reader.readUInt32()
        let namesReferent = try reader.readUInt32()
        var results: [SMBResolvedSIDName?] = []
        if namesReferent != 0 {
            let count = Int(try reader.readUInt32())
            guard count == Int(translatedEntries) else {
                throw SMBCodecError.invalidValue("translated name count mismatch")
            }
            var entries: [(use: UInt16, header: (length: UInt16, maximumLength: UInt16, referent: UInt32), domainIndex: Int32)] = []
            for _ in 0..<count {
                let use = try reader.readUInt16()
                _ = try reader.readUInt16() // NDR struct padding: RPC_UNICODE_STRING aligns to 4
                let header = try reader.readRPCUnicodeStringHeader()
                let domainIndex = Int32(bitPattern: try reader.readUInt32())
                entries.append((use, header, domainIndex))
            }
            for entry in entries {
                let name = entry.header.referent == 0 ? "" : try reader.readRPCUnicodeStringBuffer(lengthInBytes: entry.header.length)
                // SID_NAME_USE 8 = SidTypeUnknown; empty names mean unmapped.
                if name.isEmpty || entry.use == 8 {
                    results.append(nil)
                } else {
                    let domain: String?
                    if entry.domainIndex >= 0 && Int(entry.domainIndex) < domains.count {
                        domain = domains[Int(entry.domainIndex)]
                    } else {
                        domain = nil
                    }
                    results.append(SMBResolvedSIDName(use: entry.use, domain: domain, name: name))
                }
            }
        }
        _ = try reader.readUInt32() // MappedCount
        let status = try reader.readUInt32()
        guard status == 0 || status == statusSomeNotMapped || status == statusNoneMapped else {
            throw SMBErrorMapper.map(status: status, operation: "LsarLookupSids")
        }
        return results
    }

    static func encodeCloseRequest(handle: [UInt8]) throws -> [UInt8] {
        guard handle.count == 20 else { throw SMBCodecError.invalidValue("LSA policy handle must be 20 bytes") }
        return handle
    }

    private static func readUInt32LE(_ bytes: [UInt8], at offset: Int) -> UInt32 {
        UInt32(bytes[offset])
            | (UInt32(bytes[offset + 1]) << 8)
            | (UInt32(bytes[offset + 2]) << 16)
            | (UInt32(bytes[offset + 3]) << 24)
    }
}
