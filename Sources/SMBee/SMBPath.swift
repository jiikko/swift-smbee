import Foundation

public struct SMBShareName: Equatable, Sendable {
    public var rawValue: String

    public init(_ value: String) throws {
        guard !value.isEmpty else {
            throw SMBCodecError.invalidValue("SMB share name must not be empty")
        }
        guard value != ".", value != ".." else {
            throw SMBCodecError.invalidValue("SMB share name must not be . or ..")
        }
        guard !value.contains("/"), !value.contains("\\") else {
            throw SMBCodecError.invalidValue("SMB share name must not contain path separators")
        }
        rawValue = value
    }
}

public struct SMBPath: Equatable, Sendable {
    public var rawValue: String

    public init(_ value: String) throws {
        rawValue = try Self.normalize(value)
    }

    public static func normalize(_ value: String) throws -> String {
        let trimmed = value.trimmingCharacters(in: CharacterSet(charactersIn: "\\/"))
        guard !trimmed.isEmpty else { return "" }
        let parts = trimmed.split(omittingEmptySubsequences: false, whereSeparator: { $0 == "/" || $0 == "\\" })
        var normalized: [String] = []
        normalized.reserveCapacity(parts.count)
        for part in parts {
            let component = String(part)
            guard !component.isEmpty else {
                throw SMBCodecError.invalidValue("SMB path must not contain empty components")
            }
            guard component != ".", component != ".." else {
                throw SMBCodecError.invalidValue("SMB path must not contain . or .. components")
            }
            normalized.append(component)
        }
        return normalized.joined(separator: "\\")
    }

    public static func join(_ parent: String, _ child: String) throws -> String {
        let normalizedParent = try normalize(parent)
        let normalizedChild = try normalize(child)
        guard !normalizedChild.isEmpty else { return normalizedParent }
        if normalizedParent.isEmpty { return normalizedChild }
        return "\(normalizedParent)\\\(normalizedChild)"
    }
}
