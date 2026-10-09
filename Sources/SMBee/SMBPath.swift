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
        guard !SMBPathSeparator.contains(value, kind: .smb) else {
            throw SMBCodecError.invalidValue("SMB share name must not contain path separators")
        }
        rawValue = value
    }
}

public struct SMBPath: Equatable, Sendable {
    static let maxRecursionDepth = 64

    public var rawValue: String

    package static func splitSMBPathComponents(_ value: String) -> [String] {
        SMBPathSeparator.split(value, kind: .smb)
    }

    package static func splitPOSIXPathComponents(_ value: String) -> [String] {
        SMBPathSeparator.split(value, kind: .slash)
    }

    package static func replacingSMBPathSeparators(_ value: String, with replacement: String) -> String {
        SMBPathSeparator.replacingSeparators(value, kind: .smb, with: replacement)
    }

    package static func replacingPOSIXPathSeparators(_ value: String, with replacement: String) -> String {
        SMBPathSeparator.replacingSeparators(value, kind: .slash, with: replacement)
    }

    package static func trimmingSMBPathSeparators(_ value: String) -> String {
        SMBPathSeparator.trimmingBoundarySeparators(value, kind: .smb)
    }

    public init(_ value: String) throws {
        rawValue = try Self.normalize(value)
    }

    public static func normalize(_ value: String) throws -> String {
        let trimmed = SMBPathSeparator.trimmingBoundarySeparators(value, kind: .smb)
        guard !trimmed.isEmpty else { return "" }
        let parts = SMBPathSeparator.split(trimmed, kind: .smb, omittingEmptySubsequences: false)
        var normalized: [String] = []
        normalized.reserveCapacity(parts.count)
        for component in parts {
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

    package static func validateDirectoryEntryName(_ name: String) throws {
        guard !name.isEmpty, name != ".", name != "..",
              !SMBPathSeparator.contains(name, kind: .smb),
              !name.unicodeScalars.contains(where: { $0.value == 0 }) else {
            throw SMBCodecError.invalidValue("invalid directory entry name")
        }
    }

    static func validateDirectoryCopyTarget(fromPath: String, toPath: String) throws {
        let source = try normalize(fromPath)
        let destination = try normalize(toPath)
        guard !source.isEmpty else {
            throw SMBError.invalidRecursion("destination is inside source directory")
        }
        let foldedSource = canonicalComparisonComponents(source)
        let foldedDestination = canonicalComparisonComponents(destination)
        guard foldedDestination != foldedSource,
              !foldedDestination.starts(with: foldedSource) else {
            throw SMBError.invalidRecursion("destination is inside source directory")
        }
    }

    private static func canonicalComparisonComponents(_ path: String) -> [String] {
        SMBPathSeparator.split(path, kind: .backslash).map {
            $0
                .precomposedStringWithCanonicalMapping
                .folding(options: [.caseInsensitive], locale: Locale(identifier: "en_US_POSIX"))
                .precomposedStringWithCanonicalMapping
        }
    }

    static func validateRecursionDepth(_ depth: Int) throws {
        guard depth <= maxRecursionDepth else {
            throw SMBError.invalidRecursion("recursion depth exceeded \(maxRecursionDepth)")
        }
    }
}
