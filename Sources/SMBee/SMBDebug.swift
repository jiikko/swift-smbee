import Foundation

enum SMBDebug {
    private static let defaultDumpPrefixByteCount = 64

    static func hex(_ bytes: [UInt8]) -> String {
        bytes.map { String(format: "%02x", $0) }.joined()
    }

    static func hexPrefix(_ bytes: [UInt8], count: Int) -> String {
        hex(Array(bytes.prefix(count)))
    }

    static func hexSummary(_ bytes: [UInt8], prefixByteCount: Int = defaultDumpPrefixByteCount) -> String {
        let prefixCount = max(0, min(prefixByteCount, bytes.count))
        let prefix = hexPrefix(bytes, count: prefixCount)
        if prefixCount == bytes.count {
            return prefix
        }
        return "\(prefix)... totalBytes=\(bytes.count)"
    }
}
