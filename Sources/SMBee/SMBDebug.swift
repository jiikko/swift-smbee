import Foundation

enum SMBDebug {
    static func hex(_ bytes: [UInt8]) -> String {
        bytes.map { String(format: "%02x", $0) }.joined()
    }

    static func hexPrefix(_ bytes: [UInt8], count: Int) -> String {
        hex(Array(bytes.prefix(count)))
    }
}
