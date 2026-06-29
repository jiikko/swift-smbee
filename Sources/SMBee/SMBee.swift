import Foundation

/// SMBee 🐝 — a pure-Swift SMB2/3 client.
///
/// SMB protocol / framing / NTLMv2 flow / SMB3 crypto framing は本ライブラリで
/// 自作し、AES-GCM / HMAC / SHA の計算は swift-crypto に委ねる (issue 359)。
/// MVP の対象サーバは macOS の SMB サーバ (SMBX)、dialect は SMB 3.1.1。
public enum SMBee {
    /// ライブラリのバージョン (暫定)。
    public static let version = "0.0.1"
}
