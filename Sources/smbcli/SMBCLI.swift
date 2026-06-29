import ArgumentParser
import Foundation
import SMBee

@main
struct SMBCLI: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "smbcli",
        abstract: "🐝 SMBee command-line client",
        version: SMBee.version,
        subcommands: [Probe.self, List.self, Stat.self, Cat.self]
    )
}

/// `smbcli probe smb://host[:445]` — NEGOTIATE して交渉結果
/// (dialect / signing / encryption) を表示する。最初のマイルストーン。
struct Probe: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        abstract: "Negotiate with an SMB server and print the negotiated dialect/signing/encryption"
    )

    @Argument(help: "smb://host[:445]")
    var url: String

    func run() async throws {
        let endpoint = try SMBURLParser.parseProbeURL(url)
        let result = try await SMBProbe.probe(host: endpoint.host, port: endpoint.port)
        print("dialect: \(formatHex(result.dialect, width: 4))")
        print("signingRequired: \(result.signingRequired)")
        print("signing: \(formatOptionalHex(result.signingAlgorithm, width: 4))")
        print("cipher: \(formatOptionalHex(result.cipher, width: 4))")
        print("preauthHash: \(formatOptionalHex(result.preauthHashAlgorithm, width: 4))")
        print("serverGuid: \(result.serverGuid.uuidString)")
    }

    private func formatOptionalHex(_ value: UInt16?, width: Int) -> String {
        guard let value else { return "none" }
        return formatHex(value, width: width)
    }

    private func formatHex<T: FixedWidthInteger>(_ value: T, width: Int) -> String {
        "0x" + String(format: "%0\(width)x", Int(value))
    }
}

struct List: AsyncParsableCommand {
    static let configuration = CommandConfiguration(commandName: "ls", abstract: "List an SMB directory")

    @Argument(help: "smb://user@host[:445]/share/path")
    var url: String

    @Option(help: "NTLM domain/workgroup")
    var domain: String = ""

    func run() async throws {
        let endpoint = try SMBURLParser.parseReadURL(url)
        guard let username = endpoint.username, !username.isEmpty else {
            throw ValidationError("SMB URL must include a username")
        }
        guard let password = ProcessInfo.processInfo.environment["SMB_PASSWORD"] else {
            throw ValidationError("Set SMB_PASSWORD in the environment")
        }
        let credential = SMBCredential(username: username, password: password, domain: domain)
        let entries = try await SMBee.list(
            host: endpoint.host,
            port: endpoint.port,
            credential: credential,
            share: endpoint.share,
            path: endpoint.path
        )
        for entry in entries {
            let kind = entry.isDirectory ? "d" : "-"
            print("\(kind) \(entry.fileSize) \(entry.name)")
        }
    }
}

struct Stat: AsyncParsableCommand {
    static let configuration = CommandConfiguration(commandName: "stat", abstract: "Stat an SMB path")

    @Argument(help: "smb://user@host[:445]/share/path")
    var url: String

    func run() async throws {
        _ = url
        throw ValidationError("stat is not implemented yet")
    }
}

struct Cat: AsyncParsableCommand {
    static let configuration = CommandConfiguration(commandName: "cat", abstract: "Read an SMB file")

    @Argument(help: "smb://user@host[:445]/share/path")
    var url: String

    @Option(help: "Byte range a-b")
    var range: String?

    func run() async throws {
        _ = url
        _ = range
        throw ValidationError("cat is not implemented yet")
    }
}
