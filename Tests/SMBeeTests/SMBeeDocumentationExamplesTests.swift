import XCTest
import SMBee

final class SMBeeDocumentationExamplesTests: XCTestCase {
    func testDocumentedExamplesCompileAgainstPublicAPI() {
        _ = documentedSessionExample
        _ = documentedDeadlineExample
    }
}

private func documentedSessionExample(
    host: String,
    credential: SMBCredential
) async throws -> ([SMBDirectoryEntry], [SMBDirectoryEntry], [SMBShareInfo]) {
    let session = try await SMBee.connect(host: host, credential: credential, share: "public")
    do {
        let publicEntries = try await session.list()
        let privateEntries = try await session.withTree(share: "private") { tree in
            try await tree.list(path: "incoming")
        }
        let shares = try await session.listShares()
        await session.close()
        return (publicEntries, privateEntries, shares)
    } catch {
        await session.close()
        throw error
    }
}

private func documentedDeadlineExample(
    host: String,
    credential: SMBCredential,
    bytes: [UInt8]
) async throws {
    do {
        try await SMBee.upload(
            host: host,
            credential: credential,
            share: "public",
            path: "incoming/report.txt",
            data: bytes,
            operationTimeout: .seconds(30)
        )
    } catch SMBTransportError.timedOut {
        // Inspect remote state before retrying.
    } catch is CancellationError {
        throw CancellationError()
    } catch let error as SMBError {
        throw error
    } catch let error as SMBCodecError {
        throw error
    }
}
