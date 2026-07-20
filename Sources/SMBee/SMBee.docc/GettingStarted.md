# Getting Started

Connect to an SMB 3.x share and perform basic file operations.

## Connect once and reuse the session

Create credentials at the point of use. Avoid logging or retaining them after
the connection is established.

```swift
import SMBee

let credential = SMBCredential(
    username: "alice",
    password: secret,
    domain: "EXAMPLE"
)
let session = try await SMBee.connect(
    host: "files.example.com",
    credential: credential,
    share: "public"
)

do {
    let entries = try await session.list(path: "reports")
    let bytes = try await session.read(path: "reports/summary.txt")
    await session.close()
} catch {
    await session.close()
    throw error
}
```

For a secret manager or UI prompt, supply an ``SMBCredentialProvider`` instead
of retaining a credential in application state.

```swift
let session = try await SMBee.connect(
    host: "files.example.com",
    credentialProvider: {
        SMBCredential(username: "alice", password: try await loadSecret())
    },
    share: "public"
)
```

## Use a one-shot operation

The ``SMBee`` facade opens and closes a session around the operation.

```swift
let stat = try await SMBee.stat(
    host: "files.example.com",
    credential: credential,
    share: "public",
    path: "reports/summary.txt"
)
```
