# Sessions and Trees

Reuse authentication while keeping each share scoped and independently closed.

An ``SMBClientSession`` owns the authenticated SMB session and its primary tree.
Its ``SMBClientSession/withTree(share:operation:)`` method temporarily connects
another share on the same authentication session. The child tree is disconnected
when the closure returns or throws, and closing the parent disconnects any tracked
child trees before logging off.

```swift
let session = try await SMBee.connect(
    host: "files.example.com",
    credential: credential,
    share: "public"
)

let publicEntries = try await session.list()
let privateEntries = try await session.withTree(share: "private") { tree in
    try await tree.list(path: "incoming")
}
let shares = try await session.listShares() // Uses a scoped IPC$ tree.

await session.close()
```

Actors serialize session and tree state. Closures and progress callbacks are
`@Sendable`; do not assume they run on the caller's executor.
