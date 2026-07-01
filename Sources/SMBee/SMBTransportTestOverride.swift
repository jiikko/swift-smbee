@usableFromInline
enum SMBTransportTestOverride {
    @usableFromInline
    nonisolated(unsafe) static var factory: (@Sendable () -> SMBTransport)?
}
