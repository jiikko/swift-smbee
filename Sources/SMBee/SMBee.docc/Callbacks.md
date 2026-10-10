# Callback execution

SMBee invokes transfer and event callbacks on the session's serial executor (S). This
includes READ `onChunk`, WRITE `nextChunk` suppliers, directory `onEntry`, change
notification and watch `onChange`, recursive `onAction`, and direct per-chunk progress
callbacks. Each operation awaits its callback before advancing, so callback order and
existing error and cancellation propagation are preserved.

Keep these callbacks short. Move CPU-heavy work, blocking I/O, and long waits to a Task or
actor that your application owns. A synchronous callback occupies S until it returns; the
same session's cancellation, close, and deadline jobs wait behind it. An async callback
that suspends releases S, allowing those session jobs to proceed, but the transfer operation
still awaits the callback's return. Work performed before the first suspension has the same
blocking effect as synchronous work.

SMBee does not promise a particular thread. Callback code can hop to an actor required by
its own isolation. For one-shot recursive directory helpers, action callbacks are serialized
on the serial executor owned by that recursive operation because those helpers use short-lived
wire sessions for individual files.

`SMBTransferProgressEmitter` callbacks remain on their dedicated coalescing queue. They are
delivered independently from S, and transfer completion continues to await the final progress
delivery. SMBee also keeps local file reads and writes on independent I/O queues.
