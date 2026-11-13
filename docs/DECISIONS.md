# Deliberate non-goals

Decisions that look like unfinished work but are not. Each entry records what
was considered, why it was rejected, and what would have to change before it is
worth revisiting. Read this before "fixing" one of them.

## The uniffi and Node binding crates stay single-file

`bindings/luciola-uniffi/src/lib.rs` and `bindings/luciola-node/src/lib.rs` are
large (roughly 1.7k and 1.4k lines) and were repeatedly proposed for splitting
into modules.

**Not done, deliberately.** Nearly every item in those files carries a
`#[uniffi::export]` or `#[napi]` attribute; moving an item to another module
changes nothing a consumer can observe, but it does re-order macro expansion and
has already produced confusing "duplicate export" and missing-scaffolding
failures in this repository's history. The files are navigated by symbol search,
not by scrolling. Revisit only if compile time or merge conflicts become a
measured cost — not for aesthetics.

## `@luciola/core` is not published on npm

`bindings/luciola-node` is built from source by consumers, and
`package.json` still carries the same version as the Rust workspace.

**Not done, deliberately.** The Node surface is hand-written N-API code with no
prebuilt binaries for Windows/Linux, so an npm package would ship a loader that
fails on most machines. The version is bumped anyway so that a future publish
would be consistent rather than a surprise.

## `missing_docs` is not denied in `luciola-node`

Every Rust-facing crate denies `missing_docs`. The Node crate documents all of
its hand-written items but cannot deny the lint.

**Not done, deliberately.** `#[napi]` on a class generates wrapper functions
whose spans carry the attribute; those generated items are undocumented and
cannot be annotated, so a crate-level deny fails on macro output rather than on
our code. The lint is enforced everywhere it can be.

## File transfer requires a pinned peer; there is no TOFU path

`luciola-cli transfer send|recv` refuses to run without `--pin-peer` /
`--accept-pin`.

**Not done, deliberately.** Trust-on-first-use would make the first transfer the
one an attacker can intercept, and a file transfer is exactly the operation
where that matters. Pairing (QR / `luciola://pair`) is the supported way to
learn a key; the transfer command then requires the key it learned.

## A dead direct path fails the stream; it does not silently fall back

`wan::adaptive` migrates a progressive connection from the relay to a punched
UDP path. If that path stops acknowledging, the driver ends the stream instead
of switching back to the relay.

**Not done, deliberately.** The peer stopped reading the relay at the moment it
accepted the migration (that is what the barrier guarantees), so "falling back"
would write into a channel nobody drains and report success while the file is
truncated. Failing loudly is the only honest option; a reconnect starts a new
exchange and can pick a route from scratch.

## Checkpoints are written in batches, after the data fsync

`luciola-transfer` persists its chunk bitmap roughly 64 times per transfer, and
never before `sync_data` of the bytes it describes.

**Not done, deliberately.** The alternatives are both wrong: a bitmap write per
chunk is O(n²) I/O on a large file, and a bitmap written before the fsync can
record chunks that a power loss erases — a resume would then skip them and leave
a hole no checksum covers. Batching costs at most a re-send of the last
interval after a crash, which the protocol already supports.

## `--adb-device` is set up on the sending side only

The sender runs `adb forward tcp:P tcp:P` (host:P → device:P) and removes it on
exit. The receiving side runs nothing.

**Not done, deliberately.** `adb reverse` on the receiver would bind the very
port the receiver listens on inside the device and fight it for the socket. The
forward already delivers to that port. A unit test cannot cover this (it needs a
real device); the fallback is that a failed `adb forward` is now fatal, so a
same-machine run cannot masquerade as a USB transfer.

## Post-migration EOF travels over UDP and is retransmitted like data

A progressive connection that migrated to the direct path ends its half-close
with a `KIND_CLOSE` datagram inside the ARQ (`sent_udp`), not a relay frame.

**Done this way, deliberately.** After the migration barrier both sides have
stopped writing the relay, so a relay EOF can never arrive; the only honest EOF
source is the direct path. The marker is tracked in `sent_udp` so the existing
retransmit/backoff machinery keeps it alive against datagram loss, and the
receiver answers it with a cumulative ACK and flips `peer_eof` — which is what
lets the driver's termination condition (`outbound_done && peer_eof`) ever be
met. A receiver that vanished instead of closing is still bounded by the
retransmit-rounds cap, matching `udp::drive`'s semantics.

## Relay-quota admission waits for the routing decision, not a deadline

`admit` judges a large transfer on the channel it will actually use: it waits
until the channel tracker flips to direct **or** the migration gate (raised the
moment hole punching resolves, success or failure) releases the wait.

**Done this way, deliberately.** Judging on the transient relay hop rejects a
file that is about to travel free; judging on a fixed 1.5 s window rejects a
hard-NAT punch that takes three seconds and wins. The gate converts "wait a
while and hope" into "wait exactly until the answer is known", so a
relay-bound connection is still refused promptly (the guard in
`discover_and_punch` raises the flag on every return path) while a slow
success is admitted on its merits. The remaining timeout is a safety net only.

## The client adopts the Worker's epoch instead of widening the window

`connect_wan` re-derives its rendezvous room at the epoch the Worker reports in
the `x-luciola-epoch` handshake header, and redials once, when the caller left
`WanConfig::epoch` at `0`.

**Done this way, deliberately.** The room id is HKDF-derived from the PSK, the
two public keys *and* the epoch, so two peers on opposite sides of a 10-minute
boundary are not merely in the same room at different times — they are in
completely different rooms, and no amount of retrying inside one room can fix
that. Three alternatives were considered and rejected:

* *Widen the accepted window to ±1 epoch.* The Worker already admits `epoch ± 1`
  for signature validation, but admission does not help: each client still
  derives its room from its own epoch, so the two peers are routed to different
  Durable Objects. Widening changes nothing.
* *Drop the epoch from the room id.* This makes the room constant for the life
  of a pairing, which removes the 10-minute rotation the design relies on to
  bound how long a captured room id stays useful, and it removes the replay
  window the Worker enforces.
* *Client-side retry across two epochs.* Correct but doubles every connection's
  traffic and still needs the two peers to pick the same one of the two windows.

Aligning on the server's epoch keeps the rotation, keeps the replay window, and
costs one extra handshake only in the rare case where the clocks disagree. The
header is public metadata — the request URL already carries the client's own
epoch — and carries no key material.

Realignment is skipped when the caller pinned `WanConfig::epoch`, and when the
supplied room does not match what the local epoch would derive (a hand-written
room). In both cases the caller owns the boundary decision, and silently moving
them would send the connection to a room the peer is not listening in.
