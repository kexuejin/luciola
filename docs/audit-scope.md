# Audit scope — WAN traversal and the rendezvous Worker

What an external reviewer should read, in what order, and which invariants the
code claims to hold. Written so an auditor can start without a conversation.

Status: **not yet audited.** `SECURITY.md` and `CHANGELOG.md` list the WAN path
as "additional custom, unaudited code"; this document is the package that
changes that, and it is not evidence that a review happened. A **staging**
Worker was deployed and exercised on 2026-11-13; production has not been
deployed. Deployment is not review, and it is not a real-NAT field test.

## Out of scope

- The `SecureStream` handshake, cipher suites, pinning defaults and frame-size
  limit. These are unchanged by the WAN work and were reviewed before it.
- LAN discovery (`engine`, `registry`) and the tunnel/forward code.
- `luciola-ip`, `luciola-net` interface enumeration.
- Anything under `examples/` — demo apps, not shipped code.

## In scope, in reading order

| # | Path | What to review |
| :-- | :-- | :-- |
| 1 | `crates/luciola/src/pairing.rs` | HKDF room derivation (`derive_rendezvous_room_id`, `_flexible`); the fail-closed empty-room path when no PSK is supplied |
| 2 | `crates/luciola/src/wan/signaling.rs` | `auth_payload` / `auth_url`, `signaling_key`, `seal` / `open` (AES-256-GCM, AAD, sequence), relay chunking, `x-luciola-epoch` parsing, custom-stream WebSocket upgrade |
| 3 | `crates/luciola/src/wan/proxy.rs` | proxy URL parsing, env / `NO_PROXY` / loopback resolution, HTTP CONNECT framing and bounded response handling, Basic credential hygiene |
| 4 | `crates/luciola/src/wan/mod.rs` | `connect_wan` orchestration: policy gate, epoch realignment, `RouteDecision` agreement, which route is *claimed* |
| 5 | `crates/luciola/src/wan/udp.rs` | packet codec, `punch`, `drive` (ARQ driver), `start_stream` |
| 6 | `crates/luciola/src/wan/arq.rs` | `AimdWindow`, RTO backoff, duplicate-ACK handling, `sent_udp` tracking |
| 7 | `crates/luciola/src/wan/adaptive.rs` | progressive start, migration barrier (`migrate_propose` / `migrate_ack`), post-migration `KIND_CLOSE`, `RelayPacer` |
| 8 | `crates/luciola/src/wan/bridge.rs` | `StreamBridge`, flow credit, half-close semantics |
| 9 | `crates/luciola/src/stun.rs` | RFC 5389 parsing (length/padding), RFC 5780 `probe_nat_behavior`, the `Unknown` classification rule |
| 10 | `crates/luciola/src/traversal.rs` | one-socket candidate gathering, `peer_udp_targets`, srflx port preservation |
| 11 | `crates/luciola-transfer` | `TransferMeta`, `LUCMETA1` framing, CRC-32 + SHA-256, chunk bitmap persistence order |
| 12 | `deploy/cloudflare-signaling/src/auth.js` | `validateParams` (shapes, epoch window), `verifyEd25519`, join/message budgets, `currentEpoch` |
| 13 | `deploy/cloudflare-signaling/src/index.js` | Worker fetch, `RendezvousRoom` Durable Object: nonce replay store, 2-peer cap, pre-join buffer, `/health`, `101` epoch header |

## Invariants the code claims

Each of these is asserted by a test; the test is named so a reviewer can check
the claim rather than take it on faith.

1. **No AES-GCM nonce reuse.** The counter is strictly increasing, so the
   transport underneath must deliver an ordered byte stream.
   `wan::udp` puts an ARQ under it for exactly this reason. See
   `wan::udp::tests::secure_channel_runs_over_udp_byte_stream`,
   `wan::udp::tests::arq_recovers_loss_and_reorder`.
2. **Frames are bound to their context.** AAD covers room, epoch, sequence and
   frame kind, so a frame cannot be replayed into another room or relabelled.
   `wan::signaling::tests::frames_are_authenticated_replay_resistant_and_aad_bound`.
3. **No room without a PSK.** A missing PSK yields an empty room id rather than
   an all-zero HKDF key. `pairing::tests` + `wan::signaling` validation.
4. **Deny by default.** `RelayConfig::default()` has `allow_relay` and
   `allow_wan_signaling` both `false`; `connect_wan` refuses before any network
   activity. `wan::tests::default_config_is_denied_before_any_network_activity`.
5. **Pinned peer, not TOFU.** The candidate frame's public key must equal the
   pinned peer, and the secure handshake pins it again.
6. **Migration cannot interleave bytes.** Both peers stop writing the relay at
   the same barrier point; post-migration EOF is a `KIND_CLOSE` datagram inside
   the ARQ.
   `wan::adaptive::tests::migration_closes_the_relay_before_proposing`,
   `wan::adaptive::tests::migrated_driver_terminates_after_close`.
7. **A route is only claimed if it was established.** A failed race reports
   `NoRoute`, never a relay that was not up.
8. **Epoch realignment cannot widen authentication.** The Worker still rejects a
   signature more than one window from its own clock; realignment only changes
   which room the client joins, and is skipped when the caller pinned the epoch.
   `wan::tests::epoch_realignment_lands_both_peers_in_the_server_room`,
   `wan::tests::a_pinned_epoch_is_not_realigned`.
9. **Checkpoints never describe unwritten bytes.** The bitmap is written only
   after `sync_data` of the bytes it covers, in batches.
10. **Congestion control is bounded.** `AimdWindow` caps in-flight bytes; the
    bridge flow credit is the enforcement point. No unbounded queue.
11. **The Worker sees no plaintext.** It reads only
    `{"v":1,"t":…,"s":…,"ct":…}`; candidate addresses, route decisions and relay
    bytes are sealed end to end.
12. **Bounded abuse surface.** Nonce replay store per room, 20 joins/min,
    256 messages/s, 2-peer cap, 32 KiB frame cap, 35-minute room TTL.
13. **A CONNECT proxy cannot decrypt or forge signalling.** The client opens
    its own TLS with the Worker's hostname as SNI after CONNECT; the proxy sees
    only the hostname/timing. The CONNECT header read is bounded to 8 KiB and
    never consumes bytes past the `\r\n\r\n` terminator, so tunnelled TLS/WS
    bytes cannot be swallowed or injected.
    `wan::signaling::tests::connect_tunnels_through_an_http_connect_proxy`,
    `wan::signaling::tests::connect_reports_a_rejected_connect_tunnel`.

## Questions worth answering explicitly

Internal code-level answers below were verified and locked with regression tests on 2026-11-24; an external auditor should still verify each claim independently.

- **Does the ARQ's retransmission ever re-seal the same plaintext under a new counter, and is that safe?**
  - *Internal finding*: No. `SecureStream` seals frames above `StreamBridge`, before bytes enter `wan::udp` or `wan::adaptive`. Both ARQ drivers store already-sealed wire datagrams in `sent` / `sent_udp` and re-send those exact bytes without touching the AEAD counter. Locked by `wan::udp::tests::arq_retransmit_resends_exact_wire_bytes_without_resealing`.
- **Can a malicious peer force unbounded memory through the pre-join buffer, the bitmap, `recv_ooo`, or the AIMD window?**
  - *Internal finding*: Pre-join buffer is capped at `PENDING_MAX = 32` × `MAX_MESSAGE_BYTES = 32 KiB` (1 MiB); AIMD is capped at `MAX_UNACKED_BYTES = 256 KiB`. Two gaps were found and fixed: (1) `recv_ooo` in `wan::udp` and `wan::adaptive` is now capped by `MAX_OOO_PACKETS = 512` (`wan::udp::tests::arq_recv_ooo_drops_far_future_seq_to_bound_memory`); (2) `TransferMeta::decode` now enforces `MAX_BITMAP_BYTES = 1 MiB` and `chunk_count` consistency (`checkpoint::tests::decode_rejects_oversized_or_mismatched_bitmap_header`), and `FileReceiver::create` enforces `ReceiverConfig::max_file_size` (default 16 GiB) before disk/bitmap allocation (`receiver::tests::create_rejects_file_size_exceeding_receiver_limit`).
- **Does the migration barrier hold if one side dies between propose and ack?**
  - *Internal finding*: A real bug was found in `wan::adaptive::drive_progressive`: the `udp_tick` select arm was guarded by `if direct_write`, which is always `false` while `awaiting_ack.is_some()`, so `MIGRATION_ACK_TIMEOUT` could never fire. Fixed to `if direct_write || awaiting_ack.is_some()` and locked by `wan::adaptive::tests::migration_ack_timeout_resumes_relay_when_responder_silent`.
- **Is `derive_rendezvous_room_id_flexible`'s SHA-256 normalisation of non-32-byte keys safe, or does it open a collision path between a 32-byte PSK and its hash?**
  - *Internal finding*: Room IDs alone can collide if one peer passes non-32-byte `P` and another passes `SHA256(P)`, kept as-is to preserve v0.11 wire compatibility for string PSKs. However, `signaling_key` feeds the raw `psk` directly into HKDF without SHA-256 normalization (`wan::signaling::tests::signaling_key_separates_raw_psk_from_its_sha256_digest`), so `SHA256(P)` cannot derive the AEAD key or decrypt/forge frames.
- **Can the `x-luciola-epoch` header be spoofed by a MITM to move a client into a room an attacker can observe?**
  - *Internal finding*: `connect_wan` realigns at most once (non-looping), only when the caller left `epoch == 0` and used a derived room, and re-derives the new room from the PSK — an attacker without the PSK cannot compute or join the target room.
- **Does the Durable Object's hibernation path preserve the replay store and the peer cap across eviction?**
  - *Internal finding*: `nonce:*` replay keys, `joinRate`, and `pend:*` live in Durable Storage (`ctx.storage`) and sockets use the Hibernatable WebSocket API (`acceptWebSocket` / `getWebSockets` / `serializeAttachment`), so hibernation preserves both. A TTL gap was found and fixed: `ROOM_TTL_MS` was 15 min while `epoch ± 1` admits signed URLs for up to 30 min (`3 * EPOCH_SECONDS`); raised `ROOM_TTL_MS` to 35 min and locked in `deploy/cloudflare-signaling/test/auth.test.js`.
- **Can a hostile `HTTPS_PROXY` value (or a proxy that answers CONNECT with a truncated/oversized header block) do more than delay the connection?**
  - *Internal finding*: `proxy::open_socket` caps CONNECT headers at `MAX_CONNECT_HEADERS = 8 KiB` and reads byte-by-byte until `\r\n\r\n`; TLS is established afterwards by `client_async_tls_with_config(request, socket, ...)` against the Worker's original hostname/SNI; credentials live in `Zeroizing<String>` and are never logged or forwarded to the Worker.

## Evidence available

- `cargo test --all-targets --all-features` — 26 binaries, including loopback
  relay, UDP ARQ loss/reorder, migration, epoch realignment.
- `crates/luciola/tests/wan_local_worker.rs` — the real Worker and Durable
  Object under `wrangler dev` (signed upgrade, edge verification, pre-join
  buffer, 96 KiB relay transfer), and on 2026-11-13 against the **deployed
  staging** Cloudflare runtime. Two runs: first through
  `scripts/wan-proxy-tunnel.py` (TLS terminated in the bridge), then — after
  native CONNECT proxy support — **directly** against the `wss://` endpoint
  with `HTTPS_PROXY`, with the Rust client doing its own TLS (2/2 green). A
  `NO_PROXY=<worker-host>` control on the same host still timed out, confirming
  the proxy path was load-bearing.
- `scripts/probe-signaling.py` — a signed `101` upgrade on the deployed
  runtime carrying `x-luciola-epoch` matching `/health`
  (`0.11.0-local.1-staging`). The bridge logged ~198 KiB to and ~199 KiB from
  the Worker during the first two-peer relay run.
- `wan::proxy` / `wan::signaling` unit tests — proxy URL and `NO_PROXY`
  parsing as pure functions, and a fully in-process fake CONNECT proxy that
  checks the request target, Basic auth and that the `x-luciola-epoch` header
  survives the tunnel; a 407 response is asserted to fail the handshake.
- `deploy/cloudflare-signaling` — `node --test` for the pure auth helpers.
- **Operator CLI path against deployed staging** (2026-11-13): the commands in
  `docs/field-test-record.md`, i.e. `luciola-cli transfer recv/send` plus
  `scripts/field-nat-matrix.sh`, run over `HTTPS_PROXY` against the deployed
  `wss://` Worker. Three 1 MiB runs with both peers on one host: direct
  (`hole_punched_direct`, 5 s), progressive (`relay_forwarded` →
  `hole_punched_direct`, 6 s), and one harness row recording
  `channel=relay_forwarded, upgraded_to=hole_punched_direct`. Received files
  matched the sender's sha256. The winning candidate was a LAN address, so this
  exercises the signalling plane and the CLI, **not** NAT traversal.

## Evidence that does **not** exist

- No real NAT / CGNAT field run. See `docs/field-test-record.md` — the harness
  has one `local-smoke` record from the dev host and no paired two-network
  rows. That document now carries an operator runbook and the harness has an
  offline `--self-test`, but neither is a run. The deployed staging run is
  relay-only on one host and says nothing about hole punching.
- No production deployment or test. Staging is deployed and verified; the
  `101` epoch header has been exercised against the Cloudflare runtime there,
  but never under production configuration or traffic. The Worker README now
  carries a production deployment plan and the deploy script has offline
  `--self-test` / `--dry-run`, but neither deploys anything.
- No real-device background run on either mobile platform.
- No fuzzing of the STUN parser or the ARQ codec.
- No external review of the paths in the table above.

## How to report findings

Severity, the invariant number above that it violates, a minimal reproduction,
and whether it is reachable without a paired peer. Findings against an invariant
that the code documents as a deliberate trade-off (`docs/DECISIONS.md`) should
say so, since that file records what was rejected and why.
