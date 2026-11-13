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
| 2 | `crates/luciola/src/wan/signaling.rs` | `auth_payload` / `auth_url`, `signaling_key`, `seal` / `open` (AES-256-GCM, AAD, sequence), relay chunking, `x-luciola-epoch` parsing |
| 3 | `crates/luciola/src/wan/mod.rs` | `connect_wan` orchestration: policy gate, epoch realignment, `RouteDecision` agreement, which route is *claimed* |
| 4 | `crates/luciola/src/wan/udp.rs` | packet codec, `punch`, `drive` (ARQ driver), `start_stream` |
| 5 | `crates/luciola/src/wan/arq.rs` | `AimdWindow`, RTO backoff, duplicate-ACK handling, `sent_udp` tracking |
| 6 | `crates/luciola/src/wan/adaptive.rs` | progressive start, migration barrier (`migrate_propose` / `migrate_ack`), post-migration `KIND_CLOSE`, `RelayPacer` |
| 7 | `crates/luciola/src/wan/bridge.rs` | `StreamBridge`, flow credit, half-close semantics |
| 8 | `crates/luciola/src/stun.rs` | RFC 5389 parsing (length/padding), RFC 5780 `probe_nat_behavior`, the `Unknown` classification rule |
| 9 | `crates/luciola/src/traversal.rs` | one-socket candidate gathering, `peer_udp_targets`, srflx port preservation |
| 10 | `crates/luciola-transfer` | `TransferMeta`, `LUCMETA1` framing, CRC-32 + SHA-256, chunk bitmap persistence order |
| 11 | `deploy/cloudflare-signaling/src/auth.js` | `validateParams` (shapes, epoch window), `verifyEd25519`, join/message budgets, `currentEpoch` |
| 12 | `deploy/cloudflare-signaling/src/index.js` | Worker fetch, `RendezvousRoom` Durable Object: nonce replay store, 2-peer cap, pre-join buffer, `/health`, `101` epoch header |

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
    256 messages/s, 2-peer cap, 32 KiB frame cap, 15-minute room TTL.

## Questions worth answering explicitly

- Does the ARQ's retransmission ever re-seal the same plaintext under a new
  counter, and is that safe? (It should re-send the same sealed frame, not
  re-seal.)
- Can a malicious peer force unbounded memory through the pre-join buffer, the
  bitmap, or the AIMD window?
- Does the migration barrier hold if one side dies between propose and ack?
- Is `derive_rendezvous_room_id_flexible`'s SHA-256 normalisation of non-32-byte
  keys safe, or does it open a collision path between a 32-byte PSK and its
  hash?
- Can the `x-luciola-epoch` header be spoofed by a MITM to move a client into a
  room an attacker can observe? (The room id is still PSK-derived, so the
  attacker learns nothing; confirm that reasoning.)
- Does the Durable Object's hibernation path preserve the replay store and the
  peer cap across eviction?

## Evidence available

- `cargo test --all-targets --all-features` — 26 binaries, including loopback
  relay, UDP ARQ loss/reorder, migration, epoch realignment.
- `crates/luciola/tests/wan_local_worker.rs` — the real Worker and Durable
  Object under `wrangler dev` (signed upgrade, edge verification, pre-join
  buffer, 96 KiB relay transfer), and on 2026-11-13 against the **deployed
  staging** Cloudflare runtime through `scripts/wan-proxy-tunnel.py`.
- `scripts/probe-signaling.py` — a signed `101` upgrade on the deployed
  runtime carrying `x-luciola-epoch` matching `/health`
  (`0.11.0-local.1-staging`). The bridge logged ~198 KiB to and ~199 KiB from
  the Worker during the two-peer relay run.
- `deploy/cloudflare-signaling` — `node --test` for the pure auth helpers.

## Evidence that does **not** exist

- No real NAT / CGNAT field run. See `docs/field-test-record.md` — the harness
  has one `local-smoke` record from the dev host and no paired two-network
  rows. The deployed staging run is relay-only on one host and says nothing
  about hole punching.
- No production deployment or test. Staging is deployed and verified; the
  `101` epoch header has been exercised against the Cloudflare runtime there,
  but never under production configuration or traffic.
- No real-device background run on either mobile platform.
- No fuzzing of the STUN parser or the ARQ codec.
- No external review of the paths in the table above.

## How to report findings

Severity, the invariant number above that it violates, a minimal reproduction,
and whether it is reachable without a paired peer. Findings against an invariant
that the code documents as a deliberate trade-off (`docs/DECISIONS.md`) should
say so, since that file records what was rejected and why.
