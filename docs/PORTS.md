# Port plan for multi-product hosts

A luciola port is a **product-level global constant**, not a per-process value.
Discovery is one shared UDP mesh per port; the secure channel is a per-process
TCP listener. When two products pick the same number on one host they either
collide or — worse — used to collide *silently*: the loser fell back to an
ephemeral port while still announcing into the winner port, so both sides
joined one mesh and dialled each other channel ports. That is the
2026-11-02 two-product starvation this document exists to prevent.

The executable half of this document is the `luciola::ports` module plus:

    luciola-cli ports --registry docs/ports.json [--probe] [--json]

It validates the registry, optionally probes the ports on the current machine,
prints warnings for known legacy overlaps, and exits non-zero on a live
conflict (two products claiming the same protocol + number).

## Allocation rules

1. **One owner per (protocol, port).** Two products may reuse a number only
   across protocols (UDP discovery 17878 and TCP channel 17878), never within
   one protocol. Even then, prefer distinct numbers across products: a later
   TCP listener on a number another product uses for UDP looks free in a port
   scan and is easy to break.
2. **New products take one unallocated 16-port block** (`BLOCK_SIZE`). Use the
   block start for discovery UDP, +1 for the secure channel, +1 for the tunnel
   (`channel + 1`), +10 for a secondary data plane (screen). Keep the whole
   block for that product so `tunnel_port = channel + 1` and
   `screen_port = discovery + 10` can never land on someone else.
3. **Never fall back silently.** If the requested discovery port is taken, the
   engine fails with `CoreError::BindFailed` (uniffi: `bind_failed`,
   `isBound() == false`). A host that really must stay up without the
   well-known port opts into `DiscoveryConfig::allow_ephemeral_fallback`
   explicitly and surfaces `local_port()` (discovery is degraded).
4. **Well-known numbers are grandfathered.** They were chosen before this
   partition existed; the registry records them instead of renumbering live
   deployments. Renumbering is safe at the protocol level (profiles advertise
   `tcp_port` / `luciolaPort`, pairing QRs carry the port), but old peers cache
   the endpoint until the next profile update, so do it per product, not fleet
   wide in one release.
5. **A product with no inbound listener still registers its discovery UDP
   port** — that is where its mesh lives.

## Registry

`docs/ports.json` is the single source. Shape:

    {
      "version": 1,
      "block_size": 16,
      "products": [
        {
          "product": "example",
          "discovery_udp": 17900,
          "channel_tcp": 17901,
          "extra_tcp": [17910],
          "legacy_tcp": []
        }
      ]
    }

- `channel_tcp` is optional for dial-only helpers.
- `legacy_tcp` marks numbers still bound by older releases. An overlap with a
  legacy claim is a **warning** (it must be migrated); an overlap between two
  live claims is an **error** that fails the command.
- Port 0 means "system assigned" and is never a claim.

Run it in CI and at startup on a shared host. The probe result is informational:
IN USE usually means the owning process is already running, not that the plan is
wrong.

## Current fleet allocations

The authority is `docs/ports.json`. It names each registered product (the same
value that product advertises as `Profile.product`) together with its claims;
this document does not repeat the numbers, because two tables drift and the
validator reads the JSON.

Known legacy overlap recorded there today: **tcp/17879** — one product's secure
channel collides with another product's legacy plaintext file channel, which is
disabled in luciola mode. Once old releases are gone, empty the `legacy_tcp`
array and the warning disappears. A UDP discovery number and a TCP screen number
may coincide (different protocols, no collision); if either product later adds a
listener of the other protocol, the registry check catches it.

## Migration notes

- Drop legacy listeners first (they are the only live overlap today). The
  registry warning disappears when `legacy_tcp` is emptied.
- Renumbering one product: change the product constants, keep the registry in
  sync in the same change, and let the profile advertise the new port. Paired
  peers re-learn the endpoint from the next beacon; a stale endpoint produces a
  connection timeout, not a wrong-peer connection, because the secure channel
  pins the identity.
- Never work around a conflict by enabling ephemeral fallback in production: it
  puts the product back into the contaminating behaviour above.
