# @luciola/core

Node.js bindings for **Luciola (萤火)** — lightweight, resilient LAN peer
discovery and authenticated encrypted channels.

This package is the N-API surface over the same Rust core that backs the KMP and
Swift bindings. Discovery is open (UDP broadcast/multicast); the data plane is
deny-by-default (Ed25519 identities + X25519/AES-256-GCM secure channel).

## Platform support

This build ships a native `luciola.node` for **macOS arm64 (Apple Silicon)**.
`os`/`cpu` in `package.json` make npm refuse other platforms with `EBADPLATFORM`
instead of installing a package that cannot load. On other platforms build from
source:

```bash
git clone https://github.com/kexuejin/luciola.git
cd luciola
cargo build --release -p luciola-node
cp "$(cargo metadata --format-version 1 --no-deps | sed -n 's/.*"target_directory":"\([^"]*\)".*/\1/p')/release/libluciola_node.dylib" \
   bindings/luciola-node/luciola.node
```

## Quick start

```js
const luciola = require('@luciola/core');

// Discovery on UDP 17878 (use a per-product port when another luciola app owns it).
const session = new luciola.DiscoverySession('My App', 17878, null, 'my-product');
session.setProductFilter(['my-product']); // ignore other products on the same mesh
session.start((event) => {
  if (event.type === 'found') console.log('peer', event.peer.name, event.peer.ip);
  if (event.type === 'lost') console.log('lost', event.nodeId);
  if (event.type === 'error') console.error(event.message);
});
```

Secure channel (pinned peer key):

```js
const me = luciola.generateDeviceIdentity();
const peer = luciola.generateDeviceIdentity();
const channel = new luciola.SecureChannel(me.seed);
channel.connect(['192.168.1.20'], 17879, peer.publicKey, true, (ev) => {
  if (ev.state === 'connected') channel.send(Buffer.from('hello'));
  if (ev.message) console.log(ev.message.toString());
});
```

## Notes

- **Port planning**: a luciola port is a product-level constant; when several
  apps share one machine, give each product its own block (see `docs/PORTS.md`
  in the repository) and set a `productFilter`. A port conflict is reported as
  `{type:'error'}` (`bind_failed`) rather than silently moving elsewhere.
- **Identity seeds** must be persisted by the host (Keychain/Keystore/restricted
  file); a lost seed is a lost identity.
- The secure channel is a custom composition of standard primitives and is
  **pre-audit**; see `SECURITY.md` before carrying secrets.

## License

MIT OR Apache-2.0
