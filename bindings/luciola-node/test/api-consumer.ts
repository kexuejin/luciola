// Type-level contract for index.d.ts, compiled by `npm run typecheck`
// (tsc --noEmit --strict --skipLibCheck). No @types/node is installed, so
// Buffer-typed declarations resolve to any under skipLibCheck — the point
// is the call shapes, not the node typings. Any future drift between the
// .d.ts and the documented call shapes fails here before it reaches
// integrators.
import {
  buildPairingUri,
  generateDeviceIdentity,
  parsePairingUri,
  DiscoverySession,
  SecureChannel,
} from '../index';

// DiscoverySession: the nine documented constructor slots, including the
// four that used to be undocumented (extra, nodeId, tcpPort, publicKey).
const session = new DiscoverySession(
  'demo',
  0,
  null,
  'demo-product',
  'device-1',
  'extra-payload',
  'node-1',
  5000,
  undefined,
);
session.setProductFilter(['demo-product']);
session.start((event) => {
  if (event.peer) {
    const extra: string | undefined = event.peer.extra;
    const tcpPort: number | undefined = event.peer.tcpPort;
    console.log(extra, tcpPort);
  }
});
session.stop();
const nodeId: string | null = session.nodeId();
console.log(nodeId);

// Pairing: seven slots with publicKey between fingerprint and pin.
const identity = generateDeviceIdentity();
const uri: string = buildPairingUri(
  'demo',
  'demo-product',
  3000,
  ['192.168.1.2'],
  identity.fingerprint,
  identity.publicKey.toString('base64'),
  '123456',
);
const info = parsePairingUri(uri);
if (info) {
  const publicKey: string | undefined = info.publicKey;
  const pin: string | undefined = info.pin;
  console.log(publicKey, pin);
}

// SecureChannel: stats() returns six numeric fields.
const channel = new SecureChannel(identity.seed);
const stats = channel.stats();
const enqueued: number = stats.framesEnqueued;
const dequeued: number = stats.framesDequeued;
console.log(enqueued, dequeued);
channel.close();
