// Type-level contract for index.d.ts, compiled by `npm run typecheck`
// (tsc --noEmit --strict --skipLibCheck). No @types/node is installed, so
// Buffer-typed declarations resolve to any under skipLibCheck — the point
// is the call shapes, not the node typings. Any future drift between the
// .d.ts and the documented call shapes fails here before it reaches
// integrators.
import {
  buildPairingUri,
  setLogSink,
  generateDeviceIdentity,
  parsePairingUri,
  getErrorCodes,
  classifyError,
  DiscoverySession,
  SecureChannel,
  SecureHub,
  TransferCancelHandle,
  WanChannel,
  WanTunnelSession,
  connectWithPolicy,
  transferRecvLan,
  transferSendLan,
  transferSendWan,
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
  if (event.type === 'error') {
    // Structured triple: branch on code, show message, decide with retryable.
    const code: string | undefined = event.code;
    const message: string | undefined = event.message;
    const retryable: boolean | undefined = event.retryable;
    console.log(code, message, retryable);
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

// Channel events: detail stays a string, error is the structured companion.
channel.connect(['127.0.0.1'], 1, identity.publicKey, false, (event) => {
  const state: string | undefined = event.state;
  const detail: string | undefined = event.detail;
  const code: string | undefined = event.error?.code;
  const retryable: boolean | undefined = event.error?.retryable;
  console.log(state, detail, code, retryable);
});
channel.close();

// Error taxonomy: the code list is a string array; classifyError returns the
// documented record shape.
const codes: string[] = getErrorCodes();
const classified = classifyError('forward_bind_failed: port in use');
const classifiedCode: string = classified.code;
const classifiedMessage: string = classified.message;
const classifiedRetryable: boolean = classified.retryable;
console.log(codes.length, classifiedCode, classifiedMessage, classifiedRetryable);

// Log sink: the documented call shape accepts a callback or null.
setLogSink(null);
setLogSink((event) => {
  const level: string = event.level;
  const message: string = event.message;
  console.log(level, message);
});

// WanTunnelSession & transferSendWan: async call shapes.
export async function checkWanTunnelTypes(ch: WanChannel): Promise<void> {
  const tunnel: WanTunnelSession = await WanTunnelSession.fromWanChannel(ch, true);
  const tcpPort: number = await tunnel.startLocalForward(0, '127.0.0.1', 8080);
  const udpPort: number = await tunnel.startUdpForward(0, '127.0.0.1', 5353);
  await tunnel.enableForwardEndpoint([
    { host: '127.0.0.1', portFrom: 8080, portTo: 8080, udp: false },
  ]);
  await tunnel.disableForwardEndpoint();
  await tunnel.stopLocalForward(tcpPort);
  await tunnel.stopUdpForward(udpPort);
  await tunnel.shutdown();

  const cancel = new TransferCancelHandle();
  const isCancelled: boolean = cancel.isCancelled();
  cancel.cancel();
  console.log(isCancelled);

  await transferSendWan(
    ch,
    '/tmp/file.bin',
    1024,
    (p) => {
      const done: number = p.bytesDone;
      const total: number = p.totalBytes;
      const resumed: boolean = p.resumed;
      console.log(done, total, resumed);
    },
    cancel,
  );
  await transferSendLan(identity.seed, ['127.0.0.1'], 9000, identity.publicKey, '/tmp/f.bin', null, cancel);
  await transferRecvLan(identity.seed, 0, identity.publicKey, '/tmp', undefined, cancel);

  const routed: WanChannel = await connectWithPolicy(
    'lan_then_wan',
    1500,
    {
      addresses: ['127.0.0.1'],
      port: 9000,
      identitySeed: identity.seed,
      peerPublicKey: identity.publicKey,
    },
    null,
  );
  await routed.shutdown();

  const hub: SecureHub = await SecureHub.start(0, identity.seed, [identity.publicKey], (ev) => {
    const kind: string = ev.type;
    const fp: string | undefined = ev.fingerprint;
    console.log(kind, fp);
  });
  const port: number = hub.localPort();
  const added: boolean = hub.addAllowedPeer(identity.publicKey);
  const removed: boolean = hub.removeAllowedPeer(identity.publicKey);
  const peers = hub.connectedPeers();
  const sent: boolean = hub.sendTo('sha256:00', identity.publicKey);
  const failed: string[] = hub.broadcast(identity.publicKey);
  const kicked: boolean = hub.kick('sha256:00');
  console.log(port, added, removed, peers.length, sent, failed.length, kicked);
  hub.stop();
}
