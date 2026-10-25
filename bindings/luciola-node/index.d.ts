/**
 * @luciola/core TypeScript definitions
 */

/**
 * Select the single best LAN IPv4 address for QR code generation / local direct connections.
 * Automatically handles physical NIC prioritization, virtual NIC filtering (Docker, Tailscale),
 * Windows ICS mobile hotspot exclusion, and WSL2 host physical passthrough.
 */
export function selectLanIp(): string | null;

/**
 * Retrieve all clean local candidate addresses (IPv4 & domestic broadband IPv6 GUA/ULA).
 */
export function localCandidateAddresses(): string[];

/**
 * Retrieve targeted subnet broadcast addresses (e.g. `192.168.2.255`) for each physical NIC.
 * These addresses bypass Clash / Sing-box TUN mode (0.0.0.0/1) interception.
 */
export function subnetBroadcastAddresses(): string[];

/**
 * Retrieve all local addresses including VPN/tunnels (for unicast overlay sync).
 */
export function advertisedAddresses(): string[];

/**
 * Check if a peer IP belongs to the same LAN (RFC private or domestic broadband /64 GUA matching).
 */
export function isLanPeer(peerAddress: string, localAddresses: string[]): boolean;

/**
 * Check if an IP address belongs to a proxy software TUN virtual network (198.18.0.0/15).
 */
export function isTunVirtualIp(address: string): boolean;

/**
 * Check if an interface name corresponds to a virtual adapter (utun, feth, tailscale, docker, etc.).
 */
export function isVirtualNic(name: string): boolean;

/**
 * Check if an interface name looks like a real physical network interface (Wi-Fi, Ethernet).
 */
export function isPhysicalNic(name: string): boolean;

/**
 * Render a standard vector SVG QR code string for HTML/Web/Mobile display.
 */
export function renderQrSvg(content: string): string | null;

/**
 * Render a UTF-8 compact terminal QR code with proper dark terminal optical contrast.
 */
export function renderQrAscii(content: string): string | null;

export interface JsDeviceMeta {
  deviceType: 'mobile' | 'tablet' | 'laptop' | 'desktop' | 'server' | 'wsl' | 'unknown';
  icon: string;
  os: string;
  arch: string;
  model?: string;
  hostname?: string;
  /** Stable per-device grouping id (display-grade, not a security identity). */
  deviceId?: string;
}

/**
 * Detect the current machine's hardware profile, OS, architecture, and form factor.
 */
export function getDeviceMeta(): JsDeviceMeta;

/**
 * Manually configured peer for cross-subnet / VPN / localhost setups.
 * `port` is the peer's UDP discovery port.
 */
export interface JsManualPeer {
  host: string;
  port: number;
}

export interface JsPeerRecord {
  nodeId: string;
  name: string;
  ip: string;
  udpPort: number;
  tcpPort: number;
  device?: JsDeviceMeta;
  deviceId?: string;
  /** Product label running on the peer, e.g. "luciola-clipboard". */
  product?: string;
}

/**
 * Active P2P discovery session in Node.js.
 */
export class DiscoverySession {
  constructor(
    name?: string,
    port?: number,
    manualPeers?: JsManualPeer[] | null,
    product?: string,
    deviceId?: string,
  );
  /**
   * This session's engine node id (available after `start`).
   */
  nodeId(): string | null;
  /**
   * Start discovery and consume lifecycle events.
   * `found`/`updated` carry `peer`; `lost` carries `nodeId` (remove it from
   * your UI); `error` carries `message` (e.g. bind_failed: port occupied).
   */
  start(callback: (event: {
    type: 'found' | 'updated' | 'lost' | 'error';
    peer?: JsPeerRecord;
    nodeId?: string;
    message?: string;
  }) => void): void;
  /**
   * Stop discovery session and broadcast exit to neighbors.
   */
  stop(): void;
}

/**
 * Per-channel dial outcome of a Happy Eyeballs race.
 */
export interface JsDialChannel {
  address: string;
  status: 'won' | 'cancelled' | 'timeout';
  rttMs: number | null;
}

/**
 * Overall race outcome: winning address plus per-channel detail.
 */
export interface JsRaceOutcome {
  winner: string | null;
  rttMs: number | null;
  channels: JsDialChannel[];
}

/**
 * Selection policy shared across platforms: first 3 IPv4 candidates plus the
 * first IPv6 GUA. Feed the result into `happyEyeballsRace`.
 */
export function defaultRaceCandidates(addresses: string[]): string[];

/**
 * Race TCP dials across `addresses` on `port` (Happy Eyeballs): the first
 * connect wins, the rest are cancelled. Resolves with the outcome.
 */
export function happyEyeballsRace(
  addresses: string[],
  port: number,
  attemptTimeoutMs?: number,
  staggerMs?: number,
): Promise<JsRaceOutcome>;

/**
 * A generated or restored device identity. Keep `seed` secret.
 */
export interface JsDeviceIdentity {
  seed: Buffer;
  publicKey: Buffer;
  fingerprint: string;
  shortPin: string;
}

/**
 * Generate a fresh Ed25519 device identity for pairing/trust.
 */
export function generateDeviceIdentity(): JsDeviceIdentity;

/**
 * Restore an identity from a persisted 32-byte seed.
 */
export function identityFromSeed(seed: Buffer): JsDeviceIdentity;

/**
 * `sha256:<hex>` fingerprint of an Ed25519 public key.
 */
export function identityFingerprint(publicKey: Buffer): string;

/**
 * 6-digit on-screen comparison pin for pairing.
 */
export function identityShortPin(publicKey: Buffer): string;

/**
 * Sign a message with a persisted seed.
 */
export function signMessage(seed: Buffer, message: Buffer): Buffer;

/**
 * Verify a signature against an Ed25519 public key.
 */
export function verifyMessage(publicKey: Buffer, message: Buffer, signature: Buffer): boolean;

/**
 * One authenticated encrypted channel (SIGMA-style handshake: X25519 +
 * Ed25519 identity signatures + HKDF/AES-256-GCM, replay-proof counters).
 * Message-oriented: send() queues an encrypted frame; decrypted inbound
 * frames arrive through the onEvent callback.
 */
export class SecureChannel {
  constructor(identitySeed: Buffer);
  /**
   * Race-dial every candidate address (Happy Eyeballs), handshake on the
   * winning socket with a PINNED peer public key. With autoReconnect the
   * channel re-dials with 1s..30s backoff after drops until close().
   * States: 'connected' | 'retrying' | 'closed' | 'error'.
   */
  connect(
    addresses: string[],
    port: number,
    pinnedPeerPublicKey: Buffer,
    autoReconnect: boolean,
    onEvent: (event: { state?: string; detail?: string; message?: Buffer }) => void,
  ): void;
  /**
   * Accept ONE connection; expectedPeerPublicKey pins the peer, or
   * null/undefined for TOFU (verify the reported fingerprint out-of-band).
   */
  listen(
    port: number,
    expectedPeerPublicKey: Buffer | null | undefined,
    onEvent: (event: { state?: string; detail?: string; message?: Buffer }) => void,
  ): void;
  /**
   * Queue an encrypted frame. False when not connected OR the bounded queue
   * (64) is full because the peer stalled — back off and retry.
   */
  send(message: Buffer): boolean;
  /**
   * Retry policy for auto-reconnect: 2x exponential from minMs to maxMs,
   * each delay jittered +-jitterPct percent (anti-thundering-herd).
   * Defaults: 1000..60000ms, 20%.
   */
  setRetryPolicy(minMs: number, maxMs: number, jitterPct: number): void;
  /**
   * Keepalive cadence: ping after intervalMs idle; peer considered dead after
   * deadAfterMs of silence. Raise both under Android Doze. Defaults 15000/30000.
   */
  setKeepalive(intervalMs: number, deadAfterMs: number): void;
  isConnected(): boolean;
  /** Link health counters (sent/received frames, connections, retries). */
  stats(): {
    framesSent: number;
    framesReceived: number;
    connectionsEstablished: number;
    reconnectAttempts: number;
  };
  close(): void;
}

/** Canonical pairing payload (`luciola://pair` v2). */
export interface JsPairingInfo {
  name: string;
  product?: string;
  port: number;
  addrs: string[];
  /** Host identity fingerprint (`sha256:<hex>`) — bind trust on it. */
  fingerprint?: string;
  /** Optional 6-digit on-screen comparison pin. */
  pin?: string;
}

/** Build the canonical pairing URI (URL-encoded). */
export function buildPairingUri(
  name: string,
  product?: string | null,
  port: number,
  addrs: string[],
  fingerprint?: string | null,
  pin?: string | null,
): string;

/** Parse a pairing URI (`luciola://pair` v1/v2 or plain `http://host:port`). */
export function parsePairingUri(uri: string): JsPairingInfo | null;

/**
 * NOTE: event callbacks are invoked from engine threads and MUST NOT throw —
 * wrap their bodies in try/catch (an uncaught throw can abort the process).
 */
