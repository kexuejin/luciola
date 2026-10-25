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
}

/**
 * Active P2P discovery session in Node.js.
 */
export class DiscoverySession {
  constructor(name?: string, port?: number, manualPeers?: JsManualPeer[]);
  /**
   * This session's engine node id (available after `start`).
   */
  nodeId(): string | null;
  /**
   * Start discovery session and listen for discovered peers via callback.
   */
  start(callback: (peer: JsPeerRecord) => void): void;
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
