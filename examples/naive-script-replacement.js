/**
 * Example: How @luciola/core can replace ~200 lines of error-prone regex,
 * child_process ipconfig calls, and fragile network interface scanning
 * with 3 lines of code.
 */

const luciola = require('../bindings/luciola-node/index.js');

function getMobileAccessUrls(port = 3081) {
  // 1. Get the single best LAN IPv4 (clean Wi-Fi/Ethernet, WSL host passthrough, no ICS hotspot)
  const lanIpv4 = luciola.selectLanIp();

  // 2. Get all candidate addresses (including domestic broadband IPv6 without scope clutter)
  const candidates = luciola.localCandidateAddresses();

  // 3. Subnet broadcast addresses to announce presence without being swallowed by Clash/TUN
  const broadcasts = luciola.subnetBroadcastAddresses();

  // 4. Inspect local machine hardware & device identity
  const device = luciola.getDeviceMeta();

  return {
    device,
    qrUrl: lanIpv4 ? `http://${lanIpv4}:${port}` : null,
    allUrls: candidates.map(ip => ip.includes(':') ? `http://[${ip}]:${port}` : `http://${ip}:${port}`),
    antiTunBroadcasts: broadcasts,
  };
}

console.log('--- @luciola/core integration preview ---');
const access = getMobileAccessUrls(3081);
console.log(`💻 Local Hardware Identity: ${access.device.icon} ${access.device.deviceType} | ${access.device.os} (${access.device.arch}) | Model: ${access.device.model || 'Generic'}`);
console.log('📱 Generated Mobile QR URL:', access.qrUrl);
console.log('🌐 Multi-NIC / IPv6 Dual-Stack URLs:', access.allUrls);
console.log('🛡️ Subnet Broadcast Targets (Bypassing Clash TUN):', access.antiTunBroadcasts);
