const luciola = require('./index.js');

console.log('--- Testing @luciola/core in Node.js ---');
const bestIp = luciola.selectLanIp();
console.log('✅ Best LAN IP (for QR code直连):', bestIp);

const candidates = luciola.localCandidateAddresses();
console.log('✅ Local candidate IPs:', candidates);

const subnetBroadcasts = luciola.subnetBroadcastAddresses();
console.log('✅ Subnet broadcasts (anti-TUN):', subnetBroadcasts);

const isVirt = luciola.isVirtualNic('utun5');
console.log('✅ isVirtualNic("utun5"):', isVirt);
console.log('✅ isVirtualNic("en0"):', luciola.isVirtualNic('en0'));

const isTun = luciola.isTunVirtualIp('198.18.0.1');
console.log('✅ isTunVirtualIp("198.18.0.1"):', isTun);

const device = luciola.getDeviceMeta();
console.log('✅ Device Metadata:', `${device.icon} ${device.deviceType} | ${device.os} (${device.arch}) | Model: ${device.model || 'N/A'}`);

console.log('\n--- Testing DiscoverySession in Node.js ---');
const session = new luciola.DiscoverySession('NodeJS-Tester', 19876);
session.start((peer) => {
  console.log('🎉 Node.js received Peer event:', peer);
});
console.log('✅ DiscoverySession started successfully on port 19876');

setTimeout(() => {
  session.stop();
  console.log('✅ DiscoverySession stopped cleanly');
  console.log('--- Node.js Integration All Passed! ---');
  process.exit(0);
}, 1000);
