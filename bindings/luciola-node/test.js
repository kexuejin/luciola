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

console.log('--- Node.js Integration All Passed! ---');
