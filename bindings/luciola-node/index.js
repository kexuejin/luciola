const path = require('node:path');

// Dynamically locate the native module for development / release
const nativePaths = [
  path.join(__dirname, 'luciola.node'),
  path.join(__dirname, '../../target/debug/libluciola_node.dylib'),
  path.join(__dirname, '../../target/release/libluciola_node.dylib'),
  'target/debug/libluciola_node.dylib',
  'target/release/libluciola_node.dylib',
];

let nativeBinding = null;
for (const p of nativePaths) {
  try {
    nativeBinding = require(p);
    break;
  } catch (_e) {
    // continue searching
  }
}

if (!nativeBinding) {
  throw new Error('Failed to load @luciola/core native binary from candidate paths.');
}

module.exports = nativeBinding;
