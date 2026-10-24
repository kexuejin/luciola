const path = require('node:path');
const fs = require('node:fs');

function loadNative() {
  const candidates = [
    path.join(__dirname, 'luciola.node'),
    'target/debug/libluciola_node.dylib',
    'target/release/libluciola_node.dylib',
    path.join(__dirname, '../../target/debug/libluciola_node.dylib'),
    path.join(__dirname, '../../target/release/libluciola_node.dylib'),
    path.join(__dirname, '../../target/debug/libluciola_node.so'),
    path.join(__dirname, '../../target/release/libluciola_node.so'),
  ];

  for (const c of candidates) {
    if (fs.existsSync(c)) {
      try {
        if (c.endsWith('.node')) {
          return require(c);
        } else {
          const mod = { exports: {} };
          process.dlopen(mod, c);
          return mod.exports;
        }
      } catch (_e) {
        // try next candidate
      }
    }
  }
  throw new Error('Failed to load @luciola/core native binary from candidate paths.');
}

module.exports = loadNative();
