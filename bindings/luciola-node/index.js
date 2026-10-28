const path = require('node:path');
const fs = require('node:fs');

function cargoTargetDirectory() {
  if (process.env.LUCIOLA_TARGET_DIR) return process.env.LUCIOLA_TARGET_DIR;
  try {
    const { execFileSync } = require('node:child_process');
    const out = execFileSync('cargo', ['metadata', '--format-version', '1', '--no-deps'], {
      cwd: path.join(__dirname, '..', '..'),
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'ignore'],
    });
    const m = out.match(/"target_directory":"([^"]+)"/);
    return m ? JSON.parse('"' + m[1] + '"') : null;
  } catch (_e) {
    return null; // cargo is not on PATH in packaged installs, which is fine
  }
}

function cargoCandidateDirs() {
  const dir = cargoTargetDirectory();
  if (!dir) return [];
  const names = ['libluciola_node.dylib', 'libluciola_node.so', 'libluciola_node.dll'];
  const out = [];
  for (const profile of ['debug', 'release']) {
    for (const n of names) out.push(path.join(dir, profile, n));
  }
  return out;
}

function loadNative() {
  const candidates = [
    path.join(__dirname, 'luciola.node'),
    // Development inside a checkout: the cargo target directory is not always
    // ./target (a shared [build] target-dir in ~/.cargo/config.toml redirects
    // it), so ask cargo itself and allow LUCIOLA_TARGET_DIR to override.
    ...cargoCandidateDirs(),
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
