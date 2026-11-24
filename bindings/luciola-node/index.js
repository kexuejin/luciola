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
  const names = [
    'libluciola_node.dylib',
    'libluciola_node.so',
    'luciola_node.dll',
    'libluciola_node.dll',
  ];
  const out = [];
  for (const profile of ['debug', 'release']) {
    for (const n of names) out.push(path.join(dir, profile, n));
  }
  return out;
}

function prebuiltPackageName() {
  const key = `${process.platform}-${process.arch}`;
  const map = {
    'darwin-arm64': '@luciola/core-darwin-arm64',
    'darwin-x64': '@luciola/core-darwin-x64',
    'linux-x64': '@luciola/core-linux-x64-gnu',
    'linux-arm64': '@luciola/core-linux-arm64-gnu',
    'win32-x64': '@luciola/core-win32-x64-msvc',
  };
  return map[key] || null;
}

function loadNative() {
  const candidates = [
    path.join(__dirname, 'luciola.node'),
    // Development inside a checkout: the cargo target directory is not always
    // ./target (a shared [build] target-dir in ~/.cargo/config.toml redirects
    // it), so ask cargo itself and allow LUCIOLA_TARGET_DIR to override.
    ...cargoCandidateDirs(),
  ];

  // A stale `luciola.node` left in the package directory used to win over the
  // dylib cargo had just built, so `cargo build -p luciola-node && node test.js`
  // — the documented gate — silently exercised a day-old binary with no WAN
  // exports. Prefer the freshest candidate that exists: a packaged install ships
  // exactly one file, so this changes nothing there.
  const existing = [];
  for (const candidate of candidates) {
    try {
      existing.push({ candidate, mtime: fs.statSync(candidate).mtimeMs });
    } catch (_e) {
      // not present; skip
    }
  }
  existing.sort((a, b) => b.mtime - a.mtime);

  for (const { candidate: c } of existing) {
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

  // Packaged npm install fallback: optional platform prebuild package.
  const pkg = prebuiltPackageName();
  if (pkg) {
    try {
      return require(pkg);
    } catch (_e) {
      // fall through to explicit error
    }
  }

  throw new Error('Failed to load @luciola/core native binary from candidate paths.');
}

module.exports = loadNative();
