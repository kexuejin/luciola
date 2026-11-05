# Deliberate non-goals

Decisions that look like unfinished work but are not. Each entry records what
was considered, why it was rejected, and what would have to change before it is
worth revisiting. Read this before "fixing" one of them.

## The uniffi and Node binding crates stay single-file

`bindings/luciola-uniffi/src/lib.rs` and `bindings/luciola-node/src/lib.rs` are
large (roughly 1.7k and 1.4k lines) and were repeatedly proposed for splitting
into modules.

**Not done, deliberately.** Nearly every item in those files carries a
`#[uniffi::export]` or `#[napi]` attribute; moving an item to another module
changes nothing a consumer can observe, but it does re-order macro expansion and
has already produced confusing "duplicate export" and missing-scaffolding
failures in this repository's history. The files are navigated by symbol search,
not by scrolling. Revisit only if compile time or merge conflicts become a
measured cost — not for aesthetics.

## `@luciola/core` is not published on npm

`bindings/luciola-node` is built from source by consumers, and
`package.json` still carries the same version as the Rust workspace.

**Not done, deliberately.** The Node surface is hand-written N-API code with no
prebuilt binaries for Windows/Linux, so an npm package would ship a loader that
fails on most machines. The version is bumped anyway so that a future publish
would be consistent rather than a surprise.

## `missing_docs` is not denied in `luciola-node`

Every Rust-facing crate denies `missing_docs`. The Node crate documents all of
its hand-written items but cannot deny the lint.

**Not done, deliberately.** `#[napi]` on a class generates wrapper functions
whose spans carry the attribute; those generated items are undocumented and
cannot be annotated, so a crate-level deny fails on macro output rather than on
our code. The lint is enforced everywhere it can be.

## File transfer requires a pinned peer; there is no TOFU path

`luciola-cli transfer send|recv` refuses to run without `--pin-peer` /
`--accept-pin`.

**Not done, deliberately.** Trust-on-first-use would make the first transfer the
one an attacker can intercept, and a file transfer is exactly the operation
where that matters. Pairing (QR / `luciola://pair`) is the supported way to
learn a key; the transfer command then requires the key it learned.
