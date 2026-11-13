#!/usr/bin/env python3
"""Live signalling probe: confirm a deployed Luciola rendezvous Worker serves
the `x-luciola-epoch` header on a real 101 WebSocket upgrade.

Why this exists: `connect_wan` does the full two-peer handshake, but from a box
whose system DNS resolver is hijacked for `*.workers.dev` (it returns the wrong
IP) the Rust client times out before TLS. This probe replicates exactly what
`connect_wan` sends — same `LUCIOLA_WAN_AUTH` prefix, same field order, same
Ed25519 signature — but resolves through `HTTPS_PROXY` (remote DNS) and keeps
the TLS SNI correct, so it reaches the real Worker even when the host resolver
does not. It proves the Durable Object on the *deployed* runtime answers a
valid signed upgrade with the epoch header.

Requirements: python3, openssl on PATH. No pip packages.

Usage:
  scripts/probe-signaling.py https://luciola-signaling-staging.<account>.workers.dev
  HTTPS_PROXY=http://127.0.0.1:8080 scripts/probe-signaling.py https://HOST

Exit 0 if a 101 with a matching x-luciola-epoch is observed, else non-zero.
"""
import base64
import json
import os
import re
import socket
import ssl
import subprocess
import sys
import tempfile
import urllib.request
from pathlib import Path


def fetch_health(base: str) -> dict:
    # urllib honours HTTPS_PROXY from the environment, i.e. remote DNS — the
    # whole point of this probe. A plain system resolver may be hijacked.
    # The default `Python-urllib/x.y` UA is rejected by the Cloudflare edge
    # with 403; an explicit UA is required even for the public /health route.
    request = urllib.request.Request(
        base + "/health", headers={"User-Agent": "luciola-signaling-probe/1"}
    )
    with urllib.request.urlopen(request, timeout=15) as resp:
        return json.load(resp)


def read_until(sock: socket.socket, marker: bytes, limit: int = 65536) -> bytes:
    buf = b""
    while marker not in buf:
        chunk = sock.recv(4096)
        if not chunk:
            raise OSError(f"peer closed before {marker!r}; got {buf[:200]!r}")
        buf += chunk
        if len(buf) > limit:
            raise OSError("response headers exceeded the size limit")
    return buf


def tls_connection(host: str, port: int) -> ssl.SSLSocket:
    """A TLS socket whose SNI is `host`, optionally through an HTTP CONNECT proxy."""
    proxy = (
        os.environ.get("HTTPS_PROXY")
        or os.environ.get("https_proxy")
        or os.environ.get("HTTP_PROXY")
    )
    if proxy:
        match = re.match(r"https?://([^:/@]+):(\d+)", proxy)
        if not match:
            raise ValueError(f"cannot parse proxy {proxy!r}; expected http://host:port")
        sock = socket.create_connection((match.group(1), int(match.group(2))), timeout=15)
        sock.sendall(
            f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n".encode()
        )
        resp = read_until(sock, b"\r\n\r\n")
        status = resp.split(b"\r\n", 1)[0]
        if b" 200 " not in status:
            sock.close()
            raise OSError(f"CONNECT failed: {status.decode('latin1')}")
        print("CONNECT -> tunnel established through proxy")
    else:
        sock = socket.create_connection((host, port), timeout=15)
    return ssl.create_default_context().wrap_socket(sock, server_hostname=host)


def main() -> int:
    if len(sys.argv) != 2:
        print(f"usage: {sys.argv[0]} https://host", file=sys.stderr)
        return 2
    base = sys.argv[1].rstrip("/")
    if not base.startswith("https://"):
        print("the deployed Worker endpoint must be an https:// URL", file=sys.stderr)
        return 2
    host = re.sub(r"^https?://", "", base)
    port = 443

    try:
        health = fetch_health(base)
        server_epoch = int(health["epoch"])
    except Exception as exc:  # noqa: BLE001 - report any transport/parse failure
        print(f"/health failed: {exc}", file=sys.stderr)
        return 3
    print(
        f"/health -> ok={health.get('ok')} epoch={server_epoch} "
        f"version={health.get('version')}"
    )

    # Ephemeral keypair and scratch files. A probe is not a real identity, and
    # leaving a private key behind in /tmp would be worse than the DNS problem.
    with tempfile.TemporaryDirectory(prefix="luciola-probe-") as scratch:
        tmp = Path(scratch)
        key = tmp / "key.pem"
        msg = tmp / "auth.bin"
        subprocess.run(
            ["openssl", "genpkey", "-algorithm", "ed25519", "-out", str(key)],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        der = subprocess.check_output(
            ["openssl", "pkey", "-in", str(key), "-pubout", "-outform", "DER"],
            stderr=subprocess.DEVNULL,
        )
        pub_hex = der[-32:].hex()
        if len(pub_hex) != 64:
            print(f"unexpected pubkey length {len(pub_hex)}", file=sys.stderr)
            return 4

        room_hex = os.urandom(16).hex()
        nonce_hex = os.urandom(16).hex()
        epoch = server_epoch  # exact match -> |epoch - server| = 0 <= 1
        payload = f"LUCIOLA_WAN_AUTH:{room_hex}:{epoch}:{nonce_hex}:{pub_hex}"
        msg.write_bytes(payload.encode())
        sig_hex = subprocess.check_output(
            ["openssl", "pkeyutl", "-sign", "-inkey", str(key), "-rawin", "-in", str(msg)],
            stderr=subprocess.DEVNULL,
        ).hex()
        if len(sig_hex) != 128:
            print(f"unexpected signature length {len(sig_hex)}", file=sys.stderr)
            return 5

    path = (
        f"/ws?room={room_hex}&peer={pub_hex}&nonce={nonce_hex}"
        f"&epoch={epoch}&sig={sig_hex}"
    )

    try:
        ts = tls_connection(host, port)
    except Exception as exc:  # noqa: BLE001
        print(f"TLS/connect failed: {exc}", file=sys.stderr)
        return 6

    with ts:
        ws_key = base64.b64encode(os.urandom(16)).decode()
        req = (
            "GET %s HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\n"
            "Connection: Upgrade\r\nSec-WebSocket-Key: %s\r\n"
            "Sec-WebSocket-Version: 13\r\n\r\n" % (path, host, ws_key)
        )
        ts.sendall(req.encode())
        try:
            text = read_until(ts, b"\r\n\r\n").decode("latin1")
        except OSError as exc:
            print(f"upgrade response failed: {exc}", file=sys.stderr)
            return 7

    epoch_hdr = ""
    for line in text.split("\r\n"):
        if line.lower().startswith("x-luciola-epoch:"):
            epoch_hdr = line.split(":", 1)[1].strip()

    if "101" not in text.split("\r\n", 1)[0]:
        print("did not get 101; response was:")
        print(text)
        return 7
    print(f"101 received; x-luciola-epoch = {epoch_hdr!r}")
    if epoch_hdr == str(server_epoch):
        print("OK: deployed Durable Object serves the epoch header, matching /health.")
        return 0
    print(f"WARNING: epoch header {epoch_hdr} != /health {server_epoch}")
    return 8


if __name__ == "__main__":
    sys.exit(main())
