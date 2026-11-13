#!/usr/bin/env python3
"""Bridge a loopback `ws://` client to a deployed `wss://` rendezvous Worker.

`connect_wan` has no `HTTPS_PROXY` support. On a host whose system resolver is
hijacked for `*.workers.dev` (it returns an unrelated IP), a Rust client times
out before TLS even though `curl` through a proxy reaches the Worker fine. This
bridge lets the unmodified Rust client talk to the *deployed* runtime: it listens
on loopback in plain HTTP, opens a CONNECT tunnel through `HTTPS_PROXY` (remote
DNS), wraps it in TLS with the correct SNI, rewrites the `Host` header and pumps
bytes both ways. Nothing is decrypted or logged; it is a byte pipe.

Requirements: python3. No pip packages.

Usage (one terminal):

  HTTPS_PROXY=http://127.0.0.1:8080 \
    python3 scripts/wan-proxy-tunnel.py \
      https://luciola-signaling-staging.<account>.workers.dev

It prints the loopback endpoint to use, e.g. `ws://127.0.0.1:53107/ws`:

  LUCIOLA_WAN_WORKER=ws://127.0.0.1:53107/ws \
    LUCIOLA_WAN_CONNECT_TIMEOUT_MS=30000 \
    cargo test -p luciola --test wan_local_worker -- --nocapture

The port is chosen by the OS (bind 0) so two runs never collide. Stop with ^C.
Without a proxy in the environment the bridge dials the host directly, which is
only useful when local DNS already resolves it correctly.
"""
import argparse
import os
import re
import select
import socket
import ssl
import sys
import threading


def read_until(sock: socket.socket, marker: bytes, limit: int = 65536) -> bytes:
    buf = b""
    while marker not in buf:
        chunk = sock.recv(4096)
        if not chunk:
            raise OSError(f"peer closed before {marker!r}")
        buf += chunk
        if len(buf) > limit:
            raise OSError("request headers exceeded the size limit")
    return buf


def tls_upstream(host: str, port: int) -> ssl.SSLSocket:
    proxy = (
        os.environ.get("HTTPS_PROXY")
        or os.environ.get("https_proxy")
        or os.environ.get("HTTP_PROXY")
    )
    if proxy:
        match = re.match(r"https?://([^:/@]+):(\d+)", proxy)
        if not match:
            raise ValueError(f"cannot parse proxy {proxy!r}; expected http://host:port")
        raw = socket.create_connection((match.group(1), int(match.group(2))), timeout=15)
        raw.sendall(
            f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n".encode()
        )
        status = read_until(raw, b"\r\n\r\n").split(b"\r\n", 1)[0]
        if b" 200 " not in status:
            raw.close()
            raise OSError(f"CONNECT failed: {status.decode('latin1')}")
    else:
        raw = socket.create_connection((host, port), timeout=15)
    return ssl.create_default_context().wrap_socket(raw, server_hostname=host)


def rewrite_host(request: bytes, host: str) -> bytes:
    """Only the Host header changes; the upgrade request must stay byte-identical."""
    head, sep, body = request.partition(b"\r\n\r\n")
    lines = []
    for line in head.split(b"\r\n"):
        if line.lower().startswith(b"host:"):
            lines.append(f"Host: {host}".encode())
        else:
            lines.append(line)
    return b"\r\n".join(lines) + sep + body


def pump(client: socket.socket, upstream: socket.socket) -> None:
    peers = {client: upstream, upstream: client}
    readable = [client, upstream]
    idle_seconds = 180
    sent = received = 0
    while readable:
        ready, _, _ = select.select(readable, [], [], idle_seconds)
        if not ready:
            print("bridge: idle timeout, closing connection", file=sys.stderr)
            return
        for sock in ready:
            data = sock.recv(65536)
            other = peers[sock]
            if not data:
                readable.remove(sock)
                try:
                    other.shutdown(socket.SHUT_WR)
                except OSError:
                    pass
                continue
            other.sendall(data)
            if sock is client:
                sent += len(data)
            else:
                received += len(data)
    # Evidence that this was a real round trip to the deployed runtime, not a
    # green-looking test that never left loopback (AGENTS.md §12).
    print(
        f"bridge: connection done, {sent} bytes to Worker, {received} bytes back",
        file=sys.stderr,
    )


def handle(client: socket.socket, host: str, port: int) -> None:
    upstream = None
    try:
        request = read_until(client, b"\r\n\r\n")
        upstream = tls_upstream(host, port)
        upstream.sendall(rewrite_host(request, host))
        print(f"bridge: TLS upstream connected to {host}", file=sys.stderr)
        pump(client, upstream)
    except Exception as exc:  # noqa: BLE001 - a dead bridge must not kill the server
        print(f"bridge: connection failed: {exc}", file=sys.stderr)
    finally:
        for sock in (client, upstream):
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("url", help="https:// host of the deployed Worker")
    parser.add_argument(
        "--port", type=int, default=0, help="loopback listen port (0 = OS-assigned)"
    )
    args = parser.parse_args()
    host = re.sub(r"^https?://", "", args.url.rstrip("/"))
    if not host or "/" in host:
        print("url must be a bare https:// host", file=sys.stderr)
        return 2

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", args.port))
    listener.listen(16)
    assigned = listener.getsockname()[1]
    print(f"ws://127.0.0.1:{assigned}/ws  ->  wss://{host}/ws", flush=True)
    print("bridge: waiting for connections (^C to stop)", file=sys.stderr)
    try:
        while True:
            client, _ = listener.accept()
            threading.Thread(
                target=handle, args=(client, host, 443), daemon=True
            ).start()
    except KeyboardInterrupt:
        return 0
    finally:
        listener.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
