

@file:Suppress("RemoveRedundantBackticks")

package uniffi.luciola_uniffi

// Common helper code.
//
// Ideally this would live in a separate .kt file where it can be unittested etc
// in isolation, and perhaps even published as a re-useable package.
//
// However, it's important that the details of how this helper code works (e.g. the
// way that different builtin types are passed across the FFI) exactly match what's
// expected by the Rust code on the other side of the interface. In practice right
// now that means coming from the exact some version of `uniffi` that was used to
// compile the Rust component. The easiest way to ensure this is to bundle the Kotlin
// helpers directly inline like we're doing here.

public class InternalException(message: String) : kotlin.Exception(message)

// Public interface members begin here.


// Interface implemented by anything that can contain an object reference.
//
// Such types expose a `destroy()` method that must be called to cleanly
// dispose of the contained objects. Failure to call this method may result
// in memory leaks.
//
// The easiest way to ensure this method is called is to use the `.use`
// helper method to execute a block and destroy the object at the end.
@OptIn(ExperimentalStdlibApi::class)
public interface Disposable : AutoCloseable {
    public fun destroy()
    override fun close(): Unit = destroy()
    public companion object {
        internal fun destroy(vararg args: Any?) {
            for (arg in args) {
                when (arg) {
                    is Disposable -> arg.destroy()
                    is ArrayList<*> -> {
                        for (idx in arg.indices) {
                            val element = arg[idx]
                            if (element is Disposable) {
                                element.destroy()
                            }
                        }
                    }
                    is Map<*, *> -> {
                        for (element in arg.values) {
                            if (element is Disposable) {
                                element.destroy()
                            }
                        }
                    }
                    is Array<*> -> {
                        for (element in arg) {
                            if (element is Disposable) {
                                element.destroy()
                            }
                        }
                    }
                    is Iterable<*> -> {
                        for (element in arg) {
                            if (element is Disposable) {
                                element.destroy()
                            }
                        }
                    }
                }
            }
        }
    }
}

@OptIn(kotlin.contracts.ExperimentalContracts::class)
public inline fun <T : Disposable?, R> T.use(block: (T) -> R): R {
    kotlin.contracts.contract {
        callsInPlace(block, kotlin.contracts.InvocationKind.EXACTLY_ONCE)
    }
    return try {
        block(this)
    } finally {
        try {
            // N.B. our implementation is on the nullable type `Disposable?`.
            this?.destroy()
        } catch (e: Throwable) {
            // swallow
        }
    }
}

/** Used to instantiate an interface without an actual pointer, for fakes in tests, mostly. */
public object NoPointer

















/**
 * Active P2P discovery session backed by the Luciola UDP broadcast engine.
 *
 * The engine announces this device's presence (`entry`), replies to probes
 * (`alive`), keeps a periodic heartbeat (`presence`), and reports every newly
 * discovered LAN peer through the `OnPeerDiscovered` callback.
 *
 * Supervision is built in so hosts do not re-implement it per platform:
 * - `node_id` is stable for the session's lifetime — engine restarts keep the
 * same identity and remote registries do not see a "new" device.
 * - `start` retries the UDP bind so a restart racing the old socket's release
 * does not silently fall back to an ephemeral port.
 * - `restart()` rebuilds the engine with the same listener (hosts call this on
 * network changes); `seconds_since_idle()` feeds host-side watchdogs.
 */
public interface DiscoverySessionInterface {
    
    /**
     * Whether the last engine start actually bound the requested discovery
     * port. False means the port was occupied and never freed within the
     * retry window — the UI should not claim "online".
     */
    public fun `isBound`(): kotlin.Boolean
    
    /**
     * This session's stable engine node id. Companion sockets (sweeps, unicast
     * reconciliation on the host side) should present the SAME identity so
     * remote devices see ONE node, not a duplicate peer.
     */
    public fun `nodeId`(): kotlin.String
    
    /**
     * Stop the engine (announcing `exit` to neighbors) and rebuild it with the
     * same listener and identity. Hosts call this when the network set changes;
     * the internal bind-retry tolerates the old socket still releasing.
     */
    public fun `restart`()
    
    /**
     * Seconds since the last peer discovery (or session start). Host watchdogs
     * treat a long idle on a networked device as "engine stalled".
     */
    public fun `secondsSinceIdle`(): kotlin.Double
    
    /**
     * Replace the manual peer list; takes effect on the next `restart()`.
     */
    public fun `setManualPeers`(`peers`: List<ManualPeer>)
    
    /**
     * Restrict discovery to these `Profile.product` labels.
     *
     * `None` or an empty list accepts every product (the historical open
     * mesh). Takes effect on the next `start()` / `restart()`. Use it when
     * several luciola products share one discovery port or one machine:
     * without a filter each product sees the others as peers and dials the
     * channel port advertised in their profiles (the 2026-11-02 cross-dial).
     */
    public fun `setProductFilter`(`products`: List<kotlin.String>?)
    
    /**
     * Start the engine on a dedicated background thread.
     */
    public fun `start`(`listener`: OnPeerDiscovered)
    
    /**
     * Stop the session and broadcast `exit` to neighbors.
     */
    public fun `stop`()
    
    public companion object
}


/**
 * Active P2P discovery session backed by the Luciola UDP broadcast engine.
 *
 * The engine announces this device's presence (`entry`), replies to probes
 * (`alive`), keeps a periodic heartbeat (`presence`), and reports every newly
 * discovered LAN peer through the `OnPeerDiscovered` callback.
 *
 * Supervision is built in so hosts do not re-implement it per platform:
 * - `node_id` is stable for the session's lifetime — engine restarts keep the
 * same identity and remote registries do not see a "new" device.
 * - `start` retries the UDP bind so a restart racing the old socket's release
 * does not silently fall back to an ephemeral port.
 * - `restart()` rebuilds the engine with the same listener (hosts call this on
 * network changes); `seconds_since_idle()` feeds host-side watchdogs.
 */
public expect open class DiscoverySession: Disposable, DiscoverySessionInterface {
    /**
     * This constructor can be used to instantiate a fake object. Only used for tests. Any
     * attempt to actually use an object constructed this way will fail as there is no
     * connected Rust object.
     */
    /**
     * Create a session announcing `name` on the given UDP discovery port.
     *
     * `manualPeers` are unicast-only targets (host:port is the UDP discovery
     * port) for peers that broadcasts cannot reach: cross-subnet hosts, VPN
     * overlays (Tailscale/ZeroTier), or localhost debugging.
     *
     * `node_id`, `tcp_port` and `public_key` let the host pin the beacon's
     * identity to ITS OWN key material (zero-trust pairing wants the
     * advertised Ed25519 key to match the one the secure channel presents);
     * pass `None` to let the engine generate them.
     */
    public constructor(noPointer: NoPointer)

    
    /**
     * Create a session announcing `name` on the given UDP discovery port.
     *
     * `manualPeers` are unicast-only targets (host:port is the UDP discovery
     * port) for peers that broadcasts cannot reach: cross-subnet hosts, VPN
     * overlays (Tailscale/ZeroTier), or localhost debugging.
     *
     * `node_id`, `tcp_port` and `public_key` let the host pin the beacon's
     * identity to ITS OWN key material (zero-trust pairing wants the
     * advertised Ed25519 key to match the one the secure channel presents);
     * pass `None` to let the engine generate them.
     */
    public constructor(`name`: kotlin.String, `port`: kotlin.UShort, `manualPeers`: List<ManualPeer>?, `product`: kotlin.String?, `extra`: kotlin.String?, `nodeId`: kotlin.String?, `tcpPort`: kotlin.UShort?, `publicKey`: kotlin.ByteArray?)

    override fun destroy()
    override fun close()

    
    /**
     * Whether the last engine start actually bound the requested discovery
     * port. False means the port was occupied and never freed within the
     * retry window — the UI should not claim "online".
     */
    public override fun `isBound`(): kotlin.Boolean
    
    /**
     * This session's stable engine node id. Companion sockets (sweeps, unicast
     * reconciliation on the host side) should present the SAME identity so
     * remote devices see ONE node, not a duplicate peer.
     */
    public override fun `nodeId`(): kotlin.String
    
    /**
     * Stop the engine (announcing `exit` to neighbors) and rebuild it with the
     * same listener and identity. Hosts call this when the network set changes;
     * the internal bind-retry tolerates the old socket still releasing.
     */
    public override fun `restart`()
    
    /**
     * Seconds since the last peer discovery (or session start). Host watchdogs
     * treat a long idle on a networked device as "engine stalled".
     */
    public override fun `secondsSinceIdle`(): kotlin.Double
    
    /**
     * Replace the manual peer list; takes effect on the next `restart()`.
     */
    public override fun `setManualPeers`(`peers`: List<ManualPeer>)
    
    /**
     * Restrict discovery to these `Profile.product` labels.
     *
     * `None` or an empty list accepts every product (the historical open
     * mesh). Takes effect on the next `start()` / `restart()`. Use it when
     * several luciola products share one discovery port or one machine:
     * without a filter each product sees the others as peers and dials the
     * channel port advertised in their profiles (the 2026-11-02 cross-dial).
     */
    public override fun `setProductFilter`(`products`: List<kotlin.String>?)
    
    /**
     * Start the engine on a dedicated background thread.
     */
    public override fun `start`(`listener`: OnPeerDiscovered)
    
    /**
     * Stop the session and broadcast `exit` to neighbors.
     */
    public override fun `stop`()
    

    
    public companion object
}




/**
 * Concurrent multi-peer authenticated TCP server on a single dual-stack port.
 *
 * Peer keys are checked against an explicit allowlist **before** the server signs
 * handshake message 2 (deny by default; untrusted initiators learn neither the hub's
 * public key nor any signature).
 */
public interface SecureHubInterface {
    
    /**
     * Add a 32-byte Ed25519 peer public key to the pre-sign allowlist.
     * Returns `true` if newly added, `false` if already present.
     */
    @Throws(WanFfiException::class)
    public fun `addAllowedPeer`(`publicKey`: kotlin.ByteArray): kotlin.Boolean
    
    /**
     * Broadcast an encrypted frame to every connected peer.
     * Returns fingerprints whose outbound queue rejected the frame.
     */
    public fun `broadcast`(`payload`: kotlin.ByteArray): List<kotlin.String>
    
    /**
     * Snapshot of currently connected peers.
     */
    public fun `connectedPeers`(): List<HubPeerInfoDto>
    
    /**
     * Disconnect one connected peer by fingerprint and emit `on_peer_disconnected`.
     */
    public fun `kick`(`fingerprint`: kotlin.String): kotlin.Boolean
    
    /**
     * Actual listening socket address (`ip:port`).
     */
    public fun `localAddr`(): kotlin.String
    
    /**
     * Actual listening TCP port (useful when started with `port == 0`).
     */
    public fun `localPort`(): kotlin.UShort
    
    /**
     * Remove a 32-byte Ed25519 peer public key from the pre-sign allowlist.
     * Does not disconnect an already-connected session; call [`Self::kick`] to drop an active peer.
     */
    @Throws(WanFfiException::class)
    public fun `removeAllowedPeer`(`publicKey`: kotlin.ByteArray): kotlin.Boolean
    
    /**
     * Queue an encrypted frame for one connected peer (`false` if disconnected or backpressured).
     */
    public fun `sendTo`(`fingerprint`: kotlin.String, `payload`: kotlin.ByteArray): kotlin.Boolean
    
    /**
     * Stop accepting new peers and disconnect every active peer. Idempotent.
     */
    public fun `stop`()
    
    public companion object
}


/**
 * Concurrent multi-peer authenticated TCP server on a single dual-stack port.
 *
 * Peer keys are checked against an explicit allowlist **before** the server signs
 * handshake message 2 (deny by default; untrusted initiators learn neither the hub's
 * public key nor any signature).
 */
public expect open class SecureHub: Disposable, SecureHubInterface {
    /**
     * This constructor can be used to instantiate a fake object. Only used for tests. Any
     * attempt to actually use an object constructed this way will fail as there is no
     * connected Rust object.
     */
    @Suppress("ConvertSecondaryConstructorToPrimary")
    public constructor(noPointer: NoPointer)

    

    override fun destroy()
    override fun close()

    
    /**
     * Add a 32-byte Ed25519 peer public key to the pre-sign allowlist.
     * Returns `true` if newly added, `false` if already present.
     */
    @Throws(WanFfiException::class)
    public override fun `addAllowedPeer`(`publicKey`: kotlin.ByteArray): kotlin.Boolean
    
    /**
     * Broadcast an encrypted frame to every connected peer.
     * Returns fingerprints whose outbound queue rejected the frame.
     */
    public override fun `broadcast`(`payload`: kotlin.ByteArray): List<kotlin.String>
    
    /**
     * Snapshot of currently connected peers.
     */
    public override fun `connectedPeers`(): List<HubPeerInfoDto>
    
    /**
     * Disconnect one connected peer by fingerprint and emit `on_peer_disconnected`.
     */
    public override fun `kick`(`fingerprint`: kotlin.String): kotlin.Boolean
    
    /**
     * Actual listening socket address (`ip:port`).
     */
    public override fun `localAddr`(): kotlin.String
    
    /**
     * Actual listening TCP port (useful when started with `port == 0`).
     */
    public override fun `localPort`(): kotlin.UShort
    
    /**
     * Remove a 32-byte Ed25519 peer public key from the pre-sign allowlist.
     * Does not disconnect an already-connected session; call [`Self::kick`] to drop an active peer.
     */
    @Throws(WanFfiException::class)
    public override fun `removeAllowedPeer`(`publicKey`: kotlin.ByteArray): kotlin.Boolean
    
    /**
     * Queue an encrypted frame for one connected peer (`false` if disconnected or backpressured).
     */
    public override fun `sendTo`(`fingerprint`: kotlin.String, `payload`: kotlin.ByteArray): kotlin.Boolean
    
    /**
     * Stop accepting new peers and disconnect every active peer. Idempotent.
     */
    public override fun `stop`()
    

    public companion object {
        
        /**
         * Bind `port` (`0` = OS ephemeral) and start accepting concurrent peers.
         *
         * `allowed_peer_public_keys` seeds the pre-sign allowlist (each entry must be 32 bytes;
         * an empty list starts in deny-all mode until [`Self::add_allowed_peer`] is called).
         */
        @Throws(WanFfiException::class)
        public fun `start`(`port`: kotlin.UShort, `identitySeed`: kotlin.ByteArray, `allowedPeerPublicKeys`: List<kotlin.ByteArray>, `listener`: HubEventListener): SecureHub
        
    }
    
}




/**
 * One authenticated encrypted channel (see `luciola::link::secure`).
 * Message-oriented for FFI friendliness: `send` queues an encrypted frame;
 * received frames are decrypted and delivered through the listener.
 */
public interface SecureSessionInterface {
    
    /**
     * Take ownership of an established [`WanChannel`] and drive its
     * authenticated [`luciola::link::secure::SecureStream`] through this
     * session's existing `send` / `on_message` / `stats` / `disconnect` surface.
     *
     * Stops any prior LAN link and pauses the LAN dual-port tunnel (`TunnelLink`).
     * WAN sessions do not auto-reconnect (see `docs/DECISIONS.md`); on drop,
     * `on_state("closed", None)` is emitted and the caller decides whether to redial.
     */
    @Throws(WanFfiException::class)
    public fun `attachWanChannel`(`channel`: WanChannel, `listener`: SecureSessionListener)
    
    /**
     * 只断**当前这条连接**（Listen 角色的 accept 循环继续接下一个；Dial+auto 重拨）。
     *
     * 与 [`Self::disconnect`] 的语义差异是故意的也是关键的：入站会话清理（陌生连接
     * 超时、拒绝配对、等批准超时）必须用这里 —— 用 [`Self::disconnect`] 会把监听
     * 端口一起拆掉，宿主从此 TCP 连不上（真机实测过，见字段注释）。
     */
    public fun `closeCurrentChannel`()
    
    /**
     * Race-dial every candidate address (Happy Eyeballs) and run the
     * authenticated handshake on the winning socket, with a PINNED peer key.
     *
     * With `auto_reconnect` the session re-dials with exponential backoff
     * (1s..30s) whenever the channel drops, until `disconnect()`.
     */
    public fun `connect`(`addresses`: List<kotlin.String>, `port`: kotlin.UShort, `pinnedPeerPublicKey`: kotlin.ByteArray?, `autoReconnect`: kotlin.Boolean, `listener`: SecureSessionListener)
    
    /**
     * 关闭转发端点（幂等）。
     */
    public fun `disableForwardEndpoint`(): kotlin.Boolean
    
    /**
     * 关闭 remote endpoint（幂等）。
     */
    public fun `disableRemoteEndpoint`(): kotlin.Boolean
    
    /**
     * Close the channel; the peer sees the socket close. (Named
     * `disconnect` because the generated Disposable interface already owns
     * `close`.)
     */
    public fun `disconnect`()
    
    /**
     * 启用/替换服务端转发端点（仅 listen()/Responder 角色）：规则非空、
     * `port_from <= port_to`、tunnel_port 双栈冲突探测；规则主机为 IP 字面量
     * 或主机名；`udp=true` 的规则同时放行 DOPEN（UDP 拨号）。失败同上走 on_state。
     */
    public fun `enableForwardEndpoint`(`rules`: List<ForwardRuleDto>): kotlin.Boolean
    
    /**
     * 启用/替换 remote endpoint ACL（v2；仅 connect()/Dial 角色）：放行
     * Responder 发起的通道并拨本机目标。规则同 enable_forward_endpoint；
     * 未启用 = 默认拒绝一切 remote forward 拨入。
     */
    public fun `enableRemoteEndpoint`(`rules`: List<ForwardRuleDto>): kotlin.Boolean
    
    /**
     * 快照全部转发状态：active（隧道已建立且 Guard 存活）、实际监听端口、
     * 历史折叠计数、类别（local / udp_local / remote_endpoint / endpoint / remote）。
     * 注册过任何转发/端点后即有行，重建期间 active=false。
     */
    public fun `forwardStats`(): List<ForwardStatusDto>
    
    /**
     * Whether the channel currently holds an authenticated connection.
     */
    public fun `isConnected`(): kotlin.Boolean
    
    /**
     * Accept connections in a LOOP (one at a time). `expected_peer`: pin the
     * peer key, or None to accept any identity (TOFU — check the reported
     * fingerprint). The listener re-arms after each channel closes.
     */
    public fun `listen`(`port`: kotlin.UShort, `expectedPeer`: kotlin.ByteArray?, `listener`: SecureSessionListener)
    
    /**
     * 对端的 Ed25519 身份公钥（最近一次连接的）。发起侧 TOFU 时这把 key 是
     * **学来的**：调用方必须在首次连接后取走并钉存，否则重连走不了 pinned 模式。
     */
    public fun `peerPublicKey`(): kotlin.ByteArray?
    
    /**
     * Queue an encrypted frame. False when not connected OR the outbound
     * queue is full (peer stalled) — back off and retry.
     */
    public fun `send`(`message`: kotlin.ByteArray): kotlin.Boolean
    
    /**
     * Keepalive cadence: ping after `interval_ms` idle, peer considered dead
     * after `dead_after_ms` of silence. Hosts raise both under Android Doze.
     */
    public fun `setKeepalive`(`intervalMs`: kotlin.ULong, `deadAfterMs`: kotlin.ULong)
    
    /**
     * Retry policy for auto-reconnect: exponential 2x from `min_ms` to
     * `max_ms`, each delay jittered by +-`jitter_pct` percent (anti-thundering-herd).
     */
    public fun `setRetryPolicy`(`minMs`: kotlin.ULong, `maxMs`: kotlin.ULong, `jitterPct`: kotlin.ULong)
    
    /**
     * 隧道 mux keepalive（v2）：`interval_ms=0` 关闭；dead_after_ms 会被
     * clamp 到 ≥ interval_ms。仅对证明过 v2 的对端执行判死（v1 对端永不误杀）。
     * 改动随下一次隧道链路重建生效。
     */
    public fun `setTunnelKeepalive`(`intervalMs`: kotlin.ULong, `deadAfterMs`: kotlin.ULong)
    
    /**
     * 覆盖隧道端口（默认 = secure 端口 + 1；0 = 恢复默认）。改动触发链路重建。
     */
    public fun `setTunnelPort`(`port`: kotlin.UShort): kotlin.Boolean
    
    /**
     * 注册本地监听端口，经隧道转发到对端 `host:port`（仅 connect()/Dial 角色）。
     * `host` 为 IP 字面量或主机名（v2：主机名由对端解析并按会话钉扎）。
     * `listen_port=0` → 系统分配，实端口见 [`Self::forward_stats`]。
     * 同步完成目标校验与端口冲突探测：失败返回 false 并 on_state(
     * "error", "forward_bind_failed: …" / 校验信息)。懒建立：首个注册后才建隧道。
     */
    public fun `startLocalForward`(`listenPort`: kotlin.UShort, `host`: kotlin.String, `port`: kotlin.UShort): kotlin.Boolean
    
    /**
     * 注册 remote forward（v2 `-R`；仅 listen()/Responder 角色）：本机
     * 127.0.0.1:listen_port 的每条入站连接经隧道（偶数通道）转发到**对端机**
     * 上的 host:port。对端须 enable_remote_endpoint 放行该目标；对端为 v1 时
     * 通道建立失败（对端 mux 按违规终止，勿对旧版本启用）。
     */
    public fun `startRemoteForward`(`listenPort`: kotlin.UShort, `host`: kotlin.String, `port`: kotlin.UShort): kotlin.Boolean
    
    /**
     * 注册 UDP 转发（v2 NAT 式会话映射；仅 connect()/Dial 角色）：
     * 本机 127.0.0.1:listen_port 的每个源地址映射一条数据报通道到对端
     * host:port；对端 endpoint 的 ACL 规则须 `udp=true` 放行。
     * 映射空闲超时自动回收（默认 60s）。
     */
    public fun `startUdpForward`(`listenPort`: kotlin.UShort, `host`: kotlin.String, `port`: kotlin.UShort): kotlin.Boolean
    
    /**
     * Link health counters (sent/received frames, connections, retries).
     */
    public fun `stats`(): LinkStats
    
    /**
     * 注销本地转发（停止 Guard + 折叠计数）。未注册返回 false。
     */
    public fun `stopLocalForward`(`listenPort`: kotlin.UShort): kotlin.Boolean
    
    /**
     * 注销 remote forward。未注册返回 false。
     */
    public fun `stopRemoteForward`(`listenPort`: kotlin.UShort): kotlin.Boolean
    
    /**
     * 注销 UDP 转发。未注册返回 false。
     */
    public fun `stopUdpForward`(`listenPort`: kotlin.UShort): kotlin.Boolean
    
    public companion object
}


/**
 * One authenticated encrypted channel (see `luciola::link::secure`).
 * Message-oriented for FFI friendliness: `send` queues an encrypted frame;
 * received frames are decrypted and delivered through the listener.
 */
public expect open class SecureSession: Disposable, SecureSessionInterface {
    /**
     * This constructor can be used to instantiate a fake object. Only used for tests. Any
     * attempt to actually use an object constructed this way will fail as there is no
     * connected Rust object.
     */
    /**
     * Create a channel bound to a 32-byte Ed25519 identity seed.
     */
    public constructor(noPointer: NoPointer)

    
    /**
     * Create a channel bound to a 32-byte Ed25519 identity seed.
     */
    public constructor(`identitySeed`: kotlin.ByteArray)

    override fun destroy()
    override fun close()

    
    /**
     * Take ownership of an established [`WanChannel`] and drive its
     * authenticated [`luciola::link::secure::SecureStream`] through this
     * session's existing `send` / `on_message` / `stats` / `disconnect` surface.
     *
     * Stops any prior LAN link and pauses the LAN dual-port tunnel (`TunnelLink`).
     * WAN sessions do not auto-reconnect (see `docs/DECISIONS.md`); on drop,
     * `on_state("closed", None)` is emitted and the caller decides whether to redial.
     */
    @Throws(WanFfiException::class)
    public override fun `attachWanChannel`(`channel`: WanChannel, `listener`: SecureSessionListener)
    
    /**
     * 只断**当前这条连接**（Listen 角色的 accept 循环继续接下一个；Dial+auto 重拨）。
     *
     * 与 [`Self::disconnect`] 的语义差异是故意的也是关键的：入站会话清理（陌生连接
     * 超时、拒绝配对、等批准超时）必须用这里 —— 用 [`Self::disconnect`] 会把监听
     * 端口一起拆掉，宿主从此 TCP 连不上（真机实测过，见字段注释）。
     */
    public override fun `closeCurrentChannel`()
    
    /**
     * Race-dial every candidate address (Happy Eyeballs) and run the
     * authenticated handshake on the winning socket, with a PINNED peer key.
     *
     * With `auto_reconnect` the session re-dials with exponential backoff
     * (1s..30s) whenever the channel drops, until `disconnect()`.
     */
    public override fun `connect`(`addresses`: List<kotlin.String>, `port`: kotlin.UShort, `pinnedPeerPublicKey`: kotlin.ByteArray?, `autoReconnect`: kotlin.Boolean, `listener`: SecureSessionListener)
    
    /**
     * 关闭转发端点（幂等）。
     */
    public override fun `disableForwardEndpoint`(): kotlin.Boolean
    
    /**
     * 关闭 remote endpoint（幂等）。
     */
    public override fun `disableRemoteEndpoint`(): kotlin.Boolean
    
    /**
     * Close the channel; the peer sees the socket close. (Named
     * `disconnect` because the generated Disposable interface already owns
     * `close`.)
     */
    public override fun `disconnect`()
    
    /**
     * 启用/替换服务端转发端点（仅 listen()/Responder 角色）：规则非空、
     * `port_from <= port_to`、tunnel_port 双栈冲突探测；规则主机为 IP 字面量
     * 或主机名；`udp=true` 的规则同时放行 DOPEN（UDP 拨号）。失败同上走 on_state。
     */
    public override fun `enableForwardEndpoint`(`rules`: List<ForwardRuleDto>): kotlin.Boolean
    
    /**
     * 启用/替换 remote endpoint ACL（v2；仅 connect()/Dial 角色）：放行
     * Responder 发起的通道并拨本机目标。规则同 enable_forward_endpoint；
     * 未启用 = 默认拒绝一切 remote forward 拨入。
     */
    public override fun `enableRemoteEndpoint`(`rules`: List<ForwardRuleDto>): kotlin.Boolean
    
    /**
     * 快照全部转发状态：active（隧道已建立且 Guard 存活）、实际监听端口、
     * 历史折叠计数、类别（local / udp_local / remote_endpoint / endpoint / remote）。
     * 注册过任何转发/端点后即有行，重建期间 active=false。
     */
    public override fun `forwardStats`(): List<ForwardStatusDto>
    
    /**
     * Whether the channel currently holds an authenticated connection.
     */
    public override fun `isConnected`(): kotlin.Boolean
    
    /**
     * Accept connections in a LOOP (one at a time). `expected_peer`: pin the
     * peer key, or None to accept any identity (TOFU — check the reported
     * fingerprint). The listener re-arms after each channel closes.
     */
    public override fun `listen`(`port`: kotlin.UShort, `expectedPeer`: kotlin.ByteArray?, `listener`: SecureSessionListener)
    
    /**
     * 对端的 Ed25519 身份公钥（最近一次连接的）。发起侧 TOFU 时这把 key 是
     * **学来的**：调用方必须在首次连接后取走并钉存，否则重连走不了 pinned 模式。
     */
    public override fun `peerPublicKey`(): kotlin.ByteArray?
    
    /**
     * Queue an encrypted frame. False when not connected OR the outbound
     * queue is full (peer stalled) — back off and retry.
     */
    public override fun `send`(`message`: kotlin.ByteArray): kotlin.Boolean
    
    /**
     * Keepalive cadence: ping after `interval_ms` idle, peer considered dead
     * after `dead_after_ms` of silence. Hosts raise both under Android Doze.
     */
    public override fun `setKeepalive`(`intervalMs`: kotlin.ULong, `deadAfterMs`: kotlin.ULong)
    
    /**
     * Retry policy for auto-reconnect: exponential 2x from `min_ms` to
     * `max_ms`, each delay jittered by +-`jitter_pct` percent (anti-thundering-herd).
     */
    public override fun `setRetryPolicy`(`minMs`: kotlin.ULong, `maxMs`: kotlin.ULong, `jitterPct`: kotlin.ULong)
    
    /**
     * 隧道 mux keepalive（v2）：`interval_ms=0` 关闭；dead_after_ms 会被
     * clamp 到 ≥ interval_ms。仅对证明过 v2 的对端执行判死（v1 对端永不误杀）。
     * 改动随下一次隧道链路重建生效。
     */
    public override fun `setTunnelKeepalive`(`intervalMs`: kotlin.ULong, `deadAfterMs`: kotlin.ULong)
    
    /**
     * 覆盖隧道端口（默认 = secure 端口 + 1；0 = 恢复默认）。改动触发链路重建。
     */
    public override fun `setTunnelPort`(`port`: kotlin.UShort): kotlin.Boolean
    
    /**
     * 注册本地监听端口，经隧道转发到对端 `host:port`（仅 connect()/Dial 角色）。
     * `host` 为 IP 字面量或主机名（v2：主机名由对端解析并按会话钉扎）。
     * `listen_port=0` → 系统分配，实端口见 [`Self::forward_stats`]。
     * 同步完成目标校验与端口冲突探测：失败返回 false 并 on_state(
     * "error", "forward_bind_failed: …" / 校验信息)。懒建立：首个注册后才建隧道。
     */
    public override fun `startLocalForward`(`listenPort`: kotlin.UShort, `host`: kotlin.String, `port`: kotlin.UShort): kotlin.Boolean
    
    /**
     * 注册 remote forward（v2 `-R`；仅 listen()/Responder 角色）：本机
     * 127.0.0.1:listen_port 的每条入站连接经隧道（偶数通道）转发到**对端机**
     * 上的 host:port。对端须 enable_remote_endpoint 放行该目标；对端为 v1 时
     * 通道建立失败（对端 mux 按违规终止，勿对旧版本启用）。
     */
    public override fun `startRemoteForward`(`listenPort`: kotlin.UShort, `host`: kotlin.String, `port`: kotlin.UShort): kotlin.Boolean
    
    /**
     * 注册 UDP 转发（v2 NAT 式会话映射；仅 connect()/Dial 角色）：
     * 本机 127.0.0.1:listen_port 的每个源地址映射一条数据报通道到对端
     * host:port；对端 endpoint 的 ACL 规则须 `udp=true` 放行。
     * 映射空闲超时自动回收（默认 60s）。
     */
    public override fun `startUdpForward`(`listenPort`: kotlin.UShort, `host`: kotlin.String, `port`: kotlin.UShort): kotlin.Boolean
    
    /**
     * Link health counters (sent/received frames, connections, retries).
     */
    public override fun `stats`(): LinkStats
    
    /**
     * 注销本地转发（停止 Guard + 折叠计数）。未注册返回 false。
     */
    public override fun `stopLocalForward`(`listenPort`: kotlin.UShort): kotlin.Boolean
    
    /**
     * 注销 remote forward。未注册返回 false。
     */
    public override fun `stopRemoteForward`(`listenPort`: kotlin.UShort): kotlin.Boolean
    
    /**
     * 注销 UDP 转发。未注册返回 false。
     */
    public override fun `stopUdpForward`(`listenPort`: kotlin.UShort): kotlin.Boolean
    

    
    public companion object
}




/**
 * Cooperative cancellation handle shared with any `transfer_*` call.
 */
public interface TransferCancelHandleInterface {
    
    /**
     * Signal cancellation to any transfer observing this handle.
     */
    public fun `cancel`()
    
    /**
     * Whether [`Self::cancel`] has been called.
     */
    public fun `isCancelled`(): kotlin.Boolean
    
    public companion object
}


/**
 * Cooperative cancellation handle shared with any `transfer_*` call.
 */
public expect open class TransferCancelHandle: Disposable, TransferCancelHandleInterface {
    /**
     * This constructor can be used to instantiate a fake object. Only used for tests. Any
     * attempt to actually use an object constructed this way will fail as there is no
     * connected Rust object.
     */
    /**
     * Create a fresh non-cancelled handle.
     */
    public constructor(noPointer: NoPointer)

    
    /**
     * Create a fresh non-cancelled handle.
     */
    public constructor()

    override fun destroy()
    override fun close()

    
    /**
     * Signal cancellation to any transfer observing this handle.
     */
    public override fun `cancel`()
    
    /**
     * Whether [`Self::cancel`] has been called.
     */
    public override fun `isCancelled`(): kotlin.Boolean
    

    
    public companion object
}




/**
 * Persisted trust list. Serialize with [TrustStore::to_json] and store the
 * bytes in the product's secret storage; unpaired peers are simply absent
 * (default posture: deny).
 */
public interface TrustStoreInterface {
    
    /**
     * Every paired device, in insertion order.
     */
    public fun `entries`(): List<TrustedDeviceInfo>
    
    /**
     * Trust level for a public key; absent = unpaired.
     */
    public fun `levelOf`(`publicKey`: kotlin.ByteArray): TrustLevel?
    
    /**
     * Remove a paired device by fingerprint.
     */
    public fun `remove`(`fingerprint`: kotlin.String): kotlin.Boolean
    
    /**
     * JSON serialization for persistence.
     */
    public fun `toJson`(): kotlin.String
    
    /**
     * Pair or re-pair a device (replaces the entry with the same public key).
     */
    public fun `trustDevice`(`device`: TrustedDeviceInfo)
    
    public companion object
}


/**
 * Persisted trust list. Serialize with [TrustStore::to_json] and store the
 * bytes in the product's secret storage; unpaired peers are simply absent
 * (default posture: deny).
 */
public expect open class TrustStore: Disposable, TrustStoreInterface {
    /**
     * This constructor can be used to instantiate a fake object. Only used for tests. Any
     * attempt to actually use an object constructed this way will fail as there is no
     * connected Rust object.
     */
    /**
     * Restore a trust store from its JSON form, or start empty.
     */
    public constructor(noPointer: NoPointer)

    
    /**
     * Restore a trust store from its JSON form, or start empty.
     */
    public constructor(`fromJson`: kotlin.String?)

    override fun destroy()
    override fun close()

    
    /**
     * Every paired device, in insertion order.
     */
    public override fun `entries`(): List<TrustedDeviceInfo>
    
    /**
     * Trust level for a public key; absent = unpaired.
     */
    public override fun `levelOf`(`publicKey`: kotlin.ByteArray): TrustLevel?
    
    /**
     * Remove a paired device by fingerprint.
     */
    public override fun `remove`(`fingerprint`: kotlin.String): kotlin.Boolean
    
    /**
     * JSON serialization for persistence.
     */
    public override fun `toJson`(): kotlin.String
    
    /**
     * Pair or re-pair a device (replaces the entry with the same public key).
     */
    public override fun `trustDevice`(`device`: TrustedDeviceInfo)
    

    
    public companion object
}




/**
 * An established WAN channel.
 *
 * `connect_wan` blocks the calling thread while it exchanges candidates,
 * punches and runs the authenticated handshake, bounded by
 * `punch_timeout_ms` and the signalling timeout. On mobile platforms call it
 * from a worker thread, never from the UI thread.
 */
public interface WanChannelInterface {
    
    /**
     * The data plane this channel actually uses.
     *
     * Returns `Unknown` after [`WanChannel::shutdown`] or when the engine
     * reports a code this build does not know.
     */
    public fun `channelType`(): WanChannelKind
    
    /**
     * The peer's socket endpoint, when the transport exposes one.
     */
    public fun `remoteAddr`(): kotlin.String?
    
    /**
     * Close the channel. Idempotent; a second call is a no-op.
     */
    @Throws(WanFfiException::class)
    public fun `shutdown`()
    
    public companion object
}


/**
 * An established WAN channel.
 *
 * `connect_wan` blocks the calling thread while it exchanges candidates,
 * punches and runs the authenticated handshake, bounded by
 * `punch_timeout_ms` and the signalling timeout. On mobile platforms call it
 * from a worker thread, never from the UI thread.
 */
public expect open class WanChannel: Disposable, WanChannelInterface {
    /**
     * This constructor can be used to instantiate a fake object. Only used for tests. Any
     * attempt to actually use an object constructed this way will fail as there is no
     * connected Rust object.
     */
    @Suppress("ConvertSecondaryConstructorToPrimary")
    public constructor(noPointer: NoPointer)

    

    override fun destroy()
    override fun close()

    
    /**
     * The data plane this channel actually uses.
     *
     * Returns `Unknown` after [`WanChannel::shutdown`] or when the engine
     * reports a code this build does not know.
     */
    public override fun `channelType`(): WanChannelKind
    
    /**
     * The peer's socket endpoint, when the transport exposes one.
     */
    public override fun `remoteAddr`(): kotlin.String?
    
    /**
     * Close the channel. Idempotent; a second call is a no-op.
     */
    @Throws(WanFfiException::class)
    public override fun `shutdown`()
    

    
    public companion object
}




/**
 * Multiplexed TCP/UDP port-forwarding session running over one [`WanChannel`].
 * Does not alter the LAN dual-port `SecureSession` tunnel contract.
 */
public interface WanTunnelSessionInterface {
    
    /**
     * Transport plane of the underlying channel.
     */
    public fun `channelType`(): WanChannelKind
    
    /**
     * Disable the inbound ACL forward endpoint.
     */
    public fun `disableForwardEndpoint`()
    
    /**
     * Enable or replace the inbound ACL forward endpoint (`--allow`).
     */
    @Throws(WanFfiException::class)
    public fun `enableForwardEndpoint`(`rules`: List<ForwardRuleDto>)
    
    /**
     * Whether the underlying mux session is still alive.
     */
    public fun `isAlive`(): kotlin.Boolean
    
    /**
     * Stop all forwards and shut down the tunnel. Idempotent.
     */
    public fun `shutdown`()
    
    /**
     * Start a local TCP forward (`127.0.0.1:listen_port` → peer `host:port`).
     * Returns the actual bound local port (helpful when `listen_port == 0`).
     */
    @Throws(WanFfiException::class)
    public fun `startLocalForward`(`listenPort`: kotlin.UShort, `host`: kotlin.String, `port`: kotlin.UShort): kotlin.UShort
    
    /**
     * Start a local UDP forward (`127.0.0.1:listen_port` → peer `host:port`).
     */
    @Throws(WanFfiException::class)
    public fun `startUdpForward`(`listenPort`: kotlin.UShort, `host`: kotlin.String, `port`: kotlin.UShort): kotlin.UShort
    
    /**
     * Snapshot active forward stats.
     */
    public fun `stats`(): List<ForwardStatusDto>
    
    /**
     * Stop a local TCP forward on `listen_port`.
     */
    public fun `stopLocalForward`(`listenPort`: kotlin.UShort): kotlin.Boolean
    
    /**
     * Stop a local UDP forward on `listen_port`.
     */
    public fun `stopUdpForward`(`listenPort`: kotlin.UShort): kotlin.Boolean
    
    public companion object
}


/**
 * Multiplexed TCP/UDP port-forwarding session running over one [`WanChannel`].
 * Does not alter the LAN dual-port `SecureSession` tunnel contract.
 */
public expect open class WanTunnelSession: Disposable, WanTunnelSessionInterface {
    /**
     * This constructor can be used to instantiate a fake object. Only used for tests. Any
     * attempt to actually use an object constructed this way will fail as there is no
     * connected Rust object.
     */
    @Suppress("ConvertSecondaryConstructorToPrimary")
    public constructor(noPointer: NoPointer)

    

    override fun destroy()
    override fun close()

    
    /**
     * Transport plane of the underlying channel.
     */
    public override fun `channelType`(): WanChannelKind
    
    /**
     * Disable the inbound ACL forward endpoint.
     */
    public override fun `disableForwardEndpoint`()
    
    /**
     * Enable or replace the inbound ACL forward endpoint (`--allow`).
     */
    @Throws(WanFfiException::class)
    public override fun `enableForwardEndpoint`(`rules`: List<ForwardRuleDto>)
    
    /**
     * Whether the underlying mux session is still alive.
     */
    public override fun `isAlive`(): kotlin.Boolean
    
    /**
     * Stop all forwards and shut down the tunnel. Idempotent.
     */
    public override fun `shutdown`()
    
    /**
     * Start a local TCP forward (`127.0.0.1:listen_port` → peer `host:port`).
     * Returns the actual bound local port (helpful when `listen_port == 0`).
     */
    @Throws(WanFfiException::class)
    public override fun `startLocalForward`(`listenPort`: kotlin.UShort, `host`: kotlin.String, `port`: kotlin.UShort): kotlin.UShort
    
    /**
     * Start a local UDP forward (`127.0.0.1:listen_port` → peer `host:port`).
     */
    @Throws(WanFfiException::class)
    public override fun `startUdpForward`(`listenPort`: kotlin.UShort, `host`: kotlin.String, `port`: kotlin.UShort): kotlin.UShort
    
    /**
     * Snapshot active forward stats.
     */
    public override fun `stats`(): List<ForwardStatusDto>
    
    /**
     * Stop a local TCP forward on `listen_port`.
     */
    public override fun `stopLocalForward`(`listenPort`: kotlin.UShort): kotlin.Boolean
    
    /**
     * Stop a local UDP forward on `listen_port`.
     */
    public override fun `stopUdpForward`(`listenPort`: kotlin.UShort): kotlin.Boolean
    

    public companion object {
        
        /**
         * Consume `channel` and start a [`luciola_tunnel::DirectTunnelSession`] on `wan_runtime()`.
         */
        @Throws(WanFfiException::class)
        public fun `fromWanChannel`(`channel`: WanChannel, `isInitiator`: kotlin.Boolean): WanTunnelSession
        
    }
    
}




/**
 * A generated or restored device identity. Keep `seed` secret.
 */

public data class DeviceIdentityInfo (
    /**
     * 32-byte Ed25519 seed — persist it in secret storage, never log it.
     */
    var `seed`: kotlin.ByteArray, 
    /**
     * Ed25519 public key derived from `seed`.
     */
    var `publicKey`: kotlin.ByteArray, 
    /**
     * `sha256:<hex>` fingerprint of `public_key`.
     */
    var `fingerprint`: kotlin.String, 
    /**
     * 6-digit on-screen comparison pin.
     */
    var `shortPin`: kotlin.String
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as DeviceIdentityInfo
        if (!`seed`.contentEquals(other.`seed`)) return false
        if (!`publicKey`.contentEquals(other.`publicKey`)) return false
        if (`fingerprint` != other.`fingerprint`) return false
        if (`shortPin` != other.`shortPin`) return false

        return true
    }
    override fun hashCode(): Int {
        var result = `seed`.contentHashCode()
        result = 31 * result + `publicKey`.contentHashCode()
        result = 31 * result + `fingerprint`.hashCode()
        result = 31 * result + `shortPin`.hashCode()
        return result
    }
    public companion object
}



/**
 * Device hardware and OS metadata.
 */

public data class DeviceMeta (
    /**
     * Form factor of the device.
     */
    var `deviceType`: DeviceType, 
    /**
     * Emoji icon for peer-list UIs.
     */
    var `icon`: kotlin.String, 
    /**
     * Operating-system name, e.g. `macOS` or `Android`.
     */
    var `os`: kotlin.String, 
    /**
     * CPU architecture, e.g. `aarch64`.
     */
    var `arch`: kotlin.String, 
    /**
     * Hardware model string, when the platform exposes one.
     */
    var `model`: kotlin.String?, 
    /**
     * Stable per-device grouping id (display-grade, not a security identity).
     */
    var `deviceId`: kotlin.String?
) {
    public companion object
}



/**
 * Per-channel dial outcome.
 */

public data class DialChannel (
    /**
     * Address this channel dialled.
     */
    var `address`: kotlin.String, 
    /**
     * What happened to this channel.
     */
    var `status`: DialStatus, 
    /**
     * Connect latency in milliseconds, when the attempt succeeded.
     */
    var `rttMs`: kotlin.Double?
) {
    public companion object
}



/**
 * A discovered peer node in the local network.
 */

public data class DiscoveredPeer (
    /**
     * Stable node identity.
     */
    var `nodeId`: kotlin.String, 
    /**
     * Human-readable device name.
     */
    var `name`: kotlin.String, 
    /**
     * Address the peer was last heard from.
     */
    var `ip`: kotlin.String, 
    /**
     * Peer's UDP discovery port.
     */
    var `udpPort`: kotlin.UShort, 
    /**
     * Peer's secure-channel TCP port.
     */
    var `tcpPort`: kotlin.UShort, 
    /**
     * Optional hardware metadata.
     */
    var `device`: DeviceMeta?, 
    /**
     * Stable per-device grouping id (display-grade).
     */
    var `deviceId`: kotlin.String?, 
    /**
     * Product label running on the peer.
     */
    var `product`: kotlin.String?, 
    /**
     * Opaque application payload (mDNS-TXT style) — the host's richer
     * profile rides here; the engine never parses it.
     */
    var `extra`: kotlin.String?
) {
    public companion object
}



/**
 * A structured engine error, projected from `luciola_proto::ErrorInfo`.
 *
 * Hosts receive loose strings from the long-standing callback interfaces
 * (`on_error(code, message)` and `on_state("error", detail)`). This record is
 * the typed companion: call [`classify_error`] once and branch on `code`
 * instead of parsing human prose. Additive — no existing callback changes.
 */

public data class ErrorInfoDto (
    /**
     * Stable snake_case wire code; unknown codes are reported as `"unknown"`.
     */
    var `code`: kotlin.String, 
    /**
     * The original human-readable detail, never localised or truncated.
     */
    var `message`: kotlin.String, 
    /**
     * Whether the host should retry the operation.
     */
    var `retryable`: kotlin.Boolean
) {
    public companion object
}



/**
 * 转发规则（T3 `enable_forward_endpoint` / v2 `enable_remote_endpoint`）：
 * 单主机（IP 字面量或主机名）上的端口区间，含端点；`udp` 同时放行 DOPEN。
 */

public data class ForwardRuleDto (
    /**
     * IP literal or hostname (normalised to lowercase).
     */
    var `host`: kotlin.String, 
    /**
     * Inclusive lower port bound.
     */
    var `portFrom`: kotlin.UShort, 
    /**
     * Inclusive upper port bound.
     */
    var `portTo`: kotlin.UShort, 
    /**
     * v2：true = 本规则同时放行 UDP 数据报拨号；false 仅 TCP（v1 语义）。
     */
    var `udp`: kotlin.Boolean
) {
    public companion object
}



/**
 * 一条转发状态（T3 `forward_stats`）：历史折叠累计 + 实际监听端口 + 类别。
 * `kind` ∈ {"local", "udp_local", "remote_endpoint", "endpoint", "remote"}。
 */

public data class ForwardStatusDto (
    /**
     * Whether the forward / endpoint is currently bound.
     */
    var `active`: kotlin.Boolean, 
    /**
     * Port actually bound (system-assigned when 0 was requested).
     */
    var `listenPort`: kotlin.UShort, 
    /**
     * Channels currently relaying bytes.
     */
    var `channelsOpen`: kotlin.ULong, 
    /**
     * Channels granted since registration.
     */
    var `channelsTotal`: kotlin.ULong, 
    /**
     * OPEN / DOPEN rejected by the ACL.
     */
    var `dialDenied`: kotlin.ULong, 
    /**
     * Allowed dials that failed or timed out.
     */
    var `dialFailed`: kotlin.ULong, 
    /**
     * Row kind: local / udp_local / remote_endpoint / endpoint / remote.
     */
    var `kind`: kotlin.String
) {
    public companion object
}



/**
 * Metadata for a peer currently authenticated with [`SecureHub`].
 */

public data class HubPeerInfoDto (
    /**
     * Verified `sha256:<hex>` fingerprint of the peer's Ed25519 identity key.
     */
    var `fingerprint`: kotlin.String, 
    /**
     * Raw 32-byte Ed25519 public key of the peer.
     */
    var `publicKey`: kotlin.ByteArray, 
    /**
     * Peer's TCP socket address (`ip:port`).
     */
    var `remoteAddr`: kotlin.String
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as HubPeerInfoDto
        if (`fingerprint` != other.`fingerprint`) return false
        if (!`publicKey`.contentEquals(other.`publicKey`)) return false
        if (`remoteAddr` != other.`remoteAddr`) return false

        return true
    }
    override fun hashCode(): Int {
        var result = `fingerprint`.hashCode()
        result = 31 * result + `publicKey`.contentHashCode()
        result = 31 * result + `remoteAddr`.hashCode()
        return result
    }
    public companion object
}



/**
 * LAN dial parameters for [`connect_with_policy`] (pinned peer identity required; no TOFU).
 */

public data class LanDialConfigDto (
    /**
     * Candidate LAN IPv4 / IPv6 addresses.
     */
    var `addresses`: List<kotlin.String>, 
    /**
     * Peer's secure TCP port.
     */
    var `port`: kotlin.UShort, 
    /**
     * Local 32-byte Ed25519 identity seed (zeroized after validation).
     */
    var `identitySeed`: kotlin.ByteArray, 
    /**
     * Pinned 32-byte Ed25519 peer public key (mandatory; no TOFU).
     */
    var `peerPublicKey`: kotlin.ByteArray
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as LanDialConfigDto
        if (`addresses` != other.`addresses`) return false
        if (`port` != other.`port`) return false
        if (!`identitySeed`.contentEquals(other.`identitySeed`)) return false
        if (!`peerPublicKey`.contentEquals(other.`peerPublicKey`)) return false

        return true
    }
    override fun hashCode(): Int {
        var result = `addresses`.hashCode()
        result = 31 * result + `port`.hashCode()
        result = 31 * result + `identitySeed`.contentHashCode()
        result = 31 * result + `peerPublicKey`.contentHashCode()
        return result
    }
    public companion object
}



/**
 * Link health counters for UI/diagnostics.
 */

public data class LinkStats (
    /**
     * Frames written to the socket.
     */
    var `framesSent`: kotlin.ULong, 
    /**
     * Frames read from the socket.
     */
    var `framesReceived`: kotlin.ULong, 
    /**
     * Successful connections established (including reconnects).
     */
    var `connectionsEstablished`: kotlin.ULong, 
    /**
     * Reconnect attempts started after a drop.
     */
    var `reconnectAttempts`: kotlin.ULong, 
    /**
     * `send()` 被调用且 **try_send 成功**（= 入队成功）的次数。
     *
     * 与 [Self::frames_dequeued]、[Self::frames_sent] 三个数放在一起才能定位
     * 「入队成功但没发出去」到底发生在哪一步：
     * - enqueued > dequeued ⇒ 帧还在队列里或队列被丢（会话被替换/孤儿化）
     * - dequeued > sent      ⇒ 帧在链路循环里被丢（写失败 / select! 分支）
     */
    var `framesEnqueued`: kotlin.ULong, 
    /**
     * 链路循环从出站队列**取走**的帧数。
     */
    var `framesDequeued`: kotlin.ULong
) {
    public companion object
}



/**
 * A manually configured peer for cross-subnet / VPN / localhost setups.
 */

public data class ManualPeer (
    /**
     * Peer host (IP literal or hostname).
     */
    var `host`: kotlin.String, 
    /**
     * Peer UDP discovery port.
     */
    var `port`: kotlin.UShort
) {
    public companion object
}



/**
 * Canonical pairing payload. `fingerprint` is the host's identity
 * fingerprint — bind trust on it; `pin` is the optional 6-digit compare.
 */

public data class PairingInfo (
    /**
     * Display name of the host device.
     */
    var `name`: kotlin.String, 
    /**
     * Product label, when the host advertises one.
     */
    var `product`: kotlin.String?, 
    /**
     * TCP service port to dial.
     */
    var `port`: kotlin.UShort, 
    /**
     * Candidate addresses for the host, best first.
     */
    var `addrs`: List<kotlin.String>, 
    /**
     * Host identity fingerprint (`sha256:<hex>`) — bind trust on it.
     */
    var `fingerprint`: kotlin.String?, 
    /**
     * Host Ed25519 public key (base64) — the pin target.
     */
    var `publicKey`: kotlin.String?, 
    /**
     * Optional 6-digit on-screen comparison pin.
     */
    var `pin`: kotlin.String?, 
    /**
     * Optional pre-shared key for WAN rendezvous room derivation.
     */
    var `psk`: kotlin.String?
) {
    public companion object
}



/**
 * Overall race outcome: winning address plus per-channel detail.
 */

public data class RaceOutcome (
    /**
     * Address that won the race, if any.
     */
    var `winner`: kotlin.String?, 
    /**
     * Connect latency of the winner, in milliseconds.
     */
    var `rttMs`: kotlin.Double?, 
    /**
     * Per-candidate outcome, in input order.
     */
    var `channels`: List<DialChannel>
) {
    public companion object
}



/**
 * X25519 ephemeral key pair for one relay session.
 */

public data class RelayEphemeralKeyPair (
    /**
     * X25519 secret key (32 bytes) — never send this on the wire.
     */
    var `secret`: kotlin.ByteArray, 
    /**
     * X25519 public key (32 bytes) to send to the peer.
     */
    var `public_`: kotlin.ByteArray
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as RelayEphemeralKeyPair
        if (!`secret`.contentEquals(other.`secret`)) return false
        if (!`public_`.contentEquals(other.`public_`)) return false

        return true
    }
    override fun hashCode(): Int {
        var result = `secret`.contentHashCode()
        result = 31 * result + `public_`.contentHashCode()
        return result
    }
    public companion object
}



/**
 * Per-direction AEAD keys derived for one relay session.
 */

public data class RelaySessionKeys (
    /**
     * Key for frames THIS device sends.
     */
    var `sendKey`: kotlin.ByteArray, 
    /**
     * Key for frames the peer sends.
     */
    var `recvKey`: kotlin.ByteArray
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as RelaySessionKeys
        if (!`sendKey`.contentEquals(other.`sendKey`)) return false
        if (!`recvKey`.contentEquals(other.`recvKey`)) return false

        return true
    }
    override fun hashCode(): Int {
        var result = `sendKey`.contentHashCode()
        result = 31 * result + `recvKey`.contentHashCode()
        return result
    }
    public companion object
}



/**
 * Progress event delivered by [`transfer_send_lan`], [`transfer_recv_lan`],
 * [`transfer_send_wan`], and [`transfer_recv_wan`].
 */

public data class TransferProgressDto (
    /**
     * Stable transfer identifier used for checkpoint matching.
     */
    var `transferId`: kotlin.String, 
    /**
     * Contiguous acknowledged bytes so far.
     */
    var `bytesDone`: kotlin.ULong, 
    /**
     * Total expected bytes.
     */
    var `totalBytes`: kotlin.ULong, 
    /**
     * Active transport plane carrying the transfer.
     */
    var `channelType`: WanChannelKind, 
    /**
     * True when this update reports a resumed checkpoint skip.
     */
    var `resumed`: kotlin.Boolean
) {
    public companion object
}



/**
 * Verified final receipt returned when a file transfer completes.
 */

public data class TransferReceiptDto (
    /**
     * Stable transfer identifier.
     */
    var `transferId`: kotlin.String, 
    /**
     * Sanitized basename of the file.
     */
    var `fileName`: kotlin.String, 
    /**
     * Total bytes transferred.
     */
    var `totalBytes`: kotlin.ULong, 
    /**
     * Lowercase hex SHA-256 checksum of the complete file.
     */
    var `sha256Hex`: kotlin.String, 
    /**
     * Saved destination path on disk (receiver side only).
     */
    var `savedPath`: kotlin.String?, 
    /**
     * Final transport plane active on completion.
     */
    var `channelType`: WanChannelKind
) {
    public companion object
}



/**
 * A paired device entry.
 */

public data class TrustedDeviceInfo (
    /**
     * Stable per-device grouping id.
     */
    var `deviceId`: kotlin.String, 
    /**
     * Human-readable name at pairing time.
     */
    var `name`: kotlin.String, 
    /**
     * Ed25519 public key (32 bytes) — the security identity.
     */
    var `publicKey`: kotlin.ByteArray, 
    /**
     * Cached `sha256:<hex>` fingerprint of `public_key`.
     */
    var `fingerprint`: kotlin.String, 
    /**
     * Current trust level.
     */
    var `level`: TrustLevel, 
    /**
     * When the device was pinned (epoch milliseconds).
     */
    var `pinnedAtMs`: kotlin.ULong
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as TrustedDeviceInfo
        if (`deviceId` != other.`deviceId`) return false
        if (`name` != other.`name`) return false
        if (!`publicKey`.contentEquals(other.`publicKey`)) return false
        if (`fingerprint` != other.`fingerprint`) return false
        if (`level` != other.`level`) return false
        if (`pinnedAtMs` != other.`pinnedAtMs`) return false

        return true
    }
    override fun hashCode(): Int {
        var result = `deviceId`.hashCode()
        result = 31 * result + `name`.hashCode()
        result = 31 * result + `publicKey`.contentHashCode()
        result = 31 * result + `fingerprint`.hashCode()
        result = 31 * result + `level`.hashCode()
        result = 31 * result + `pinnedAtMs`.hashCode()
        return result
    }
    public companion object
}



/**
 * Everything a host supplies to establish one WAN channel.
 *
 * The identity fields are the same pinned Ed25519 material the LAN
 * `SecureStream` uses; `psk` is the high-entropy secret from the v3 pairing
 * URI. Byte arrays are length-checked at this boundary, so a malformed
 * identity is reported as `InvalidConfig` instead of reaching the engine.
 */

public data class WanConfig (
    /**
     * `wss://` rendezvous endpoint (`ws://` is accepted for loopback tests).
     */
    var `signalingEndpoint`: kotlin.String, 
    /**
     * 32-character hex room id from [`wan_derive_room_id`].
     */
    var `room`: kotlin.String, 
    /**
     * Rendezvous epoch; `0` means "use the current epoch".
     */
    var `epoch`: kotlin.ULong, 
    /**
     * Pairing PSK (secret; zeroized inside the engine).
     */
    var `psk`: kotlin.ByteArray, 
    /**
     * Local 32-byte Ed25519 identity seed.
     */
    var `identitySeed`: kotlin.ByteArray, 
    /**
     * Local 32-byte Ed25519 public key.
     */
    var `myPublicKey`: kotlin.ByteArray, 
    /**
     * Pinned peer 32-byte Ed25519 public key (never TOFU).
     */
    var `peerPublicKey`: kotlin.ByteArray, 
    /**
     * Relay and signalling policy.
     */
    var `relay`: WanRelayConfig, 
    /**
     * Optional single STUN server override.
     */
    var `stunServer`: kotlin.String?, 
    /**
     * Candidate-gathering and punching budget in milliseconds; `0` uses the
     * engine default of 5000 ms.
     */
    var `punchTimeoutMs`: kotlin.ULong, 
    /**
     * Skip UDP punching (and the public STUN query) entirely.
     */
    var `enableHolePunching`: kotlin.Boolean, 
    /**
     * Local LAN TCP port advertised in candidates (diagnostic metadata).
     */
    var `tcpPort`: kotlin.UShort, 
    /**
     * Start streaming over the relay immediately and migrate to direct later.
     */
    var `progressive`: kotlin.Boolean
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as WanConfig
        if (`signalingEndpoint` != other.`signalingEndpoint`) return false
        if (`room` != other.`room`) return false
        if (`epoch` != other.`epoch`) return false
        if (!`psk`.contentEquals(other.`psk`)) return false
        if (!`identitySeed`.contentEquals(other.`identitySeed`)) return false
        if (!`myPublicKey`.contentEquals(other.`myPublicKey`)) return false
        if (!`peerPublicKey`.contentEquals(other.`peerPublicKey`)) return false
        if (`relay` != other.`relay`) return false
        if (`stunServer` != other.`stunServer`) return false
        if (`punchTimeoutMs` != other.`punchTimeoutMs`) return false
        if (`enableHolePunching` != other.`enableHolePunching`) return false
        if (`tcpPort` != other.`tcpPort`) return false
        if (`progressive` != other.`progressive`) return false

        return true
    }
    override fun hashCode(): Int {
        var result = `signalingEndpoint`.hashCode()
        result = 31 * result + `room`.hashCode()
        result = 31 * result + `epoch`.hashCode()
        result = 31 * result + `psk`.contentHashCode()
        result = 31 * result + `identitySeed`.contentHashCode()
        result = 31 * result + `myPublicKey`.contentHashCode()
        result = 31 * result + `peerPublicKey`.contentHashCode()
        result = 31 * result + `relay`.hashCode()
        result = 31 * result + (`stunServer`?.hashCode() ?: 0)
        result = 31 * result + `punchTimeoutMs`.hashCode()
        result = 31 * result + `enableHolePunching`.hashCode()
        result = 31 * result + `tcpPort`.hashCode()
        result = 31 * result + `progressive`.hashCode()
        return result
    }
    public companion object
}



/**
 * Relay and signalling policy for one WAN channel. Both flags are `false` by
 * default, so a host must opt in to third-party signalling explicitly.
 */

public data class WanRelayConfig (
    /**
     * Permit an end-to-end encrypted relay when a direct path fails.
     */
    var `allowRelay`: kotlin.Boolean, 
    /**
     * Permit third-party signalling (public keys, public IPs and online times
     * leave the LAN).
     */
    var `allowWanSignaling`: kotlin.Boolean, 
    /**
     * Reserved for dedicated relay endpoints. The current engine reuses the
     * already-authenticated signalling WebSocket and does not read this list.
     */
    var `relayEndpoints`: List<kotlin.String>, 
    /**
     * WebSocket connect timeout in milliseconds (the engine clamps it to a
     * 500 ms floor).
     */
    var `connectionTimeoutMs`: kotlin.ULong
) {
    public companion object
}




/**
 * The network transport channel currently backing a session.
 */


public enum class ChannelType {
    
    /**
     * Local network direct link.
     */
    LAN_DIRECT,
    /**
     * Direct P2P connection established across WAN.
     */
    HOLE_PUNCHED_DIRECT,
    /**
     * End-to-end encrypted link relayed through an external relay server.
     */
    RELAY_FORWARDED,
    /**
     * Physical direct link via Android Debug Bridge over USB bus.
     */
    USB_ADB_DIRECT;
    public companion object
}






/**
 * Device form factor classification.
 */


public enum class DeviceType {
    
    /**
     * Phone.
     */
    MOBILE,
    /**
     * Tablet.
     */
    TABLET,
    /**
     * Portable computer.
     */
    LAPTOP,
    /**
     * Desktop computer.
     */
    DESKTOP,
    /**
     * Headless server.
     */
    SERVER,
    /**
     * Windows Subsystem for Linux guest.
     */
    WSL,
    /**
     * Form factor could not be determined.
     */
    UNKNOWN;
    public companion object
}






/**
 * Fate of one candidate in a Happy Eyeballs race.
 */


public enum class DialStatus {
    
    /**
     * Connected first; the caller dials on this address.
     */
    WON,
    /**
     * A sibling channel won and this attempt was cancelled.
     */
    CANCELLED,
    /**
     * The attempt exceeded its connect timeout.
     */
    TIMEOUT;
    public companion object
}







/**
 * Errors surfaced by the relay crypto exports.
 */
public sealed class RelayCryptoException: kotlin.Exception() {
    
    /**
     * AEAD open failed: tampering or a wrong key/sequence.
     */
    public class AeadOpenFailed(
    ) : RelayCryptoException() {
        override val message: String
            get() = ""
    }
    
    /**
     * The supplied AEAD key was not 32 bytes.
     */
    public class BadKeyLength(
    ) : RelayCryptoException() {
        override val message: String
            get() = ""
    }
    
}




/**
 * Route selection strategy for [`connect_with_policy`].
 */


public enum class RoutePolicyKind {
    
    /**
     * Dial LAN candidates only; never contact signalling or relay.
     */
    LAN_ONLY,
    /**
     * Race LAN candidates up to `lan_budget_ms`, falling back to WAN on connectivity failure.
     * Security failures (pin mismatch / tamper) fail immediately without WAN fallback.
     */
    LAN_THEN_WAN,
    /**
     * Skip LAN and dial WAN directly.
     */
    WAN_ONLY;
    public companion object
}







/**
 * Errors returned by the FFI file transfer helpers.
 */
public sealed class TransferFfiException: kotlin.Exception() {
    
    /**
     * Invalid key, path, or already-consumed channel.
     */
    public class InvalidConfig(
        /**
         * Diagnostic description.
         */
        public val `detail`: kotlin.String,
    ) : TransferFfiException() {
        override val message: String
            get() = "detail=${ `detail` }"
    }
    
    /**
     * Transfer size exceeds the active channel quota (for example over relay).
     */
    public class QuotaExceeded(
        /**
         * Diagnostic description.
         */
        public val `detail`: kotlin.String,
    ) : TransferFfiException() {
        override val message: String
            get() = "detail=${ `detail` }"
    }
    
    /**
     * Transfer was cancelled by the caller via [`TransferCancelHandle`].
     */
    public class Cancelled(
    ) : TransferFfiException() {
        override val message: String
            get() = ""
    }
    
    /**
     * Network, handshake, or I/O failure during transfer.
     */
    public class TransferFailed(
        /**
         * Diagnostic description.
         */
        public val `detail`: kotlin.String,
    ) : TransferFfiException() {
        override val message: String
            get() = "detail=${ `detail` }"
    }
    
}




/**
 * How much a paired device may do without per-action confirmation.
 */


public enum class TrustLevel {
    
    /**
     * Own devices: silent/background push allowed.
     */
    FULL,
    /**
     * Paired but restricted: per-action confirmation required.
     */
    PARTIAL;
    public companion object
}






/**
 * The data plane a [`WanChannel`] actually uses.
 */


public enum class WanChannelKind {
    
    /**
     * Local network direct link.
     */
    LAN_DIRECT,
    /**
     * Direct WAN path (IPv6 GUA or a UDP hole punch).
     */
    HOLE_PUNCHED_DIRECT,
    /**
     * End-to-end encrypted relay.
     */
    RELAY_FORWARDED,
    /**
     * Physical USB link through ADB.
     */
    USB_ADB_DIRECT,
    /**
     * The channel is closed, or reported a code this build does not know.
     */
    UNKNOWN;
    public companion object
}







/**
 * Errors surfaced by the WAN exports.
 *
 * The variants mirror [`luciola::wan::WanError`], so a host can distinguish a
 * policy refusal from a signalling failure, a missing route and a failed
 * handshake without parsing strings.
 */
public sealed class WanFfiException: kotlin.Exception() {
    
    /**
     * Third-party signalling or relay was not enabled by policy.
     */
    public class PolicyDenied(
        /**
         * Engine detail.
         */
        public val `detail`: kotlin.String,
    ) : WanFfiException() {
        override val message: String
            get() = "detail=${ `detail` }"
    }
    
    /**
     * Operating-system I/O failure.
     */
    public class Io(
        /**
         * Engine detail.
         */
        public val `detail`: kotlin.String,
    ) : WanFfiException() {
        override val message: String
            get() = "detail=${ `detail` }"
    }
    
    /**
     * Signalling transport, authentication or framing failure.
     */
    public class Signaling(
        /**
         * Engine detail.
         */
        public val `detail`: kotlin.String,
    ) : WanFfiException() {
        override val message: String
            get() = "detail=${ `detail` }"
    }
    
    /**
     * No direct path and no permitted relay.
     */
    public class NoRoute(
        /**
         * Engine detail.
         */
        public val `detail`: kotlin.String,
    ) : WanFfiException() {
        override val message: String
            get() = "detail=${ `detail` }"
    }
    
    /**
     * The authenticated handshake failed on the chosen transport.
     */
    public class Handshake(
        /**
         * Engine detail.
         */
        public val `detail`: kotlin.String,
    ) : WanFfiException() {
        override val message: String
            get() = "detail=${ `detail` }"
    }
    
    /**
     * The supplied configuration was missing or inconsistent.
     */
    public class InvalidConfig(
        /**
         * Which field was rejected and why.
         */
        public val `detail`: kotlin.String,
    ) : WanFfiException() {
        override val message: String
            get() = "detail=${ `detail` }"
    }
    
}





/**
 * Callback interface receiving lifecycle and message events from [`SecureHub`].
 */
public interface HubEventListener {
    
    /**
     * A peer completed the authenticated handshake and passed the pre-sign allowlist check.
     */
    public fun `onPeerConnected`(`peer`: HubPeerInfoDto)
    
    /**
     * A decrypted application frame arrived from an authenticated peer.
     */
    public fun `onMessage`(`fingerprint`: kotlin.String, `remoteAddr`: kotlin.String, `payload`: kotlin.ByteArray)
    
    /**
     * A connected peer disconnected or was kicked.
     */
    public fun `onPeerDisconnected`(`fingerprint`: kotlin.String)
    
    /**
     * An inbound connection was rejected by the allowlist or failed handshake.
     */
    public fun `onPeerRejected`(`remoteAddr`: kotlin.String, `reason`: kotlin.String)
    
    public companion object
}





/**
 * 平台日志出口（可选）：宿主实现 [`LogSink`] 后调 [`set_log_sink`]，引擎内
 * 的 tracing 日志以 (level, message) 文本送达 FFI。
 *
 * 进程内全局 tracing subscriber 只能安装一次：首次调用会尝试安装桥接
 * subscriber；宿主应用若已自带 subscriber（如 Android Logcat 桥），安装会
 * 失败并被忽略——此时日志归宿主自己的 subscriber 处理，这是有意的让位。
 * 回调内不要再调用会打日志的引擎 API（无重入防护）。
 */
public interface LogSink {
    
    /**
     * Receive one engine log line. Do not call logging engine APIs here.
     */
    public fun `log`(`level`: kotlin.String, `message`: kotlin.String)
    
    public companion object
}





/**
 * Callbacks from the discovery engine. Products must implement all four;
 * `on_peer_updated` fires on profile/address changes, `on_peer_lost` when a
 * peer exits or ages out (update your peer table), `on_error` reports
 * fatal setup problems (e.g. discovery port occupied by another product).
 */
public interface OnPeerDiscovered {
    
    /**
     * A new peer appeared; add it to the host's peer table.
     */
    public fun `onPeerDiscovered`(`peer`: DiscoveredPeer)
    
    /**
     * A known peer's profile or address changed; replace the entry.
     */
    public fun `onPeerUpdated`(`peer`: DiscoveredPeer)
    
    /**
     * A peer exited or aged out; remove it from the host's peer table.
     */
    public fun `onPeerLost`(`nodeId`: kotlin.String)
    
    /**
     * Fatal setup problem (e.g. discovery port occupied); `code` is a stable
     * `snake_case` wire code (see `errorCodes()`).
     */
    public fun `onError`(`code`: kotlin.String, `message`: kotlin.String)
    
    public companion object
}





/**
 * Events from a [SecureSession]: state transitions and decrypted messages.
 */
public interface SecureSessionListener {
    
    /**
     * `state`: "connected" | "closed" | "error"; `detail` carries the peer
     * fingerprint on connect and the error message on failure.
     */
    public fun `onState`(`state`: kotlin.String, `detail`: kotlin.String?)
    
    /**
     * `peer_fingerprint` is the authenticated identity of the sender (the
     * engine verified it during the handshake); `remote_addr` is the socket
     * endpoint the frame physically arrived from. Hosts use them to route
     * the datagram without reverse-engineering session state.
     */
    public fun `onMessage`(`message`: kotlin.ByteArray, `peerFingerprint`: kotlin.String, `remoteAddr`: kotlin.String?)
    
    public companion object
}





/**
 * Callback receiving transfer progress updates.
 */
public interface TransferListener {
    
    /**
     * Called as contiguous acknowledged bytes advance.
     */
    public fun `onProgress`(`progress`: TransferProgressDto)
    
    public companion object
}















































/**
 * Retrieve all local addresses including VPN/tunnels (for unicast overlay sync).
 */
public expect fun `advertisedAddresses`(): List<kotlin.String>

/**
 * Build the canonical `luciola://pair` URI (URL-encoded).
 */
public expect fun `buildPairingUri`(`name`: kotlin.String, `product`: kotlin.String?, `port`: kotlin.UShort, `addrs`: List<kotlin.String>, `fingerprint`: kotlin.String?, `publicKey`: kotlin.String?, `pin`: kotlin.String?): kotlin.String

/**
 * Build a v3 `luciola://pair` URI (carrying optional PSK for WAN rendezvous).
 */
public expect fun `buildPairingUriV3`(`name`: kotlin.String, `product`: kotlin.String?, `port`: kotlin.UShort, `addrs`: List<kotlin.String>, `fingerprint`: kotlin.String?, `publicKey`: kotlin.String?, `pin`: kotlin.String?, `psk`: kotlin.String?): kotlin.String

/**
 * Normalise either callback shape into one [`ErrorInfoDto`]:
 * - `classify_error(code, Some(message))` for `on_error`;
 * - `classify_error(detail, None)` for `on_state("error", detail)`, where the
 * detail is a `"<code>: <message>"` wire string.
 *
 * Legacy tunnel prefixes (`forward_bind_failed:`, `tunnel_*`) map to their
 * canonical codes; unrecognised text becomes `code = "unknown"` with the
 * full text preserved in `message`.
 */
public expect fun `classifyError`(`codeOrDetail`: kotlin.String, `message`: kotlin.String?): ErrorInfoDto

/**
 * Symmetrical 6-digit on-screen comparison pin between two devices during pairing.
 */
public expect fun `comparisonPin`(`localPk`: kotlin.ByteArray, `remotePk`: kotlin.ByteArray): kotlin.String

/**
 * Establish a WAN secure channel.
 *
 * Order of attempts: encrypted candidate exchange over WSS, simultaneous UDP
 * hole punching on the same socket, then an end-to-end encrypted relay over
 * the signalling WebSocket only when both peers allow it and agree on the
 * route. The returned channel reports the plane it actually uses.
 */
@Throws(WanFfiException::class)
public expect fun `connectWan`(`config`: WanConfig): WanChannel

/**
 * Establish an authenticated channel according to `policy` (`LanOnly`, `LanThenWan`, or `WanOnly`).
 *
 * When `policy` is [`RoutePolicyKind::LanThenWan`], `lan_budget_ms == 0` uses a 1500 ms default
 * budget. The returned [`WanChannel`] always reports the honest transport plane (`LanDirect`,
 * `HolePunchedDirect`, or `RelayForwarded`). Call from a worker thread, never from the UI thread.
 */
@Throws(WanFfiException::class)
public expect fun `connectWithPolicy`(`policy`: RoutePolicyKind, `lanBudgetMs`: kotlin.ULong, `lan`: LanDialConfigDto?, `wan`: WanConfig?): WanChannel

/**
 * Selection policy shared with the demos: first 3 IPv4 candidates plus the
 * first IPv6 GUA. Feed the result into [race_connect].
 */
public expect fun `defaultRaceCandidates`(`addresses`: List<kotlin.String>): List<kotlin.String>

/**
 * Derive a deterministic Cloudflare Worker rendezvous room ID from two public keys and an optional PSK.
 */
public expect fun `deriveRendezvousRoomId`(`myPk`: kotlin.String, `peerPk`: kotlin.String, `psk`: kotlin.String?, `epoch`: kotlin.ULong?): kotlin.String

/**
 * Every code in the error contract, in a stable order. Use this to validate
 * that a host handles the full set (and to detect a newer engine).
 */
public expect fun `errorCodes`(): List<kotlin.String>

/**
 * Generate a fresh device identity (Ed25519). Keep the seed secret.
 */
public expect fun `generateDeviceIdentity`(): DeviceIdentityInfo

/**
 * Detect the current machine's hardware profile, OS, architecture, and form factor.
 */
public expect fun `getDeviceMeta`(): DeviceMeta

/**
 * `sha256:<hex>` fingerprint of an Ed25519 public key.
 */
public expect fun `identityFingerprint`(`publicKey`: kotlin.ByteArray): kotlin.String

/**
 * Restore an identity from a persisted 32-byte seed.
 */
public expect fun `identityFromSeed`(`seed`: kotlin.ByteArray): DeviceIdentityInfo

/**
 * 6-digit on-screen comparison pin for pairing.
 */
public expect fun `identityShortPin`(`publicKey`: kotlin.ByteArray): kotlin.String

/**
 * Check if a peer address is in the same local network:
 * Returns true if either RFC private IPv4/IPv6 OR domestic broadband /64 GUA matching.
 */
public expect fun `isLanPeer`(`peerAddress`: kotlin.String, `localAddresses`: List<kotlin.String>): kotlin.Boolean

/**
 * Check if an interface name looks like a real physical network interface (Wi-Fi, Ethernet).
 */
public expect fun `isPhysicalNic`(`name`: kotlin.String): kotlin.Boolean

/**
 * Check if an IP address belongs to a proxy software TUN virtual network (198.18.0.0/15).
 */
public expect fun `isTunVirtualIp`(`address`: kotlin.String): kotlin.Boolean

/**
 * Check if an interface name corresponds to a virtual adapter (utun, feth, tailscale, docker, etc.).
 */
public expect fun `isVirtualNic`(`name`: kotlin.String): kotlin.Boolean

/**
 * Retrieve clean local candidate IP addresses (high-scoring IPv4 and domestic IPv6 GUA/ULA).
 */
public expect fun `localCandidateAddresses`(): List<kotlin.String>

/**
 * Parse a pairing URI (`luciola://pair` v1/v2/v3 or plain `http://host:port`).
 */
public expect fun `parsePairingUri`(`uri`: kotlin.String): PairingInfo?

/**
 * Race TCP dials across `addresses` on `port` (Happy Eyeballs): the first
 * connect wins, the rest are cancelled. Blocking; call off the UI thread.
 */
public expect fun `raceConnect`(`addresses`: List<kotlin.String>, `port`: kotlin.UShort, `attemptTimeoutMs`: kotlin.ULong?, `staggerMs`: kotlin.ULong?): RaceOutcome

/**
 * Open one relay frame payload. Throws on tampering or a key/seq mismatch.
 */
@Throws(RelayCryptoException::class)
public expect fun `relayAeadOpen`(`key`: kotlin.ByteArray, `seq`: kotlin.ULong, `aad`: kotlin.ByteArray, `ciphertext`: kotlin.ByteArray): kotlin.ByteArray

/**
 * Seal one relay frame payload (AES-256-GCM, AAD = the 12-byte frame header).
 */
public expect fun `relayAeadSeal`(`key`: kotlin.ByteArray, `seq`: kotlin.ULong, `aad`: kotlin.ByteArray, `plaintext`: kotlin.ByteArray): kotlin.ByteArray

/**
 * Fresh X25519 ephemeral key pair for one relay session.
 */
public expect fun `relayEphemeralKeypair`(): RelayEphemeralKeyPair

/**
 * Public key for a (serialized) ephemeral secret.
 */
public expect fun `relayEphemeralPublic`(`secret`: kotlin.ByteArray): kotlin.ByteArray

/**
 * Raw HKDF-SHA256, exported for the cross-language wire vectors.
 */
public expect fun `relayHkdfSha256`(`ikm`: kotlin.ByteArray, `salt`: kotlin.ByteArray, `info`: kotlin.ByteArray, `outLen`: kotlin.UInt): kotlin.ByteArray

/**
 * Derive the two directional traffic keys for one relay session.
 */
public expect fun `relaySessionKeys`(`ephemeralSecret`: kotlin.ByteArray, `peerEphemeralPublic`: kotlin.ByteArray, `transcript`: kotlin.ByteArray, `initiatorFingerprint`: kotlin.String, `responderFingerprint`: kotlin.String, `isInitiator`: kotlin.Boolean): RelaySessionKeys

/**
 * The byte string the Ed25519 handshake signature covers.
 *
 * Pass `ephemeral_public` only when the handshake carries the X25519
 * ephemeral key; legacy peers sign `"{timestamp_ms}:{node_id}"`.
 */
public expect fun `relaySignedHandshakePayload`(`timestampMs`: kotlin.ULong, `nodeId`: kotlin.String, `ephemeralPublic`: kotlin.ByteArray?): kotlin.String

/**
 * SHA-256 over both raw handshake byte strings, initiator first.
 */
public expect fun `relayTranscriptHash`(`initiatorHandshake`: kotlin.ByteArray, `responderHandshake`: kotlin.ByteArray): kotlin.ByteArray

/**
 * Render a compact terminal QR code for a given URL or text content.
 *
 * In dark terminals, swaps dark and light colors so that white background border
 * and black QR modules are rendered correctly for optical scanning.
 */
public expect fun `renderQrAscii`(`content`: kotlin.String): kotlin.String?

/**
 * Select the best local IPv4 address for QR code / LAN access.
 */
public expect fun `selectLanIp`(): kotlin.String?

/**
 * 安装（或替换）平台日志出口。传 `None` 仅清空出口，不卸载 subscriber
 * （全局 subscriber 无法卸载）。
 */
public expect fun `setLogSink`(`sink`: LogSink?)

/**
 * Sign a message with a persisted seed.
 */
public expect fun `signMessage`(`seed`: kotlin.ByteArray, `message`: kotlin.ByteArray): kotlin.ByteArray

/**
 * Retrieve per-NIC subnet broadcast addresses (e.g. `192.168.2.255`).
 *
 * These addresses bypass Clash / Sing-box TUN mode (0.0.0.0/1) route capture.
 */
public expect fun `subnetBroadcastAddresses`(): List<kotlin.String>

/**
 * Accept one pin-verified LAN file transfer into `dest_dir` (no TOFU).
 * Call from a background worker thread.
 */
@Throws(TransferFfiException::class)
public expect fun `transferRecvLan`(`identitySeed`: kotlin.ByteArray, `listenPort`: kotlin.UShort, `acceptPeerPublicKey`: kotlin.ByteArray, `destDir`: kotlin.String, `listener`: TransferListener?, `cancel`: TransferCancelHandle?): TransferReceiptDto

/**
 * Receive one file over an already-established [`WanChannel`] (consumes the channel).
 */
@Throws(TransferFfiException::class)
public expect fun `transferRecvWan`(`channel`: WanChannel, `destDir`: kotlin.String, `listener`: TransferListener?, `cancel`: TransferCancelHandle?): TransferReceiptDto

/**
 * Send one file over a pin-verified LAN connection (no TOFU).
 * Call from a background worker thread.
 */
@Throws(TransferFfiException::class)
public expect fun `transferSendLan`(`identitySeed`: kotlin.ByteArray, `addresses`: List<kotlin.String>, `port`: kotlin.UShort, `pinnedPeerPublicKey`: kotlin.ByteArray, `filePath`: kotlin.String, `listener`: TransferListener?, `cancel`: TransferCancelHandle?): TransferReceiptDto

/**
 * Send one file over an already-established [`WanChannel`] (consumes the channel).
 */
@Throws(TransferFfiException::class)
public expect fun `transferSendWan`(`channel`: WanChannel, `filePath`: kotlin.String, `maxRelayBytes`: kotlin.ULong?, `listener`: TransferListener?, `cancel`: TransferCancelHandle?): TransferReceiptDto

/**
 * Verify a signature against an Ed25519 public key.
 */
public expect fun `verifyMessage`(`publicKey`: kotlin.ByteArray, `message`: kotlin.ByteArray, `signature`: kotlin.ByteArray): kotlin.Boolean

/**
 * The current 10-minute rendezvous epoch (`unix_seconds / 600`).
 */
public expect fun `wanCurrentEpoch`(): kotlin.ULong

/**
 * Derive the room id both peers must use for `epoch`.
 *
 * The PSK is required: without one the engine returns an empty room id rather
 * than deriving a room any third party could predict from the two public keys.
 */
@Throws(WanFfiException::class)
public expect fun `wanDeriveRoomId`(`myPublicKey`: kotlin.ByteArray, `peerPublicKey`: kotlin.ByteArray, `psk`: kotlin.ByteArray, `epoch`: kotlin.ULong): kotlin.String

