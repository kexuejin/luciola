

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
 * One authenticated encrypted channel (see `luciola::link::secure`).
 * Message-oriented for FFI friendliness: `send` queues an encrypted frame;
 * received frames are decrypted and delivered through the listener.
 */
public interface SecureSessionInterface {
    
    /**
     * Race-dial every candidate address (Happy Eyeballs) and run the
     * authenticated handshake on the winning socket, with a PINNED peer key.
     *
     * With `auto_reconnect` the session re-dials with exponential backoff
     * (1s..30s) whenever the channel drops, until `disconnect()`.
     */
    public fun `connect`(`addresses`: List<kotlin.String>, `port`: kotlin.UShort, `pinnedPeerPublicKey`: kotlin.ByteArray, `autoReconnect`: kotlin.Boolean, `listener`: SecureSessionListener)
    
    /**
     * 关闭转发端点（幂等）。
     */
    public fun `disableForwardEndpoint`(): kotlin.Boolean
    
    /**
     * Close the channel; the peer sees the socket close. (Named
     * `disconnect` because the generated Disposable interface already owns
     * `close`.)
     */
    public fun `disconnect`()
    
    /**
     * 启用/替换服务端转发端点（仅 listen()/Responder 角色）：规则非空、
     * `port_from <= port_to`、tunnel_port 双栈冲突探测；失败同上走 on_state。
     */
    public fun `enableForwardEndpoint`(`rules`: List<ForwardRuleDto>): kotlin.Boolean
    
    /**
     * 快照全部转发状态：active（隧道已建立且 Guard 存活）、实际监听端口、
     * 历史折叠计数。注册过任何转发/端点后即有行，重建期间 active=false。
     */
    public fun `forwardStats`(): List<ForwardStatusDto>
    
    public fun `isConnected`(): kotlin.Boolean
    
    /**
     * Accept connections in a LOOP (one at a time). `expected_peer`: pin the
     * peer key, or None to accept any identity (TOFU — check the reported
     * fingerprint). The listener re-arms after each channel closes.
     */
    public fun `listen`(`port`: kotlin.UShort, `expectedPeer`: kotlin.ByteArray?, `listener`: SecureSessionListener)
    
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
     * 覆盖隧道端口（默认 = secure 端口 + 1；0 = 恢复默认）。改动触发链路重建。
     */
    public fun `setTunnelPort`(`port`: kotlin.UShort): kotlin.Boolean
    
    /**
     * 注册本地监听端口，经隧道转发到对端 `host:port`（仅 connect()/Dial 角色）。
     * `listen_port=0` → 系统分配，实端口见 [`Self::forward_stats`]。
     * 同步完成目标校验与端口冲突探测：失败返回 false 并 on_state(
     * "error", "forward_bind_failed: …" / 校验信息)。懒建立：首个注册后才建隧道。
     */
    public fun `startLocalForward`(`listenPort`: kotlin.UShort, `host`: kotlin.String, `port`: kotlin.UShort): kotlin.Boolean
    
    /**
     * Link health counters (sent/received frames, connections, retries).
     */
    public fun `stats`(): LinkStats
    
    /**
     * 注销本地转发（停止 Guard + 折叠计数）。未注册返回 false。
     */
    public fun `stopLocalForward`(`listenPort`: kotlin.UShort): kotlin.Boolean
    
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
    public constructor(noPointer: NoPointer)

    
    public constructor(`identitySeed`: kotlin.ByteArray)

    override fun destroy()
    override fun close()

    
    /**
     * Race-dial every candidate address (Happy Eyeballs) and run the
     * authenticated handshake on the winning socket, with a PINNED peer key.
     *
     * With `auto_reconnect` the session re-dials with exponential backoff
     * (1s..30s) whenever the channel drops, until `disconnect()`.
     */
    public override fun `connect`(`addresses`: List<kotlin.String>, `port`: kotlin.UShort, `pinnedPeerPublicKey`: kotlin.ByteArray, `autoReconnect`: kotlin.Boolean, `listener`: SecureSessionListener)
    
    /**
     * 关闭转发端点（幂等）。
     */
    public override fun `disableForwardEndpoint`(): kotlin.Boolean
    
    /**
     * Close the channel; the peer sees the socket close. (Named
     * `disconnect` because the generated Disposable interface already owns
     * `close`.)
     */
    public override fun `disconnect`()
    
    /**
     * 启用/替换服务端转发端点（仅 listen()/Responder 角色）：规则非空、
     * `port_from <= port_to`、tunnel_port 双栈冲突探测；失败同上走 on_state。
     */
    public override fun `enableForwardEndpoint`(`rules`: List<ForwardRuleDto>): kotlin.Boolean
    
    /**
     * 快照全部转发状态：active（隧道已建立且 Guard 存活）、实际监听端口、
     * 历史折叠计数。注册过任何转发/端点后即有行，重建期间 active=false。
     */
    public override fun `forwardStats`(): List<ForwardStatusDto>
    
    public override fun `isConnected`(): kotlin.Boolean
    
    /**
     * Accept connections in a LOOP (one at a time). `expected_peer`: pin the
     * peer key, or None to accept any identity (TOFU — check the reported
     * fingerprint). The listener re-arms after each channel closes.
     */
    public override fun `listen`(`port`: kotlin.UShort, `expectedPeer`: kotlin.ByteArray?, `listener`: SecureSessionListener)
    
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
     * 覆盖隧道端口（默认 = secure 端口 + 1；0 = 恢复默认）。改动触发链路重建。
     */
    public override fun `setTunnelPort`(`port`: kotlin.UShort): kotlin.Boolean
    
    /**
     * 注册本地监听端口，经隧道转发到对端 `host:port`（仅 connect()/Dial 角色）。
     * `listen_port=0` → 系统分配，实端口见 [`Self::forward_stats`]。
     * 同步完成目标校验与端口冲突探测：失败返回 false 并 on_state(
     * "error", "forward_bind_failed: …" / 校验信息)。懒建立：首个注册后才建隧道。
     */
    public override fun `startLocalForward`(`listenPort`: kotlin.UShort, `host`: kotlin.String, `port`: kotlin.UShort): kotlin.Boolean
    
    /**
     * Link health counters (sent/received frames, connections, retries).
     */
    public override fun `stats`(): LinkStats
    
    /**
     * 注销本地转发（停止 Guard + 折叠计数）。未注册返回 false。
     */
    public override fun `stopLocalForward`(`listenPort`: kotlin.UShort): kotlin.Boolean
    

    
    public companion object
}




/**
 * Persisted trust list. Serialize with [TrustStore::to_json] and store the
 * bytes in the product's secret storage; unpaired peers are simply absent
 * (default posture: deny).
 */
public interface TrustStoreInterface {
    
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
    public constructor(noPointer: NoPointer)

    
    public constructor(`fromJson`: kotlin.String?)

    override fun destroy()
    override fun close()

    
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
 * A generated or restored device identity. Keep `seed` secret.
 */

public data class DeviceIdentityInfo (
    var `seed`: kotlin.ByteArray, 
    var `publicKey`: kotlin.ByteArray, 
    var `fingerprint`: kotlin.String, 
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
    var `deviceType`: DeviceType, 
    var `icon`: kotlin.String, 
    var `os`: kotlin.String, 
    var `arch`: kotlin.String, 
    var `model`: kotlin.String?, 
    var `deviceId`: kotlin.String?
) {
    public companion object
}



/**
 * Per-channel dial outcome.
 */

public data class DialChannel (
    var `address`: kotlin.String, 
    var `status`: DialStatus, 
    var `rttMs`: kotlin.Double?
) {
    public companion object
}



/**
 * A discovered peer node in the local network.
 */

public data class DiscoveredPeer (
    var `nodeId`: kotlin.String, 
    var `name`: kotlin.String, 
    var `ip`: kotlin.String, 
    var `udpPort`: kotlin.UShort, 
    var `tcpPort`: kotlin.UShort, 
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
 * 转发规则（T3 `enable_forward_endpoint`）：单 IP 上的端口区间，含端点。
 */

public data class ForwardRuleDto (
    var `host`: kotlin.String, 
    var `portFrom`: kotlin.UShort, 
    var `portTo`: kotlin.UShort
) {
    public companion object
}



/**
 * 一条转发状态（T3 `forward_stats`）：历史折叠累计 + 实际监听端口。
 */

public data class ForwardStatusDto (
    var `active`: kotlin.Boolean, 
    var `listenPort`: kotlin.UShort, 
    var `channelsOpen`: kotlin.ULong, 
    var `channelsTotal`: kotlin.ULong, 
    var `dialDenied`: kotlin.ULong, 
    var `dialFailed`: kotlin.ULong
) {
    public companion object
}



/**
 * Link health counters for UI/diagnostics.
 */

public data class LinkStats (
    var `framesSent`: kotlin.ULong, 
    var `framesReceived`: kotlin.ULong, 
    var `connectionsEstablished`: kotlin.ULong, 
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
    var `host`: kotlin.String, 
    var `port`: kotlin.UShort
) {
    public companion object
}



/**
 * Canonical pairing payload. `fingerprint` is the host's identity
 * fingerprint — bind trust on it; `pin` is the optional 6-digit compare.
 */

public data class PairingInfo (
    var `name`: kotlin.String, 
    var `product`: kotlin.String?, 
    var `port`: kotlin.UShort, 
    var `addrs`: List<kotlin.String>, 
    var `fingerprint`: kotlin.String?, 
    var `publicKey`: kotlin.String?, 
    var `pin`: kotlin.String?
) {
    public companion object
}



/**
 * Overall race outcome: winning address plus per-channel detail.
 */

public data class RaceOutcome (
    var `winner`: kotlin.String?, 
    var `rttMs`: kotlin.Double?, 
    var `channels`: List<DialChannel>
) {
    public companion object
}



/**
 * A paired device entry.
 */

public data class TrustedDeviceInfo (
    var `deviceId`: kotlin.String, 
    var `name`: kotlin.String, 
    var `publicKey`: kotlin.ByteArray, 
    var `fingerprint`: kotlin.String, 
    var `level`: TrustLevel, 
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
 * Device form factor classification.
 */


public enum class DeviceType {
    
    MOBILE,
    TABLET,
    LAPTOP,
    DESKTOP,
    SERVER,
    WSL,
    UNKNOWN;
    public companion object
}








public enum class DialStatus {
    
    WON,
    CANCELLED,
    TIMEOUT;
    public companion object
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
 * Callbacks from the discovery engine. Products must implement all four;
 * `on_peer_updated` fires on profile/address changes, `on_peer_lost` when a
 * peer exits or ages out (update your peer table), `on_error` reports
 * fatal setup problems (e.g. discovery port occupied by another product).
 */
public interface OnPeerDiscovered {
    
    public fun `onPeerDiscovered`(`peer`: DiscoveredPeer)
    
    public fun `onPeerUpdated`(`peer`: DiscoveredPeer)
    
    public fun `onPeerLost`(`nodeId`: kotlin.String)
    
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
 * Retrieve all local addresses including VPN/tunnels (for unicast overlay sync).
 */
public expect fun `advertisedAddresses`(): List<kotlin.String>

public expect fun `buildPairingUri`(`name`: kotlin.String, `product`: kotlin.String?, `port`: kotlin.UShort, `addrs`: List<kotlin.String>, `fingerprint`: kotlin.String?, `publicKey`: kotlin.String?, `pin`: kotlin.String?): kotlin.String

/**
 * Symmetrical 6-digit on-screen comparison pin between two devices during pairing.
 */
public expect fun `comparisonPin`(`localPk`: kotlin.ByteArray, `remotePk`: kotlin.ByteArray): kotlin.String

/**
 * Selection policy shared with the demos: first 3 IPv4 candidates plus the
 * first IPv6 GUA. Feed the result into [race_connect].
 */
public expect fun `defaultRaceCandidates`(`addresses`: List<kotlin.String>): List<kotlin.String>

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

public expect fun `parsePairingUri`(`uri`: kotlin.String): PairingInfo?

/**
 * Race TCP dials across `addresses` on `port` (Happy Eyeballs): the first
 * connect wins, the rest are cancelled. Blocking; call off the UI thread.
 */
public expect fun `raceConnect`(`addresses`: List<kotlin.String>, `port`: kotlin.UShort, `attemptTimeoutMs`: kotlin.ULong?, `staggerMs`: kotlin.ULong?): RaceOutcome

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
 * Verify a signature against an Ed25519 public key.
 */
public expect fun `verifyMessage`(`publicKey`: kotlin.ByteArray, `message`: kotlin.ByteArray, `signature`: kotlin.ByteArray): kotlin.Boolean

