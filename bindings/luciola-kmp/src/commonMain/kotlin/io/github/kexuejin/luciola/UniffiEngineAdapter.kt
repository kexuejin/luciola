package io.github.kexuejin.luciola

import uniffi.luciola_uniffi.DiscoveredPeer
import uniffi.luciola_uniffi.DiscoverySession
import uniffi.luciola_uniffi.ManualPeer
import uniffi.luciola_uniffi.OnPeerDiscovered

/**
 * [DiscoveryEnginePort] over the uniffi-generated Kotlin bindings (JVM/Android,
 * JNA-backed). Supervision primitives (stable identity, in-place `restart`,
 * bind retry, idle timestamp) live in the Rust engine itself, so this adapter
 * stays thin.
 */
class UniffiEngineAdapter(
    private val sessionName: String,
    private val discoveryPort: UShort = 17878u,
    manualPeers: List<Pair<String, UShort>> = emptyList(),
    private val product: String? = null,
    private val extra: String? = null,
) : DiscoveryEnginePort {

    private val manualPeers = manualPeers.toMutableList()

    private fun rebuildSession() = DiscoverySession(
        sessionName,
        discoveryPort,
        manualPeers.map { ManualPeer(host = it.first, port = it.second) },
        product,
        extra,
    )

    private val lock = SafeLock()
    private var session = rebuildSession()

    // 跨平台：JVM 的 synchronized 在 Kotlin/Native 不存在，用模块自带的 SafeLock。
    override fun nodeId(): String? = lock.withLock { session }.nodeId()

    override fun start(onEvent: (DiscoveryEventUi) -> Unit) {
        session.start(object : OnPeerDiscovered {
            override fun onPeerDiscovered(peer: DiscoveredPeer) {
                onEvent(DiscoveryEventUi.Found(peer.toUiModel()))
            }

            override fun onPeerUpdated(peer: DiscoveredPeer) {
                onEvent(DiscoveryEventUi.Updated(peer.toUiModel()))
            }

            override fun onPeerLost(nodeId: String) {
                onEvent(DiscoveryEventUi.Lost(nodeId))
            }

            override fun onError(code: String, message: String) {
                onEvent(DiscoveryEventUi.Error(code, message))
            }
        })
    }

    override fun restart() {
        session.restart()
    }

    /**
     * Directed dial: add (or refresh) a unicast target and re-announce to it
     * immediately — the discovery-layer equivalent of a directed `entry`.
     */
    fun dial(host: String, port: UShort) {
        manualPeers.removeAll { it.first == host }
        manualPeers += host to port
        session.setManualPeers(manualPeers.map { ManualPeer(host = it.first, port = it.second) })
        session.restart()
    }

    override fun stop() {
        session.stop()
    }

    override fun secondsSinceIdle(): Double = session.secondsSinceIdle()
}

fun DiscoveredPeer.toUiModel(): PeerUiModel = PeerUiModel(
    nodeId = nodeId,
    name = name,
    ip = ip,
    udpPort = udpPort.toInt(),
    tcpPort = tcpPort.toInt(),
    deviceType = device?.deviceType?.name?.lowercase(),
    icon = device?.icon,
    os = device?.os,
    arch = device?.arch,
    model = device?.model,
    deviceId = deviceId ?: device?.deviceId,
    product = product,
    extra = extra,
)