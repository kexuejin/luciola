package com.kapp.luciola

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
    sessionName: String,
    discoveryPort: UShort = 17878u,
    manualPeers: List<Pair<String, UShort>> = emptyList(),
    product: String? = null,
) : DiscoveryEnginePort {

    private val session = DiscoverySession(
        sessionName,
        discoveryPort,
        manualPeers.map { ManualPeer(host = it.first, port = it.second) },
        product,
    )

    override fun nodeId(): String? = session.nodeId()

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
)
