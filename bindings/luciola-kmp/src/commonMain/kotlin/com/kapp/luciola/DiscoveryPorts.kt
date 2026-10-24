package com.kapp.luciola

/** A discovered LAN peer, normalized for UI layers. */
data class PeerUiModel(
    val nodeId: String,
    val name: String,
    val ip: String,
    val udpPort: Int,
    val tcpPort: Int,
    val deviceType: String?,
    val icon: String?,
    val os: String?,
    val arch: String?,
    val model: String?,
)

/**
 * Port to the platform engine binding. Implementations:
 * - Android/JVM: the uniffi-generated Kotlin bindings (`uniffi.luciola_uniffi`).
 * - iOS: a Swift adapter over the uniffi Swift bindings (bindings/luciola-swift),
 *   handed to [DiscoveryController] through the KMP framework.
 */
interface DiscoveryEnginePort {
    /** Stable identity of this device's engine; host-side helper sockets (sweeps,
     *  unicast reconciliation) must present the same id and name. */
    fun nodeId(): String?

    /** Begin discovery. `onPeer` may be invoked from any thread. */
    fun start(onPeer: (PeerUiModel) -> Unit)

    /** Rebuild the engine in place (same listener + identity). */
    fun restart()

    /** Stop the engine and announce exit to neighbors. */
    fun stop()

    /** Seconds since the last peer discovery (or start). Large values on a
     *  networked device mean the engine stalled. */
    fun secondsSinceIdle(): Double
}

/** Port to platform network-state observation. */
interface NetworkMonitorPort {
    /** Register a handler invoked whenever the network set changes
     *  (interface up/down, VPN tunnel toggles). May fire multiple times in a
     *  burst for one user-visible change. */
    fun onChange(handler: () -> Unit)

    /** True when the system has at least one usable network. */
    fun isNetworkUp(): Boolean
}

/** Host-provided timer: run [task] on some scheduler after [delayMs]. */
typealias TaskScheduler = (delayMs: Long, task: () -> Unit) -> Unit

data class ControllerConfig(
    /** Merge bursts of network callbacks into one restart. */
    val restartDebounceMs: Long = 800L,
    /** Watchdog poll cadence. */
    val watchdogIntervalMs: Long = 15_000L,
    /** Engine silent for this long with a live network => rebuild. */
    val watchdogIdleMs: Double = 45_000.0,
    /** Stop auto-rebuilding after this many consecutive watchdog restarts so a
     *  genuinely dead network does not spin. */
    val watchdogMaxConsecutive: Int = 3,
)
