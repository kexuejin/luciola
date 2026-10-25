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
    /** Stable per-device grouping id (display-grade). */
    val deviceId: String? = null,
    /** Product label running on the peer. */
    val product: String? = null,
)

/** Discovery lifecycle events delivered to [DiscoveryController]. */
sealed interface DiscoveryEventUi {
    data class Found(val peer: PeerUiModel) : DiscoveryEventUi
    data class Updated(val peer: PeerUiModel) : DiscoveryEventUi
    data class Lost(val nodeId: String) : DiscoveryEventUi
    /** Fatal setup problems, e.g. discovery port occupied by another product. */
    data class Error(val code: String, val message: String) : DiscoveryEventUi
}

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

    /** Begin discovery. `onEvent` may be invoked from any thread. */
    fun start(onEvent: (DiscoveryEventUi) -> Unit)

    /** Rebuild the engine in place (same listener + identity). */
    fun restart()

    /** Stop the engine and announce exit to neighbors. */
    fun stop()

    /** Seconds since the last peer discovery (or start). Large values on a
     *  networked device mean the engine stalled. */
    fun secondsSinceIdle(): Double
}

/** Canonical pairing payload (`luciola://pair` v2), common UI model. */
data class PairingUi(
    val name: String,
    val product: String?,
    val port: Int,
    val addrs: List<String>,
    /** Host identity fingerprint (`sha256:<hex>`) — bind trust on it. */
    val fingerprint: String?,
    /** Optional 6-digit on-screen comparison pin. */
    val pin: String?,
)

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

/** Per-channel dial outcome of a Happy Eyeballs race (common, UI-friendly). */
data class RaceChannelUi(
    val address: String,
    val won: Boolean,
    val cancelled: Boolean,
    val rttMs: Double?,
)

/** Overall race outcome: the winning address (if any) plus per-channel detail. */
data class RaceOutcomeUi(
    val winner: String?,
    val rttMs: Double?,
    val channels: List<RaceChannelUi>,
)
