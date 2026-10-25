package com.kapp.luciola

/**
 * Platform-agnostic supervision core for a Luciola discovery session.
 *
 * Owns three concerns that host integrations should not have to re-implement:
 * - Peer table maintenance with change notifications.
 * - Debounced engine rebuilds when the network set changes (VPN tunnels,
 *   Wi-Fi switches) — one restart per burst, not per callback.
 * - A watchdog: when the network is up but the engine has been silent past
 *   [ControllerConfig.watchdogIdleMs], rebuild it (bounded by
 *   [ControllerConfig.watchdogMaxConsecutive] so a genuinely dead network
 *   does not spin).
 *
 * Thread model: engine callbacks may arrive on any thread; peer state is
 * guarded by [lock]. [onPeersChanged] is invoked synchronously — hosts
 * dispatch it to their own UI thread (the Android wrapper already does).
 *
 * Runs on Android, JVM and iOS: the engine/network ports are injected
 * (Android/JVM via the uniffi Kotlin bindings, iOS via a Swift adapter over
 * the uniffi Swift bindings).
 */
class DiscoveryController(
    private val engine: DiscoveryEnginePort,
    private val network: NetworkMonitorPort,
    private val config: ControllerConfig = ControllerConfig(),
    private val scheduler: TaskScheduler,
    private val onPeersChanged: (List<PeerUiModel>) -> Unit,
    /** Fatal engine problems (e.g. port occupied); hosts surface these in UI. */
    private val onEngineError: ((code: String, message: String) -> Unit)? = null,
) {
    private val lock = SafeLock()
    private val peers = LinkedHashMap<String, PeerUiModel>()
    private var started = false
    private var restartPending = false
    private var watchdogConsecutive = 0
    private var watchdogScheduled = false

    /** Begin discovery and supervision. Idempotent. */
    fun start() {
        val wasStarted = lock.withLock {
            val was = started
            started = true
            was
        }
        if (wasStarted) return
        engine.start(::onEventFromEngine)
        network.onChange { scheduleRestart("network change") }
        scheduleWatchdog()
    }

    /** Stop the engine and supervision. Peer table is kept for the host UI. */
    fun stop() {
        lock.withLock { started = false }
        engine.stop()
    }

    /** Current peer snapshot. */
    fun snapshot(): List<PeerUiModel> = lock.withLock { peers.values.toList() }

    /** Clear the peer table (e.g. host wants a clean slate after a long stall). */
    fun clearPeers() {
        val snapshot = lock.withLock {
            peers.clear()
            peers.values.toList()
        }
        onPeersChanged(snapshot)
    }

    fun scheduleRestart(reason: String) {
        val shouldSchedule = lock.withLock {
            if (restartPending || !started) {
                false
            } else {
                restartPending = true
                true
            }
        }
        if (!shouldSchedule) return
        scheduler(config.restartDebounceMs) {
            lock.withLock { restartPending = false }
            engine.restart()
        }
    }

    private fun onEventFromEngine(event: DiscoveryEventUi) {
        when (event) {
            is DiscoveryEventUi.Found -> upsert(event.peer)
            is DiscoveryEventUi.Updated -> upsert(event.peer)
            is DiscoveryEventUi.Lost -> {
                val snapshot = lock.withLock {
                    peers.remove(event.nodeId)
                    peers.values.toList()
                }
                onPeersChanged(snapshot)
            }
            is DiscoveryEventUi.Error -> onEngineError?.invoke(event.code, event.message)
        }
    }

    private fun upsert(peer: PeerUiModel) {
        val snapshot = lock.withLock {
            peers[peer.nodeId] = peer
            watchdogConsecutive = 0
            peers.values.toList()
        }
        onPeersChanged(snapshot)
    }

    private fun scheduleWatchdog() {
        val shouldSchedule = lock.withLock {
            if (watchdogScheduled) {
                false
            } else {
                watchdogScheduled = true
                true
            }
        }
        if (!shouldSchedule) return
        scheduler(config.watchdogIntervalMs) {
            lock.withLock { watchdogScheduled = false }
            watchdogTick()
        }
    }

    private fun watchdogTick() {
        val idleSeconds = engine.secondsSinceIdle()
        val networkUp = runCatching { network.isNetworkUp() }.getOrElse { false }
        val shouldRebuild = networkUp &&
            idleSeconds * 1000.0 > config.watchdogIdleMs &&
            watchdogConsecutive < config.watchdogMaxConsecutive
        if (shouldRebuild) {
            watchdogConsecutive = lock.withLock { watchdogConsecutive + 1 }
            scheduleRestart("watchdog: engine idle ${idleSeconds.toLong()}s with network up")
        }
        scheduleWatchdog()
    }
}
