package io.github.kexuejin.luciola

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
 * - Recovery from a failed bind, on a separate backoff track: see
 *   [ControllerConfig.bindRetryBaseMs]. A bind failure is not a dead network,
 *   so it must not consume the watchdog budget.
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
    private var bindRetryAttempt = 0

    /** Begin discovery and supervision. Idempotent. */
    fun start() {
        val wasStarted = lock.withLock {
            val was = started
            started = true
            if (!was) bindRetryAttempt = 0
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

    fun scheduleRestart(reason: String): Boolean =
        scheduleRestartAfter(config.restartDebounceMs, reason)

    /**
     * Debounced rebuild. Returns false when a restart was already pending (or
     * the session is stopped), so callers that keep a budget — the watchdog —
     * only charge themselves for restarts that actually happened.
     */
    private fun scheduleRestartAfter(delayMs: Long, reason: String): Boolean {
        val shouldSchedule = lock.withLock {
            if (restartPending || !started) {
                false
            } else {
                restartPending = true
                true
            }
        }
        if (!shouldSchedule) return false
        scheduler(delayMs) {
            lock.withLock { restartPending = false }
            engine.restart()
        }
        return true
    }

    /**
     * The engine could not bind its discovery port. Retry on its own backoff
     * track, outside the watchdog budget: whoever holds the port may release
     * it at any time (a sibling product on the same device uses the same
     * well-known port), and the only cost of retrying is a thread that lives
     * for the engine's bind window — no packets are sent while unbound.
     */
    private fun scheduleBindRetry() {
        // `SafeLock.withLock` is not inline, so the stopped case has to fall
        // through as a value rather than a non-local `return`.
        val attempt = lock.withLock {
            if (started) {
                bindRetryAttempt += 1
                bindRetryAttempt
            } else {
                0
            }
        }
        if (attempt == 0) return
        // 15s, 30s, 60s, 60s, … capped so a permanently occupied port settles
        // into one attempt per minute instead of one per watchdog tick.
        val shift = (attempt - 1).coerceAtMost(8)
        val delay = minOf(config.bindRetryBaseMs shl shift, config.bindRetryMaxMs)
        scheduleRestartAfter(delay, "bind failed (retry #$attempt)")
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
            is DiscoveryEventUi.Error -> {
                onEngineError?.invoke(event.code, event.message)
                if (event.code == ERROR_BIND_FAILED) scheduleBindRetry()
            }
        }
    }

    private fun upsert(peer: PeerUiModel) {
        val snapshot = lock.withLock {
            peers[peer.nodeId] = peer
            watchdogConsecutive = 0
            // A peer proves the engine bound and is receiving: the next bind
            // failure (if any) starts its backoff from the base delay again.
            bindRetryAttempt = 0
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
            // Charge the budget only when the rebuild was actually scheduled;
            // a restart already in flight (e.g. a bind retry) is not evidence
            // that the watchdog is spinning.
            val scheduled = scheduleRestart(
                "watchdog: engine idle ${idleSeconds.toLong()}s with network up",
            )
            if (scheduled) {
                lock.withLock { watchdogConsecutive += 1 }
            }
        }
        scheduleWatchdog()
    }

    private companion object {
        /** `ErrorCode::BindFailed` as reported by the Rust engine. */
        const val ERROR_BIND_FAILED = "bind_failed"
    }
}
