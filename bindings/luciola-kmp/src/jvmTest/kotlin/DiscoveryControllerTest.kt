package io.github.kexuejin.luciola

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * Supervision policy of [DiscoveryController], driven by hand: the scheduler is
 * a queue the test pumps, so nothing here waits on a real clock.
 *
 * The case these tests exist for is the one found on a physical Pixel 6: a
 * co-resident app held UDP 17878, the engine failed to bind, and the session
 * then stayed dead forever — the watchdog spent its 3-restart budget on a
 * failure it could not fix and never tried again.
 */

private const val WATCHDOG_INTERVAL = 10_000L
private const val DEBOUNCE = 100L

private class FakeEngine : DiscoveryEnginePort {
    var emit: ((DiscoveryEventUi) -> Unit)? = null
    var starts = 0
    var restarts = 0
    var stops = 0
    var idleSeconds = 0.0

    override fun nodeId(): String = "fake-node"

    override fun start(onEvent: (DiscoveryEventUi) -> Unit) {
        starts += 1
        emit = onEvent
    }

    override fun restart() {
        restarts += 1
    }

    override fun stop() {
        stops += 1
    }

    override fun secondsSinceIdle(): Double = idleSeconds
}

private class FakeNetwork : NetworkMonitorPort {
    var up = true
    var handler: (() -> Unit)? = null

    override fun onChange(handler: () -> Unit) {
        this.handler = handler
    }

    override fun isNetworkUp(): Boolean = up
}

/** A [TaskScheduler] that only runs tasks when the test asks it to. */
private class ManualScheduler : (Long, () -> Unit) -> Unit {
    private val pending = mutableListOf<Pair<Long, () -> Unit>>()

    override fun invoke(delayMs: Long, task: () -> Unit) {
        pending += delayMs to task
    }

    private fun takeFirst(predicate: (Long) -> Boolean): Pair<Long, () -> Unit>? {
        val index = pending.indexOfFirst { predicate(it.first) }
        if (index < 0) return null
        return pending.removeAt(index)
    }

    /** Run the next non-watchdog task (a restart) and report its delay. */
    fun runRestart(): Long {
        val task = requireNotNull(takeFirst { it != WATCHDOG_INTERVAL }) {
            "no restart was scheduled; queue=$pending"
        }
        task.second()
        return task.first
    }

    /** Run one watchdog poll, plus the restart it scheduled (if any). */
    fun runWatchdog() {
        val tick = requireNotNull(takeFirst { it == WATCHDOG_INTERVAL }) {
            "watchdog did not re-arm; queue=$pending"
        }
        tick.second()
        takeFirst { it != WATCHDOG_INTERVAL }?.second()
    }

    fun delays(): List<Long> = pending.map { it.first }
}

private fun controllerWith(
    engine: FakeEngine,
    network: FakeNetwork,
    scheduler: ManualScheduler,
    onEngineError: (String, String) -> Unit,
): DiscoveryController = DiscoveryController(
    engine = engine,
    network = network,
    config = ControllerConfig(
        restartDebounceMs = DEBOUNCE,
        watchdogIntervalMs = WATCHDOG_INTERVAL,
        watchdogIdleMs = 60_000.0,
        watchdogMaxConsecutive = 3,
        bindRetryBaseMs = 1_000L,
        bindRetryMaxMs = 4_000L,
    ),
    scheduler = scheduler,
    onPeersChanged = {},
    onEngineError = onEngineError,
)

class DiscoveryControllerTest {

    @Test
    fun bindFailureRetriesBackOffAndOutliveTheWatchdogBudget() {
        val engine = FakeEngine()
        val network = FakeNetwork()
        val scheduler = ManualScheduler()
        val errors = mutableListOf<String>()
        val controller = controllerWith(engine, network, scheduler) { code, message ->
            errors += "$code: $message"
        }

        controller.start()
        assertEquals(1, engine.starts)

        // 1s, 2s, 4s, then the 4s cap — five failures is already more than
        // watchdogMaxConsecutive (3), which is the whole point.
        val expected = listOf(1_000L, 2_000L, 4_000L, 4_000L, 4_000L)
        expected.forEach { want ->
            engine.emit!!.invoke(DiscoveryEventUi.Error("bind_failed", "port 17878 busy"))
            assertEquals(want, scheduler.runRestart(), "backoff delay")
        }
        assertEquals(5, engine.restarts)
        assertEquals(5, errors.size)
        assertTrue(errors.first().startsWith("bind_failed: "), errors.first())

        // A bind failure must not have eaten the watchdog budget: an idle
        // engine with a live network still gets rebuilt.
        engine.idleSeconds = 120.0
        scheduler.runWatchdog()
        assertEquals(6, engine.restarts)
    }

    @Test
    fun idleWatchdogStaysBounded() {
        val engine = FakeEngine()
        val network = FakeNetwork()
        val scheduler = ManualScheduler()
        val controller = controllerWith(engine, network, scheduler) { _, _ -> }

        controller.start()
        engine.idleSeconds = 120.0 // > watchdogIdleMs

        repeat(4) { scheduler.runWatchdog() }

        // 3 rebuilds (watchdogMaxConsecutive), then the watchdog stops
        // scheduling restarts even though the engine is still idle.
        assertEquals(3, engine.restarts)
    }

    @Test
    fun networkChangeRestartsOnce() {
        val engine = FakeEngine()
        val network = FakeNetwork()
        val scheduler = ManualScheduler()
        val controller = controllerWith(engine, network, scheduler) { _, _ -> }

        controller.start()
        network.handler!!.invoke()
        network.handler!!.invoke() // same burst: debounced away
        assertEquals(DEBOUNCE, scheduler.runRestart())
        assertEquals(1, engine.restarts)
    }

    @Test
    fun stoppedControllerDoesNotRetry() {
        val engine = FakeEngine()
        val network = FakeNetwork()
        val scheduler = ManualScheduler()
        val controller = controllerWith(engine, network, scheduler) { _, _ -> }

        controller.start()
        controller.stop()
        engine.emit!!.invoke(DiscoveryEventUi.Error("bind_failed", "port 17878 busy"))

        assertTrue(
            scheduler.delays().none { it != WATCHDOG_INTERVAL },
            "a stopped session must not schedule a bind retry; queue=${scheduler.delays()}",
        )
    }
}
