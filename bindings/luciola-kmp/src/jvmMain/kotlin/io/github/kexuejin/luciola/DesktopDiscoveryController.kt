package io.github.kexuejin.luciola

import java.util.concurrent.Executor
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.TimeUnit

/**
 * Desktop / plain-JVM entry point of the KMP library: the sibling of
 * `AndroidDiscoveryController` for hosts with no Android `Context` — CLI
 * tooling, Compose Desktop, a headless sweep helper.
 *
 * It wires the three existing pieces together and adds nothing of its own:
 * [UniffiEngineAdapter] (engine port), [DesktopNetworkMonitor] (network port —
 * the JVM has no push-based connectivity callback, so it polls interfaces) and
 * the platform-agnostic [DiscoveryController] supervision core.
 *
 * Native library: the JVM binding surface reaches the Rust core through JNA, so
 * `libluciola_uniffi.dylib` (macOS) or `libluciola_uniffi.so` (Linux) has to be
 * loadable before the engine adapter is constructed. A missing library surfaces
 * as an `UnsatisfiedLinkError` from JNA, not as a discovery bug — point JNA at
 * the build output with `-Djna.library.path=<dir>`.
 *
 * Thread model, spelled out because a desktop host has no main looper to fall
 * back on (the Android shell marshals to one implicitly; this one refuses to
 * guess):
 * - Timers (debounced restarts, watchdog) run on the host's [taskScheduler] if
 *   one is given, otherwise on an internal single-thread **daemon**
 *   [ScheduledExecutorService] (`luciola-kmp-desktop-timer`). Daemon so a host
 *   that forgets to [close] can still exit the JVM.
 * - [onPeersChanged] and [onEngineError] are delivered through
 *   [callbackExecutor] when one is supplied. With **null they are invoked
 *   synchronously on the thread that produced the event** — an engine callback
 *   thread or the monitor's polling thread. A Compose Desktop host should pass
 *   an executor backed by its UI dispatcher so state writes stay on one thread;
 *   a headless host can pass null and skip the hop.
 * - [snapshot], [nodeId] and [clearPeers] are safe from any thread.
 *
 * A rejected callback delivery (executor already shut down) is swallowed rather
 * than propagated: throwing inside an engine callback would kill the callback
 * thread the Rust side owns. The next beacon re-delivers the peers, so a dropped
 * snapshot is self-healing while a dead engine thread is not.
 */
class DesktopDiscoveryController(
    /** Engine port; the convenience constructor supplies [UniffiEngineAdapter]. */
    private val engine: DiscoveryEnginePort,
    /**
     * Network port. Null means "create a [DesktopNetworkMonitor] on this
     * controller's own scheduler" — it cannot be a plain default expression
     * because the monitor needs the scheduler this object ends up using, which
     * is only known after [taskScheduler] is resolved.
     */
    network: NetworkMonitorPort? = null,
    /** Timer source; null means the internal daemon-thread scheduler. */
    taskScheduler: TaskScheduler? = null,
    /** Where UI callbacks are delivered; null means "same thread as the event". */
    private val callbackExecutor: Executor? = null,
    /** Only used when [network] is null. */
    networkPollIntervalMs: Long = 5_000L,
    private val onPeersChanged: (List<PeerUiModel>) -> Unit,
    private val onEngineError: ((code: String, message: String) -> Unit)? = null,
) : AutoCloseable {

    /**
     * Convenience wiring for a desktop host that only wants discovery: same
     * argument meanings as the Android shell (session name, UDP discovery port,
     * unicast manual peers, advertised product label), minus `Context`.
     */
    constructor(
        sessionName: String,
        discoveryPort: UShort = 17878u,
        manualPeers: List<Pair<String, UShort>> = emptyList(),
        product: String? = null,
        callbackExecutor: Executor? = null,
        taskScheduler: TaskScheduler? = null,
        onPeersChanged: (List<PeerUiModel>) -> Unit,
        onEngineError: ((code: String, message: String) -> Unit)? = null,
    ) : this(
        engine = UniffiEngineAdapter(sessionName, discoveryPort, manualPeers, product),
        network = null,
        taskScheduler = taskScheduler,
        callbackExecutor = callbackExecutor,
        onPeersChanged = onPeersChanged,
        onEngineError = onEngineError,
    )

    /**
     * Always allocated, but a `ScheduledThreadPoolExecutor` starts its worker
     * thread lazily on the first task, so a host that injects its own scheduler
     * pays an object, not a thread. [close] shuts it down either way.
     */
    private val timer: ScheduledExecutorService =
        Executors.newSingleThreadScheduledExecutor { runnable ->
            Thread(runnable, "luciola-kmp-desktop-timer").apply { isDaemon = true }
        }

    private val scheduler: TaskScheduler = taskScheduler
        ?: { delayMs: Long, task: () -> Unit ->
            timer.schedule(task, delayMs, TimeUnit.MILLISECONDS)
        }

    private val networkMonitor: NetworkMonitorPort =
        network ?: DesktopNetworkMonitor(networkPollIntervalMs, scheduler)

    private val controller = DiscoveryController(
        engine = engine,
        network = networkMonitor,
        scheduler = scheduler,
        onPeersChanged = { peers -> deliver { onPeersChanged(peers) } },
        onEngineError = { code, message -> deliver { onEngineError?.invoke(code, message) } },
    )

    /** Stable identity of this device's engine — helper sockets must present the same id. */
    val nodeId: String? get() = engine.nodeId()

    /** Begin discovery and supervision. Idempotent. */
    fun start() = controller.start()

    /** Stop the engine and supervision; the peer table is kept for the host UI. */
    fun stop() = controller.stop()

    /** Current peer snapshot; safe from any thread. */
    fun snapshot(): List<PeerUiModel> = controller.snapshot()

    /** Drop the peer table (clean slate after a long stall). */
    fun clearPeers() = controller.clearPeers()

    /** [stop] plus shutdown of the internal timer. Idempotent. */
    override fun close() {
        controller.stop()
        timer.shutdown()
    }

    private inline fun deliver(crossinline body: () -> Unit) {
        val executor = callbackExecutor
        if (executor == null) {
            body()
        } else {
            try {
                executor.execute { body() }
            } catch (_: RuntimeException) {
                // Rejection after shutdown — see the class KDoc for why this is swallowed.
            }
        }
    }
}
