package io.github.kexuejin.luciola

import java.net.NetworkInterface
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

/**
 * Desktop JVM [NetworkMonitorPort]: polls [NetworkInterface] since the JVM has
 * no push-based connectivity callback. Good enough for tooling and the future
 * Compose Desktop demo.
 */
class DesktopNetworkMonitor(
    pollIntervalMs: Long = 5_000L,
    private val scheduler: TaskScheduler,
) : NetworkMonitorPort {

    private val lock = Any()
    private val handlers = mutableListOf<() -> Unit>()
    private val executor = Executors.newSingleThreadScheduledExecutor { r ->
        Thread(r, "luciola-kmp-netmon").apply { isDaemon = true }
    }
    private var lastSignature = signature()

    init {
        executor.scheduleWithFixedDelay({
            val sig = signature()
            synchronized(lock) {
                if (sig != lastSignature) {
                    lastSignature = sig
                    handlers.toList().forEach { it() }
                }
            }
        }, pollIntervalMs, pollIntervalMs, TimeUnit.MILLISECONDS)
    }

    private fun signature(): String = runCatching {
        NetworkInterface.getNetworkInterfaces().asSequence()
            .filter { it.isUp }
            .map { it.name }
            .toList().sorted().joinToString(",")
    }.getOrElse { "unknown" }

    override fun onChange(handler: () -> Unit) {
        synchronized(lock) { handlers.add(handler) }
    }

    override fun isNetworkUp(): Boolean = runCatching {
        NetworkInterface.getNetworkInterfaces().asSequence().any { it.isUp && !it.isLoopback }
    }.getOrElse { false }
}
