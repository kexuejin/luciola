package io.github.kexuejin.luciola

import kotlin.concurrent.Volatile
import kotlinx.cinterop.ExperimentalForeignApi
import platform.Network.nw_path_get_status
import platform.Network.nw_path_monitor_create
import platform.Network.nw_path_monitor_set_queue
import platform.Network.nw_path_monitor_set_update_handler
import platform.Network.nw_path_monitor_start
import platform.Network.nw_path_status_satisfied
import platform.darwin.dispatch_queue_create

/**
 * iOS [NetworkMonitorPort] over Network.framework's path monitor
 * (`nw_path_monitor`): one push callback per path change — interface flips,
 * VPN tunnel toggles, Wi-Fi to cellular handover.
 *
 * Uses the C `path_monitor` API rather than the Swift `NWPathMonitor`
 * class: this source set is Kotlin/Native over cinterop, and the
 * `platform.Network` klib exposes `nw_path_monitor_*` while the ObjC class
 * is Swift-only. Same underlying system monitor, different spelling.
 *
 * Behaviour mirrors [AndroidNetworkMonitor]:
 * - the first path update is the monitor's **baseline** (the system always
 *   reports the current path on start); it is recorded but not dispatched,
 *   because it is not a *change*;
 * - later updates dispatch all registered handlers on the monitor's serial
 *   queue thread. Hosts dispatch to the main thread themselves (the
 *   [DiscoveryController] contract: engine/network callbacks arrive on any
 *   thread).
 *
 * [isNetworkUp] reports the last path status. Before the first update it
 * reports **true** (unknown treated as up): a wrong "up" costs at most
 * `watchdogMaxConsecutive` bounded rebuilds, while a wrong "down" would starve
 * the watchdog entirely.
 */
@OptIn(ExperimentalForeignApi::class)
class IosNetworkMonitor : NetworkMonitorPort {

    private val lock = SafeLock()
    private val handlers = mutableListOf<() -> Unit>()

    /** True once the monitor delivered its baseline path. */
    private var baselineSeen = false

    /** Last reported path status; `true` until the first update arrives. */
    @Volatile
    private var satisfied = true

    private val queue = dispatch_queue_create("io.github.kexuejin.luciola.pathmon", null)

    private val monitor = requireNotNull(nw_path_monitor_create()) {
        "nw_path_monitor_create returned null"
    }

    init {
        nw_path_monitor_set_queue(monitor, queue)
        nw_path_monitor_set_update_handler(monitor) { path ->
            onPathUpdate(path?.let { nw_path_get_status(it) == nw_path_status_satisfied } ?: false)
        }
        nw_path_monitor_start(monitor)
    }

    private fun onPathUpdate(isSatisfied: Boolean) {
        satisfied = isSatisfied
        val dispatch: List<() -> Unit> = lock.withLock {
            if (!baselineSeen) {
                baselineSeen = true
                emptyList()
            } else {
                handlers.toList()
            }
        }
        dispatch.forEach { it() }
    }

    override fun onChange(handler: () -> Unit) {
        lock.withLock { handlers.add(handler) }
    }

    override fun isNetworkUp(): Boolean = satisfied
}
