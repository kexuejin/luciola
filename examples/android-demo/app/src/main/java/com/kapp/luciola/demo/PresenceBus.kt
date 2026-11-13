package com.kapp.luciola.demo

import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import io.github.kexuejin.luciola.PeerUiModel

/** UDP discovery port; must match the desktop console's default. */
internal val DISCOVERY_PORT: UShort = 17878u

/** Product id carried in the engine's discovery envelopes. */
internal const val PRODUCT_ID = "luciola-radar-demo"

/**
 * Process-wide presence state, owned by [LuciolaPresenceService].
 *
 * The engine has to outlive the Activity: the whole point of the foreground
 * service is that the device stays visible on the LAN with the screen off or
 * the task swiped away. So the Activity no longer owns the
 * `AndroidDiscoveryController` — the service does, and publishes here.
 *
 * A process-wide object is sufficient because the service and the UI always
 * live in the same process; nothing here survives process death, and nothing
 * needs to (the service is `START_STICKY` and rebuilds the engine).
 *
 * The lists are Compose snapshot state so a write from the service's main-thread
 * callback recomposes the UI directly, with no extra plumbing.
 */
object PresenceBus {
    /** Peers as last reported by the engine. */
    val peers = mutableStateListOf<PeerUiModel>()

    /** True once the engine has bound its discovery socket. */
    val engineOn = mutableStateOf(false)

    /** Short human-readable lifecycle state for the status strip. */
    val status = mutableStateOf("stopped")

    fun publishPeers(list: List<PeerUiModel>) {
        peers.clear()
        peers.addAll(list)
    }
}
