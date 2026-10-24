package com.kapp.luciola

import android.content.Context
import android.net.wifi.WifiManager
import android.os.Handler
import android.os.Looper

/**
 * Android entry point of the KMP library: one object wires the uniffi engine,
 * the MulticastLock (Wi-Fi drivers drop broadcast frames without it), the
 * network watcher and the supervision core together. Host UI code only calls
 * [start]/[close] and consumes [onPeersChanged] (always on the main thread).
 */
class AndroidDiscoveryController(
    context: Context,
    sessionName: String,
    discoveryPort: UShort = 17878u,
    private val onPeersChanged: (List<PeerUiModel>) -> Unit,
) : AutoCloseable {

    private val appContext: Context = context.applicationContext
    private val mainHandler = Handler(Looper.getMainLooper())

    private val multicastLock: WifiManager.MulticastLock
    private val engine = UniffiEngineAdapter(sessionName, discoveryPort)
    private val network = AndroidNetworkMonitor(appContext)

    val nodeId: String? get() = engine.nodeId()

    private val controller = DiscoveryController(
        engine = engine,
        network = network,
        scheduler = { delayMs, task -> mainHandler.postDelayed(task, delayMs) },
        onPeersChanged = { peers -> mainHandler.post { onPeersChanged(peers) } },
    )

    init {
        val wifi = appContext.getSystemService(Context.WIFI_SERVICE) as WifiManager
        multicastLock = wifi.createMulticastLock("luciola-kmp").apply {
            setReferenceCounted(false)
            acquire()
        }
    }

    fun start() = controller.start()

    override fun close() {
        controller.stop()
        multicastLock.release()
    }
}
