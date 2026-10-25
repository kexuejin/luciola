package com.kapp.luciola

import android.content.Context
import android.net.ConnectivityManager
import android.net.Network

/**
 * [NetworkMonitorPort] over [ConnectivityManager]: fires on interface up/down
 * and VPN tunnel toggles (ZeroTier, Tailscale, ...). The registration-time
 * onAvailable is swallowed — it is not a network *change*.
 */
class AndroidNetworkMonitor(context: Context) : NetworkMonitorPort {

    private val appContext: Context = context.applicationContext
    private val cm: ConnectivityManager =
        appContext.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager

    private val lock = Any()
    private val handlers = mutableListOf<() -> Unit>()
    private var firstCallback = true

    private val callback = object : ConnectivityManager.NetworkCallback() {
        override fun onAvailable(network: Network) {
            if (firstCallback) { firstCallback = false; return }
            dispatch()
        }
        override fun onLost(network: Network) = dispatch()
    }

    init {
        cm.registerDefaultNetworkCallback(callback)
        // Default-network tracking misses non-default interface changes (e.g.
        // a secondary VPN overlay like ZeroTier); an empty request watches ALL
        // networks. Registration-time callbacks are swallowed per registration.
        runCatching {
            cm.registerNetworkCallback(
                android.net.NetworkRequest.Builder().build(),
                object : ConnectivityManager.NetworkCallback() {
                    private var first = true
                    override fun onAvailable(network: Network) {
                        if (first) { first = false; return }
                        dispatch()
                    }
                    override fun onLost(network: Network) = dispatch()
                },
            )
        }
    }

    private fun dispatch() {
        synchronized(lock) { handlers.toList() }.forEach { it() }
    }

    override fun onChange(handler: () -> Unit) {
        synchronized(lock) { handlers.add(handler) }
    }

    override fun isNetworkUp(): Boolean = runCatching {
        cm.activeNetwork != null
    }.getOrElse { false }
}
