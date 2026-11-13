package com.kapp.luciola.demo

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.IBinder
import android.util.Log
import androidx.core.app.NotificationCompat
import androidx.core.app.ServiceCompat
import io.github.kexuejin.luciola.AndroidDiscoveryController

/**
 * Keeps the LAN discovery engine alive while the app is not in the foreground.
 *
 * ## Why a foreground service, and why `connectedDevice`
 *
 * The engine holds a bound UDP socket and answers `alive`/`presence` probes.
 * An Activity-scoped engine dies with the Activity, so a phone with the screen
 * off silently disappears from every peer's radar — the exact failure this
 * service exists to prevent. Only a foreground service with an ongoing
 * notification is allowed to hold a socket like that indefinitely.
 *
 * `dataSync` would be the obvious type, but Android 15+ caps `dataSync`
 * foreground services at **6 hours per 24-hour period** and then calls
 * `onTimeout`, which is worse than useless for a presence socket. `connectedDevice`
 * has no such cap and matches the intent (maintaining a network link to an
 * external device); its prerequisite is one of `BLUETOOTH_*`,
 * `CHANGE_NETWORK_STATE`, `CHANGE_WIFI_STATE`, `CHANGE_WIFI_MULTICAST_STATE`,
 * `NFC`, `TRANSMIT_IR` or `UWB_RANGING` — this app already declares
 * `CHANGE_WIFI_MULTICAST_STATE` for the `MulticastLock`, so no extra
 * prerequisite is needed.
 *
 * ## Lifecycle
 *
 * `START_STICKY`: if the system reclaims the process, the service is recreated
 * with a null intent, falls through to [startEngine] and re-announces. The
 * engine's own supervision (watchdog, network watcher, debounced rebuilds)
 * lives in the KMP library, so this class only owns process-level lifetime.
 */
class LuciolaPresenceService : Service() {

    private var controller: AndroidDiscoveryController? = null

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onCreate() {
        super.onCreate()
        createChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            ServiceCompat.stopForeground(this, ServiceCompat.STOP_FOREGROUND_REMOVE)
            stopSelf()
            return START_NOT_STICKY
        }
        // Must precede the engine work: the system kills a service that fails to
        // post its notification in time, and binding the socket can take a
        // moment on a cold start.
        goForeground()
        startEngine()
        return START_STICKY
    }

    override fun onDestroy() {
        controller?.close()
        controller = null
        PresenceBus.engineOn.value = false
        PresenceBus.status.value = "stopped"
        PresenceBus.publishPeers(emptyList())
        super.onDestroy()
    }

    // ---------------------------------------------------------------------
    // Engine
    // ---------------------------------------------------------------------

    /**
     * All supervision (MulticastLock, network watcher, watchdog, debounced
     * engine rebuilds) lives in the KMP library — this only owns the lifetime.
     */
    private fun startEngine() {
        if (controller != null) return
        val name = Build.MODEL ?: "Android Peer"
        try {
            val c = AndroidDiscoveryController(
                context = this,
                sessionName = name,
                discoveryPort = DISCOVERY_PORT,
                product = PRODUCT_ID,
                onPeersChanged = { list ->
                    PresenceBus.publishPeers(list)
                    refreshNotification()
                },
                onEngineError = { code, message ->
                    Log.w(TAG, "engine error $code: $message")
                    // The engine failed *after* start() returned, so the
                    // "online" state set below is now a lie. Clear it: the
                    // notification and the header both read this flag, and a
                    // dead engine that renders as online is worse than no
                    // status at all. The controller retries a bind failure on
                    // its own, so the service stays up — only the claim
                    // changes.
                    PresenceBus.engineOn.value = false
                    PresenceBus.status.value = "error: $code"
                    refreshNotification()
                },
            )
            c.start()
            controller = c
            PresenceBus.engineOn.value = true
            PresenceBus.status.value = "online"
            Log.i(TAG, "presence engine started as $name on :$DISCOVERY_PORT (nodeId=${c.nodeId})")
            refreshNotification()
        } catch (e: Exception) {
            // A failed bind must not leave a "running" service with no engine:
            // report it and stop, so the notification does not lie.
            Log.e(TAG, "engine start failed", e)
            PresenceBus.engineOn.value = false
            PresenceBus.status.value = "failed: ${e.message}"
            ServiceCompat.stopForeground(this, ServiceCompat.STOP_FOREGROUND_REMOVE)
            stopSelf()
        }
    }

    // ---------------------------------------------------------------------
    // Notification
    // ---------------------------------------------------------------------

    private fun createChannel() {
        val manager = getSystemService(NotificationManager::class.java) ?: return
        // minSdk 26, so NotificationChannel is always available.
        val channel = NotificationChannel(
            CHANNEL_ID,
            "局域网在线状态",
            NotificationManager.IMPORTANCE_LOW,
        ).apply {
            description = "保持本机在局域网中可见所需的常驻通知"
            setShowBadge(false)
        }
        manager.createNotificationChannel(channel)
    }

    private fun goForeground() {
        val notification = buildNotification(PresenceBus.peers.size)
        // Foreground-service types only exist from API 29. `ServiceCompat`
        // drops the argument below that, so pass 0 explicitly rather than
        // referencing a Q-only constant from a minSdk-26 code path.
        val type = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            ServiceInfo.FOREGROUND_SERVICE_TYPE_CONNECTED_DEVICE
        } else {
            0
        }
        ServiceCompat.startForeground(this, NOTIFICATION_ID, notification, type)
    }

    private fun refreshNotification() {
        if (controller == null) return
        val manager = getSystemService(NotificationManager::class.java) ?: return
        manager.notify(NOTIFICATION_ID, buildNotification(PresenceBus.peers.size))
    }

    private fun buildNotification(peerCount: Int): Notification {
        val open = PendingIntent.getActivity(
            this,
            0,
            Intent(this, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        val stop = PendingIntent.getService(
            this,
            1,
            Intent(this, LuciolaPresenceService::class.java).setAction(ACTION_STOP),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("Luciola 萤火")
            .setContentText(
                if (PresenceBus.engineOn.value) {
                    "局域网发现在线 · $peerCount 台设备可见"
                } else {
                    "引擎未启动"
                },
            )
            // Demo-grade icon: a real app ships a monochrome vector. The system
            // tints a small icon, so a coloured drawable renders as a silhouette.
            .setSmallIcon(android.R.drawable.ic_menu_compass)
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .setShowWhen(false)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .setContentIntent(open)
            .addAction(0, "停止", stop)
            .build()
    }

    companion object {
        private const val TAG = "LuciolaPresence"
        private const val CHANNEL_ID = "luciola.presence"
        private const val NOTIFICATION_ID = 0x4C75
        const val ACTION_STOP = "com.kapp.luciola.demo.STOP_PRESENCE"

        /** Start the presence service. Safe to call repeatedly. */
        fun start(context: Context) {
            context.startForegroundService(
                Intent(context, LuciolaPresenceService::class.java),
            )
        }

        /** Stop the presence service and tear the engine down. */
        fun stop(context: Context) {
            context.stopService(Intent(context, LuciolaPresenceService::class.java))
        }
    }
}
