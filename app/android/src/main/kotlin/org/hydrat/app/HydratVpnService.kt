package org.hydrat.app

import android.Manifest
import android.content.pm.PackageManager
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.os.PowerManager
import org.json.JSONObject
import java.util.concurrent.Executors

class HydratVpnService : VpnService() {
    private val worker = Executors.newSingleThreadExecutor()
    private var tunnel: ParcelFileDescriptor? = null
    private var nativeRunning = false
    private var stopping = false
    private var destroyed = false
    private var screenReceiverRegistered = false
    private val screenReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) {
            NativeEngine.setScreenInteractive(intent.action == Intent.ACTION_SCREEN_ON)
        }
    }


    override fun onCreate() {
        super.onCreate()
        UiLanguage.load(this)
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == STOP) {
            disconnect()
            return START_NOT_STICKY
        }
        if ((state == "off" || state == "failed") && !stopping && !destroyed) {
            state = "starting"
            startForeground(NOTIFICATION, notification(tr("Подключение")))
            worker.execute {
                val ready = runCatching {
                    NativeEngine.initialize(this)
                    val status = NativeEngine.status()?.decodeToString()?.let(::JSONObject)
                    (status?.optInt("Sources") ?: 0) > 0
                }.getOrDefault(false)
                mainExecutor.execute {
                    if (!stopping && !destroyed) {
                        if (ready) establishTunnel() else fail()
                    }
                }
            }
        }
        return START_NOT_STICKY
    }

    private fun establishTunnel() {
        val descriptor = tunnel ?: runCatching {
            Builder().setSession("Hydrat")
                .setMtu(1500)
                .addAddress("10.231.90.2", 32)
                .addRoute("0.0.0.0", 0)
                .addAddress("fd24:6b91:e70d::2", 126)
                .addRoute("::", 0)
                // DNS needs a distinct destination so Android sends requests into the TUN.
                .addDnsServer("10.231.90.1")
                .addDisallowedApplication(packageName)
                .establish()
        }.getOrNull()
        if (descriptor == null) {
            fail()
            return
        }
        tunnel = descriptor
        blockingTraffic = true
        if (NativeEngine.prepare() != 0) {
            fail()
            return
        }
        nativeRunning = true
        state = "running"
        updateNotification(tr("VPN включён"))
        val preferences = ConnectionPreferences(this)
        val dnsPreset = preferences.dnsPreset
        val geoRules = preferences.geoRules
        val settings = preferences.settingsJson()
        if (!screenReceiverRegistered) monitorScreen()
        worker.execute {
            runCatching { NativeEngine.run(descriptor.fd, dnsPreset, geoRules, settings) }
            mainExecutor.execute {
                nativeRunning = false
                if (stopping || destroyed) closeTunnel() else fail()
            }
        }
    }

    private fun monitorScreen() {
        val filter = IntentFilter().apply {
            addAction(Intent.ACTION_SCREEN_ON)
            addAction(Intent.ACTION_SCREEN_OFF)
        }
        if (Build.VERSION.SDK_INT >= 33) {
            registerReceiver(screenReceiver, filter, RECEIVER_NOT_EXPORTED)
        } else {
            @Suppress("DEPRECATION")
            registerReceiver(screenReceiver, filter)
        }
        screenReceiverRegistered = true
        NativeEngine.setScreenInteractive(getSystemService(PowerManager::class.java).isInteractive)
    }

    private fun fail() {
        state = "failed"
        updateNotification(tr("Ошибка подключения"))
    }

    private fun disconnect() {
        stopping = true
        state = "stopping"
        if (nativeRunning) NativeEngine.stop() else closeTunnel()
    }

    private fun closeTunnel() {
        runCatching { tunnel?.close() }
        tunnel = null
        blockingTraffic = false
        state = "off"
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    override fun onRevoke() {
        mainExecutor.execute { disconnect() }
    }

    override fun onDestroy() {
        destroyed = true
        if (screenReceiverRegistered) {
            unregisterReceiver(screenReceiver)
            screenReceiverRegistered = false
        }
        disconnect()
        worker.shutdown()
        super.onDestroy()
    }

    private fun updateNotification(message: String) {
        if (Build.VERSION.SDK_INT >= 33 &&
            checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
        ) return
        getSystemService(NotificationManager::class.java).notify(NOTIFICATION, notification(message))
    }

    private fun notification(message: String): Notification {
        val manager = getSystemService(NotificationManager::class.java)
        manager.createNotificationChannel(NotificationChannel("vpn", "Hydrat VPN", NotificationManager.IMPORTANCE_LOW))
        val open = PendingIntent.getActivity(this, 0, Intent(this, MainActivity::class.java), PendingIntent.FLAG_IMMUTABLE)
        val stop = PendingIntent.getService(this, 0, Intent(this, HydratVpnService::class.java).setAction(STOP), PendingIntent.FLAG_IMMUTABLE)
        return Notification.Builder(this, "vpn")
            .setContentTitle("Hydrat").setContentText(message)
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setContentIntent(open)
            .addAction(Notification.Action.Builder(null, tr("Отключить"), stop).build())
            .setOngoing(true)
            .build()
    }

    companion object {
        private const val NOTIFICATION = 1
        const val STOP = "org.hydrat.app.DISCONNECT"
        @Volatile var blockingTraffic = false
            private set
        internal val stateListeners = mutableSetOf<() -> Unit>() // Accessed on the main thread.
        @Volatile var state = "off"
            private set(value) {
                field = value
                stateListeners.forEach { it() }
            }
    }
}
