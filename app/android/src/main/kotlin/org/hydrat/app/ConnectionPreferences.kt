package org.hydrat.app

import android.content.Context
import org.json.JSONObject

internal class ConnectionPreferences(context: Context) {
    private val store = context.getSharedPreferences("connection", Context.MODE_PRIVATE)

    var dnsPreset: Int
        get() = store.getInt("dnsPreset", 0).coerceIn(0, 3)
        set(value) { store.edit().putInt("dnsPreset", value).apply() }

    var geoRules: Boolean
        get() = store.getBoolean("geoRules", true)
        set(value) { store.edit().putBoolean("geoRules", value).apply() }

    var fastWorkers: Int
        get() = store.getInt("fastWorkers", 8).coerceIn(1, 8)
        set(value) { store.edit().putInt("fastWorkers", value).apply() }

    var backgroundWorkers: Int
        get() = store.getInt("backgroundWorkers", 4).coerceIn(1, 8)
        set(value) { store.edit().putInt("backgroundWorkers", value).apply() }

    var minVlessScore: Int
        get() = store.getInt("minVlessScore", 75).coerceIn(50, 100)
        set(value) { store.edit().putInt("minVlessScore", value).apply() }

    var backgroundInterval: Int
        get() = store.getInt("backgroundInterval", 15).coerceIn(15, 900)
        set(value) { store.edit().putInt("backgroundInterval", value).apply() }

    var refreshMinutes: Int
        get() = store.getInt("refreshMinutes", 60).coerceIn(15, 1440)
        set(value) { store.edit().putInt("refreshMinutes", value).apply() }

    var pauseOnScreenOff: Boolean
        get() = store.getBoolean("pauseOnScreenOff", true)
        set(value) { store.edit().putBoolean("pauseOnScreenOff", value).apply() }

    var notificationPrompted: Boolean
        get() = store.getBoolean("notification_prompted", false)
        set(value) { store.edit().putBoolean("notification_prompted", value).apply() }

    var hwid: String
        get() = store.getString("hwid", "").orEmpty()
        set(value) { store.edit().putString("hwid", value).apply() }

    fun settingsJson() = JSONObject()
        .put("FastWorkers", fastWorkers)
        .put("BackgroundWorkers", backgroundWorkers)
        .put("MinVLESSScore", minVlessScore)
        .put("BackgroundIntervalSeconds", backgroundInterval)
        .put("SourceRefreshMinutes", refreshMinutes)
        .put("PauseOnScreenOff", pauseOnScreenOff)
        .toString()
}
