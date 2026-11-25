package org.hydrat.app

import android.annotation.SuppressLint
import android.app.PendingIntent
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.service.quicksettings.Tile
import android.service.quicksettings.TileService

class VpnQuickTile : TileService() {
    private val refresh = { render() }

    override fun onStartListening() {
        UiLanguage.load(this)
        HydratVpnService.stateListeners.add(refresh)
        render()
    }

    override fun onStopListening() {
        HydratVpnService.stateListeners.remove(refresh)
    }

    override fun onDestroy() {
        HydratVpnService.stateListeners.remove(refresh)
        super.onDestroy()
    }

    override fun onClick() {
        if (isLocked) unlockAndRun { toggle() } else toggle()
    }

    private fun toggle() {
        val intent = Intent(this, HydratVpnService::class.java)
        when (currentView().action) {
            TileAction.CONNECT -> {
                if (VpnService.prepare(this) != null) openHydrat()
                else runCatching { startForegroundService(intent) }.onFailure { openHydrat() }
            }
            TileAction.DISCONNECT -> {
                intent.action = HydratVpnService.STOP
                runCatching { startService(intent) }.onFailure { openHydrat() }
            }
            TileAction.NONE -> Unit
        }
    }

    private fun render() {
        val view = currentView()
        qsTile?.apply {
            state = view.state
            subtitle = view.subtitle
            contentDescription = "Hydrat · ${view.subtitle}"
            updateTile()
        }
    }

    private fun currentView() = vpnTileView(HydratVpnService.state, HydratVpnService.blockingTraffic)

    // The Intent overload is available only on Android 13 and older.
    @SuppressLint("StartActivityAndCollapseDeprecated")
    @Suppress("DEPRECATION")
    private fun openHydrat() {
        val intent = Intent(this, MainActivity::class.java).addFlags(
            Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP or Intent.FLAG_ACTIVITY_SINGLE_TOP,
        )
        if (Build.VERSION.SDK_INT >= 34) {
            val activity = PendingIntent.getActivity(this, 0, intent, PendingIntent.FLAG_IMMUTABLE)
            startActivityAndCollapse(activity)
        } else {
            startActivityAndCollapse(intent)
        }
    }
}

internal enum class TileAction { CONNECT, DISCONNECT, NONE }
internal data class VpnTileView(val state: Int, val subtitle: String, val action: TileAction)

internal fun vpnTileView(service: String, blocking: Boolean) = when (service) {
    "starting" -> VpnTileView(Tile.STATE_ACTIVE, tr("Запуск VPN…"), TileAction.DISCONNECT)
    "running" -> VpnTileView(Tile.STATE_ACTIVE, tr("Туннель включён"), TileAction.DISCONNECT)
    "stopping" -> VpnTileView(Tile.STATE_UNAVAILABLE, tr("Отключение…"), TileAction.NONE)
    "failed" -> if (blocking) VpnTileView(Tile.STATE_ACTIVE, tr("Трафик заблокирован"), TileAction.DISCONNECT)
        else VpnTileView(Tile.STATE_INACTIVE, tr("Ошибка подключения"), TileAction.CONNECT)
    else -> VpnTileView(Tile.STATE_INACTIVE, tr("VPN отключён"), TileAction.CONNECT)
}
