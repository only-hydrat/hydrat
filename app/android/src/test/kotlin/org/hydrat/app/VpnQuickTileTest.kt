package org.hydrat.app

import android.service.quicksettings.Tile
import org.junit.Assert.assertEquals
import org.junit.Test

class VpnQuickTileTest {
    @Test fun reflectsTunnelStateAndAction() {
        assertEquals(VpnTileView(Tile.STATE_INACTIVE, "VPN отключён", TileAction.CONNECT),
            vpnTileView("off", false))
        assertEquals(VpnTileView(Tile.STATE_ACTIVE, "Запуск VPN…", TileAction.DISCONNECT),
            vpnTileView("starting", false))
        assertEquals(VpnTileView(Tile.STATE_ACTIVE, "Туннель включён", TileAction.DISCONNECT),
            vpnTileView("running", true))
        assertEquals(VpnTileView(Tile.STATE_UNAVAILABLE, "Отключение…", TileAction.NONE),
            vpnTileView("stopping", true))
    }

    @Test fun keepsDisconnectAvailableWhenFailClosed() {
        assertEquals(VpnTileView(Tile.STATE_ACTIVE, "Трафик заблокирован", TileAction.DISCONNECT),
            vpnTileView("failed", true))
        assertEquals(VpnTileView(Tile.STATE_INACTIVE, "Ошибка подключения", TileAction.CONNECT),
            vpnTileView("failed", false))
    }
}
