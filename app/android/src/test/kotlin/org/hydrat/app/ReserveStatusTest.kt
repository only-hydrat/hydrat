package org.hydrat.app

import org.junit.Assert.assertEquals
import org.junit.Test

class ReserveStatusTest {
    @Test fun distinguishesMissingReserveFromVerificationAndStartup() {
        assertEquals("Подходящий резерв пока не найден", reserveMessage("missing"))
        assertEquals("Проверяем резервный маршрут", reserveMessage("checking"))
        assertEquals("Ожидает основного маршрута", reserveMessage("no_primary"))
    }

    @Test fun handlesOlderNativeStatus() {
        assertEquals("Подходящий резерв пока не найден", reserveMessage(null))
    }
}
