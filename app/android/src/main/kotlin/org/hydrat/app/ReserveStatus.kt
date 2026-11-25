package org.hydrat.app

internal fun reserveMessage(status: String?): String = when (status) {
    "checking" -> "Проверяем резервный маршрут"
    "no_primary" -> "Ожидает основного маршрута"
    else -> "Подходящий резерв пока не найден"
}
