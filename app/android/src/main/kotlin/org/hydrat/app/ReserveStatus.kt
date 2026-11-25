package org.hydrat.app

internal fun reserveMessage(status: String?): String = when (status) {
    "checking" -> tr("Проверяем резервный маршрут")
    "no_primary" -> tr("Ожидает основного маршрута")
    else -> tr("Подходящий резерв пока не найден")
}
