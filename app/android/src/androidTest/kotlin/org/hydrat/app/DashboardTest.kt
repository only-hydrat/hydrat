package org.hydrat.app

import android.content.Context
import android.content.Intent
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import androidx.test.uiautomator.By
import androidx.test.uiautomator.Direction
import androidx.test.uiautomator.UiDevice
import androidx.test.uiautomator.Until
import org.junit.Assert.assertNotNull
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class DashboardTest {
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val context = instrumentation.targetContext
    private val device = UiDevice.getInstance(instrumentation)

    @Test fun threeScreensAndSourceManagement() {
        context.getSharedPreferences("connection", Context.MODE_PRIVATE).edit().remove("hwid").commit()
        context.startActivity(Intent(context, MainActivity::class.java)
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK))
        requireText("Поиск маршрутов")
        requireText("Основные маршруты")

        openTab("Подключения", "Добавить источник")
        requireText("Добавить источник").click()
        editText().text =
            "vless://11111111-1111-1111-1111-111111111111@example.invalid:443?security=tls#QA"
        scrollTo("Импортировать")
        requireText("Импортировать").click()
        scrollTo("Удалить источник")
        requireText("Удалить источник QA", description = true).click()
        requireText("УДАЛИТЬ").click()
        scrollTo("Источник удалён", Direction.UP)

        openTab("Настройки", "Порог качества VLESS")
        scrollTo("HWID")
        requireText("Автоматический HWID").click()
        requireText("HWID подписок")
        editText().text = "test-device-12345"
        requireText("СОХРАНИТЬ").click()
        requireText("Пользовательский HWID")
        device.pressHome()
        context.startActivity(Intent(context, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK))
        openTab("Настройки", "Порог качества VLESS")
        scrollTo("HWID")
        requireText("Пользовательский HWID").click()
        requireText("HWID подписок")
        editText().clear()
        requireText("СОХРАНИТЬ").click()
        requireText("Автоматический HWID")
    }

    private fun openTab(label: String, heading: String) {
        repeat(3) {
            requireText(label).click()
            if (device.wait(Until.hasObject(By.text(heading).pkg(context.packageName)), 2_000)) return
        }
        requireText(heading)
    }

    private fun editText() =
        requireNotNull(device.wait(Until.findObject(By.clazz("android.widget.EditText").pkg(context.packageName)), 8_000))

    private fun requireText(value: String, description: Boolean = false) =
        device.wait(Until.findObject((if (description) By.desc(value) else By.text(value)).pkg(context.packageName)), 8_000).also {
            assertNotNull(value, it)
        }!!

    private fun scrollTo(value: String, direction: Direction = Direction.DOWN) {
        repeat(10) {
            if (device.hasObject(By.text(value))) return
            device.findObject(By.clazz("android.widget.ScrollView"))?.scroll(direction, 0.6f)
            device.waitForIdle()
        }
        requireText(value)
    }
}
