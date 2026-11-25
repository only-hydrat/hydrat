package org.hydrat.app

import android.app.Activity
import android.app.AlertDialog
import android.text.InputFilter
import android.text.InputType
import android.view.View
import android.widget.EditText
import android.widget.ScrollView
import org.json.JSONObject
import java.util.concurrent.Executor

internal class GeoSettingsDialog(
    private val activity: Activity,
    private val ui: DashboardStyle,
    private val worker: Executor,
) {
    fun show(settings: JSONObject) {
        val content = ui.column().apply { setPadding(ui.dp(20), ui.dp(12), ui.dp(20), ui.dp(12)) }
        val inputs = linkedMapOf<String, EditText>()
        fun field(key: String, label: String, url: Boolean = false) {
            content.addView(ui.text(label, 15, bold = true), ui.block(12))
            inputs[key] = EditText(activity).apply {
                contentDescription = label
                inputType = InputType.TYPE_CLASS_TEXT or if (url) InputType.TYPE_TEXT_VARIATION_URI
                    else InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS
                setSingleLine(true)
                filters = arrayOf(InputFilter.LengthFilter(4096))
                isSaveEnabled = false
                importantForAutofill = View.IMPORTANT_FOR_AUTOFILL_NO
                if (url) hint = tr("База из приложения")
                setText(settings.optString(key))
            }.also { content.addView(it, ui.block(3)) }
        }
        content.addView(ui.text(tr("Укажите HTTPS-ссылки на базы .dat или оставьте поля пустыми для баз из приложения."), 14))
        field("IPURL", tr("Ссылка на GeoIP"), url = true)
        field("SiteURL", tr("Ссылка на GeoSite"), url = true)
        content.addView(ui.text(tr("Группы через запятую. Правила VPN имеют приоритет над прямым доступом."), 14), ui.block(16))
        field("TunnelIP", tr("GeoIP через VPN"))
        field("DirectIP", tr("GeoIP напрямую"))
        field("TunnelSite", tr("GeoSite через VPN"))
        field("DirectSite", tr("GeoSite напрямую"))
        content.addView(ui.text(tr("Новые настройки применятся при следующем подключении."), 14), ui.block(12))
        val dialog = AlertDialog.Builder(activity).setTitle(tr("GeoIP и GeoSite"))
            .setView(ScrollView(activity).apply { addView(content) })
            .setNegativeButton(tr("Отмена"), null).setPositiveButton(tr("Сохранить"), null).create()
        dialog.setOnShowListener {
            val save = dialog.getButton(AlertDialog.BUTTON_POSITIVE)
            save.setOnClickListener {
                val payload = JSONObject()
                inputs.forEach { (key, input) -> payload.put(key, input.text.toString().trim()) }
                save.isEnabled = false
                dialog.getButton(AlertDialog.BUTTON_NEGATIVE).isEnabled = false
                dialog.setCancelable(false)
                save.text = tr("Проверяем…")
                worker.execute {
                    val result = runCatching { NativeEngine.saveGeoSettings(payload.toString()) }.getOrNull()
                    activity.runOnUiThread {
                        if (!dialog.isShowing || activity.isDestroyed) return@runOnUiThread
                        if (result == "") {
                            dialog.dismiss()
                        } else {
                            save.text = tr("Сохранить")
                            save.isEnabled = true
                            dialog.getButton(AlertDialog.BUTTON_NEGATIVE).isEnabled = true
                            dialog.setCancelable(true)
                            AlertDialog.Builder(activity).setMessage(message(result))
                                .setPositiveButton(tr("Закрыть"), null).show()
                        }
                    }
                }
            }
        }
        dialog.show()
    }

    private fun message(code: String?): String = when (code) {
        "invalid_geo_url" -> tr("Укажите HTTPS-ссылку на файл .dat.")
        "invalid_geo_tags" -> tr("Проверьте имена групп. Укажите до 32 групп через запятую в каждом поле.")
        "missing_geo_tags" -> tr("Для каждой подключённой базы укажите хотя бы одну группу.")
        "geoip_download" -> tr("Не удалось скачать базу GeoIP.")
        "geosite_download" -> tr("Не удалось скачать базу GeoSite.")
        "geoip_groups" -> tr("Не удалось прочитать указанные группы GeoIP. Проверьте файл и имена групп.")
        "geosite_groups" -> tr("Не удалось прочитать указанные группы GeoSite. Проверьте файл и имена групп.")
        else -> tr("Не удалось сохранить настройки GeoIP и GeoSite.")
    }
}
