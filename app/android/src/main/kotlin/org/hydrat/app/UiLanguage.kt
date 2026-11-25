package org.hydrat.app

import android.content.Context
import org.json.JSONObject
import java.util.Locale

internal object UiLanguage {
    val choices = listOf("", "ru", "en", "zh-CN")
    @Volatile private var catalog: JSONObject? = null
    @Volatile private var language = "ru"

    fun labels() = arrayOf(tr("Автоматически"), "Русский", "English", "简体中文")

    fun choice(context: Context): String =
        preferences(context).getString("language", "").orEmpty().takeIf(choices::contains).orEmpty()

    @Synchronized
    fun load(context: Context) {
        if (catalog == null) {
            catalog = context.assets.open("messages.json").bufferedReader().use { JSONObject(it.readText()) }
        }
        val locales = context.resources.configuration.locales
        language = choice(context).ifEmpty {
            chooseUiLanguage((0 until locales.size()).map { locales[it].toLanguageTag() })
        }
    }

    fun select(context: Context, selected: String) {
        if (selected in choices) {
            preferences(context).edit().putString("language", selected).apply()
            load(context)
        }
    }

    fun locale(): Locale = Locale.forLanguageTag(language)

    fun text(source: String): String = catalog?.optJSONObject(language)?.optString(source, source) ?: source

    private fun preferences(context: Context) = context.getSharedPreferences("ui", Context.MODE_PRIVATE)
}

internal fun chooseUiLanguage(detected: List<String>): String {
    for (tag in detected) {
        when (val base = tag.substringBefore('-').lowercase(Locale.ROOT)) {
            "ru", "en" -> return base
            "zh" -> return "zh-CN"
        }
    }
    return "ru"
}

private val placeholder = Regex("\\{(\\d+)\\}")

internal fun tr(source: String, vararg values: Any?): String {
    val translated = UiLanguage.text(source)
    return if (values.isEmpty()) translated else placeholder.replace(translated) { match ->
        val index = match.groupValues[1].toInt()
        if (index in values.indices) values[index].toString() else match.value
    }
}
