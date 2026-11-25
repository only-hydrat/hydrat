package org.hydrat.app

import org.junit.Assert.assertEquals
import org.junit.Test

class UiLanguageTest {
    @Test fun honorsTheFirstSupportedSystemLanguage() {
        assertEquals("en", chooseUiLanguage(listOf("de-DE", "en-GB", "zh-Hans-CN")))
        assertEquals("zh-CN", chooseUiLanguage(listOf("zh-TW")))
        assertEquals("ru", chooseUiLanguage(listOf("fr-FR")))
    }

    @Test fun formatsPlaceholdersWithoutRewritingUserText() {
        assertEquals("Источник {1} · 12", tr("Источник {0} · {1}", "{1}", 12))
    }
}
