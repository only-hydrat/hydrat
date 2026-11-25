package org.hydrat.app

import android.Manifest
import android.app.Activity
import android.content.pm.PackageManager
import android.app.AlertDialog
import android.app.StatusBarManager
import android.content.ComponentName
import android.content.Intent
import android.graphics.drawable.Icon
import android.net.Uri
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.text.InputType
import android.view.Gravity
import android.view.View
import android.view.WindowInsets
import android.view.WindowManager
import android.widget.Button
import android.widget.EditText
import android.widget.FrameLayout
import android.widget.LinearLayout
import android.widget.ProgressBar
import android.widget.ScrollView
import android.widget.Switch
import android.widget.TextView
import org.json.JSONObject
import java.text.DateFormat
import java.util.Date
import java.util.concurrent.Executors

class MainActivity : Activity() {
    private val worker = Executors.newSingleThreadExecutor()
    private val handler = Handler(Looper.getMainLooper())
    private lateinit var ui: DashboardStyle
    private lateinit var preferences: ConnectionPreferences
    private lateinit var title: TextView
    private lateinit var summary: TextView
    private lateinit var toggle: Button
    private lateinit var retry: Button
    private lateinit var searchStatus: TextView
    private lateinit var searchSummary: TextView
    private lateinit var searchProgress: ProgressBar
    private lateinit var nodes: LinearLayout
    private lateinit var sources: LinearLayout
    private lateinit var sourceInput: EditText
    private lateinit var sourceHWIDInput: EditText
    private lateinit var sourceForm: LinearLayout
    private lateinit var addSource: Button
    private lateinit var sourceHeading: TextView
    private lateinit var importButton: Button
    private lateinit var refreshButton: Button
    private lateinit var suggestionButton: Button
    private lateinit var sourceResult: TextView
    private var refreshing = false
    private var statusChecked = false
    private var sourceOperationPending = false
    private var currentStatus: JSONObject? = null
    private var nodesKey = ""
    private var sourcesKey = ""
    private var selectedPage = 0
    private val pages = mutableListOf<ScrollView>()
    private val navigation = mutableListOf<Button>()
    private val sectionNames by lazy { listOf(tr("Главная"), tr("Подключения"), tr("Настройки")) }

    private val tick = object : Runnable {
        override fun run() {
            readStatus()
            handler.postDelayed(this, 2000)
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        UiLanguage.load(this)
        window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        if (Build.VERSION.SDK_INT < 30) {
            @Suppress("DEPRECATION")
            window.setSoftInputMode(WindowManager.LayoutParams.SOFT_INPUT_ADJUST_RESIZE)
        }
        ui = DashboardStyle(this)
        preferences = ConnectionPreferences(this)
        setContentView(buildLayout())
        selectPage(savedInstanceState?.getInt("page")?.coerceIn(0, 2) ?: 0)
        render(null)
    }

    private fun buildLayout(): LinearLayout = ui.column().apply {
        setBackgroundColor(DashboardStyle.BACKGROUND)
        setOnApplyWindowInsetsListener { view, insets ->
            if (Build.VERSION.SDK_INT >= 30) {
                val bars = insets.getInsets(WindowInsets.Type.systemBars() or WindowInsets.Type.displayCutout())
                val keyboard = insets.getInsets(WindowInsets.Type.ime())
                view.setPadding(bars.left, bars.top, bars.right, maxOf(bars.bottom, keyboard.bottom))
            } else {
                @Suppress("DEPRECATION")
                view.setPadding(insets.systemWindowInsetLeft, insets.systemWindowInsetTop,
                    insets.systemWindowInsetRight, insets.systemWindowInsetBottom)
            }
            insets
        }
        title = ui.text("Hydrat", 24, bold = true).apply {
            setAccessibilityHeading(true)
            setPadding(ui.dp(20), ui.dp(12), ui.dp(20), ui.dp(9))
        }
        addView(title)
        addView(FrameLayout(this@MainActivity).apply {
            for (content in listOf(overviewPage(), connectionsPage(), settingsPage())) {
                val pane = ScrollView(this@MainActivity).apply {
                    clipToPadding = false
                    isFillViewport = true
                    setPadding(ui.dp(20), ui.dp(8), ui.dp(20), ui.dp(20))
                    addView(content)
                }
                pages.add(pane)
                addView(pane, FrameLayout.LayoutParams(-1, -1))
            }
        }, LinearLayout.LayoutParams(-1, 0, 1f))
        addView(LinearLayout(this@MainActivity).apply {
            setPadding(ui.dp(12), ui.dp(7), ui.dp(12), ui.dp(7))
            isBaselineAligned = false
            setBackgroundColor(DashboardStyle.SURFACE)
            sectionNames.forEachIndexed { index, label ->
                val button = ui.button(label, primary = false) { selectPage(index) }.apply {
                    textSize = 14f
                    setPadding(ui.dp(4), ui.dp(6), ui.dp(4), ui.dp(6))
                }
                navigation.add(button)
                addView(button, LinearLayout.LayoutParams(0, -1, 1f).apply {
                    marginStart = ui.dp(3)
                    marginEnd = ui.dp(3)
                })
            }
        })
    }

    private fun overviewPage(): LinearLayout = ui.column().apply {
        addView(ui.card().apply {
            summary = ui.text("", 24, bold = true).apply { accessibilityLiveRegion = View.ACCESSIBILITY_LIVE_REGION_POLITE }
            addView(summary)
            toggle = ui.button(tr("Подключить")) { toggleVPN() }
            addView(toggle, ui.block(12))
            retry = ui.button(tr("Повторить подключение"), primary = false) { connect() }
            addView(retry, ui.block(8))
        })
        nodes = ui.column()
        addView(nodes, ui.block(18))
        addView(ui.card().apply {
            addView(ui.heading(tr("Поиск маршрутов")))
            searchStatus = ui.text("", 14)
            addView(searchStatus, ui.block(4))
            searchProgress = ProgressBar(this@MainActivity, null, android.R.attr.progressBarStyleHorizontal).apply {
                importantForAccessibility = View.IMPORTANT_FOR_ACCESSIBILITY_NO
                progressTintList = android.content.res.ColorStateList.valueOf(DashboardStyle.ACCENT)
            }
            addView(searchProgress, ui.block(9))
            searchSummary = ui.text("", 14, muted = true)
            addView(searchSummary, ui.block(7))
        }, ui.block(18))
    }

    private fun settingsPage(): LinearLayout = ui.column().apply {
        addView(ui.heading(tr("Язык")))
        addView(ui.card().apply {
            val choices = UiLanguage.labels()
            val current = UiLanguage.choices.indexOf(UiLanguage.choice(this@MainActivity))
            addView(ui.button(choices[current], primary = false) {
                AlertDialog.Builder(this@MainActivity).setTitle(tr("Язык"))
                    .setSingleChoiceItems(choices, current) { dialog, selected ->
                        dialog.dismiss()
                        if (selected != current) {
                            UiLanguage.select(this@MainActivity, UiLanguage.choices[selected])
                            recreate()
                        }
                    }
                    .setNegativeButton(tr("Отмена"), null)
                    .show()
            })
        }, ui.block(9))
        addView(ui.heading(tr("Подключение")))
        addView(ui.card().apply {
            val dnsNames = listOf(tr("Автоматически"), "Cloudflare", "Quad9", "Google")
            addView(choiceSetting(tr("DNS-резолвер"), preferences.dnsPreset, dnsNames) {
                preferences.dnsPreset = it
            })
            val geo = Switch(this@MainActivity).apply {
                text = tr("Правила GeoIP и GeoSite")
                setTextColor(DashboardStyle.TEXT)
                textSize = 16f
                minHeight = ui.dp(48)
                isChecked = preferences.geoRules
                setOnCheckedChangeListener { _, enabled -> preferences.geoRules = enabled }
            }
            addView(geo, ui.block(10))
            val editor = ui.button(tr("Источники и правила GeoIP / GeoSite"), primary = false) {}
            editor.setOnClickListener { openGeoSettings(editor) }
            addView(editor, ui.block(7))
        }, ui.block(10))
        addView(ui.heading(tr("Поиск и качество")), ui.block(22))
        addView(ui.card().apply {
            addView(numberSetting(tr("Быстрые проверки при подключении"), preferences.fastWorkers, (1..8).toList()) {
                preferences.fastWorkers = it
            })
            addView(numberSetting(tr("Быстрые проверки в фоне"), preferences.backgroundWorkers, (1..8).toList()) {
                preferences.backgroundWorkers = it
            }, ui.block(10))
            addView(numberSetting(tr("Порог качества VLESS"), preferences.minVlessScore, (50..100 step 5).toList()) {
                preferences.minVlessScore = it
            }, ui.block(10))
        }, ui.block(9))
        addView(ui.heading(tr("Фоновая работа")), ui.block(22))
        addView(ui.card().apply {
            addView(numberSetting(tr("Интервал поиска"), preferences.backgroundInterval,
                listOf(15, 30, 60, 120, 300, 900), tr("с")) { preferences.backgroundInterval = it })
            addView(numberSetting(tr("Обновлять подписки каждые"), preferences.refreshMinutes,
                listOf(15, 30, 60, 180, 360, 1440), tr("мин")) { preferences.refreshMinutes = it }, ui.block(10))
            addView(Switch(this@MainActivity).apply {
                text = tr("Экономия при выключенном экране")
                setTextColor(DashboardStyle.TEXT)
                textSize = 16f
                minHeight = ui.dp(48)
                isChecked = preferences.pauseOnScreenOff
                setOnCheckedChangeListener { _, enabled -> preferences.pauseOnScreenOff = enabled }
            }, ui.block(10))
            addView(ui.text(tr("VPN остаётся подключённым. В фоне маршрут проверяется чаще, когда приложения передают данные."),
                14, muted = true), ui.block(5))
        }, ui.block(9))
        addView(ui.text(tr("Настройки подключения и поиска применяются при следующем подключении."),
            14, muted = true), ui.block(9))
        addView(ui.heading(tr("Подписки VLESS")), ui.block(22))
        addView(ui.card().apply {
            addView(ui.text("HWID", 17, bold = true))
            val button = ui.button(hwidLabel(), primary = false) {}
            button.setOnClickListener { editHWID(button) }
            addView(button, ui.block(7))
            addView(ui.text(tr("Значение отправляется при следующем запросе на HTTPS-адрес подписки."), 14, muted = true), ui.block(5))
        }, ui.block(9))
        addView(ui.heading(tr("Быстрое подключение")), ui.block(22))
        addView(ui.card().apply {
            addView(ui.text(tr("Управляйте VPN плиткой Hydrat в быстрых настройках Android."), 14, muted = true))
            if (Build.VERSION.SDK_INT >= 33) {
                addView(ui.button(tr("Добавить в шторку"), primary = false) {
                    getSystemService(StatusBarManager::class.java).requestAddTileService(
                        ComponentName(this@MainActivity, VpnQuickTile::class.java),
                        "Hydrat", Icon.createWithResource(this@MainActivity, R.drawable.ic_quick_vpn),
                        mainExecutor,
                    ) {}
                }, ui.block(8))
            } else {
                addView(ui.text(tr("Откройте шторку, нажмите «Изменить» и перетащите плитку Hydrat."), 14), ui.block(8))
            }
        }, ui.block(9))
        addView(ui.heading(tr("Обновления")), ui.block(22))
        addView(updateCard(), ui.block(9))
    }

    private fun updateCard(): LinearLayout = ui.card().apply {
        addView(ui.text(tr("Установлена версия {0}", BuildConfig.VERSION_NAME), 16))
        val status = ui.text("", 14, muted = true).apply {
            accessibilityLiveRegion = View.ACCESSIBILITY_LIVE_REGION_POLITE
        }
        var downloadURL = ""
        val download = ui.button(tr("Скачать APK")) {
            if (downloadURL.isNotEmpty()) {
                runCatching { startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(downloadURL))) }
                    .onFailure { status.text = tr("Не удалось открыть браузер.") }
            }
        }.apply { visibility = View.GONE }
        val check = ui.button(tr("Проверить обновления"), primary = false) {}
        check.setOnClickListener {
            check.isEnabled = false
            download.visibility = View.GONE
            status.text = tr("Проверяем обновления…")
            worker.execute {
                val result = runCatching { NativeEngine.checkUpdate()?.let(::JSONObject) }.getOrNull()
                handler.post {
                    if (isDestroyed || isFinishing) return@post
                    check.isEnabled = true
                    downloadURL = result?.optString("DownloadURL").orEmpty()
                    val latest = result?.optString("Latest").orEmpty()
                    status.text = when {
                        result == null -> tr("Не удалось проверить обновления. Повторите попытку.")
                        downloadURL.isNotEmpty() -> tr("Доступна версия {0}", latest)
                        latest.isEmpty() -> tr("Подходящих релизов пока нет.")
                        else -> tr("Установлена актуальная версия.")
                    }
                    download.visibility = if (downloadURL.isEmpty()) View.GONE else View.VISIBLE
                }
            }
        }
        addView(check, ui.block(8))
        addView(status, ui.block(5))
        addView(download, ui.block(5))
    }

    private fun openGeoSettings(button: Button) {
        button.isEnabled = false
        worker.execute {
            val settings = runCatching {
                NativeEngine.initialize(this)
                NativeEngine.geoSettings()?.let(::JSONObject)
            }.getOrNull()
            handler.post {
                button.isEnabled = true
                if (isDestroyed || isFinishing) return@post
                if (settings == null) {
                    AlertDialog.Builder(this).setMessage(tr("Не удалось прочитать настройки GeoIP и GeoSite."))
                        .setPositiveButton(tr("Закрыть"), null).show()
                } else {
                    GeoSettingsDialog(this, ui, worker).show(settings)
                }
            }
        }
    }

    private fun numberSetting(label: String, current: Int, choices: List<Int>, unit: String = "", save: (Int) -> Unit): View {
        fun format(value: Int) = if (unit.isEmpty()) value.toString() else "$value $unit"
        return choiceSetting(label, choices.indexOf(current), choices.map(::format), format(current)) {
            save(choices[it])
        }
    }

    private fun choiceSetting(label: String, current: Int, choices: List<String>, fallback: String = tr("Выбрать"), save: (Int) -> Unit) =
        LinearLayout(this).apply {
            gravity = Gravity.CENTER_VERTICAL
            isBaselineAligned = false
            addView(ui.text(label, 15, bold = true), LinearLayout.LayoutParams(0, -2, 1f))
            var selected = current
            val button = ui.button(choices.getOrElse(selected) { fallback }, primary = false) {}.apply {
                minWidth = ui.dp(56)
            }
            button.contentDescription = "$label, ${button.text}"
            button.setOnClickListener {
                AlertDialog.Builder(this@MainActivity).setTitle(label)
                    .setSingleChoiceItems(choices.toTypedArray(), selected) { dialog, index ->
                        save(index)
                        selected = index
                        button.text = choices[index]
                        button.contentDescription = "$label, ${button.text}"
                        dialog.dismiss()
                    }
                    .setNegativeButton(tr("Отмена"), null)
                    .show()
            }
            addView(button, LinearLayout.LayoutParams(-2, -2).apply { marginStart = ui.dp(12) })
        }

    private fun hwidLabel() = if (preferences.hwid.isEmpty()) tr("Автоматический HWID") else tr("Пользовательский HWID")

    private fun editHWID(button: Button) {
        val input = EditText(this).apply {
            setSingleLine(true)
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS
            setText(preferences.hwid)
            hint = tr("Автоматически")
            isSaveEnabled = false
            importantForAutofill = View.IMPORTANT_FOR_AUTOFILL_NO
        }
        val dialog = AlertDialog.Builder(this).setTitle(tr("HWID подписок"))
            .setMessage(tr("От 10 до 64 символов. Латинские буквы, цифры, дефис и знак равенства. Пустое поле включает автоматический выбор."))
            .setView(input).setNegativeButton(tr("Отмена"), null).setPositiveButton(tr("Сохранить"), null).create()
        dialog.setOnShowListener {
            val save = dialog.getButton(AlertDialog.BUTTON_POSITIVE)
            save.setOnClickListener {
                val value = input.text.toString().trim()
                save.isEnabled = false
                worker.execute {
                    val accepted = runCatching {
                        NativeEngine.initialize(this)
                        NativeEngine.setHWID(value)
                    }.getOrDefault(false)
                    if (accepted) preferences.hwid = value
                    handler.post {
                        if (isDestroyed) return@post
                        if (accepted) {
                            button.text = hwidLabel()
                            dialog.dismiss()
                        } else if (dialog.isShowing) {
                            input.error = tr("Не удалось сохранить HWID. Проверьте формат.")
                            save.isEnabled = true
                        }
                    }
                }
            }
        }
        dialog.show()
    }

    private fun connectionsPage(): LinearLayout = ui.column().apply {
        addSource = ui.button(tr("Добавить источник")) {
            setSourceFormExpanded(sourceForm.visibility != View.VISIBLE)
        }
        addView(addSource)
        refreshButton = ui.button(tr("Обновить источники"), primary = false) { refreshSources() }
        addView(refreshButton, ui.block(6))
        sourceForm = ui.card().apply {
            visibility = View.GONE
            sourceInput = EditText(this@MainActivity).apply {
                hint = tr("Подписка, VLESS или мост Tor")
                contentDescription = tr("Данные источника")
                inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_MULTI_LINE or InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS
                minLines = 2
                maxLines = 5
                isSaveEnabled = false
                importantForAutofill = View.IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS
                setTextColor(DashboardStyle.TEXT)
                setHintTextColor(DashboardStyle.MUTED)
                background = ui.shape(DashboardStyle.BACKGROUND, 12)
                setPadding(ui.dp(12), ui.dp(10), ui.dp(12), ui.dp(10))
            }
            addView(sourceInput, ui.block(9))
            addView(ui.text(tr("HWID одной HTTPS-подписки"), 14, muted = true), ui.block(5))
            sourceHWIDInput = makeSourceHWIDInput(tr("Общий HWID"))
            addView(sourceHWIDInput, ui.block(4))
            importButton = ui.button(tr("Импортировать")) { importSource() }
            addView(importButton, ui.block(9))
            suggestionButton = ui.button(tr("Добавить бесплатные подписки"), primary = false) { importSuggested() }
            addView(suggestionButton, ui.block(8))
        }
        addView(sourceForm, ui.block(10))
        sourceResult = ui.text("", 14, muted = true).apply {
            visibility = View.GONE
            accessibilityLiveRegion = View.ACCESSIBILITY_LIVE_REGION_POLITE
        }
        addView(sourceResult, ui.block(9))
        sourceHeading = ui.heading(tr("Источники"))
        addView(sourceHeading, ui.block(18))
        sources = ui.column()
        addView(sources, ui.block(8))
    }

    private fun setSourceFormExpanded(expanded: Boolean) {
        sourceForm.visibility = if (expanded) View.VISIBLE else View.GONE
        addSource.text = if (expanded) tr("Свернуть импорт") else tr("Добавить источник")
        if (!expanded) {
            sourceInput.clearFocus()
            getSystemService(android.view.inputmethod.InputMethodManager::class.java)
                .hideSoftInputFromWindow(sourceInput.windowToken, 0)
        }
    }

    private fun selectPage(index: Int) {
        selectedPage = index
        title.text = if (index == 0) "Hydrat" else sectionNames[index]
        pages.forEachIndexed { page, view -> view.visibility = if (page == index) View.VISIBLE else View.GONE }
        navigation.forEachIndexed { page, button ->
            button.isSelected = page == index
            ui.styleButton(button, primary = false, selected = page == index)
        }
    }

    override fun onSaveInstanceState(outState: Bundle) {
        outState.putInt("page", selectedPage)
        super.onSaveInstanceState(outState)
    }

    override fun onStart() {
        super.onStart()
        handler.post(tick)
    }

    override fun onStop() {
        handler.removeCallbacks(tick)
        super.onStop()
    }

    override fun onDestroy() {
        worker.shutdown()
        super.onDestroy()
    }

    private fun readStatus() {
        if (refreshing || sourceOperationPending) return
        refreshing = true
        worker.execute {
            val result = runCatching {
                NativeEngine.initialize(this)
                NativeEngine.status()?.decodeToString()?.let(::JSONObject)
            }.getOrNull()
            handler.post {
                refreshing = false
                statusChecked = true
                if (!isDestroyed) render(result)
            }
        }
    }

    private fun render(status: JSONObject?) {
        currentStatus = status
        val service = HydratVpnService.state
        val tcp = service == "running" && status?.optBoolean("TCP") == true
        val udp = service == "running" && status?.optBoolean("UDP") == true
        val recovering = service == "running" && status?.optBoolean("Recovering") == true
        val message = when {
            service == "failed" && HydratVpnService.blockingTraffic -> tr("Ошибка VPN · трафик заблокирован")
            service == "failed" -> tr("Ошибка подключения")
            service == "starting" -> tr("Запуск VPN…")
            service == "stopping" -> tr("Отключение…")
            status == null -> if (statusChecked) tr("Состояние недоступно") else tr("Загрузка Hydrat…")
            recovering -> tr("Ищем замену маршрута")
            tcp && udp -> tr("VPN подключён")
            tcp -> tr("VPN подключён · UDP недоступен")
            udp -> tr("VPN подключён · TCP недоступен")
            service == "running" && status.optInt("SearchingSeconds") >= 30 -> tr("Рабочий маршрут пока не найден")
            service == "running" -> tr("Подбираем маршрут")
            else -> tr("VPN отключён")
        }
        if (summary.text != message) summary.text = message
        summary.setTextColor(if ((tcp || udp) && !recovering) DashboardStyle.ACCENT else DashboardStyle.TEXT)
        val action = when {
            service != "off" -> tr("Отключить")
            status?.optInt("Sources") == 0 -> tr("Добавить источник")
            else -> tr("Подключить")
        }
        if (toggle.text != action) {
            toggle.text = action
            ui.styleButton(toggle, primary = service == "off")
        }
        retry.visibility = if (service == "failed") View.VISIBLE else View.GONE
        toggle.isEnabled = service != "stopping" && (service != "off" || status != null)
        renderSearch(status, service)
        updateSourceButtons()
        renderNodes(status, service)
    }

    private fun renderSearch(status: JSONObject?, service: String) {
        val search = status?.optJSONObject("Search")
        val workers = search?.optInt("Workers") ?: 0
        searchStatus.text = when {
            service == "off" -> tr("Поиск выключен")
            service == "failed" -> tr("Поиск недоступен")
            search?.optString("Mode") == "paused" -> tr("Фоновый поиск приостановлен")
            search?.optString("Mode") == "background" -> if (workers > 0) tr("Фоновый поиск · потоки: {0}", workers) else tr("Проверяем сохранённые ноды")
            search?.optString("Mode") == "search" -> if (workers > 0) tr("Ищем маршрут · потоки: {0}", workers) else tr("Проверяем кандидатов")
            else -> tr("Ожидание следующего обхода")
        }
        val total = status?.optInt("Candidates") ?: 0
        val checked = status?.optInt("Checked") ?: 0
        searchProgress.visibility = if (service == "running" && total > 0) View.VISIBLE else View.GONE
        searchProgress.max = maxOf(total, 1)
        searchProgress.progress = checked
        searchSummary.text = when {
            status == null -> ""
            service != "running" -> tr("В каталоге {0} нод", total)
            else -> tr("Проверено {0} из {1}\nРабочий пул {2} · Сохранено {3}", checked, total, status.optInt("Qualified"), status.optInt("Saved"))
        }
        searchSummary.visibility = if (status == null) View.GONE else View.VISIBLE
    }

    private fun renderNodes(status: JSONObject?, service: String) {
        val data = if (service == "running") status?.optJSONArray("Nodes") else null
        val tcpReserveStatus = status?.optString("TCPReserveStatus")
        val udpReserveStatus = status?.optString("UDPReserveStatus")
        val key = "$service:$tcpReserveStatus:$udpReserveStatus:${data?.toString().orEmpty()}"
        if (nodesKey == key) return
        nodesKey = key
        nodes.removeAllViews()
        val selected = (0 until (data?.length() ?: 0)).mapNotNull { data?.optJSONObject(it) }.associateBy { it.optString("Role") }
        val groups = listOf(tr("Основные маршруты") to listOf("tcp", "udp"),
            tr("Резерв") to listOf("tcp_reserve", "udp_reserve"))
        for ((heading, roles) in groups) {
            if (service != "running" && roles.first().endsWith("reserve")) continue
            nodes.addView(ui.heading(heading), ui.block(if (nodes.childCount == 0) 0 else 16))
            if (service != "running") {
                if (heading == tr("Основные маршруты")) {
                    nodes.addView(ui.text(tr("Маршруты появятся после подключения."), 14, muted = true), ui.block(4))
                }
                continue
            }
            nodes.addView(ui.card().apply {
                roles.forEachIndexed { index, role ->
                    if (index > 0) addView(ui.divider(), LinearLayout.LayoutParams(-1, ui.dp(1)).apply {
                        topMargin = ui.dp(10)
                        bottomMargin = ui.dp(10)
                    })
                    val reserve = if (role.startsWith("tcp")) tcpReserveStatus else udpReserveStatus
                    addView(nodeRow(role, selected[role], reserve))
                }
            }, ui.block(7))
        }
    }

    private fun nodeRow(role: String, node: JSONObject?, reserve: String?): View = LinearLayout(this).apply {
        isBaselineAligned = false
        val transport = if (role.startsWith("tcp")) "TCP" else "UDP"
        addView(ui.text(transport, 14, muted = true, bold = true).apply {
            minWidth = ui.dp(38)
        }, LinearLayout.LayoutParams(-2, -2).apply { marginEnd = ui.dp(10) })
        addView(ui.column().apply {
            if (node == null) {
                val message = if (role.endsWith("reserve")) reserveMessage(reserve) else tr("Ожидает маршрута")
                addView(ui.text(message, 15, muted = true))
            } else {
                val protocol = protocolName(node.optString("Protocol"))
                val name = node.optString("Label").ifBlank { protocol.ifBlank { tr("Назначенная нода") } }
                addView(ui.text(name, 16, bold = true))
                val detail = listOf(protocol, node.optString("Source"))
                    .filter { it.isNotBlank() && it != name }.distinct()
                if (detail.isNotEmpty()) addView(ui.text(detail.joinToString(" · "), 13, muted = true), ui.block(2))
                val state = node.optString("State")
                val health = when (state) {
                    "available" -> tr("Доступен")
                    "unavailable" -> tr("Проверка не прошла")
                    else -> tr("Ожидает проверки")
                }
                addView(ui.text(health, 13, muted = true).apply {
                    if (state == "available") setTextColor(DashboardStyle.ACCENT)
                }, ui.block(3))
                val metrics = listOf(
                    node.optDouble("LatencyMS", 0.0).takeIf { it > 0 }?.let { tr("{0} мс", it.toInt()) },
                    node.optDouble("ThroughputMbps", 0.0).takeIf { it > 0 }?.let { tr("{0} Мбит/с", String.format(UiLanguage.locale(), "%.1f", it)) },
                    node.optDouble("Score", 0.0).takeIf { it > 0 }?.let { "${it.toInt()} / 100" },
                ).filterNotNull()
                if (metrics.isNotEmpty()) addView(ui.text(metrics.joinToString(" · "), 13, muted = true), ui.block(2))
                if (node.optLong("MeasuredAt") > 0) {
                    addView(ui.text(tr("Замер {0}", formatTime(node.optLong("MeasuredAt"))), 12, muted = true), ui.block(2))
                }
            }
        }, LinearLayout.LayoutParams(0, -2, 1f))
    }

    private fun renderSources(status: JSONObject?) {
        val inventory = status?.optJSONArray("Inventory")
        val key = if (status == null) "missing:$statusChecked" else "$sourceOperationPending:${inventory?.toString().orEmpty()}"
        if (sourcesKey == key && sources.childCount > 0) return
        sourcesKey = key
        sources.removeAllViews()
        val count = inventory?.length() ?: 0
        sourceHeading.text = if (count > 0) tr("Источники · {0}", count) else tr("Источники")
        if (count == 0) {
            val message = when {
                status != null -> tr("Источников пока нет")
                statusChecked -> tr("Состояние источников недоступно")
                else -> tr("Загрузка…")
            }
            sources.addView(ui.text(message, 15, muted = true))
            return
        }
        for (index in 0 until inventory!!.length()) {
            val item = inventory.optJSONObject(index) ?: continue
            sources.addView(ui.card().apply {
                val kind = protocolName(item.optString("Kind")).ifBlank { tr("Подписка") }
                addView(ui.text(item.optString("Label").ifBlank { kind }, 16, bold = true))
                val state = when {
                    !item.optBoolean("Enabled") -> tr("Отключён")
                    item.optBoolean("Failed") -> tr("Ошибка обновления")
                    item.optLong("UpdatedAt") > 0 -> tr("Обновлён {0}", formatTime(item.optLong("UpdatedAt")))
                    else -> tr("Ожидает обновления")
                }
                addView(ui.text(tr("{0}  ·  Ноды {1}", state, item.optInt("Candidates")), 14, muted = true), ui.block(4))
                val id = item.optString("ID")
                if (id.isNotBlank()) {
                    val name = item.optString("Label").ifBlank { kind }
                    if (item.optString("Kind") in setOf("vless_subscription", "tor_subscription", "remote_auto")) {
                        val custom = item.optBoolean("CustomHWID")
                        addView(ui.button(if (custom) tr("Свой HWID") else tr("Задать HWID"), primary = false) {
                            editSourceHWID(id, name, custom)
                        }.apply {
                            isEnabled = !sourceOperationPending
                            contentDescription = tr("HWID источника {0}", name)
                        }, LinearLayout.LayoutParams(-2, -2).apply { topMargin = ui.dp(5) })
                    }
                    addView(ui.button(tr("Удалить источник"), primary = false) { confirmSourceRemoval(id, name) }.apply {
                        isEnabled = !sourceOperationPending
                        contentDescription = tr("Удалить источник {0}", name)
                    }, LinearLayout.LayoutParams(-2, -2).apply { topMargin = ui.dp(5) })
                }
            }, ui.block(if (index == 0) 0 else 8))
        }
    }

    private fun protocolName(protocol: String) = when (protocol) {
        "vless" -> "VLESS"
        "tor_bridge" -> "Tor"
        "vless_subscription" -> tr("Подписка VLESS")
        "tor_subscription" -> tr("Подписка Tor")
        "public_subscription" -> tr("Публичная подписка")
        else -> ""
    }

    private fun formatTime(seconds: Long): String =
        DateFormat.getDateTimeInstance(DateFormat.SHORT, DateFormat.SHORT, UiLanguage.locale()).format(Date(seconds * 1000))

    private fun toggleVPN() {
        if (HydratVpnService.state != "off") {
            startService(Intent(this, HydratVpnService::class.java).setAction(HydratVpnService.STOP))
            return
        }
        if (currentStatus?.optInt("Sources") == 0) {
            selectPage(1)
            setSourceFormExpanded(true)
            return
        }
        val consent = VpnService.prepare(this)
        if (consent == null) connectAfterConsent() else startActivityForResult(consent, VPN_CONSENT)
    }

    private fun connectAfterConsent() {
        if (Build.VERSION.SDK_INT >= 33 &&
            checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED &&
            !preferences.notificationPrompted
        ) {
            preferences.notificationPrompted = true
            requestPermissions(arrayOf(Manifest.permission.POST_NOTIFICATIONS), NOTIFICATION_CONSENT)
        } else {
            connect()
        }
    }

    override fun onRequestPermissionsResult(requestCode: Int, permissions: Array<out String>, grantResults: IntArray) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)
        if (requestCode == NOTIFICATION_CONSENT) connect()
    }

    private fun connect() {
        startForegroundService(Intent(this, HydratVpnService::class.java))
    }

    @Deprecated("Android Activity result for system VPN consent")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == VPN_CONSENT && resultCode == RESULT_OK) connectAfterConsent()
    }

    private fun confirmSourceRemoval(id: String, name: String) {
        AlertDialog.Builder(this).setTitle(tr("Удалить «{0}»?", name))
            .setMessage(tr("Ноды этого источника будут исключены из поиска маршрутов."))
            .setNegativeButton(tr("Отмена"), null)
            .setPositiveButton(tr("Удалить")) { _, _ ->
                runSourceOperation(tr("Удаляем источник…"), {
                    if (NativeEngine.removeSource(id)) "{}" else null
                }) { tr("Источник удалён") }
            }
            .show()
    }

    private fun importSource() {
        val input = sourceInput.text.toString().trim()
        if (input.isEmpty()) {
            showSourceResult(tr("Введите ссылку подписки, VLESS или строку моста."))
            return
        }
        val hwid = validatedSourceHWID(sourceHWIDInput) ?: return
        if (hwid.isNotEmpty() && input.lineSequence().count { it.isNotBlank() } != 1) {
            sourceHWIDInput.error = tr("Импортируйте подписку с отдельным HWID одной строкой.")
            return
        }
        runSourceOperation(tr("Импорт…"), { NativeEngine.importSources(input.toByteArray(), hwid) }) { report ->
            if (sourceInput.text.toString().trim() == input) sourceInput.text.clear()
            if (sourceHWIDInput.text.toString().trim() == hwid) sourceHWIDInput.text.clear()
            val added = report.optInt("Imported") + report.optInt("Restored")
            val errors = report.optInt("RefreshFailed") + report.optInt("Unavailable")
            tr("Добавлено {0} · Пропущено {1} · Ошибок {2}", added, report.optInt("Skipped"), errors)
        }
    }

    private fun makeSourceHWIDInput(placeholder: String) = EditText(this).apply {
        setSingleLine(true)
        hint = placeholder
        contentDescription = tr("HWID источника")
        inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS
        imeOptions = android.view.inputmethod.EditorInfo.IME_FLAG_NO_PERSONALIZED_LEARNING
        isSaveEnabled = false
        importantForAutofill = View.IMPORTANT_FOR_AUTOFILL_NO
    }

    private fun validatedSourceHWID(input: EditText): String? {
        val value = input.text.toString().trim()
        if (value.isNotEmpty() && !Regex("[A-Za-z0-9=-]{10,64}").matches(value)) {
            input.error = tr("Нужно от 10 до 64 символов: латиница, цифры, дефис или знак равенства.")
            return null
        }
        return value
    }

    private fun editSourceHWID(id: String, name: String, custom: Boolean) {
        val input = makeSourceHWIDInput(tr("Общий HWID"))
        val dialog = AlertDialog.Builder(this).setTitle(tr("HWID источника"))
            .setMessage(tr("{0}\nОставьте поле пустым, чтобы использовать общий HWID.", name))
            .setView(input).setNegativeButton(tr("Отмена"), null).setPositiveButton(tr("Сохранить"), null).create()
        dialog.setOnShowListener {
            val save = dialog.getButton(AlertDialog.BUTTON_POSITIVE)
            save.setOnClickListener {
                val value = validatedSourceHWID(input) ?: return@setOnClickListener
                dialog.dismiss()
                runSourceOperation(tr("Сохраняем HWID…"), { NativeEngine.setSourceHWID(id, value) }) { report ->
                    if (report.optInt("Failed") > 0) tr("HWID сохранён. Не удалось обновить источник.")
                    else tr("HWID сохранён. Источник обновлён.")
                }
            }
            if (custom) {
                input.isEnabled = false
                save.isEnabled = false
                worker.execute {
                    val saved = runCatching { NativeEngine.sourceHWID(id) }.getOrNull()
                    handler.post {
                        if (!isDestroyed && dialog.isShowing) {
                            if (saved == null) {
                                input.error = tr("Не удалось прочитать HWID.")
                            } else {
                                input.setText(saved)
                                input.isEnabled = true
                                save.isEnabled = true
                            }
                        }
                    }
                }
            }
        }
        dialog.show()
    }

    private fun importSuggested() {
        runSourceOperation(tr("Проверяем бесплатные подписки…"), NativeEngine::importSuggested) { report ->
            val added = report.optInt("Imported") + report.optInt("Restored")
            val unavailable = report.optInt("Unavailable") + report.optInt("RefreshFailed")
            tr("Добавлено {0} · Уже добавлено {1} · Ошибок {2}", added, report.optInt("Skipped"), unavailable)
        }
    }

    private fun refreshSources() {
        runSourceOperation(tr("Обновление…"), NativeEngine::refreshSources) { report ->
            tr("Обновлено {0} · Ошибок {1}", report.optInt("Updated"), report.optInt("Failed"))
        }
    }

    private fun runSourceOperation(message: String, operation: () -> String?, success: (JSONObject) -> String) {
        if (sourceOperationPending) return
        sourceOperationPending = true
        updateSourceButtons()
        showSourceResult(message)
        worker.execute {
            val result = runCatching {
                NativeEngine.initialize(this)
                operation()?.let(::JSONObject)
            }.getOrNull()
            handler.post {
                if (isDestroyed) return@post
                sourceOperationPending = false
                updateSourceButtons()
                showSourceResult(result?.let(success) ?: tr("Не удалось обработать источники."))
                readStatus()
            }
        }
    }

    private fun updateSourceButtons() {
        importButton.isEnabled = !sourceOperationPending
        sourceHWIDInput.isEnabled = !sourceOperationPending
        refreshButton.isEnabled = !sourceOperationPending && (currentStatus?.optInt("Sources") ?: 0) > 0
        suggestionButton.isEnabled = !sourceOperationPending
        renderSources(currentStatus)
    }

    private fun showSourceResult(message: String) {
        sourceResult.text = message
        sourceResult.visibility = View.VISIBLE
    }

    companion object {
        private const val NOTIFICATION_CONSENT = 12
        private const val VPN_CONSENT = 1
    }
}
