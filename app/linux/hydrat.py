#!/usr/bin/python3

import argparse
import http.client
import json
from pathlib import Path
import re
import socket
import threading
from urllib.parse import quote

import gi

gi.require_version("Gtk", "3.0")
gi.require_version("Gdk", "3.0")
gi.require_version("GdkPixbuf", "2.0")
from gi.repository import Gdk, GdkPixbuf, GLib, Gtk


APP_DIR = Path(__file__).resolve().parent
SOCKET = "/run/hydrat-app/control.sock"
SUBSCRIPTION_KINDS = {"vless_subscription", "tor_subscription", "remote_auto"}

ISSUE_TEXT = {
    "unsupported source format": "ожидается подписка, конфиг VLESS или мост Tor",
    "invalid VLESS URI": "проверьте ссылку VLESS",
    "invalid subscription URL": "проверьте адрес подписки",
    "invalid Tor bridge line": "проверьте строку моста Tor",
    "unsupported Tor bridge transport": "транспорт моста Tor не поддерживается",
    "source refresh failed": "источник сохранён, загрузить ноды не удалось",
}


class LocalConnection(http.client.HTTPConnection):
    def __init__(self, path, timeout):
        super().__init__("localhost", timeout=timeout)
        self.path = path

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self.path)


class LocalAPI:
    def __init__(self, path):
        self.path = path

    def request(self, method, path, body=None, timeout=95, headers=None):
        with_connection = LocalConnection(self.path, timeout)
        try:
            if isinstance(body, dict):
                body = json.dumps(body).encode()
            elif isinstance(body, str):
                body = body.encode()
            with_connection.request(method, path, body, headers or {})
            response = with_connection.getresponse()
            raw = response.read(2 << 20)
            if not raw:
                result = {}
            elif response.headers.get_content_type() == "application/json":
                result = json.loads(raw)
            else:
                result = {}
            if response.status >= 300 or result.get("Error"):
                raise ValueError(result.get("Error") or "Служба Hydrat отклонила запрос.")
            return result
        except PermissionError:
            raise ValueError("Для доступа нужна группа hydrat-users. После добавления в неё войдите в систему заново.") from None
        except (OSError, http.client.HTTPException):
            raise ValueError("Служба Hydrat недоступна. Проверьте hydrat-app.service.") from None
        finally:
            with_connection.close()


def box(horizontal=False, gap=10):
    direction = Gtk.Orientation.HORIZONTAL if horizontal else Gtk.Orientation.VERTICAL
    return Gtk.Box(orientation=direction, spacing=gap)


def css(widget, style):
    widget.get_style_context().add_class(style)
    return widget


def label(value="", style=None):
    widget = Gtk.Label(label=value, xalign=0)
    widget.set_line_wrap(True)
    return css(widget, style) if style else widget


def add(parent, child, expand=False):
    parent.pack_start(child, expand, expand, 0)
    return child


def panel(title=None):
    result = css(box(), "panel")
    if title:
        add(result, label(title, "section"))
    return result


def scrolled(widget):
    view = Gtk.ScrolledWindow()
    view.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
    view.add(widget)
    return view


def button(text, clicked, style=None):
    result = Gtk.Button(label=text)
    result.connect("clicked", clicked)
    return css(result, style) if style else result


class Window(Gtk.ApplicationWindow):
    def __init__(self, application, api):
        super().__init__(application=application, title="Hydrat")
        self.api = api
        self.status = None
        self.polling = False
        self.busy = False
        self.closing = False
        self.inventory = None
        self.prefs_loaded = False
        self.geo_loaded = False
        self.set_default_size(760, 660)
        self.set_size_request(480, 440)
        css(self, "hydrat")
        root = box(gap=12)
        root.set_border_width(18)
        self.add(root)
        header = add(root, box(horizontal=True, gap=12))
        icon = Gtk.Image.new_from_pixbuf(GdkPixbuf.Pixbuf.new_from_file_at_scale(str(APP_DIR / "icon.png"), 30, 30, True))
        add(header, icon)
        add(header, label("Hydrat", "brand"))
        self.pages = Gtk.Stack()
        self.pages.set_transition_type(Gtk.StackTransitionType.NONE)
        switch = Gtk.StackSwitcher()
        switch.set_stack(self.pages)
        add(header, switch)
        add(root, self.pages, True)
        self.pages.add_titled(scrolled(self.overview()), "home", "Главная")
        self.pages.add_titled(scrolled(self.sources()), "sources", "Подключения")
        self.pages.add_titled(self.settings(), "settings", "Настройки")
        self.pages.connect("notify::visible-child-name", self.page_changed)
        self.connect("destroy", self.on_destroy)
        self.show_all()
        self.log_button.hide()
        self.refresh()
        self.timer = GLib.timeout_add_seconds(2, self.refresh)

    def on_destroy(self, *_):
        self.closing = True
        GLib.source_remove(self.timer)

    def request(self, method, path, body=None, *, complete, timeout=95, headers=None):
        def work():
            try:
                result, error = self.api.request(method, path, body, timeout, headers), None
            except (ValueError, TypeError) as exc:
                result, error = None, str(exc)
            GLib.idle_add(deliver, result, error)

        def deliver(result, error):
            if not self.closing:
                complete(result, error)
            return False

        threading.Thread(target=work, daemon=True).start()

    def action(self, method, path, body, message, pending, complete=None, *, headers=None):
        if self.busy:
            return
        self.busy = True
        message.set_text(pending)
        self.render_actions()

        def finished(result, error):
            self.busy = False
            self.render_actions()
            if error:
                message.set_text(error)
            elif complete:
                complete(result)
            self.refresh()

        self.request(method, path, body, complete=finished, headers=headers)

    def refresh(self):
        if self.polling:
            return True
        self.polling = True

        def received(status, error):
            self.polling = False
            self.status = status
            if error:
                self.connection.set_text("Статус VPN недоступен")
                self.connection_hint.set_text(error)
                self.log_button.show()
                self.render_actions()
                return
            self.render_status(status)

        self.request("GET", "/status", complete=received, timeout=3)
        return True

    def overview(self):
        page = box(gap=12)
        status = add(page, panel())
        self.connection = add(status, label("Загружаем состояние…", "headline"))
        self.connection_hint = add(status, label(style="muted"))
        self.connection_action = add(status, label(style="muted"))
        actions = add(status, box(horizontal=True))
        self.primary = add(actions, button("Подключить", self.toggle, "primary"))
        self.log_button = add(actions, button("Журнал службы", self.open_log))
        routes = add(page, panel("Маршруты"))
        grid = Gtk.Grid(row_spacing=8, column_spacing=18)
        self.routes = {}
        for row, (key, name) in enumerate((("tcp", "TCP"), ("udp", "UDP"), ("tcp_reserve", "Резерв TCP"), ("udp_reserve", "Резерв UDP"))):
            grid.attach(label(name, "muted"), 0, row, 1, 1)
            self.routes[key] = label("Маршрут не выбран")
            grid.attach(self.routes[key], 1, row, 1, 1)
        add(routes, grid)
        self.search = add(routes, label("Загружаем состояние…", "muted"))
        return page

    def open_log(self, _):
        self.connection_action.set_text("Откройте журнал в терминале: sudo journalctl -u hydrat-app")
        self.connection_action.set_selectable(True)

    def toggle(self, _):
        status = self.status
        if status is None:
            return
        if status["Connection"] == "requested":
            self.action("DELETE", "/connection", None, self.connection_action, "Отключаем VPN…",
                        lambda _: self.connection_action.set_text(""))
        elif status["Sources"] == 0:
            self.pages.set_visible_child_name("sources")
            self.input.grab_focus()
        else:
            self.action("POST", "/connection", None, self.connection_action, "Запускаем VPN…",
                        lambda _: self.connection_action.set_text(""))

    def render_status(self, status):
        connection = status["Connection"]
        tcp, udp = status["TCP"], status["UDP"]
        running = status["Running"]
        searching = status["SearchingSeconds"]
        hint, tone = "", None
        if connection == "failed":
            title, hint, tone = "Не удалось запустить VPN", "Подробности в журнале службы Hydrat.", "error"
        elif connection == "stopping":
            title = "Отключаем VPN…"
        elif status["Recovering"]:
            title, tone = "Восстанавливаем подключение…", "warning"
        elif tcp and udp:
            title, tone = "VPN подключён", "accent"
        elif tcp:
            title, tone = "VPN подключён · UDP недоступен", "warning"
        elif udp:
            title, tone = "VPN подключён · TCP недоступен", "warning"
        elif not status["Sources"]:
            title, hint = "Добавьте источник", "Подойдёт подписка, конфиг VLESS или мост Tor."
        elif running and searching >= 30:
            title = "Рабочий маршрут пока не найден"
        elif running:
            title = "Подбираем маршрут…"
        elif connection == "requested":
            title = "Запускаем VPN…"
        else:
            title = "VPN отключён"
        styles = self.connection.get_style_context()
        for item in ("error", "warning", "accent"):
            styles.remove_class(item)
        if tone:
            styles.add_class(tone)
        self.connection.set_text(title)
        self.connection_hint.set_text(hint)
        self.log_button.set_visible(connection == "failed")
        for role, widget in self.routes.items():
            reserve = "TCPReserveStatus" if role.startswith("tcp") else "UDPReserveStatus"
            widget.set_text("Проверяется" if role.endswith("reserve") and status[reserve] == "checking" else "Маршрут не выбран")
        for node in status.get("Nodes") or ():
            if node["Role"] not in self.routes:
                continue
            parts = [node["Label"] or "Маршрут", node["Protocol"].upper()]
            if node["LatencyMS"]:
                parts.append(f'{node["LatencyMS"]:.0f} мс')
            if node["ThroughputMbps"]:
                parts.append(f'{node["ThroughputMbps"]:.1f} Мбит/с')
            if node["State"] == "unavailable":
                parts.append("сбой")
            self.routes[node["Role"]].set_text(" · ".join(filter(None, parts)))
        if running:
            search = status["Search"]
            phase = {"search": "Поиск", "background": "Фоновый поиск", "paused": "Пауза", "waiting": "Ожидание"}.get(search["Mode"], "Проверки")
            if search["Workers"]:
                phase += f' · потоки: {search["Workers"]}'
            self.search.set_text(f'{phase} · Проверено {status["Checked"]}/{status["Candidates"]} · '
                                 f'Готово {status["Qualified"]} · Сохранено {status["Saved"]}')
        else:
            self.search.set_text(f'Нод в каталоге: {status["Candidates"]}')
        self.render_sources(status.get("Inventory") or [])
        self.render_actions()

    def render_actions(self):
        status = self.status
        connection = status["Connection"] if status else ""
        self.primary.set_sensitive(not self.busy and bool(status) and connection != "stopping")
        if status:
            if connection == "requested":
                title = "Отключить"
            elif connection == "stopping":
                title = "Отключаем…"
            elif not status["Sources"]:
                title = "Добавить источник"
            elif connection == "failed":
                title = "Подключить снова"
            else:
                title = "Подключить"
            self.primary.set_label(title)
        for widget in (self.import_button, self.suggested, self.refresh_button, self.remove, self.save, self.save_geo):
            widget.set_sensitive(not self.busy and bool(status))
        self.refresh_button.set_sensitive(not self.busy and bool(status and self.inventory))
        row = self.source_list.get_selected_row()
        self.remove.set_sensitive(not self.busy and bool(status and row))
        self.edit_hwid.set_sensitive(not self.busy and bool(status and row and row.source["Kind"] in SUBSCRIPTION_KINDS))
        self.save.set_sensitive(not self.busy and bool(status) and self.prefs_loaded)
        self.save_geo.set_sensitive(not self.busy and bool(status) and self.geo_loaded)
        self.input.set_editable(not self.busy)
        self.import_hwid.set_editable(not self.busy)

    def sources(self):
        page = box(gap=12)
        inventory = add(page, panel("Источники"))
        self.empty = add(inventory, label("Источников пока нет.", "muted"))
        self.source_list = Gtk.ListBox()
        self.source_list.set_selection_mode(Gtk.SelectionMode.SINGLE)
        self.source_list.connect("row-selected", lambda *_: self.render_actions())
        add(inventory, self.source_list)
        inventory_buttons = add(inventory, box(horizontal=True))
        self.refresh_button = add(inventory_buttons, button("Обновить", self.refresh_sources))
        self.edit_hwid = add(inventory_buttons, button("HWID источника", self.edit_source_hwid))
        self.remove = add(inventory_buttons, button("Удалить источник", self.delete_source, "danger"))
        importer = add(page, panel("Добавить источники"))
        add(importer, label("Вставьте ссылки на подписки или конфиги, по одной на строку.", "muted"))
        self.input = Gtk.TextView()
        self.input.set_wrap_mode(Gtk.WrapMode.CHAR)
        view = scrolled(self.input)
        view.set_min_content_height(106)
        add(importer, view)
        self.import_hwid = Gtk.Entry(max_length=64, placeholder_text="Общий HWID")
        add_field(importer, "HWID одной HTTPS-подписки", self.import_hwid)
        buttons = add(importer, box(horizontal=True))
        self.import_button = add(buttons, button("Импортировать", self.import_sources, "primary"))
        self.suggested = add(buttons, button("Добавить бесплатные подписки", self.import_suggested))
        self.source_notice = add(importer, label(style="muted"))
        return page

    def render_sources(self, inventory):
        if inventory == self.inventory:
            return
        selected = self.source_list.get_selected_row()
        selected_id = selected.source["ID"] if selected else None
        self.inventory = inventory
        for item in self.source_list.get_children():
            self.source_list.remove(item)
        for index, item in enumerate(inventory, 1):
            row = Gtk.ListBoxRow()
            row.source = item
            name = item["Label"] or f"Источник {index}"
            state = " · ошибка обновления" if item["Failed"] else ""
            if item.get("CustomHWID"):
                state += " · свой HWID"
            row.add(label(f'{name} · Ноды: {item["Candidates"]}{state}'))
            self.source_list.add(row)
            row.show_all()
            if item["ID"] == selected_id:
                self.source_list.select_row(row)
        self.empty.set_visible(not inventory)

    def import_sources(self, _):
        buffer = self.input.get_buffer()
        raw = buffer.get_text(*buffer.get_bounds(), True)
        hwid = self.import_hwid.get_text().strip()
        if not raw.strip():
            self.source_notice.set_text("Вставьте ссылку или конфиг.")
            self.input.grab_focus()
            return

        def completed(result):
            lines = raw.split("\n")
            retry, details = [], []
            for issue in result.get("Issues") or ():
                number = issue["Line"]
                if 1 <= number <= len(lines):
                    retry.append(lines[number - 1])
                    details.append(f'Строка {len(retry)} — {ISSUE_TEXT.get(issue["Reason"], "проверьте источник")}')
            buffer.set_text("\n".join(retry))
            if not retry:
                self.import_hwid.set_text("")
            self.source_notice.set_text("\n".join((self.import_summary(result), *details)))

        if hwid and not re.fullmatch(r"[A-Za-z0-9=-]{10,64}", hwid):
            self.source_notice.set_text("В HWID должно быть 10–64 символа: латиница, цифры, дефис или знак равенства.")
            self.import_hwid.grab_focus()
            return
        self.action("POST", "/sources/import", raw, self.source_notice, "Импортируем источники…", completed,
                    headers={"X-Hydrat-Source-HWID": hwid} if hwid else None)

    @staticmethod
    def import_summary(result):
        counts = [f"{name}: {result[key]}" for key, name in
                  (("Imported", "Добавлено"), ("Restored", "Восстановлено"), ("Skipped", "Уже в списке"),
                   ("Unavailable", "Некорректных строк"), ("RefreshFailed", "Ошибок загрузки")) if result.get(key)]
        return " · ".join(counts) or "Нет источников для импорта."

    def import_suggested(self, _):
        self.action("POST", "/sources/suggested", None, self.source_notice, "Проверяем подписки…",
                    lambda result: self.source_notice.set_text(self.import_summary(result)))

    def refresh_sources(self, _):
        self.action("POST", "/sources/refresh", None, self.source_notice, "Обновляем источники…",
                    lambda result: self.source_notice.set_text(f'Обновлено: {result["Updated"]} · Ошибок: {result["Failed"]}'))

    def edit_source_hwid(self, _):
        row = self.source_list.get_selected_row()
        if row is None or row.source["Kind"] not in SUBSCRIPTION_KINDS:
            return
        source = row.source
        path = "/sources/" + quote(source["ID"], safe="") + "/hwid"

        def loaded(result):
            self.source_notice.set_text("")
            dialog = css(Gtk.Dialog(title="HWID источника", transient_for=self, modal=True, destroy_with_parent=True), "hydrat")
            dialog.add_buttons("Отмена", Gtk.ResponseType.CANCEL, "Сохранить", Gtk.ResponseType.OK)
            dialog.set_default_response(Gtk.ResponseType.OK)
            content = dialog.get_content_area()
            content.set_border_width(16)
            content.set_spacing(8)
            add(content, label(source["Label"] or "Подписка", "section"))
            entry = add(content, Gtk.Entry(text=result["HWID"], max_length=64, placeholder_text="Общий HWID"))
            entry.set_activates_default(True)
            entry.get_accessible().set_name("HWID источника")
            add(content, label("Пустое поле использует общий HWID.", "muted"))
            content.show_all()
            response = dialog.run()
            value = entry.get_text().strip()
            dialog.destroy()
            if response == Gtk.ResponseType.OK:
                self.action("PUT", path, {"HWID": value}, self.source_notice, "Сохраняем HWID…",
                            lambda report: self.source_notice.set_text("HWID сохранён. Не удалось обновить источник."
                                                                     if report["Failed"] else "HWID сохранён. Источник обновлён."))

        self.action("GET", path, None, self.source_notice, "Загружаем HWID…", loaded)

    def delete_source(self, _):
        row = self.source_list.get_selected_row()
        if row is None:
            return
        source = row.source
        name = source["Label"] or "выбранный источник"
        dialog = Gtk.MessageDialog(transient_for=self, modal=True, message_type=Gtk.MessageType.QUESTION,
                                   buttons=Gtk.ButtonsType.OK_CANCEL, text=f"Удалить «{name}» и его ноды?")
        dialog.set_default_response(Gtk.ResponseType.CANCEL)
        response = dialog.run()
        dialog.destroy()
        if response == Gtk.ResponseType.OK:
            self.action("DELETE", "/sources/" + quote(source["ID"], safe=""), None, self.source_notice, "Удаляем источник…",
                        lambda _: self.source_notice.set_text("Источник удалён."))

    def settings(self):
        outer = box(gap=6)
        tabs = Gtk.Stack()
        switcher = Gtk.StackSwitcher()
        switcher.set_stack(tabs)
        add(outer, switcher)
        add(outer, tabs, True)
        tabs.add_titled(self.connection_settings(), "common", "Общие")
        tabs.add_titled(self.geo_settings(), "geo", "GeoIP / GeoSite")
        tabs.add_titled(scrolled(self.update_settings()), "updates", "Обновления")
        return outer

    def update_settings(self):
        page = box()
        card = add(page, panel("Обновления"))
        try:
            version = (APP_DIR / "VERSION").read_text().strip()
        except OSError:
            version = ""
        self.installed_version = add(card, label(f"Установлена версия {version}" if version else "Установленная версия", "muted"))
        self.check_update_button = add(card, button("Проверить обновления", self.check_update))
        self.check_update_button.set_halign(Gtk.Align.START)
        self.update_notice = add(card, label(style="muted"))
        self.download_update = add(card, Gtk.LinkButton(label="Скачать DEB"))
        self.download_update.set_halign(Gtk.Align.START)
        self.download_update.set_no_show_all(True)
        return page

    def check_update(self, _):
        self.check_update_button.set_sensitive(False)
        self.download_update.hide()
        self.update_notice.set_text("Проверяем обновления…")

        def checked(result, error):
            self.check_update_button.set_sensitive(True)
            if error:
                self.update_notice.set_text(error)
                return
            self.installed_version.set_text(f'Установлена версия {result["Current"]}')
            if result["DownloadURL"]:
                self.update_notice.set_text(f'Доступна версия {result["Latest"]}')
                self.download_update.set_uri(result["DownloadURL"])
                self.download_update.show()
            else:
                self.update_notice.set_text("Установлена актуальная версия." if result["Latest"] else "Подходящих релизов пока нет.")

        self.request("GET", "/updates", complete=checked, timeout=16)

    def connection_settings(self):
        page, fields = box(), box()
        self.fields = {}
        conn = add(fields, panel("Подключение"))
        self.dns = Gtk.ComboBoxText()
        for name in ("Авто", "Cloudflare", "Quad9", "Google"):
            self.dns.append_text(name)
        self.dns.set_active(0)
        add_field(conn, "DNS-резолвер", self.dns)
        self.geo_rules = add(conn, Gtk.CheckButton(label="Правила GeoIP и GeoSite"))
        search = add(fields, panel("Поиск и качество"))
        for key, name, low, high in (
            ("FastWorkers", "Проверок при подключении", 1, 8),
            ("BackgroundWorkers", "Проверок в фоне", 1, 8),
            ("MinVLESSScore", "Порог качества VLESS", 50, 100),
            ("BackgroundIntervalSeconds", "Интервал поиска, с", 15, 900),
        ):
            widget = Gtk.SpinButton.new_with_range(low, high, 1)
            self.fields[key] = widget
            add_field(search, name, widget)
        sources = add(fields, panel("Подписки"))
        interval = Gtk.SpinButton.new_with_range(15, 1440, 1)
        self.fields["SourceRefreshMinutes"] = interval
        add_field(sources, "Обновлять каждые, мин", interval)
        self.hwid = Gtk.Entry(max_length=64, placeholder_text="Автоматически")
        add_field(sources, "HWID для VLESS", self.hwid)
        add(sources, label("10–64 символа. Латиница, цифры, дефис и знак равенства.", "muted"))
        add(page, scrolled(fields), True)
        add(page, label("Настройки подключения применяются при следующем подключении.", "muted"))
        self.settings_notice = add(page, label(style="muted"))
        self.save = add(page, button("Сохранить", self.save_settings, "primary"))
        self.save.set_halign(Gtk.Align.END)
        return page

    def geo_settings(self):
        page, fields = box(), box()
        self.geofields = {}
        for group, specs in (
            ("Базы", (("IPURL", "Ссылка на GeoIP"), ("SiteURL", "Ссылка на GeoSite"))),
            ("Правила маршрутизации", (("TunnelIP", "GeoIP через VPN"), ("DirectIP", "GeoIP напрямую"),
                                      ("TunnelSite", "GeoSite через VPN"), ("DirectSite", "GeoSite напрямую"))),
        ):
            card = add(fields, panel(group))
            if group == "Базы":
                add(card, label("Укажите HTTPS-ссылки на .dat. Пустые поля используют встроенные базы.", "muted"))
            for key, name in specs:
                widget = Gtk.Entry(max_length=4096)
                self.geofields[key] = widget
                add_field(card, name, widget)
        add(page, scrolled(fields), True)
        add(page, label("Правила применяются при следующем подключении.", "muted"))
        self.geo_notice = add(page, label(style="muted"))
        self.save_geo = add(page, button("Проверить и сохранить", self.save_geo_rules, "primary"))
        self.save_geo.set_halign(Gtk.Align.END)
        return page

    def page_changed(self, *_):
        if self.pages.get_visible_child_name() != "settings":
            return

        def connected(result, error):
            if error:
                self.settings_notice.set_text(error)
                return
            self.dns.set_active(result["DNSPreset"])
            self.geo_rules.set_active(result["GeoRules"])
            self.hwid.set_text(result["HWID"])
            for key, widget in self.fields.items():
                widget.set_value(result[key])
            self.prefs_loaded = True
            self.render_actions()

        def geo_loaded(result, error):
            if error:
                self.geo_notice.set_text(error)
                return
            for key, widget in self.geofields.items():
                widget.set_text(result[key])
            self.geo_loaded = True
            self.render_actions()

        if not self.prefs_loaded:
            self.request("GET", "/settings", complete=connected, timeout=5)
        if not self.geo_loaded:
            self.request("GET", "/settings/geo", complete=geo_loaded, timeout=5)

    def save_settings(self, _):
        values = {key: widget.get_value_as_int() for key, widget in self.fields.items()}
        values.update(DNSPreset=self.dns.get_active(), GeoRules=self.geo_rules.get_active(),
                      HWID=self.hwid.get_text().strip())
        self.action("PUT", "/settings", values, self.settings_notice, "Сохраняем…",
                    lambda _: self.settings_notice.set_text("Настройки сохранены."))

    def save_geo_rules(self, _):
        values = {key: widget.get_text().strip() for key, widget in self.geofields.items()}
        self.action("PUT", "/settings/geo", values, self.geo_notice, "Проверяем правила…",
                    lambda _: self.geo_notice.set_text("Правила сохранены."))


def add_field(parent, title, widget):
    row = add(parent, box(horizontal=True, gap=12))
    field_label = add(row, label(title, "muted"))
    field_label.set_size_request(155, -1)
    field_label.set_mnemonic_widget(widget)
    add(row, widget, not isinstance(widget, Gtk.SpinButton))


def main():
    args = argparse.ArgumentParser()
    args.add_argument("--socket", default=SOCKET)
    api = LocalAPI(args.parse_args().socket)
    application = Gtk.Application(application_id="org.hydrat.App")

    def activate(app):
        window = app.get_active_window()
        if window is None:
            provider = Gtk.CssProvider()
            provider.load_from_path(str(APP_DIR / "theme.css"))
            Gtk.StyleContext.add_provider_for_screen(Gdk.Screen.get_default(), provider,
                                                     Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION)
            window = Window(app, api)
        window.present()

    application.connect("activate", activate)
    return application.run([])


if __name__ == "__main__":
    raise SystemExit(main())
